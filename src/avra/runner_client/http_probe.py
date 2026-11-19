"""Windows-side ``http_probe`` pipeline (ADR 0007, M8.1).

Same shape as ``run_nmap_connect_scan`` (M6):

1. Windows-side policy: the request must be in the Orchestrator's own scope
   for ``http_probe`` at the registry-fixed tier (passive). Default deny:
   no scope lists this tool today, so nothing is sent.
2. Audit ``tool_request_sent`` (fail closed if it can't be written).
3. Tunnel + health + one run request; the Runner re-checks its own scope.
4. Verify: request_id matches, output hash matches; store the envelope as
   write-once evidence; check the envelope (exact bytes, hashes, pairing)
   and parse the HTTP response — read, never repair.
5. Audit the outcome — hashes, sizes, flags, indication *sources*; no
   server-controlled text goes into the audit log.

Not exposed to the model. M8.3: reached only via ``avra probe http``,
which passes ``approval`` after an interactive owner confirmation.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from avra.control.killswitch import KillSwitch, KillSwitchEngaged
from avra.policy.scope import ScopeChecker
from avra.policy.tools import authorize_tool_request
from avra.recon.http_probe import (
    HttpProbeEnvelope,
    HttpProbeError,
    HttpResponseFacts,
    parse_envelope,
    parse_http_response,
)
from avra.runner.schemas import (
    HttpGetPathRequest,
    HttpProbeRequest,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner_client.client import RunnerClient, RunnerClientError, RunnerToken
from avra.runner_client.stop import (
    call_interruptibly,
    cancel_after_interrupt,
    record_unfinished_request,
)
from avra.runner_client.tunnel import SshTunnel, TunnelConfig, TunnelError
from avra.storage.audit import AuditLog
from avra.storage.evidence import EvidenceError, EvidenceRef, store_evidence


@dataclass
class HttpProbeOutcome:
    request: HttpProbeRequest | HttpGetPathRequest
    allowed_locally: bool
    local_reason: str
    result: ToolRunResult | None = None
    rejection: RunnerRejection | None = None
    hash_verified: bool | None = None
    evidence: EvidenceRef | None = None
    envelope: HttpProbeEnvelope | None = None
    facts: HttpResponseFacts | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """The probe ran and its evidence is trustworthy. Says nothing about
        whether the target answered (see ``envelope.outcome``)."""
        return (
            self.allowed_locally
            and self.result is not None
            and self.result.status is ToolRunStatus.COMPLETED
            and self.result.exit_code == 0
            and self.hash_verified is True
            and self.evidence is not None
            and self.evidence.sha256 == self.result.output_sha256
            and self.envelope is not None
            and not self.errors
        )


# The only accepted approval: the owner typed "y" at the CLI's TTY prompt.
APPROVAL_INTERACTIVE_TTY = "interactive_tty_confirm"

TunnelFactory = Callable[[TunnelConfig], SshTunnel]
ClientFactory = Callable[[str, RunnerToken], RunnerClient]


def run_http_probe(
    *,
    checker: ScopeChecker,
    audit: AuditLog,
    session_id: uuid.UUID,
    host: str,
    port: int,
    timeout_seconds: int,
    token: RunnerToken,
    evidence_root: Path,
    tunnel_cfg: TunnelConfig,
    approval: str | None = None,
    tunnel_factory: TunnelFactory = SshTunnel,
    client_factory: ClientFactory = RunnerClient,
    killswitch: KillSwitch | None = None,
    notify: Callable[[str], None] | None = None,
    path: str | None = None,
    request_id: uuid.UUID | None = None,
) -> HttpProbeOutcome:
    """``approval`` must be ``APPROVAL_INTERACTIVE_TTY`` — set by the CLI only
    after the owner explicitly confirmed in a real terminal (M8.3). Anything
    else is refused before a tunnel is opened, even if scope allows it."""
    # M10.5 (ADR 0018): with ``path`` this is an http_get_path request (same gates).
    # M14.2 (ADR 0022): ``request_id`` lets an investigation record the id BEFORE sending, so
    # its result correlates; it only names the request and passes no gate.
    rid = request_id or uuid.uuid4()
    if path is None:
        request = HttpProbeRequest(request_id=rid, session_id=session_id, host=host,
                                   port=port, timeout_seconds=timeout_seconds)
    else:
        request = HttpGetPathRequest(request_id=rid, session_id=session_id,
                                     host=host, port=port, path=path,
                                     timeout_seconds=timeout_seconds)
    base = {"request_id": str(request.request_id), "tool": request.tool.value,
            "host": request.host, "port": request.port,
            "timeout_seconds": request.timeout_seconds,
            **({} if path is None else {"path": path})}

    decision = authorize_tool_request(checker, request)
    outcome = HttpProbeOutcome(request, decision.allowed, decision.reason)
    if not decision.allowed:
        audit.record("tool_request_denied_locally", {**base, "reason": decision.reason})
        return outcome
    if approval != APPROVAL_INTERACTIVE_TTY:
        outcome.allowed_locally = False
        outcome.local_reason = "no interactive owner approval"
        audit.record("tool_request_denied_locally", {**base, "reason": outcome.local_reason})
        return outcome

    # Kill switch (M8.7 Stage 3): see runner_client.scan.
    stack = ExitStack()
    try:
        ticket = stack.enter_context(
            (killswitch or KillSwitch()).active(request.tool.value, session_id=str(session_id)))
    except KillSwitchEngaged as exc:
        outcome.allowed_locally, outcome.local_reason = False, "kill switch engaged"
        audit.record("tool_request_denied_locally", {**base, "reason": outcome.local_reason,
                                                     "kill_switch": exc.status.latch.value})
        return outcome
    # M8.8 (F-1): whatever leaves the pipeline from here on - Ctrl+C or an
    # error, before or after the Runner answered - the sent request still gets
    # exactly one terminal audit record (see record_unfinished_request).
    run = None
    try:
        with stack:
            audit.record("tool_request_sent", {**base, "local_policy": decision.reason,
                                               "approval": approval})
            submitted = False
            try:
                ticket.check("before_tunnel")
                with tunnel_factory(tunnel_cfg) as base_url:
                    client = client_factory(base_url, token)
                    call_interruptibly(client.health)
                    submitted = True  # from here the Runner may have the request
                    run = call_interruptibly(client.run, request)
            except KeyboardInterrupt:
                # M8.7 Stage 5: terminal record + one bounded cancel of THIS job,
                # then the interrupt continues (never swallowed).
                cancel_after_interrupt(audit=audit, base=base, request_id=request.request_id,
                                       session_id=request.session_id, submitted=submitted,
                                       token=token, tunnel_cfg=tunnel_cfg,
                                       tunnel_factory=tunnel_factory,
                                       client_factory=client_factory, notify=notify)
                raise
            except (TunnelError, RunnerClientError, KillSwitchEngaged) as exc:
                outcome.errors.append(f"{type(exc).__name__}: {exc}")
                audit.record("tool_request_failed", {**base, "error": type(exc).__name__,
                                                     "detail": str(exc)[:500],
                                                     "errors": list(outcome.errors)})
                return outcome

        if run.rejection is not None:
            outcome.rejection = run.rejection
            audit.record("tool_request_rejected", {**base, "http_status": run.http_status,
                                                   "stage": run.rejection.stage.value,
                                                   "reason": run.rejection.reason})
            return outcome

        result = run.result
        outcome.result, outcome.hash_verified = result, run.hash_verified
        record = {**base, "status": result.status.value, "exit_code": result.exit_code,
                  "output_sha256": result.output_sha256, "hash_verified": run.hash_verified,
                  "output_truncated": result.output_truncated, "reason": result.reason,
                  "started_at": result.started_at.isoformat() if result.started_at else None,
                  "finished_at": result.finished_at.isoformat() if result.finished_at else None}

        if result.raw_output is not None:
            try:
                outcome.evidence = store_evidence(evidence_root, session_id, request.request_id,
                                                  ".json", result.raw_output.encode("utf-8"))
                record.update(evidence_path=str(outcome.evidence.path),
                              evidence_sha256=outcome.evidence.sha256)
            except (EvidenceError, OSError) as exc:
                outcome.errors.append(f"evidence: {exc}")
        if run.hash_verified is not True:
            outcome.errors.append("output hash could not be verified")

        if result.status is ToolRunStatus.CANCELLED:
            # M8.7: stopped on request; nothing it produced is evidence.
            outcome.errors.append(f"cancelled by the Runner ({result.reason}); not evidence")
        if result.status is ToolRunStatus.COMPLETED:
            if result.exit_code != 0:
                outcome.errors.append(f"http_probe exited with code {result.exit_code}")
            elif result.raw_output is not None:
                try:
                    env, _req, resp = parse_envelope(result.raw_output, host=request.host,
                                                     port=request.port, path=path)
                    outcome.envelope = env
                    # Partial bytes before a reset/error are still evidence: read them.
                    if env.outcome in ("response_received", "read_timeout") or resp:
                        outcome.facts = parse_http_response(resp, complete=env.complete,
                                                            truncated=env.truncated)
                    f = outcome.facts
                    record.update(
                        probe_outcome=env.outcome, probe_error=env.error,
                        request_sha256=env.request_sha256, response_sha256=env.response_sha256,
                        response_bytes=env.response_bytes, response_truncated=env.truncated,
                        response_complete=env.complete,
                        protocol_observed=bool(f and f.protocol_observed),
                        http_status_code=f.status_code if f else None,
                        is_redirect=bool(f and f.is_redirect), binary=bool(f and f.binary),
                        body_sha256=f.body_sha256 if f else None,
                        indication_sources=[i.source for i in f.indications] if f else [],
                        malformed_count=len(f.malformed) if f else 0)
                except HttpProbeError as exc:
                    outcome.errors.append(f"envelope: {exc}")

        record["errors"] = outcome.errors
        audit.record("tool_result_received", record)
        return outcome
    except BaseException as exc:
        record_unfinished_request(audit=audit, base=base, exc=exc, run=run, outcome=outcome)
        raise
