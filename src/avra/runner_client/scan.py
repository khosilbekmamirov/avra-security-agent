"""One end-to-end nmap_connect_scan from Windows (ADR 0003, M6.5).

Order — each step must succeed before the next:

1. Windows-side policy: the request must be in the Orchestrator's own scope
   (default deny). Denied → audited, nothing leaves Windows.
2. Audit ``tool_request_sent`` BEFORE sending (fail closed: if the audit
   log can't record it, the request is not sent).
3. Tunnel → health → run. The Runner checks its own scope again.
4. Verify: request_id matches, output hash matches; store the raw output
   as evidence (exclusive create) and parse it with defusedxml.
5. Audit the outcome — hashes, status, parsed port states, evidence path.
   Never the token, never the raw output itself.

Observations only: a port state is not a finding.
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
from avra.recon.nmap_xml import NmapReport, NmapXmlError, parse_nmap_xml
from avra.runner.schemas import (
    NmapConnectScanRequest,
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
class ScanOutcome:
    request: NmapConnectScanRequest
    allowed_locally: bool
    local_reason: str
    result: ToolRunResult | None = None
    rejection: RunnerRejection | None = None
    hash_verified: bool | None = None
    evidence: EvidenceRef | None = None
    report: NmapReport | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.allowed_locally
            and self.result is not None
            and self.result.status is ToolRunStatus.COMPLETED
            and self.hash_verified is True
            and self.evidence is not None
            and self.evidence.sha256 == self.result.output_sha256
            and self.report is not None
            and not self.errors
        )


TunnelFactory = Callable[[TunnelConfig], SshTunnel]
ClientFactory = Callable[[str, RunnerToken], RunnerClient]


def run_nmap_connect_scan(
    *,
    checker: ScopeChecker,
    audit: AuditLog,
    session_id: uuid.UUID,
    host: str,
    ports: list[int],
    timeout_seconds: int,
    token: RunnerToken,
    evidence_root: Path,
    tunnel_cfg: TunnelConfig,
    tunnel_factory: TunnelFactory = SshTunnel,
    client_factory: ClientFactory = RunnerClient,
    killswitch: KillSwitch | None = None,
    notify: Callable[[str], None] | None = None,
    request_id: uuid.UUID | None = None,
) -> ScanOutcome:
    # M14.2: see run_http_probe - an investigation's pre-recorded request id
    request = NmapConnectScanRequest(
        request_id=request_id or uuid.uuid4(), session_id=session_id, host=host,
        ports=ports, timeout_seconds=timeout_seconds,
    )
    base = {"request_id": str(request.request_id), "tool": request.tool.value,
            "host": request.host, "ports": list(request.ports),
            "timeout_seconds": request.timeout_seconds}

    decision = authorize_tool_request(checker, request)
    outcome = ScanOutcome(request, decision.allowed, decision.reason)
    if not decision.allowed:
        audit.record("tool_request_denied_locally", {**base, "reason": decision.reason})
        return outcome

    # Kill switch (M8.7 Stage 3): checked and registered as running work before
    # anything is recorded as sent; re-checked right before the tunnel opens.
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
            audit.record("tool_request_sent", {**base, "local_policy": decision.reason})
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
                # "errors" is the exact list the report shows (M7.9.2 replay); it is
                # the same text the report file already contains, nothing new.
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
                outcome.evidence = store_evidence(
                    evidence_root, session_id, request.request_id, ".xml",
                    result.raw_output.encode("utf-8"),
                )
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
            # A nonzero process exit must never be reported as clean evidence.
            if result.exit_code not in (0, None):
                outcome.errors.append(f"nmap exited with code {result.exit_code}")
            if result.raw_output is not None:
                try:
                    outcome.report = parse_nmap_xml(result.raw_output)
                    # nmap's own runstats verdict: "error" means the scan is incomplete.
                    if outcome.report.exit_status == "error":
                        outcome.errors.append("nmap runstats reported exit=error (incomplete scan)")
                    record["nmap_exit_status"] = outcome.report.exit_status
                    record["host_statuses"] = [{"host": h.address, "status": h.status}
                                               for h in outcome.report.hosts]
                    record["port_states"] = [
                        {"host": h.address, "port": p.port, "state": p.state, "reason": p.reason,
                         "service": p.service, "service_method": p.service_method,
                         "service_confidence": p.service_confidence}
                        for h in outcome.report.hosts for p in h.ports
                    ]
                except NmapXmlError as exc:
                    outcome.errors.append(f"parse: {exc}")

        record["errors"] = outcome.errors
        audit.record("tool_result_received", record)
        return outcome
    except BaseException as exc:
        record_unfinished_request(audit=audit, base=base, exc=exc, run=run, outcome=outcome)
        raise
