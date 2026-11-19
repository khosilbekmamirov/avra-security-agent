"""Stop-only Runner transport (ADR 0012 Stage 5).

The ONLY way AVRA reaches the Runner while the local kill switch blocks.
It deliberately does not consult the kill switch - it cannot start work:

- it opens the usual restricted SSH tunnel (same fixed argv, pinned host
  key, loopback only) and talks to the Runner through ``StopOnlyClient``,
  which exposes exactly two methods: ``cancel`` and ``emergency_stop``
  (``/v1/tools/cancel``, ``/v1/emergency-stop``). There is no ``run``, no
  ``health``, no generic request method and no reset (the Runner has none);
- every call is bounded (tunnel ready timeout <= 15 s, HTTP timeout 15/20 s,
  16 KiB response cap) and never retried;
- even if a caller reached the underlying ``RunnerClient``, its ``run``
  refuses while the latch blocks.

Results are ``StopCallResult``s: only an explicit, schema-valid Runner
answer can confirm anything. A delivered request, a 404 (older Runner), a
timeout or a reset connection all mean UNCONFIRMED.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import replace
from uuid import UUID

from avra.runner.schemas import CancelReason, EmergencyReason
from avra.runner_client.client import RunnerClient, RunnerToken, StopCallResult
from avra.runner_client.tunnel import SshTunnel, TunnelConfig, TunnelError

STOP_TUNNEL_READY_TIMEOUT = 15.0


class StopOnlyClient:
    """A RunnerClient view that can only stop things."""

    __slots__ = ("_client",)

    def __init__(self, client: RunnerClient) -> None:
        self._client = client

    def cancel(self, request_id: UUID, session_id: UUID, reason: CancelReason) -> StopCallResult:
        return self._client.cancel(request_id, session_id, reason)

    def emergency_stop(self, reason: EmergencyReason) -> StopCallResult:
        return self._client.emergency_stop(reason)


TunnelFactory = Callable[[TunnelConfig], SshTunnel]
ClientFactory = Callable[[str, RunnerToken], RunnerClient]


def _stop_tunnel_cfg(cfg: TunnelConfig) -> TunnelConfig:
    return replace(cfg, ready_timeout=min(cfg.ready_timeout, STOP_TUNNEL_READY_TIMEOUT))


def _with_stop_client(fn, *, token: RunnerToken, tunnel_cfg: TunnelConfig,
                      tunnel_factory: TunnelFactory, client_factory: ClientFactory
                      ) -> StopCallResult:
    try:
        with tunnel_factory(_stop_tunnel_cfg(tunnel_cfg)) as base_url:
            return fn(StopOnlyClient(client_factory(base_url, token)))
    except TunnelError as exc:
        return StopCallResult("transport", detail=f"tunnel: {str(exc).splitlines()[0][:120]}")
    except KeyboardInterrupt:  # the operator gave up waiting: say so, then stop
        raise
    except Exception as exc:  # noqa: BLE001 - a stop attempt must never crash its caller
        return StopCallResult("transport", detail=type(exc).__name__)


def remote_cancel(*, request_id: UUID, session_id: UUID, reason: CancelReason,
                  token: RunnerToken, tunnel_cfg: TunnelConfig,
                  tunnel_factory: TunnelFactory = SshTunnel,
                  client_factory: ClientFactory = RunnerClient) -> StopCallResult:
    """One bounded cancel attempt for ONE job over a fresh restricted tunnel."""
    return _with_stop_client(lambda c: c.cancel(request_id, session_id, reason), token=token,
                             tunnel_cfg=tunnel_cfg, tunnel_factory=tunnel_factory,
                             client_factory=client_factory)


REMOTE_UNCONFIRMED = "REMOTE CANCELLATION UNCONFIRMED"
_WAIT_STEP_SECONDS = 0.2


def call_interruptibly(fn, *args):
    """Run a blocking Runner call so Ctrl+C takes effect at once (Stage 7
    finding): on Windows a KeyboardInterrupt is only delivered when the main
    thread runs Python code, so a socket read blocked inside ``urllib`` held
    Ctrl+C back until the Runner answered (measured: 67 s, i.e. the job's own
    timeout - too late to cancel anything). The call runs in a daemon worker;
    the main thread waits in short steps and receives the interrupt within
    ~0.2 s. The caller then cancels the job and closes the tunnel, which ends
    the worker's connection; its late result, if any, is discarded."""
    box: dict = {}

    def work() -> None:
        try:
            box["value"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller's thread
            box["error"] = exc

    worker = threading.Thread(target=work, name="avra-runner-call", daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(_WAIT_STEP_SECONDS)
    if "error" in box:
        raise box["error"]
    return box["value"]


def _safe_record(audit, event: str, data: dict) -> bool:
    """Stop paths: an audit failure is reported, never a reason to skip stopping."""
    try:
        audit.record(event, data)
        return True
    except Exception:  # noqa: BLE001
        return False


# Records that END a submitted request's story in the session audit.
TERMINAL_TOOL_EVENTS = frozenset({"tool_result_received", "tool_request_interrupted",
                                  "tool_request_failed", "tool_request_rejected",
                                  "tool_request_denied_locally"})


def _terminal_recorded(audit, request_id: str) -> bool:
    """True if the session audit already holds a terminal record for this request.
    Unreadable log -> False (the caller then attempts its own record)."""
    try:
        return any(r.event in TERMINAL_TOOL_EVENTS and isinstance(r.data, dict)
                   and r.data.get("request_id") == request_id for r in audit.read_all())
    except Exception:  # noqa: BLE001 - deciding about a stop record must not crash
        return False


def record_unfinished_request(*, audit, base: dict, exc: BaseException, run, outcome) -> None:
    """M8.8 (F-1): the pipeline is being left by an exception or Ctrl+C.

    Guarantees one terminal record for a sent request, without duplicates:
    if a terminal record already exists (the tunnel-phase handlers, or a
    ``tool_result_received`` that was durably written just before the
    interrupt), nothing is added. Otherwise:

    * ``run`` is set (the Runner already answered): ``phase: after_result``.
      The job is finished, so NO cancel is ever sent. The record carries the
      Runner's status and ``output_sha256`` and, if stored, the evidence hash
      and path, so evidence written before the interrupt stays traceable.
    * ``run`` is None: ``phase: before_result`` (an unexpected error; a
      Ctrl+C in that phase is handled by ``cancel_after_interrupt``).

    KeyboardInterrupt -> ``tool_request_interrupted``; anything else (e.g. an
    audit write failure) -> ``tool_request_failed``: a failed write is never
    reported as a completed request. The caller re-raises ``exc``."""
    if _terminal_recorded(audit, base["request_id"]):
        return
    data = {**base, "submitted": True if run is not None else None,
            "phase": "after_result" if run is not None else "before_result"}
    if run is not None:
        result = run.result
        evidence = getattr(outcome, "evidence", None)
        data.update(
            remote_cancel="not sent: the Runner had already answered",
            http_status=run.http_status,
            runner_rejection_stage=run.rejection.stage.value if run.rejection else None,
            result_status=result.status.value if result else None,
            exit_code=result.exit_code if result else None,
            output_sha256=result.output_sha256 if result else None,
            evidence_sha256=evidence.sha256 if evidence else None,
            evidence_path=str(evidence.path) if evidence else None)
    if isinstance(exc, KeyboardInterrupt):
        _safe_record(audit, "tool_request_interrupted", data)
        return
    detail = f"{type(exc).__name__}: {str(exc)[:300]}"
    errors = [*getattr(outcome, "errors", []), detail]
    _safe_record(audit, "tool_request_failed", {**data, "error": type(exc).__name__,
                                                "detail": str(exc)[:500], "errors": errors})


def cancel_after_interrupt(*, audit, base: dict, request_id: UUID, session_id: UUID,
                           submitted: bool, token: RunnerToken, tunnel_cfg: TunnelConfig,
                           tunnel_factory: TunnelFactory = SshTunnel,
                           client_factory: ClientFactory = RunnerClient,
                           notify: Callable[[str], None] | None = None) -> StopCallResult | None:
    """Ctrl+C during a Runner request (scan/probe pipelines). Records a
    terminal ``tool_request_interrupted``; if the request may have reached
    the Runner, makes ONE bounded cancel attempt for exactly this job and
    records what the Runner confirmed. The caller re-raises the interrupt.

    The tunnel closing may already have cancelled the job (Stage 4
    disconnect-cancel); the Runner then answers already_cancelled /
    already_finished / not_active - all confirmations that it is not running."""
    say = notify or (lambda text: None)
    _safe_record(audit, "tool_request_interrupted", {**base, "submitted": submitted})
    if not submitted:
        say("Interrupted before the request was sent to the Runner; nothing to cancel.")
        return None
    ids = {"request_id": str(request_id), "session_id": str(session_id)}
    _safe_record(audit, "remote_cancel_requested", {**ids, "reason": "client_interrupt"})
    say("Interrupted - asking the Runner to cancel this job (press Ctrl+C again to give up)...")
    try:
        res = remote_cancel(request_id=request_id, session_id=session_id,
                            reason=CancelReason.CLIENT_INTERRUPT, token=token,
                            tunnel_cfg=tunnel_cfg, tunnel_factory=tunnel_factory,
                            client_factory=client_factory)
    except KeyboardInterrupt:
        res = StopCallResult("interrupted", detail="operator interrupted the cancel attempt")
    data = {**ids, "category": res.category, "http_status": res.http_status,
            "outcome": res.cancel.outcome.value if res.cancel else None}
    if res.cancel_confirmed:
        _safe_record(audit, "remote_cancel_confirmed", data)
        say(f"Runner confirmed: {res.cancel.outcome.value} - the job is not running.")
    else:
        _safe_record(audit, "remote_cancel_unconfirmed", data)
        what = res.cancel.outcome.value if res.cancel else res.category
        say(f"{REMOTE_UNCONFIRMED} ({what}). The job may still be running on the Runner "
            "until its own timeout.")
    return res


def remote_emergency_stop(*, reason: EmergencyReason, token: RunnerToken,
                          tunnel_cfg: TunnelConfig, tunnel_factory: TunnelFactory = SshTunnel,
                          client_factory: ClientFactory = RunnerClient) -> StopCallResult:
    """One bounded emergency-stop attempt over a fresh restricted tunnel."""
    return _with_stop_client(lambda c: c.emergency_stop(reason), token=token,
                             tunnel_cfg=tunnel_cfg, tunnel_factory=tunnel_factory,
                             client_factory=client_factory)
