"""Runner core: the single entry point for tool requests (ADR 0003,
M2.2b Part 2; cancellation and emergency stop: ADR 0012 Stage 4).

``Runner.handle(payload)`` is the only path from a request to a process:

    audit "request_received"         (fail closed if it can't be written)
    emergency latch not READY        -> audit "request_denied" (emergency_stop)
    RunnerPolicy.authorize_request   (registry + schema + Runner's own scope)
      denied  -> audit "request_denied"  -> RunnerRejection, nothing runs
      allowed -> [under the state lock] latch re-check, tombstone check,
                 register the ActiveJob
              -> audit "execution_started" (fail closed if it can't be written)
              -> executor.run(argv from the registry, fixed limits, job cancel event)
              -> audit "execution_finished" (incl. cancel_requested / reason)
              -> ToolRunResult

Cancellation (``cancel``) and emergency stop (``emergency_stop``) never take
the execution lock; they use a separate, short state lock, so they work
while a job runs. A cancel names ONE job by request_id AND session_id; it
can only set that job's cancel event - the executor then stops the
process group IT created. No PID, signal or path ever comes from a request.

Job lifecycle (one at a time, deterministic):

    (none) --register--> ACCEPTED --execution_started--> RUNNING --> FINISHED
      cancel before register  -> tombstone (TTL, bounded): that run is refused
      cancel while ACCEPTED/RUNNING -> event set; the executor ends it as CANCELLED
        (or it had already EXITED: the cancel answer is already_finished)
      cancel after FINISHED   -> already_finished / already_cancelled (bounded memory)

Audit records never contain the raw payload or raw tool output — only
hashes, sizes and validated fields — so nothing a requester sends and
nothing a tool prints ends up in the log verbatim.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol
from uuid import UUID

from pydantic import ValidationError

from avra.runner.emergency import RunnerLatch
from avra.runner.execution import (
    DEFAULT_MAX_STDERR_BYTES,
    DEFAULT_MAX_STDOUT_BYTES,
    ExecutionLimits,
    ProcessOutcome,
    ProcessResult,
)
from avra.runner.policy import Authorized, Denied, RunnerPolicy
from avra.runner.registry import get_tool, registered_tools
from avra.runner.schemas import (
    MAX_REASON_CHARS,
    CancelOutcome,
    CancelRequest,
    CancelResponse,
    EmergencyStopRequest,
    EmergencyStopResponse,
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)

# Extra wall-clock time on top of the tool's own timeout (nmap's
# --host-timeout), so the tool can finish cleanly before it's killed.
PROCESS_TIMEOUT_GRACE_SECONDS = 10
TOMBSTONE_TTL_SECONDS = 900.0
MAX_TOMBSTONES = 256
MAX_RECENT_JOBS = 64
CANCEL_WAIT_SECONDS = 6.0  # > kill grace (2 s) + reap; then "requested" is answered
STATE_LOCK_TIMEOUT_SECONDS = 5.0


class ToolExecutor(Protocol):
    @property
    def executables(self) -> Mapping[str, str]: ...

    def run(self, argv: Sequence[str], limits: ExecutionLimits,
            cancel: threading.Event | None = None) -> ProcessResult: ...


class AuditSink(Protocol):
    def record(self, event: str, data: dict[str, Any] | None = None) -> Any: ...


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _payload_digest(payload: object) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True, default=repr, separators=(",", ":"))
    except (TypeError, ValueError, RecursionError):
        raw = repr(type(payload))
    return _sha256(raw.encode("utf-8", errors="replace"))


def _request_id_of(payload: object) -> UUID | None:
    if isinstance(payload, dict):
        try:
            return UUID(str(payload.get("request_id")))
        except (ValueError, TypeError, AttributeError):
            return None
    return None


def _tool_label(payload: object) -> str:
    """Tool name for the log — only if it's a registered one, never echo
    arbitrary requester text."""
    name = payload.get("tool") if isinstance(payload, dict) else None
    return name if isinstance(name, str) and name in registered_tools() else "<unregistered>"


class JobState(str, Enum):
    ACCEPTED = "accepted"
    RUNNING = "running"
    FINISHED = "finished"


@dataclass
class ActiveJob:
    """Bounded, non-secret metadata of the one job the Runner owns."""

    request_id: UUID
    session_id: UUID
    accepted_at: float
    state: JobState = JobState.ACCEPTED
    cancel_event: threading.Event = field(default_factory=threading.Event)
    cancel_reason: str | None = None
    done: threading.Event = field(default_factory=threading.Event)
    outcome: str | None = None  # ProcessOutcome value once FINISHED
    # Opaque identity of the HTTP connection that submitted this run (review
    # R1): a disconnect may only cancel the job ITS connection registered.
    owner: object | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class _Finished:
    session_id: UUID
    outcome: str
    cancelled: bool


class Runner:
    def __init__(
        self,
        policy: RunnerPolicy,
        executor: ToolExecutor,
        audit: AuditSink,
        *,
        max_stdout_bytes: int = DEFAULT_MAX_STDOUT_BYTES,
        max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES,
        latch: RunnerLatch | None = None,
        clock: Callable[[], float] = time.monotonic,
        cancel_wait_seconds: float = CANCEL_WAIT_SECONDS,
    ) -> None:
        missing = [
            get_tool(name).executable
            for name in registered_tools()
            if get_tool(name).executable not in executor.executables
        ]
        if missing:
            raise ValueError(
                f"executor has no trusted path configured for: {sorted(set(missing))}"
            )
        self._policy = policy
        self._executor = executor
        self._audit = audit
        self._max_stdout = max_stdout_bytes
        self._max_stderr = max_stderr_bytes
        self._lock = threading.Lock()  # one execution at a time
        # M8.7 Stage 4: short-lived state lock for the job registry, never
        # held while a tool runs.
        self._state_lock = threading.Lock()
        self._latch = latch
        self._clock = clock
        self._cancel_wait = cancel_wait_seconds
        self._active: ActiveJob | None = None
        self._recent: OrderedDict[UUID, _Finished] = OrderedDict()
        self._tombstones: OrderedDict[tuple[UUID, UUID], float] = OrderedDict()
        self._stopped_in_memory = False  # set by emergency_stop; only a restart clears it

    # -- public -----------------------------------------------------------------------------

    def handle(self, payload: object, *, owner: object | None = None
               ) -> ToolRunResult | RunnerRejection:
        """Handle one request, waiting if another is in progress."""
        with self._lock:
            return self._guarded(payload, owner)

    def try_handle(self, payload: object, *, owner: object | None = None
                   ) -> ToolRunResult | RunnerRejection | None:
        """Like ``handle`` but never waits: returns None if busy, in which
        case nothing was recorded or run (the caller reports "busy").
        ``owner``: an opaque object identifying the caller's connection."""
        if not self._lock.acquire(blocking=False):
            return None
        try:
            return self._guarded(payload, owner)
        finally:
            self._lock.release()

    def emergency_blocked(self) -> str | None:
        """Why new executions are refused right now, or None (READY)."""
        if self._stopped_in_memory:
            return "emergency stop engaged (in this Runner process)"
        if self._latch is not None:
            st = self._latch.load()
            if st.blocking:
                return f"emergency latch {st.state.value}: {st.detail}"[:MAX_REASON_CHARS]
        return None

    # -- internals ---------------------------------------------------------------------------

    def _guarded(self, payload: object, owner: object | None = None
                 ) -> ToolRunResult | RunnerRejection:
        try:
            return self._handle(payload, owner)
        except Exception as exc:  # last-resort guard: never raise to caller
            self._try_record(
                "internal_error",
                {"error_type": type(exc).__name__},
            )
            return RunnerRejection(
                stage=RejectionStage.INTERNAL_ERROR,
                reason="internal Runner error; nothing further was executed",
                request_id=_request_id_of(payload),
            )

    def _try_record(self, event: str, data: dict[str, Any]) -> bool:
        try:
            self._audit.record(event, data)
            return True
        except Exception:
            return False

    def _handle(self, payload: object, owner: object | None = None
                ) -> ToolRunResult | RunnerRejection:
        request_id = _request_id_of(payload)
        rid = str(request_id) if request_id else None
        received = {
            "request_id": rid,
            "tool": _tool_label(payload),
            "payload_sha256": _payload_digest(payload),
        }
        if not self._try_record("request_received", received):
            return RunnerRejection(
                stage=RejectionStage.AUDIT_UNAVAILABLE,
                reason="audit log unavailable; request not processed",
                request_id=request_id,
            )

        blocked = self.emergency_blocked()
        if blocked is not None:
            return self._deny(rid, request_id, RejectionStage.EMERGENCY_STOP, blocked)

        decision = self._policy.authorize_request(payload)

        if isinstance(decision, Denied):
            stage = RejectionStage(decision.stage)
            # Don't echo requester-supplied tool names into the log.
            reason = (
                "unknown or missing tool name"
                if stage is RejectionStage.UNKNOWN_TOOL
                else decision.reason
            )[:MAX_REASON_CHARS]
            return self._deny(rid, request_id, stage, reason)

        if not isinstance(decision, Authorized):  # fail closed, not `assert`
            raise TypeError("policy returned neither Authorized nor Denied")
        return self._execute(decision, owner)

    def _deny(self, rid, request_id, stage: RejectionStage, reason: str) -> RunnerRejection:
        self._try_record("request_denied", {"request_id": rid, "stage": stage.value,
                                            "reason": reason})
        return RunnerRejection(stage=stage, reason=reason, request_id=request_id)

    def _expire_tombstones(self) -> None:
        now = self._clock()
        for key in [k for k, exp in self._tombstones.items() if exp <= now]:
            del self._tombstones[key]

    def _register(self, req, owner: object | None = None) -> ActiveJob | RunnerRejection:
        """Under the state lock: latch re-check, tombstone check, register."""
        rid = str(req.request_id)
        with self._state_lock:
            blocked = self.emergency_blocked()
            if blocked is not None:
                return self._deny(rid, req.request_id, RejectionStage.EMERGENCY_STOP, blocked)
            self._expire_tombstones()
            # Kept until it expires: a retried copy of the run is refused too.
            if (req.request_id, req.session_id) in self._tombstones:
                return self._deny(rid, req.request_id, RejectionStage.CANCELLED,
                                  "cancelled before it started; nothing ran")
            job = ActiveJob(req.request_id, req.session_id, self._clock(), owner=owner)
            self._active = job
            return job

    def _finish(self, job: ActiveJob, outcome: str) -> None:
        with self._state_lock:
            job.state, job.outcome = JobState.FINISHED, outcome
            self._recent[job.request_id] = _Finished(
                job.session_id, outcome, outcome == ProcessOutcome.CANCELLED.value)
            while len(self._recent) > MAX_RECENT_JOBS:
                self._recent.popitem(last=False)
            if self._active is job:
                self._active = None
        job.done.set()

    def _execute(self, auth: Authorized, owner: object | None = None
                 ) -> ToolRunResult | RunnerRejection:
        req = auth.request
        spec = auth.spec
        cmd = auth.command
        limits = ExecutionLimits(
            timeout_seconds=cmd.timeout_seconds + PROCESS_TIMEOUT_GRACE_SECONDS,
            max_stdout_bytes=self._max_stdout,
            max_stderr_bytes=self._max_stderr,
        )
        job = self._register(req, owner)
        if isinstance(job, RunnerRejection):
            return job
        started = {
            "request_id": str(req.request_id),
            "session_id": str(req.session_id),
            "tool": spec.name.value,
            "tier": spec.tier.value,
            "argv": list(cmd.argv),
            "timeout_seconds": limits.timeout_seconds,
        }
        if not self._try_record("execution_started", started):
            self._finish(job, "not_started")
            return RunnerRejection(
                stage=RejectionStage.AUDIT_UNAVAILABLE,
                reason="audit log unavailable; tool was not started",
                request_id=req.request_id,
            )

        started_at = datetime.now(UTC)
        with self._state_lock:
            job.state = JobState.RUNNING
        try:
            proc = self._executor.run(cmd.argv, limits, cancel=job.cancel_event)
        except Exception as exc:
            proc = ProcessResult(
                outcome=ProcessOutcome.START_FAILED,
                exit_code=None,
                stdout=b"",
                stderr=b"",
                stdout_truncated=False,
                stderr_truncated=False,
                duration_seconds=0.0,
                error=f"executor error: {type(exc).__name__}",
            )
        finished_at = datetime.now(UTC)

        result = self._to_result(req.request_id, spec.name, proc, started_at, finished_at,
                                 job.cancel_reason)

        finished = {
            "request_id": str(req.request_id),
            "status": result.status.value,
            "outcome": proc.outcome.value,
            "exit_code": proc.exit_code,
            "duration_seconds": round(proc.duration_seconds, 3),
            "stdout_sha256": _sha256(proc.stdout),
            "stdout_bytes": len(proc.stdout),
            "stdout_truncated": proc.stdout_truncated,
            "stderr_sha256": _sha256(proc.stderr),
            "stderr_bytes": len(proc.stderr),
            "stderr_truncated": proc.stderr_truncated,
            "start_error": proc.error[:200],
            "cleanup_error": proc.cleanup_error[:200],
            "cancel_requested": job.cancel_event.is_set(),
            "cancel_reason": job.cancel_reason,
        }
        recorded = self._try_record("execution_finished", finished)
        self._finish(job, proc.outcome.value)
        if not recorded:
            # The tool ran but its result isn't on record: withhold it.
            return ToolRunResult(
                request_id=req.request_id,
                tool=spec.name,
                status=ToolRunStatus.FAILED,
                reason="post-execution audit failed; result withheld",
                started_at=started_at,
                finished_at=finished_at,
            )
        return result

    @staticmethod
    def _to_result(request_id, tool, proc: ProcessResult, started_at, finished_at,
                   cancel_reason: str | None = None):
        status, reason = {
            ProcessOutcome.EXITED: (ToolRunStatus.COMPLETED, ""),
            ProcessOutcome.TIMED_OUT: (ToolRunStatus.TIMED_OUT, "process timed out"),
            ProcessOutcome.OUTPUT_LIMIT: (ToolRunStatus.FAILED, "output limit exceeded"),
            ProcessOutcome.START_FAILED: (
                ToolRunStatus.FAILED,
                f"tool could not be started: {proc.error}",
            ),
            ProcessOutcome.CANCELLED: (
                ToolRunStatus.CANCELLED,
                f"cancelled ({cancel_reason or 'requested'}); output withheld",
            ),
        }[proc.outcome]
        common = {
            "request_id": request_id,
            "tool": tool,
            "status": status,
            "reason": reason[:MAX_REASON_CHARS],
            "started_at": started_at,
            "finished_at": finished_at,
        }
        if proc.outcome in (ProcessOutcome.START_FAILED, ProcessOutcome.CANCELLED):
            # A cancelled run's partial output is never returned as evidence
            # (its hashes are in execution_finished).
            return ToolRunResult(**common, exit_code=proc.exit_code
                                 if proc.outcome is ProcessOutcome.CANCELLED else None)
        try:
            return ToolRunResult(
                **common,
                exit_code=proc.exit_code,
                raw_output=proc.stdout.decode("utf-8", errors="replace"),
                output_truncated=proc.stdout_truncated,
                output_sha256=_sha256(proc.stdout),
            )
        except ValidationError:
            return ToolRunResult(
                **{**common, "status": ToolRunStatus.FAILED,
                   "reason": "tool output could not be represented safely"},
            )

    # -- cancellation (M8.7 Stage 4) --------------------------------------------------------

    def _internal_error(self, operation: str, exc: Exception) -> RunnerRejection:
        """Last-resort guard for the stop paths (review R5): contained,
        audited by type only, never a traceback or detail to the client."""
        self._try_record("internal_error", {"error_type": type(exc).__name__,
                                            "operation": operation})
        return RunnerRejection(stage=RejectionStage.INTERNAL_ERROR,
                               reason="internal Runner error; new runs stay refused if an "
                                      "emergency stop was requested")

    def cancel(self, payload: object, *, wait: bool = True) -> CancelResponse | RunnerRejection:
        """Cancel ONE job named by request_id AND session_id. Never raises."""
        try:
            req = CancelRequest.model_validate(payload)
        except ValidationError as exc:
            self._try_record("cancel_rejected", {"stage": "invalid_request",
                                                 "payload_sha256": _payload_digest(payload),
                                                 "errors": exc.error_count()})
            return RunnerRejection(stage=RejectionStage.INVALID_REQUEST,
                                   reason=f"invalid cancel request: {exc.error_count()} "
                                          "validation error(s)")
        try:
            return self._cancel(req.request_id, req.session_id, req.reason.value, wait=wait)
        except Exception as exc:  # noqa: BLE001 - contained, see _internal_error
            return self._internal_error("cancel", exc)

    def cancel_owned(self, owner: object) -> CancelResponse | None:
        """The HTTP layer saw a run request's own connection close: cancel
        the job THAT connection registered - never one named by payload ids
        (a retried/replayed duplicate on another connection must not cancel
        the original). None if that connection owns no running job."""
        if owner is None:
            return None
        try:
            with self._state_lock:
                job = self._active
                if job is None or job.owner is not owner:
                    return None
                ids = (job.request_id, job.session_id)
            return self._cancel(*ids, "client_disconnected", wait=False, tombstone=False)
        except Exception as exc:  # noqa: BLE001
            self._internal_error("cancel_owned", exc)
            return None

    def cancel_active(self, reason: str, *, wait: bool = True) -> str:
        """Cancel whatever job is running (Runner shutdown, review R3).
        Returns "none", "cancelled", "already_finished" or "cancel_requested"."""
        job = self._cancel_active_job(reason)
        if job is None:
            return "none"
        if wait:
            job.done.wait(self._cancel_wait)
        return ("cancelled" if job.outcome == ProcessOutcome.CANCELLED.value
                else "already_finished" if job.done.is_set() else "cancel_requested")

    def _cancel_active_job(self, reason: str) -> ActiveJob | None:
        with self._state_lock:
            job = self._active
            if job is not None and not job.cancel_event.is_set():
                job.cancel_reason = reason
                job.cancel_event.set()
        return job

    def _cancel(self, request_id: UUID, session_id: UUID, reason: str, *, wait: bool,
                tombstone: bool = True) -> CancelResponse:
        if not self._state_lock.acquire(timeout=STATE_LOCK_TIMEOUT_SECONDS):
            outcome, job = CancelOutcome.UNAVAILABLE, None
        else:
            try:
                outcome, job = self._decide_cancel(request_id, session_id, reason, tombstone)
            finally:
                self._state_lock.release()
        if job is not None and wait:
            job.done.wait(self._cancel_wait)
            if job.done.is_set():
                outcome = (CancelOutcome.APPLIED if job.outcome == ProcessOutcome.CANCELLED.value
                           else CancelOutcome.ALREADY_FINISHED)
        ok = self._try_record("cancel_handled", {
            "request_id": str(request_id), "session_id": str(session_id), "reason": reason,
            "outcome": outcome.value})
        return CancelResponse(outcome=outcome, request_id=request_id, session_id=session_id,
                              audit_recorded=ok)

    def _decide_cancel(self, request_id, session_id, reason, tombstone):
        job = self._active
        if job is not None and job.request_id == request_id:
            if job.session_id != session_id:
                return CancelOutcome.MISMATCH, None  # the active job is NOT touched
            if job.cancel_event.is_set():
                return CancelOutcome.ALREADY_CANCELLED, None
            job.cancel_reason = reason
            job.cancel_event.set()
            return CancelOutcome.REQUESTED, job
        done = self._recent.get(request_id)
        if done is not None:
            if done.session_id != session_id:  # the request_id is known, the session is not
                return CancelOutcome.MISMATCH, None
            return (CancelOutcome.ALREADY_CANCELLED if done.cancelled
                    else CancelOutcome.ALREADY_FINISHED), None
        if tombstone:  # the run may still be on its way: refuse it when it arrives
            self._expire_tombstones()
            key = (request_id, session_id)
            if key in self._tombstones:
                return CancelOutcome.ALREADY_CANCELLED, None
            self._tombstones[key] = self._clock() + TOMBSTONE_TTL_SECONDS
            while len(self._tombstones) > MAX_TOMBSTONES:
                self._tombstones.popitem(last=False)
        return CancelOutcome.NOT_ACTIVE, None

    # -- emergency stop (M8.7 Stage 4) --------------------------------------------------------

    def emergency_stop(self, payload: object) -> EmergencyStopResponse | RunnerRejection:
        """Engage the persistent latch FIRST, then cancel the active job.
        Never reports success unless the latch reads back as STOPPED."""
        try:
            req = EmergencyStopRequest.model_validate(payload)
        except ValidationError as exc:
            self._try_record("emergency_stop_rejected", {
                "stage": "invalid_request", "payload_sha256": _payload_digest(payload)})
            return RunnerRejection(stage=RejectionStage.INVALID_REQUEST,
                                   reason=f"invalid emergency-stop request: "
                                          f"{exc.error_count()} validation error(s)")
        # FIRST, before anything that could fail: no new registration from
        # this instant, for the rest of this process's life (review R5).
        with self._state_lock:
            self._stopped_in_memory = True
        try:
            return self._emergency_stop(req.reason.value)
        except Exception as exc:  # noqa: BLE001 - contained; runs stay refused
            return self._internal_error("emergency_stop", exc)

    def _emergency_stop(self, reason: str) -> EmergencyStopResponse:
        requested_ok = self._try_record("emergency_stop_requested", {"reason": reason})
        durable, already, engaged_ok, latch_state = False, False, False, "NONE"
        if self._latch is not None:
            try:
                eng = self._latch.engage(reason, by="http")
                durable, already, engaged_ok = eng.durable, eng.already, eng.audit_recorded
            except Exception:  # noqa: BLE001 - reported as not durable, never as success
                durable = False
            latch_state = self._latch.load().state.value
        job = self._cancel_active_job("emergency_stop")
        active = "none"
        if job is not None:
            job.done.wait(self._cancel_wait)
            active = ("cancelled" if job.outcome == ProcessOutcome.CANCELLED.value
                      else "already_finished" if job.done.is_set() else "cancel_requested")
            self._try_record("emergency_stop_cancelled_job", {
                "request_id": str(job.request_id), "session_id": str(job.session_id),
                "result": active})
        outcome = ("not_durable" if not durable else "already_engaged" if already
                   else "engaged")
        return EmergencyStopResponse(outcome=outcome, latch=latch_state, durable=durable,
                                     audit_recorded=requested_ok and engaged_ok,
                                     active_job=active)
