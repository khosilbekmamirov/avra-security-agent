"""M14.1 (ADR 0022): a persistent, audited investigation state machine.

An *investigation* is one owner objective worked through
Observe -> Analyze -> Plan -> Propose -> Approve -> Execute -> Verify -> Report.

This module holds only the STATE: which phase the investigation is in, and the life of each
live action it proposed. It plans nothing, calls no model and contacts no host. Planning
reuses ``avra.research.next_steps``; verdicts come from the Verification Engine; execution
goes through the existing audited pipelines. The controller that wires them is separate.

Design rules (the security invariants of M14):

* **Event-sourced and hash-chained.** Every change is one record in an append-only
  ``AuditLog`` (``<root>/<investigation_id>.jsonl``). The state is never stored - it is
  rebuilt by replaying the records, and every replayed transition is validated again. A
  broken chain or an illegal replayed transition refuses to load (fail closed).
* **Deterministic transitions.** ``TRANSITIONS`` is the whole state graph. Model output can
  never set a state; only these methods can, and each one validates first.
* **Default deny.** A proposal is checked by an injected scope check (the same
  ``authorize_tool_request`` path the pipelines use). No check -> refused.
* **Approval is bound and single-use.** ``approve`` must be given the action's
  ``fingerprint`` (a SHA-256 over every field that defines what will run), expires after
  ``approval_ttl``, and moves the action out of PROPOSED, so it can never be approved twice.
  The second terminal confirmation is the caller's job and happens BEFORE ``approve``.
* **At most once.** ``begin_execution`` is recorded before anything is sent. If the process
  dies before ``finish_execution``, ``load`` marks the action INTERRUPTED - it is never run
  again; a retry needs a fresh proposal and a fresh approval. A (tool, host, port, path) that
  already has an approved, running or successful action cannot be proposed again.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from avra.storage.audit import AuditLog


class InvestigationError(Exception):
    """A refused operation. The message is secret-free and safe to show."""


class InvState(StrEnum):
    CREATED = "CREATED"
    OBSERVING = "OBSERVING"
    ANALYZING = "ANALYZING"
    PLANNING = "PLANNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL = frozenset({InvState.COMPLETED, InvState.INCONCLUSIVE, InvState.FAILED,
                      InvState.CANCELLED})
_ENDS = {InvState.INCONCLUSIVE, InvState.FAILED, InvState.CANCELLED}
TRANSITIONS: dict[InvState, frozenset[InvState]] = {
    InvState.CREATED: frozenset({InvState.OBSERVING} | _ENDS),
    InvState.OBSERVING: frozenset({InvState.ANALYZING} | _ENDS),
    InvState.ANALYZING: frozenset({InvState.PLANNING, InvState.COMPLETED} | _ENDS),
    InvState.PLANNING: frozenset({InvState.WAITING_APPROVAL, InvState.COMPLETED} | _ENDS),
    # back to PLANNING after a denial or an expired approval; the controller decides to stop
    InvState.WAITING_APPROVAL: frozenset({InvState.EXECUTING, InvState.PLANNING} | _ENDS),
    InvState.EXECUTING: frozenset({InvState.VERIFYING} | _ENDS),
    InvState.VERIFYING: frozenset({InvState.ANALYZING, InvState.COMPLETED} | _ENDS),
    **{t: frozenset() for t in TERMINAL},
}


class ActionStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    INTERRUPTED = "INTERRUPTED"
    REFUSED = "REFUSED"   # out of scope / duplicate: recorded, never pending


# an action in one of these blocks a new proposal of the same (tool, host, port, path)
_BLOCKING = frozenset({ActionStatus.PROPOSED, ActionStatus.APPROVED, ActionStatus.EXECUTING,
                       ActionStatus.SUCCEEDED})
DEFAULT_APPROVAL_TTL = timedelta(minutes=15)
MAX_REASON = 300
# M14.2: notes record what the controller observed/analysed/planned. They never change the
# phase or an action; the report reads them. Kinds are a closed set, payloads are bounded.
NOTE_KINDS = frozenset({"scope_bound", "observation", "analysis", "plan", "verification",
                        "explanation", "explanation_failed", "stop"})
MAX_NOTE_CHARS = 4000

ScopeCheck = Callable[[str, str, int, str | None], bool]


@dataclass
class ActionRecord:
    action_id: str
    investigation_id: str
    tool: str
    host: str
    port: int
    path: str
    tier: str
    reason: str
    expected_evidence: str
    scope_allowed: bool
    fingerprint: str
    proposed_at: str
    status: ActionStatus = ActionStatus.PROPOSED
    request_id: str | None = None
    evidence_sha256: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def risk(self) -> str:
        """Risk follows the registry-fixed tier; it is never chosen by the model."""
        return {"passive": "low", "active-safe": "medium"}.get(self.tier, "high")

    @property
    def key(self) -> tuple[str, str, int, str]:
        return (self.tool, self.host, self.port, self.path)

    def describe(self) -> str:
        p = self.path or ""
        return (f"{self.action_id[:8]}: {self.tool} {self.host}:{self.port}{p} "
                f"[{self.tier}, risk {self.risk}] fingerprint {self.fingerprint[:12]}")


def fingerprint(investigation_id: str, action_id: str, tool: str, host: str, port: int,
                path: str, tier: str) -> str:
    """SHA-256 over everything that defines WHAT would run. Approval must quote it."""
    canon = json.dumps({"investigation_id": investigation_id, "action_id": action_id,
                        "tool": tool, "host": host, "port": port, "path": path, "tier": tier},
                       sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def _tier_for(tool: str) -> str:
    from avra.runner.registry import UnknownToolError, get_tool

    try:
        return get_tool(tool).tier.value
    except UnknownToolError:
        raise InvestigationError(f"unknown tool {tool!r}") from None


def _now() -> datetime:
    return datetime.now(UTC)


class Investigation:
    """One investigation, rebuilt from its own hash-chained event log."""

    def __init__(self, log: AuditLog, *, clock: Callable[[], datetime] = _now,
                 approval_ttl: timedelta = DEFAULT_APPROVAL_TTL) -> None:
        self._log = log
        self._clock = clock
        self.approval_ttl = approval_ttl
        self.investigation_id = ""
        self.objective = ""
        self.session_id = ""
        self.scope_name = ""
        self.state = InvState.CREATED
        self.actions: dict[str, ActionRecord] = {}
        self.history: list[tuple[str, str, str]] = []   # (from, to, reason)
        self.notes: list[dict[str, Any]] = []            # {"kind", "state", "data"}

    # --- create / load ------------------------------------------------------------------

    @classmethod
    def create(cls, root: Path, *, objective: str, session_id: str, scope_name: str = "",
               clock: Callable[[], datetime] = _now,
               approval_ttl: timedelta = DEFAULT_APPROVAL_TTL) -> Investigation:
        inv_id = str(uuid.uuid4())
        path = Path(root) / f"{inv_id}.jsonl"
        if path.exists():  # pragma: no cover - uuid4 collision
            raise InvestigationError("investigation id collision")
        inv = cls(AuditLog(path), clock=clock, approval_ttl=approval_ttl)
        data = {"investigation_id": inv_id, "objective": str(objective)[:500],
                "session_id": str(session_id), "scope_name": str(scope_name)}
        inv._log.record("investigation_created", data)
        inv._apply("investigation_created", data)
        return inv

    @classmethod
    def load(cls, root: Path, investigation_id: str, *, clock: Callable[[], datetime] = _now,
             approval_ttl: timedelta = DEFAULT_APPROVAL_TTL,
             reconcile: bool = True) -> Investigation:
        """Rebuild from the log. ``reconcile=False`` is a read-only view (``show``/``report``)
        that writes nothing - an unfinished action is then shown as EXECUTING; only the
        process that holds ``run_lock`` reconciles it to INTERRUPTED."""
        try:
            inv_id = str(uuid.UUID(str(investigation_id)))
        except ValueError:
            raise InvestigationError("not a valid investigation id") from None
        path = Path(root) / f"{inv_id}.jsonl"
        if not path.is_file():
            raise InvestigationError(f"no investigation {inv_id}")
        inv = cls(AuditLog(path), clock=clock, approval_ttl=approval_ttl)
        if not inv._log.verify():
            raise InvestigationError("the investigation log failed its hash-chain check; "
                                     "refusing to load it")
        for rec in inv._log.read_all():
            inv._apply(rec.event, rec.data)  # re-validates every transition
        if inv.investigation_id != inv_id:
            raise InvestigationError("the investigation log does not match its id")
        if not reconcile:
            return inv
        # crash recovery: anything that started but never finished is INTERRUPTED, never rerun
        for act in list(inv.actions.values()):
            if act.status is ActionStatus.EXECUTING:
                inv._emit("action_interrupted", {"action_id": act.action_id,
                                                 "request_id": act.request_id})
        if inv.state is InvState.EXECUTING:
            inv._emit("state_changed", {"to": InvState.FAILED.value,
                                        "reason": "interrupted during execution"})
        return inv

    # --- event application (the ONLY place state changes) ------------------------------

    def _emit(self, event: str, data: dict[str, Any]) -> None:
        # validate on a dry run first so an illegal change is never written
        self._apply(event, data, dry_run=True)
        self._log.record(event, data)
        self._apply(event, data)

    def _apply(self, event: str, data: dict[str, Any], *, dry_run: bool = False) -> None:
        if event == "investigation_created":
            if self.investigation_id:
                raise InvestigationError("duplicate investigation_created record")
            if not dry_run:
                self.investigation_id = data["investigation_id"]
                self.objective = data["objective"]
                self.session_id = data["session_id"]
                self.scope_name = data.get("scope_name", "")
            return
        if not self.investigation_id:
            raise InvestigationError("log does not start with investigation_created")
        if event == "state_changed":
            to = InvState(data["to"])
            if to not in TRANSITIONS[self.state]:
                raise InvestigationError(f"illegal transition {self.state} -> {to}")
            if not dry_run:
                self.history.append((self.state.value, to.value, str(data.get("reason", ""))))
                self.state = to
            return
        if event in ("action_proposed", "action_refused"):
            if data["action_id"] in self.actions:
                raise InvestigationError("duplicate action id")
            if not dry_run:
                fields = {k: data[k] for k in ActionRecord.__dataclass_fields__ if k in data}
                act = ActionRecord(**fields)
                act.status = (ActionStatus.PROPOSED if event == "action_proposed"
                              else ActionStatus.REFUSED)
                self.actions[act.action_id] = act
            return
        if event == "note_recorded":
            if data.get("kind") not in NOTE_KINDS:
                raise InvestigationError("unknown note kind")
            if not dry_run:
                self.notes.append({"kind": data["kind"], "state": self.state.value,
                                   "data": data.get("data")})
            return
        act = self.actions.get(data.get("action_id", ""))
        if act is None:
            raise InvestigationError("record names an unknown action")
        allowed = {"action_approved": ({ActionStatus.PROPOSED}, ActionStatus.APPROVED),
                   # APPROVED -> DENIED: an approval left unused by a crashed process is withdrawn
                   # on resume, never carried over (M14.2)
                   "action_denied": ({ActionStatus.PROPOSED, ActionStatus.APPROVED},
                                     ActionStatus.DENIED),
                   # APPROVED -> EXPIRED: an approval never used (its process stopped) lapses;
                   # a retry needs a fresh proposal and a fresh approval (M14.2)
                   "action_expired": ({ActionStatus.PROPOSED, ActionStatus.APPROVED},
                                      ActionStatus.EXPIRED),
                   "action_started": ({ActionStatus.APPROVED}, ActionStatus.EXECUTING),
                   "action_finished": ({ActionStatus.EXECUTING}, None),
                   "action_interrupted": ({ActionStatus.EXECUTING}, ActionStatus.INTERRUPTED)}
        if event not in allowed:
            raise InvestigationError(f"unknown investigation event {event!r}")
        sources, target = allowed[event]
        if act.status not in sources:
            raise InvestigationError(f"{event} is not valid for an action in {act.status}")
        if dry_run:
            return
        if event == "action_started":
            act.request_id = data["request_id"]
        if event == "action_finished":
            target = ActionStatus.SUCCEEDED if data.get("ok") else ActionStatus.FAILED
            act.evidence_sha256 = data.get("evidence_sha256")
            act.errors = list(data.get("errors") or [])[:3]
        act.status = target

    # --- phase transitions --------------------------------------------------------------

    def transition(self, to: InvState | str, reason: str = "") -> None:
        to = InvState(to)
        if to is InvState.EXECUTING:
            raise InvestigationError("EXECUTING is entered only by begin_execution")
        if to is InvState.WAITING_APPROVAL and not self.pending():
            raise InvestigationError("WAITING_APPROVAL needs a pending proposal")
        self._emit("state_changed", {"to": to.value, "reason": str(reason)[:200]})

    def note(self, kind: str, data: dict[str, Any]) -> None:
        """Record a bounded, state-neutral note (what was observed, analysed, planned)."""
        body = json.loads(json.dumps(data, sort_keys=True, default=str))
        if len(json.dumps(body)) > MAX_NOTE_CHARS:
            body = {"truncated": True,
                    "sha256": hashlib.sha256(json.dumps(body, sort_keys=True).encode())
                    .hexdigest(),
                    "head": json.dumps(body, sort_keys=True)[:MAX_NOTE_CHARS // 2]}
        self._emit("note_recorded", {"kind": kind, "data": body})

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    def pending(self) -> list[ActionRecord]:
        return [a for a in self.actions.values() if a.status is ActionStatus.PROPOSED]

    # --- proposals ----------------------------------------------------------------------

    def propose(self, *, tool: str, host: str, port: int, path: str | None = None,
                reason: str = "", expected_evidence: str = "",
                scope_check: ScopeCheck | None = None) -> ActionRecord:
        """Record a proposal. Out-of-scope or duplicate proposals are recorded as REFUSED
        and returned with that status - they can never be approved."""
        if self.state is not InvState.PLANNING:
            raise InvestigationError(f"proposals are made only in PLANNING (now {self.state})")
        if not isinstance(port, int) or isinstance(port, bool):
            raise InvestigationError("port must be an integer")
        tier = _tier_for(tool)
        path = path or ""
        allowed = False
        if scope_check is not None:
            try:
                allowed = bool(scope_check(tool, host, port, path or None))
            except Exception:  # noqa: BLE001 - any failure of the check is a denial
                allowed = False
        duplicate = any(a.key == (tool, host, port, path) and a.status in _BLOCKING
                        for a in self.actions.values())
        action_id = str(uuid.uuid4())
        data = {"action_id": action_id, "investigation_id": self.investigation_id,
                "tool": tool, "host": str(host), "port": port, "path": path, "tier": tier,
                "reason": str(reason)[:MAX_REASON],
                "expected_evidence": str(expected_evidence)[:MAX_REASON],
                "scope_allowed": allowed,
                "fingerprint": fingerprint(self.investigation_id, action_id, tool, str(host),
                                           port, path, tier),
                "proposed_at": self._clock().isoformat()}
        if not allowed or duplicate:
            data["refusal"] = "duplicate" if duplicate and allowed else "scope"
            self._emit("action_refused", data)
        else:
            self._emit("action_proposed", data)
        return self.actions[action_id]

    # --- owner decisions ----------------------------------------------------------------

    def _get(self, action_id: str) -> ActionRecord:
        act = self.actions.get(str(action_id))
        if act is None:
            raise InvestigationError("no such action")
        return act

    def _expired(self, act: ActionRecord) -> bool:
        return self._clock() - datetime.fromisoformat(act.proposed_at) > self.approval_ttl

    def approve(self, action_id: str, fingerprint_: str, *,
                scope_check: ScopeCheck | None = None, by: str = "owner") -> ActionRecord:
        """The owner's single-use approval of ONE proposal. Call it only after the second
        terminal confirmation. Re-checks scope; a stale or mismatched approval fails closed."""
        act = self._get(action_id)
        if self.state is not InvState.WAITING_APPROVAL:
            raise InvestigationError(f"nothing can be approved in {self.state}")
        if act.status is not ActionStatus.PROPOSED:
            raise InvestigationError(f"action is {act.status}, not PROPOSED")
        if str(fingerprint_) != act.fingerprint:
            raise InvestigationError("approval does not match the proposed action")
        if self._expired(act):
            self._emit("action_expired", {"action_id": act.action_id})
            raise InvestigationError("the approval window expired; propose it again")
        ok = False
        if scope_check is not None:
            try:
                ok = bool(scope_check(act.tool, act.host, act.port, act.path or None))
            except Exception:  # noqa: BLE001
                ok = False
        if not ok:
            self._emit("action_denied", {"action_id": act.action_id, "by": "scope_recheck"})
            raise InvestigationError("the scope no longer allows this action")
        self._emit("action_approved", {"action_id": act.action_id, "by": str(by)[:40],
                                       "fingerprint": act.fingerprint})
        return act

    def withdraw_approval(self, action_id: str) -> ActionRecord:
        """An APPROVED action whose approving process is gone lapses (EXPIRED); approvals
        are single-use within one process and never carried over a restart."""
        act = self._get(action_id)
        if act.status is not ActionStatus.APPROVED:
            raise InvestigationError(f"action is {act.status}, not APPROVED")
        self._emit("action_expired", {"action_id": act.action_id,
                                      "why": "approval unused when its process stopped"})
        return act

    def deny(self, action_id: str, *, by: str = "owner") -> ActionRecord:
        act = self._get(action_id)
        self._emit("action_denied", {"action_id": act.action_id, "by": str(by)[:40]})
        return act

    # --- execution bookkeeping (the caller runs the audited pipeline in between) ---------

    def begin_execution(self, action_id: str) -> str:
        """Record the start BEFORE anything is sent; returns the request id to use."""
        act = self._get(action_id)
        if self.state is not InvState.WAITING_APPROVAL:
            raise InvestigationError(f"cannot execute from {self.state}")
        if act.status is not ActionStatus.APPROVED:
            raise InvestigationError(f"action is {act.status}, not APPROVED")
        request_id = str(uuid.uuid4())
        self._emit("action_started", {"action_id": act.action_id, "request_id": request_id})
        self._emit("state_changed", {"to": InvState.EXECUTING.value,
                                     "reason": f"action {act.action_id}"})
        return request_id

    def finish_execution(self, action_id: str, *, ok: bool, request_id: str,
                         evidence_sha256: str | None = None,
                         errors: list[str] | None = None) -> ActionRecord:
        act = self._get(action_id)
        if request_id != act.request_id:
            raise InvestigationError("result does not correlate with the started request")
        if ok and not evidence_sha256:
            ok = False  # a success without evidence is not a success
            errors = [*(errors or []), "no evidence recorded"]
        from avra.chat.store import redact

        self._emit("action_finished", {"action_id": act.action_id, "ok": bool(ok),
                                       "request_id": request_id,
                                       "evidence_sha256": evidence_sha256,
                                       "errors": [redact(str(e))[:300]
                                                  for e in (errors or [])[:3]]})
        self._emit("state_changed", {"to": InvState.VERIFYING.value,
                                     "reason": "result received"})
        return act

    # --- views --------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        return {"investigation_id": self.investigation_id, "objective": self.objective,
                "session_id": self.session_id, "scope_name": self.scope_name,
                "state": self.state.value, "terminal": self.terminal,
                "history": [list(h) for h in self.history],
                "notes": list(self.notes),
                "actions": [{**asdict(a), "status": a.status.value, "risk": a.risk}
                            for a in self.actions.values()]}

    def verify(self) -> bool:
        return self._log.verify()

    def log_summary(self) -> dict[str, Any]:
        """Audit references for the report: path, record count and the chain head."""
        recs = self._log.read_all()
        return {"path": str(self._log.path), "records": len(recs),
                "head_hash": recs[-1].hash if recs else None, "chain_valid": self.verify()}


class RunLockBusy(InvestigationError):
    """Another process is driving this investigation."""


@contextmanager
def run_lock(root: Path, investigation_id: str, timeout: float = 0.5) -> Iterator[None]:
    """Exclusive, cross-process lock for DRIVING one investigation (``<id>.lock``).

    Only the holder may reconcile or advance it, so a second ``avra investigate`` can never
    mark a still-running action INTERRUPTED. Reuses the audit log's OS-level file lock."""
    from avra.storage.audit import AuditWriteError, audit_file_lock

    inv_id = str(uuid.UUID(str(investigation_id)))
    path = Path(root) / f"{inv_id}.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    try:
        lock = audit_file_lock(path, timeout)
        lock.__enter__()
    except AuditWriteError:
        raise RunLockBusy("this investigation is being run by another process") from None
    try:
        yield
    finally:
        lock.__exit__(None, None, None)
