"""Windows-side emergency kill switch (ADR 0012 Stage 3) - LOCAL ONLY.

A persistent, fail-closed latch that stops THIS machine's AVRA from starting
new work: no new tool requests (nmap, HTTP probe), no tunnels for them, no
model/API calls, no approval prompts for work that would execute. Read-only
inspection, reports and verification stay available.

What it does NOT do (Stage 3): it does not reach the Kali Runner. A job
already running there continues until the Runner's own timeout (or manual
intervention). The CLI says so: "LOCAL STOP ENGAGED - REMOTE CANCELLATION
NOT YET VERIFIED". Remote cancel / a Runner-side latch are Stages 4-5.

Files (``<state>`` = ``AVRA_STATE_DIR`` or ``%LOCALAPPDATA%\\AVRA``):

    <state>/control/killswitch.json      the latch (versioned, <= 4 KiB)
    <state>/control/control-audit.jsonl  hash-chained control audit (AuditLog)
    <state>/control/killswitch.lock      cross-process transition/gate lock
    <state>/control/active/*.active      locked markers of running work

Latch semantics (``status()``, read-only, never creates anything):

    no state file, no control audit transitions   DISENGAGED (fresh machine)
    valid "engaged" file                          ENGAGED
    valid "disengaged" file backed by the matching
      kill_switch_reset record in the control audit DISENGAGED
    anything else - malformed/oversized file, file
      contradicting the audit, damaged control audit,
      symlink/junction/reparse point, wrong owner    CORRUPT   (blocks)
    I/O error                                     UNREADABLE (blocks)

Transitions (``engage``/``reset``) are serialized by the control lock.

- engage: write the ENGAGED file atomically + fsync FIRST (the effective
  action), re-read it, THEN append ``kill_switch_engaged``. A crash in
  between leaves ENGAGED without its record (still blocks; reported).
- reset: refuse unless ENGAGED and valid, the control audit is intact and no
  active local work is registered; append ``kill_switch_reset`` FIRST (if
  that fails nothing changes), THEN atomically write DISENGAGED. A crash in
  between leaves the ENGAGED file -> still ENGAGED. No crash can make an
  engaged latch read as disengaged.
- A corrupt or unreadable latch file is never overwritten or repaired; it
  stays as evidence and keeps AVRA blocked until the owner investigates.

Gate (``active(operation)``): under the control lock, check the latch and
register a locked "active work" marker; the returned ticket re-checks the
latch AND its epoch (the transition id seen at entry) at later checkpoints,
so an engage-then-reset during a long run still stops it. Residual race
(documented): work that passed its last checkpoint just before ``avra kill``
finished proceeds; a synchronous network call in flight is not interrupted.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from avra.storage.anchors import state_dir
from avra.storage.audit import (
    AuditLockTimeout,
    AuditLog,
    AuditStatus,
    AuditVerification,
    audit_file_lock,
    inspect_audit_file,
)

STATE_VERSION = 1
MAX_STATE_BYTES = 4096
MAX_REASON_CHARS = 500
CONTROL_DIR = "control"
STATE_NAME = "killswitch.json"
AUDIT_NAME = "control-audit.jsonl"
LOCK_NAME = "killswitch.lock"
ACTIVE_DIR = "active"
REMOTE_NOTICE = ("LOCAL STOP ENGAGED - REMOTE CANCELLATION NOT YET VERIFIED: a job already "
                 "running on the Kali Runner continues until its own timeout or manual "
                 "intervention.")

EV_ENGAGED = "kill_switch_engaged"
EV_RESET = "kill_switch_reset"
EV_DENIED = "kill_switch_execution_denied"
EV_FAILED = "kill_switch_transition_failed"
_TRANSITIONS = (EV_ENGAGED, EV_RESET)
_FIELDS = frozenset({"v", "state", "transition_id", "changed_at", "reason", "by"})
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MARKER = re.compile(r"[0-9]{1,10}-[0-9a-f]{32}\.active", re.ASCII)
_HEX32 = re.compile(r"[0-9a-f]{32}", re.ASCII)

# Indirections so tests can inject failures.
_fsync = os.fsync
_replace = os.replace


class Latch(str, Enum):
    DISENGAGED = "DISENGAGED"
    ENGAGED = "ENGAGED"
    CORRUPT = "CORRUPT"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True)
class KillSwitchStatus:
    latch: Latch
    detail: str
    epoch: str | None = None  # transition id of the current state (None: never engaged)
    state: dict[str, Any] | None = None
    audit: AuditVerification | None = None
    notes: tuple[str, ...] = ()

    @property
    def blocking(self) -> bool:
        """Fail closed: everything except a verified DISENGAGED blocks."""
        return self.latch is not Latch.DISENGAGED


class KillSwitchEngaged(Exception):
    """Work refused because the latch is not a verified DISENGAGED."""

    def __init__(self, operation: str, status: KillSwitchStatus, why: str = "") -> None:
        msg = (f"AVRA kill switch is {status.latch.value}: '{operation}' refused, nothing was "
               f"started or sent ({why or status.detail})")
        super().__init__(msg)
        self.operation, self.status = operation, status


class KillSwitchError(Exception):
    """A transition could not be completed durably (message says what holds)."""


@dataclass(frozen=True)
class TransitionResult:
    status: KillSwitchStatus
    changed: bool
    audit_recorded: bool
    notes: tuple[str, ...] = field(default_factory=tuple)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _clean_reason(reason: str) -> str:
    text = " ".join(str(reason).split())
    if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("a non-empty, printable reason is required")
    if len(text) > MAX_REASON_CHARS:
        raise ValueError(f"reason must be at most {MAX_REASON_CHARS} characters")
    return text


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


class _Unsafe(Exception):
    pass


def _kind(path: Path) -> str:
    """"absent" | "dir" | "file"; raises _Unsafe for links/reparse points/
    foreign owners, OSError for I/O problems. Never follows links."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        raise _Unsafe(f"{path.name} is a symlink, junction or reparse point")
    if os.name == "posix" and st.st_uid != os.geteuid():
        raise _Unsafe(f"{path.name} is owned by another user")
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    raise _Unsafe(f"{path.name} is not a regular file or directory")


class KillSwitch:
    def __init__(self, state: Path | None = None, *, lock_timeout: float = 10.0,
                 acl: Callable[[Path], None] | None = None) -> None:
        self.state = Path(state) if state is not None else state_dir()
        self.control = self.state / CONTROL_DIR
        self.state_path = self.control / STATE_NAME
        self.audit_path = self.control / AUDIT_NAME
        self.lock_path = self.control / LOCK_NAME
        self.active_dir = self.control / ACTIVE_DIR
        self.lock_timeout = lock_timeout
        self._acl = acl

    # -- reading -------------------------------------------------------------------------

    def _read_state_file(self) -> dict[str, Any] | None:
        """None if absent. Raises _Unsafe / ValueError (corrupt) / OSError."""
        kind = _kind(self.state_path)
        if kind == "absent":
            return None
        if kind != "file":
            raise _Unsafe("latch path is not a regular file")
        fd = os.open(self.state_path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOINHERIT", 0))
        try:
            before, after = os.lstat(self.state_path), os.fstat(fd)
            if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
                raise _Unsafe("state file changed while it was opened")
            raw = os.read(fd, MAX_STATE_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError("state file is larger than allowed")
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes)
        if not isinstance(obj, dict) or set(obj) != _FIELDS or obj["v"] != STATE_VERSION \
                or obj["state"] not in ("engaged", "disengaged") \
                or not isinstance(obj["transition_id"], str) \
                or not _HEX32.fullmatch(obj["transition_id"]) \
                or not isinstance(obj["changed_at"], str) or not isinstance(obj["by"], str) \
                or not isinstance(obj["reason"], str) or len(obj["reason"]) > MAX_REASON_CHARS:
            raise ValueError("state file does not match the v1 schema")
        return obj

    def _status_once(self) -> KillSwitchStatus:
        try:
            for d in (self.state, self.control):
                kind = _kind(d)
                if kind == "absent":
                    return KillSwitchStatus(Latch.DISENGAGED, "never engaged on this machine")
                if kind != "dir":
                    raise _Unsafe(f"{d.name} is not a directory")
            audit_kind = _kind(self.audit_path)
            state = self._read_state_file()
        except _Unsafe as exc:
            return KillSwitchStatus(Latch.CORRUPT, f"unsafe control path: {exc}")
        except (ValueError, UnicodeDecodeError, RecursionError):
            return KillSwitchStatus(Latch.CORRUPT, "latch file is malformed (kept as evidence)")
        except OSError as exc:
            return KillSwitchStatus(Latch.UNREADABLE,
                                    f"control state not readable ({type(exc).__name__})")

        audit, last = None, None
        if audit_kind == "file":
            snap = inspect_audit_file(self.audit_path)
            audit = snap.verification
            if audit.status is AuditStatus.UNREADABLE:
                return KillSwitchStatus(Latch.UNREADABLE, f"control audit: {audit.describe()}",
                                        state=state, audit=audit)
            if not audit.ok:
                return KillSwitchStatus(Latch.CORRUPT, f"control audit damaged: "
                                        f"{audit.describe()}", state=state, audit=audit)
            last = next((r for r in reversed(snap.records) if r.event in _TRANSITIONS), None)
        last_id = last.data.get("transition_id") if last and isinstance(last.data, dict) else None

        if state is not None and state["state"] == "engaged":
            notes = () if (last is not None and last.event == EV_ENGAGED
                           and last_id == state["transition_id"]) else (
                "engagement is not (yet) recorded in the control audit",)
            return KillSwitchStatus(Latch.ENGAGED, f"engaged at {state['changed_at']}: "
                                    f"{state['reason']}", state["transition_id"], state, audit,
                                    notes)
        if state is not None:  # disengaged: must be backed by the matching reset record
            if last is not None and last.event == EV_RESET and last_id == state["transition_id"]:
                return KillSwitchStatus(Latch.DISENGAGED, f"reset at {state['changed_at']}",
                                        state["transition_id"], state, audit)
            return KillSwitchStatus(Latch.CORRUPT, "disengaged latch file is not backed by its "
                                    "reset record in the control audit", state=state, audit=audit)
        if last is not None and last.event == EV_ENGAGED:
            return KillSwitchStatus(Latch.CORRUPT, "latch file is missing but the control audit "
                                    "says engaged (deleted?)", audit=audit)
        if last is not None:
            return KillSwitchStatus(Latch.DISENGAGED, "reset; latch file absent", last_id,
                                    audit=audit, notes=("latch file absent after a reset",))
        return KillSwitchStatus(Latch.DISENGAGED, "never engaged", audit=audit)

    def status(self) -> KillSwitchStatus:
        """Read-only; never creates, changes or locks anything."""
        st = self._status_once()
        if st.latch is Latch.UNREADABLE:  # e.g. sharing violation during os.replace
            time.sleep(0.05)
            st = self._status_once()
        return st

    # -- helpers for writing ----------------------------------------------------------------

    def _prepare_dirs(self) -> None:
        for d in (self.state, self.control, self.active_dir):
            kind = _kind(d)
            if kind == "absent":
                d.mkdir(parents=d == self.state, exist_ok=True)
                kind = _kind(d)
            if kind != "dir":
                raise _Unsafe(f"{d.name} is not a directory")
        if _kind(self.lock_path) == "absent":
            with self.lock_path.open("ab"):
                pass
        if _kind(self.lock_path) != "file":
            raise _Unsafe("lock path is not a regular file")

    def _audit(self) -> AuditLog:
        return AuditLog(self.audit_path, lock_timeout=self.lock_timeout)

    def _try_record(self, event: str, data: dict[str, Any]) -> bool:
        try:
            if _kind(self.control) != "dir":
                return False
            self._audit().record(event, data)
            return True
        except Exception:  # noqa: BLE001 - best effort; the caller reports the failure
            return False

    def _write_state(self, state: str, transition_id: str, reason: str, by: str) -> None:
        doc = {"v": STATE_VERSION, "state": state, "transition_id": transition_id,
               "changed_at": _now(), "reason": reason, "by": by}
        data = json.dumps(doc, sort_keys=True).encode("utf-8") + b"\n"
        if _kind(self.state_path) not in ("absent", "file"):
            raise _Unsafe("latch path is not a regular file")
        tmp = self.control / f".{STATE_NAME}.{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOINHERIT", 0), 0o600)
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                _fsync(fd)
            finally:
                os.close(fd)
            _replace(tmp, self.state_path)
        except BaseException:
            try:
                tmp.unlink()  # only our own just-created temp file
            except OSError:
                pass
            raise
        if os.name == "posix":
            dfd = os.open(self.control, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self._prepare_dirs()
            with audit_file_lock(self.lock_path, self.lock_timeout):
                yield
        except _Unsafe as exc:
            raise KillSwitchError(f"unsafe control path: {exc}") from None
        except AuditLockTimeout:
            raise KillSwitchError("control lock busy; try again") from None

    # -- transitions -------------------------------------------------------------------------

    def engage(self, reason: str = "operator emergency stop", *, by: str = "cli") -> \
            TransitionResult:
        reason = _clean_reason(reason)
        notes: list[str] = []
        try:
            ctx = self._locked()
            ctx.__enter__()
        except (KillSwitchError, OSError) as exc:
            raise KillSwitchError(f"kill switch NOT engaged: {exc}") from None
        try:
            current = self.status()
            if current.latch in (Latch.CORRUPT, Latch.UNREADABLE) and current.state is None \
                    and os.path.lexists(self.state_path):
                # A damaged latch file is evidence: never overwritten. Still blocks.
                ok = self._try_record(EV_ENGAGED, {"transition_id": None, "reason": reason,
                                                   "by": by, "already": current.latch.value})
                raise KillSwitchError(f"latch file is {current.latch.value} and was kept as "
                                      f"evidence; AVRA stays blocked (fail closed), but a clean "
                                      f"ENGAGED state could not be written"
                                      f"{'' if ok else '; control audit record also failed'}")
            if current.latch is Latch.ENGAGED and current.state is not None:
                ok = self._try_record(EV_ENGAGED, {"transition_id": current.epoch,
                                                   "reason": reason, "by": by,
                                                   "already": "ENGAGED",
                                                   "active_work": len(self.active_work())})
                return TransitionResult(current, False, ok, ("already engaged",))
            if self._acl is not None:
                try:
                    self._acl(self.control)
                except Exception:  # noqa: BLE001 - must not prevent engaging
                    notes.append("could not restrict the control folder ACL")
            tid = uuid.uuid4().hex
            try:
                self._write_state("engaged", tid, reason, by)
            except (OSError, _Unsafe) as exc:
                self._try_record(EV_FAILED, {"transition": "engage", "transition_id": tid,
                                             "error": type(exc).__name__})
                raise KillSwitchError(f"kill switch NOT engaged: latch could not be written "
                                      f"({type(exc).__name__})") from None
            after = self.status()
            if after.latch is not Latch.ENGAGED or after.epoch != tid:
                raise KillSwitchError(f"latch written but reads back as {after.latch.value}: "
                                      f"{after.detail}")
            ok = self._try_record(EV_ENGAGED, {"transition_id": tid, "reason": reason, "by": by,
                                               "previous": current.latch.value,
                                               "active_work": len(self.active_work())})
            if not ok:
                notes.append("ENGAGED, but the control audit record FAILED")
            return TransitionResult(self.status(), True, ok, tuple(notes))
        finally:
            ctx.__exit__(None, None, None)

    def reset(self, reason: str, *, by: str = "cli") -> TransitionResult:
        reason = _clean_reason(reason)
        with self._locked():
            current = self.status()
            if current.latch is not Latch.ENGAGED or current.state is None:
                raise KillSwitchError(f"reset refused: latch is {current.latch.value} "
                                      f"({current.detail}); only a valid ENGAGED latch can be "
                                      "reset")
            if current.audit is not None and not current.audit.ok:  # (status is CORRUPT then)
                raise KillSwitchError("reset refused: the control audit is damaged")
            active = self.active_work()
            if active:
                raise KillSwitchError(f"reset refused: {len(active)} AVRA operation(s) still "
                                      f"registered as running: {', '.join(active)[:300]}")
            tid = uuid.uuid4().hex
            try:  # record FIRST: if this fails, nothing changes
                self._audit().record(EV_RESET, {"transition_id": tid,
                                                "previous_transition_id": current.epoch,
                                                "reason": reason, "by": by})
            except Exception as exc:  # noqa: BLE001
                raise KillSwitchError(f"reset NOT done: control audit record failed "
                                      f"({type(exc).__name__}); still ENGAGED") from None
            try:
                self._write_state("disengaged", tid, reason, by)
            except (OSError, _Unsafe) as exc:
                self._try_record(EV_FAILED, {"transition": "reset", "transition_id": tid,
                                             "error": type(exc).__name__})
                raise KillSwitchError(f"reset NOT done: latch could not be written "
                                      f"({type(exc).__name__}); still ENGAGED") from None
            after = self.status()
            if after.latch is not Latch.DISENGAGED:
                raise KillSwitchError(f"reset written but latch reads {after.latch.value}: "
                                      f"{after.detail}")
            return TransitionResult(after, True, True)

    # -- gate -------------------------------------------------------------------------------

    def record_event(self, event: str, data: dict[str, Any]) -> bool:
        """Best-effort control-audit record for the remote stop path (Stage 5).
        Only ``remote_emergency_stop_*`` events; never a latch transition."""
        if not event.startswith("remote_emergency_stop_"):
            raise ValueError("only remote_emergency_stop_* events may be recorded here")
        return self._try_record(event, data)

    def last_remote_stop(self) -> dict[str, Any] | None:
        """The most recent remote emergency-stop outcome in the control audit
        (read-only), so status/reset never hide an unconfirmed remote stop."""
        if _kind(self.control) != "dir" or not self.audit_path.exists():
            return None
        recs = [r for r in inspect_audit_file(self.audit_path).records
                if r.event.startswith("remote_emergency_stop_")
                and r.event != "remote_emergency_stop_requested"]
        return {"event": recs[-1].event, "ts": recs[-1].ts, **recs[-1].data} if recs else None

    def deny(self, operation: str, status: KillSwitchStatus, why: str = "",
             **context: Any) -> KillSwitchEngaged:
        """Record the denial (best effort) and return the exception to raise."""
        self._try_record(EV_DENIED, {"operation": operation[:80], "latch": status.latch.value,
                                     **{k: (str(v)[:80] if v is not None else None)
                                        for k, v in context.items()}})
        return KillSwitchEngaged(operation, status, why)

    def check(self, operation: str, **context: Any) -> None:
        """Quick read-only check (no registration). Raises KillSwitchEngaged."""
        st = self.status()
        if st.blocking:
            raise self.deny(operation, st, **context)

    @contextmanager
    def active(self, operation: str, **context: Any) -> Iterator[GateTicket]:
        """Check the latch and register running work, atomically w.r.t.
        transitions. Fail closed: if the gate itself cannot work, refuse."""
        marker_lock = None
        marker: Path | None = None
        try:
            with self._locked():
                st = self.status()
                if st.blocking:
                    raise self.deny(operation, st, **context)
                marker = self.active_dir / f"{os.getpid()}-{uuid.uuid4().hex}.active"
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0), 0o600)
                try:
                    os.write(fd, json.dumps({"operation": operation[:80], "pid": os.getpid(),
                                             "started_at": _now()}).encode("utf-8"))
                finally:
                    os.close(fd)
                marker_lock = audit_file_lock(marker, self.lock_timeout)
                marker_lock.__enter__()
        except KillSwitchEngaged:
            raise
        except (KillSwitchError, OSError) as exc:
            st = KillSwitchStatus(Latch.UNREADABLE, f"kill switch gate unavailable: {exc}")
            raise self.deny(operation, st, **context) from None
        try:
            yield GateTicket(self, operation, st.epoch, context)
        finally:
            if marker_lock is not None:
                marker_lock.__exit__(None, None, None)
            if marker is not None:
                try:
                    marker.unlink()  # our own marker only
                except OSError:
                    pass

    def active_work(self) -> list[str]:
        """Operations registered as running by live processes (their marker is
        still locked). Unknown/unlockable markers count as active (fail closed)."""
        try:
            if _kind(self.active_dir) != "dir":
                return []
            names = sorted(os.listdir(self.active_dir))
        except (OSError, _Unsafe):
            return ["<active-work registry unreadable>"]
        out = []
        for name in names:
            if not _MARKER.fullmatch(name):
                continue
            path = self.active_dir / name
            try:
                with audit_file_lock(path, 0.05):
                    continue  # lock acquired: owner process is gone (stale marker)
            except AuditLockTimeout:
                pass
            except OSError:
                pass
            try:
                op = json.loads(path.read_bytes()[:1024].decode("utf-8")).get("operation", "?")
            except (OSError, ValueError, AttributeError):
                op = "?"
            out.append(f"{op} (pid {name.split('-', 1)[0]})")
        return out


@dataclass
class GateTicket:
    """Held while registered work runs; ``check`` at every later checkpoint."""

    switch: KillSwitch
    operation: str
    epoch: str | None
    context: dict[str, Any]

    def check(self, checkpoint: str) -> None:
        st = self.switch.status()
        if st.blocking:
            raise self.switch.deny(f"{self.operation}:{checkpoint}", st, **self.context)
        if st.epoch != self.epoch:
            raise self.switch.deny(f"{self.operation}:{checkpoint}", st,
                                   "the kill switch was engaged and reset during this run; "
                                   "work does not resume automatically", **self.context)


def default_killswitch() -> KillSwitch:
    return KillSwitch()
