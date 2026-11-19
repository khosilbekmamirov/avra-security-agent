"""Runner emergency-stop latch (ADR 0012 Stage 4).

A persistent, fail-closed latch next to the Runner's audit log
(``<audit dir>/emergency-stop.json``). While it is not a verified READY,
the Runner refuses every new tool execution. It survives Runner restarts,
``systemctl restart`` and crashes; a restart never clears it.

The state is decided from BOTH the latch file and the Runner audit log
(append-only, ``chattr +a`` on Kali), exactly like the Windows kill switch
(``avra.control.killswitch``):

    no latch file and no emergency transition in the audit  READY (fresh install)
    valid "stopped" file                                    STOPPED
    valid "ready" file backed by the matching
      emergency_stop_reset record                           READY
    anything else (malformed/oversized file, file vs audit
      contradiction - e.g. latch deleted while the audit
      says stopped -, damaged audit, link/reparse point,
      foreign owner)                                        CORRUPT    (blocks)
    I/O error                                               UNREADABLE (blocks)

Engage: write STOPPED atomically (fsync) FIRST, read it back, THEN record
``emergency_stop_engaged``. Reset is NOT an HTTP operation: only the local
operator command ``python -m avra.runner --reset-emergency-stop`` (Runner
stopped, interactive) records ``emergency_stop_reset`` FIRST and then writes
READY. A corrupt latch is never repaired or overwritten.

Limit: someone who can delete the latch file AND truncate the append-only
audit log (root on Kali) can make the Runner look freshly installed.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from avra.storage.audit import AuditLog, AuditStatus, inspect_audit_file

LATCH_NAME = "emergency-stop.json"
LATCH_VERSION = 1
MAX_LATCH_BYTES = 4096
MAX_REASON_CHARS = 200
EV_REQUESTED = "emergency_stop_requested"
EV_ENGAGED = "emergency_stop_engaged"
EV_ENGAGE_FAILED = "emergency_stop_engage_failed"
EV_RESET = "emergency_stop_reset"
_TRANSITIONS = (EV_ENGAGED, EV_RESET)
_FIELDS = frozenset({"v", "state", "transition_id", "changed_at", "reason", "by"})
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# Indirections so tests can inject failures.
_fsync = os.fsync
_replace = os.replace


class LatchState(str, Enum):
    READY = "READY"
    STOPPED = "STOPPED"
    CORRUPT = "CORRUPT"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True)
class LatchStatus:
    state: LatchState
    detail: str
    transition_id: str | None = None

    @property
    def blocking(self) -> bool:
        return self.state is not LatchState.READY


@dataclass(frozen=True)
class EngageOutcome:
    status: LatchStatus
    durable: bool  # the STOPPED latch is on disk and reads back as STOPPED
    already: bool
    audit_recorded: bool


class LatchError(Exception):
    """A latch transition could not be completed (message says what holds)."""


class _Unsafe(Exception):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _check_path(path: Path) -> bool:
    """True if a regular file exists, False if absent; raises _Unsafe."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        raise _Unsafe("latch is a symlink or reparse point")
    if not stat.S_ISREG(st.st_mode):
        raise _Unsafe("latch is not a regular file")
    if os.name == "posix" and st.st_uid != os.geteuid():
        raise _Unsafe("latch is owned by another user")
    return True


def _no_dupes(pairs):
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def clean_reason(reason: str) -> str:
    text = " ".join(str(reason).split())
    if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("a non-empty, printable reason is required")
    if len(text) > MAX_REASON_CHARS:
        raise ValueError(f"reason must be at most {MAX_REASON_CHARS} characters")
    return text


class RunnerLatch:
    def __init__(self, path: Path, audit: AuditLog) -> None:
        self.path = Path(path)
        self.audit = audit

    @classmethod
    def beside(cls, audit: AuditLog) -> RunnerLatch:
        return cls(Path(audit.path).parent / LATCH_NAME, audit)

    # -- reading ---------------------------------------------------------------------------

    def _read(self) -> dict[str, Any] | None:
        if not _check_path(self.path):
            return None
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            before, after = os.lstat(self.path), os.fstat(fd)
            if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
                raise _Unsafe("latch changed while it was opened")
            raw = os.read(fd, MAX_LATCH_BYTES + 1)
        finally:
            os.close(fd)
        if len(raw) > MAX_LATCH_BYTES:
            raise ValueError("latch is larger than allowed")
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_dupes)
        if not isinstance(obj, dict) or set(obj) != _FIELDS or obj["v"] != LATCH_VERSION \
                or obj["state"] not in ("stopped", "ready") \
                or not isinstance(obj["transition_id"], str) or len(obj["transition_id"]) != 32 \
                or any(c not in "0123456789abcdef" for c in obj["transition_id"]) \
                or not all(isinstance(obj[k], str) for k in ("changed_at", "reason", "by")) \
                or len(obj["reason"]) > MAX_REASON_CHARS:
            raise ValueError("latch does not match the v1 schema")
        return obj

    def load(self) -> LatchStatus:
        """Read-only. Never creates, repairs or changes anything."""
        try:
            latch = self._read()
        except _Unsafe as exc:
            return LatchStatus(LatchState.CORRUPT, f"unsafe latch path: {exc}")
        except (ValueError, UnicodeDecodeError, RecursionError):
            return LatchStatus(LatchState.CORRUPT, "latch file is malformed (kept as evidence)")
        except OSError as exc:
            return LatchStatus(LatchState.UNREADABLE, f"latch not readable ({type(exc).__name__})")
        snap = inspect_audit_file(self.audit.path)
        if snap.verification.status is AuditStatus.UNREADABLE:
            return LatchStatus(LatchState.UNREADABLE, "audit log not readable")
        if not snap.verification.ok:
            return LatchStatus(LatchState.CORRUPT, f"audit log damaged: "
                               f"{snap.verification.describe()}")
        last = next((r for r in reversed(snap.records) if r.event in _TRANSITIONS
                     and isinstance(r.data, dict) and not r.data.get("already")), None)
        last_id = last.data.get("transition_id") if last is not None else None
        if latch is not None and latch["state"] == "stopped":
            return LatchStatus(LatchState.STOPPED, f"emergency stop since {latch['changed_at']} "
                               f"({latch['reason']})", latch["transition_id"])
        if latch is not None:
            if last is not None and last.event == EV_RESET and last_id == latch["transition_id"]:
                return LatchStatus(LatchState.READY, "reset by the local operator",
                                   latch["transition_id"])
            return LatchStatus(LatchState.CORRUPT, "ready latch is not backed by its reset record")
        if last is not None and last.event == EV_ENGAGED:
            return LatchStatus(LatchState.CORRUPT, "latch file missing but the audit log says "
                               "stopped (deleted?)")
        if last is not None:
            return LatchStatus(LatchState.CORRUPT, "latch file missing after a reset")
        return LatchStatus(LatchState.READY, "never stopped (fresh installation)")

    # -- writing ---------------------------------------------------------------------------

    def _write(self, state: str, transition_id: str, reason: str, by: str) -> None:
        if os.path.lexists(self.path):
            _check_path(self.path)
        data = json.dumps({"v": LATCH_VERSION, "state": state, "transition_id": transition_id,
                           "changed_at": _now(), "reason": reason, "by": by},
                          sort_keys=True).encode("utf-8") + b"\n"
        tmp = self.path.with_name(f".{LATCH_NAME}.{secrets.token_hex(8)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                     0o600)
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                _fsync(fd)
            finally:
                os.close(fd)
            _replace(tmp, self.path)
        except BaseException:
            try:
                tmp.unlink()  # our own temp file only
            except OSError:
                pass
            raise
        if os.name == "posix":
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    def _record(self, event: str, data: dict[str, Any]) -> bool:
        try:
            self.audit.record(event, data)
            return True
        except Exception:  # noqa: BLE001 - reported to the caller as audit_recorded=False
            return False

    def _file_state(self) -> tuple[str, str | None]:
        """("absent"|"stopped"|"ready"|"invalid", transition_id) of the FILE
        alone - independent of the audit log (review R4)."""
        try:
            obj = self._read()
        except (_Unsafe, ValueError, UnicodeDecodeError, RecursionError, OSError):
            return "invalid", None
        if obj is None:
            return "absent", None
        return obj["state"], obj["transition_id"]

    def engage(self, reason: str, *, by: str) -> EngageOutcome:
        """Idempotent. ``durable`` = the STOPPED latch FILE reads back (an
        audit-log problem is reported separately and never prevents writing
        STOPPED). Only a malformed/unsafe latch file is kept untouched."""
        reason = clean_reason(reason)
        current = self.load()
        kind, file_tid = self._file_state()
        if kind == "stopped":
            ok = self._record(EV_ENGAGED, {"transition_id": file_tid,
                                           "reason": reason, "by": by, "already": True})
            return EngageOutcome(self.load(), True, True, ok)
        if kind == "invalid":
            # Evidence: never overwritten. It already blocks (CORRUPT/UNREADABLE),
            # but a clean STOPPED could not be written.
            ok = self._record(EV_ENGAGE_FAILED, {"reason": reason, "by": by,
                                                 "latch": current.state.value})
            return EngageOutcome(current, False, False, ok)
        tid = uuid.uuid4().hex
        try:
            self._write("stopped", tid, reason, by)
        except (OSError, _Unsafe) as exc:
            ok = self._record(EV_ENGAGE_FAILED, {"transition_id": tid, "reason": reason,
                                                 "by": by, "error": type(exc).__name__})
            return EngageOutcome(self.load(), False, False, ok)
        durable = self._file_state() == ("stopped", tid)
        ok = self._record(EV_ENGAGED, {"transition_id": tid, "reason": reason, "by": by,
                                       "previous": current.state.value, "durable": durable})
        return EngageOutcome(self.load(), durable, False, ok)

    def reset(self, reason: str, *, by: str) -> LatchStatus:
        """LOCAL OPERATOR ONLY (never reachable over HTTP). The caller must
        hold the Runner's AuditOwnerLock, i.e. no Runner is running."""
        reason = clean_reason(reason)
        current = self.load()
        if current.state is not LatchState.STOPPED:
            raise LatchError(f"reset refused: latch is {current.state.value} ({current.detail})")
        tid = uuid.uuid4().hex
        try:  # record FIRST: if this fails nothing changes
            self.audit.record(EV_RESET, {"transition_id": tid,
                                         "previous_transition_id": current.transition_id,
                                         "reason": reason, "by": by})
        except Exception as exc:  # noqa: BLE001
            raise LatchError(f"reset NOT done: audit record failed ({type(exc).__name__}); "
                             "still STOPPED") from None
        try:
            self._write("ready", tid, reason, by)
        except (OSError, _Unsafe) as exc:
            raise LatchError(f"reset NOT done: latch could not be written "
                             f"({type(exc).__name__}); still STOPPED") from None
        after = self.load()
        if after.state is not LatchState.READY:
            raise LatchError(f"reset written but latch reads {after.state.value}")
        return after
