"""Append-only, hash-chained audit log (docs/security.md).

Every AVRA action must be recorded here — CLAUDE.md: "Every action is
audited." Each record's hash commits to its own content and to the
previous record's hash, so an edited or removed line breaks the chain and
``verify()`` catches it.

M8.7 Stage 1 (ADR 0012) — reliability:

- **Durable appends.** Each record is written, flushed and ``fsync``-ed
  before ``record()`` returns. A failure raises ``AuditWriteError`` (an
  ``OSError``): the caller must treat the action as NOT recorded and fail
  closed. (If the failure came after the bytes reached the file, the log
  shows a record the caller considered failed — it may over-report, never
  under-report.)
- **One writer at a time, across processes.** ``record()`` holds an
  in-process lock (threads) and an OS-level lock on the audit file itself
  (processes), both acquired with a bounded wait; ``AuditLockTimeout`` if
  either cannot be had. The OS lock is a one-byte range lock at a fixed
  offset far beyond any real log size on Windows (``msvcrt.locking``;
  reads and appends are unaffected) and ``flock`` on POSIX. No extra file
  is created. The Runner additionally holds its process-lifetime
  ``AuditOwnerLock`` (``avra.runner.audit_owner``).
- **Never extend a damaged log.** Before appending, the whole file is
  checked (format + chain). Any problem raises ``AuditCorruptError`` and
  nothing is written. A damaged log is never truncated, repaired,
  rewritten or normalized here — it is reported and left as is.
- **Structured diagnostics.** ``verify_detailed()`` returns an
  ``AuditVerification`` naming the first problem (torn tail, malformed
  record, sequence error, hash mismatch, unreadable) and its line.
  ``verify() -> bool`` is unchanged in meaning and never raises.
- **Controlled errors.** ``read_all()`` raises ``AuditCorruptError`` (a
  ``ValueError``) for unparseable data and ``AuditUnreadableError`` (an
  ``OSError``) for I/O problems — never a raw ``JSONDecodeError`` /
  ``TypeError``. It still returns records whose chain is broken: callers
  that inspect tampered logs keep working, and ``verify()`` decides.

Record format and hash semantics are exactly as before (historical logs —
written in text mode, CRLF on Windows — verify unchanged).
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Self

if os.name == "posix":
    import fcntl
else:  # pragma: no cover - exercised on the Windows dev host
    import msvcrt

GENESIS_HASH = "0" * 64
DEFAULT_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_POLL_SECONDS = 0.02
# Windows range lock position: within a signed 32-bit offset (the CRT's
# _locking uses the current file position), beyond any realistic log size.
_WINDOWS_LOCK_OFFSET = 0x7FFF_FFF0
_FIELDS = frozenset({"seq", "ts", "event", "data", "prev_hash", "hash"})
_CONTENDED = {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK, getattr(errno, "EDEADLOCK", 36)}

# Indirection so tests can inject an fsync failure.
_fsync = os.fsync

_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.Lock] = {}


def _lock_for(path: Path) -> threading.Lock:
    """One in-process lock per audit file, shared across instances."""
    key = os.path.normcase(os.path.abspath(path))
    with _LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = _PATH_LOCKS[key] = threading.Lock()
        return lock


# --- errors ---------------------------------------------------------------------


class AuditError(Exception):
    """Base class for audit-log problems. Messages never contain record data."""


class AuditCorruptError(AuditError, ValueError):
    """The log's content is malformed or its chain is broken (fail closed)."""

    def __init__(self, verification: AuditVerification) -> None:
        super().__init__(verification.describe())
        self.verification = verification


class AuditUnreadableError(AuditError, OSError):
    """The log exists but could not be read."""


class AuditWriteError(AuditError, OSError):
    """A record could not be durably appended; treat the action as unrecorded."""


class AuditLockTimeout(AuditWriteError):
    """Another writer held the audit log for longer than the allowed wait."""


# --- verification result ----------------------------------------------------------


class AuditStatus(str, Enum):
    VALID = "valid"
    TORN_TAIL = "torn_tail"  # last line unterminated or unparseable (e.g. crash mid-write)
    MALFORMED_RECORD = "malformed_record"  # an earlier line is not a well-formed record
    SEQ_GAP = "seq_gap"  # seq is not exactly 1..n (gap, repeat or reorder)
    HASH_MISMATCH = "hash_mismatch"  # prev_hash link or record hash wrong (edit)
    UNREADABLE = "unreadable"  # I/O error: cannot read the file at all


_FORMAT_PROBLEMS = frozenset({AuditStatus.TORN_TAIL, AuditStatus.MALFORMED_RECORD})


@dataclass(frozen=True)
class AuditVerification:
    """Deterministic result of checking one audit file."""

    status: AuditStatus
    exists: bool
    record_count: int  # well-formed records read (all of them if format is valid)
    line: int | None = None  # 1-based physical line of the first problem
    detail: str = ""
    last_seq: int = 0  # of the valid chain prefix
    head_hash: str = GENESIS_HASH  # of the valid chain prefix

    @property
    def ok(self) -> bool:
        return self.status is AuditStatus.VALID

    def describe(self) -> str:
        if self.ok:
            return f"valid ({self.record_count} records)"
        where = f" at line {self.line}" if self.line is not None else ""
        return f"{self.status.value}{where}: {self.detail}"


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    ts: str
    event: str
    data: dict[str, Any]
    prev_hash: str
    hash: str


def _record_hash(
    seq: int, ts: str, event: str, data: dict[str, Any], prev_hash: str
) -> str:
    payload = json.dumps(
        {"seq": seq, "ts": ts, "event": event, "data": data, "prev_hash": prev_hash},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate key")
        obj[key] = value
    return obj


def _parse_line(raw: bytes) -> tuple[AuditRecord | None, str]:
    """One line -> (record, "") or (None, reason). Never raises."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "not valid UTF-8"
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError):
        return None, "not valid JSON (or duplicate keys)"
    if not isinstance(obj, dict):
        return None, "not a JSON object"
    if set(obj) != _FIELDS:
        return None, "unexpected or missing record fields"
    seq = obj["seq"]
    if type(seq) is not int:
        return None, "seq is not an integer"
    for name in ("ts", "event", "prev_hash", "hash"):
        if not isinstance(obj[name], str):
            return None, f"{name} is not a string"
    # ``data`` may be any JSON value, exactly as before: record() never
    # restricted it, and event-level validators (e.g. reporting.store) judge it.
    return AuditRecord(**obj), ""


@dataclass
class _Scan:
    records: list[AuditRecord]
    verification: AuditVerification  # first problem in file order, or VALID
    format_problem: AuditVerification | None = None  # first unparseable line, if any

    @property
    def format_ok(self) -> bool:
        return self.format_problem is None


def _scan(path: Path) -> _Scan:
    """Read and check the whole file. Deterministic; never raises."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return _Scan([], AuditVerification(AuditStatus.VALID, exists=False, record_count=0))
    except OSError as exc:
        v = AuditVerification(AuditStatus.UNREADABLE, exists=True, record_count=0,
                              detail=f"cannot read the audit file ({type(exc).__name__})")
        return _Scan([], v, v)

    segments = raw.split(b"\n")
    terminated = segments[:-1]  # every segment followed by "\n"
    tail = segments[-1]  # bytes after the last "\n" (empty if well terminated)
    lines = [(i, seg) for i, seg in enumerate(terminated, start=1) if seg.strip()]
    last_line_no = lines[-1][0] if lines else 0

    records: list[AuditRecord] = []
    chain_problem: AuditVerification | None = None
    format_problem: AuditVerification | None = None
    prev_hash, last_seq = GENESIS_HASH, 0

    for line_no, seg in lines:
        rec, why = _parse_line(seg)
        if rec is None:
            status = (AuditStatus.TORN_TAIL if line_no == last_line_no and not tail
                      else AuditStatus.MALFORMED_RECORD)
            format_problem = AuditVerification(status, True, len(records), line_no, why,
                                               last_seq, prev_hash)
            break
        records.append(rec)
        if chain_problem is not None:
            continue  # keep parsing (read_all), chain is already known broken
        expected_seq = last_seq + 1
        if rec.seq != expected_seq:
            chain_problem = AuditVerification(
                AuditStatus.SEQ_GAP, True, 0, line_no,
                f"expected seq {expected_seq}, found {rec.seq}", last_seq, prev_hash)
        elif rec.prev_hash != prev_hash:
            chain_problem = AuditVerification(
                AuditStatus.HASH_MISMATCH, True, 0, line_no,
                f"prev_hash does not link to record {last_seq}", last_seq, prev_hash)
        elif _record_hash(rec.seq, rec.ts, rec.event, rec.data, rec.prev_hash) != rec.hash:
            chain_problem = AuditVerification(
                AuditStatus.HASH_MISMATCH, True, 0, line_no,
                f"record {rec.seq} content does not match its hash", last_seq, prev_hash)
        else:
            prev_hash, last_seq = rec.hash, rec.seq

    if format_problem is None and tail.strip():
        format_problem = AuditVerification(
            AuditStatus.TORN_TAIL, True, len(records), len(segments),
            "last line is not newline-terminated (incomplete write)", last_seq, prev_hash)

    # Report the first problem in file order (deterministic).
    problems = [p for p in (chain_problem, format_problem) if p is not None]
    if problems:
        first = min(problems, key=lambda p: p.line or 0)
        first = AuditVerification(first.status, True, len(records), first.line, first.detail,
                                  first.last_seq, first.head_hash)
        return _Scan(records, first, format_problem)
    v = AuditVerification(AuditStatus.VALID, True, len(records), None, "", last_seq, prev_hash)
    return _Scan(records, v)


# --- cross-process lock -------------------------------------------------------------


class _FileLock:
    """Exclusive OS-level lock on the audit file, bounded wait."""

    def __init__(self, path: Path, timeout: float) -> None:
        self._path = path
        self._timeout = timeout
        self._fd: int | None = None

    def _try(self, fd: int) -> None:
        if os.name == "posix":
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)

    def __enter__(self) -> Self:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0) \
            | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self._path, flags)
        except OSError as exc:
            raise AuditWriteError(f"cannot open the audit log for locking "
                                  f"({type(exc).__name__})") from None
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                self._try(fd)
                self._fd = fd
                return self
            except OSError as exc:
                if exc.errno not in _CONTENDED:
                    os.close(fd)
                    raise AuditWriteError(f"cannot lock the audit log "
                                          f"({type(exc).__name__})") from None
            if time.monotonic() >= deadline:
                os.close(fd)
                raise AuditLockTimeout(
                    f"audit log is locked by another writer (waited {self._timeout:g}s); "
                    "nothing was recorded")
            time.sleep(_LOCK_POLL_SECONDS)

    def __exit__(self, *exc: object) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "posix":
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                os.lseek(fd, _WINDOWS_LOCK_OFFSET, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass  # closing the descriptor releases the lock anyway
        finally:
            os.close(fd)


def audit_file_lock(path: str | Path, timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS) -> _FileLock:
    """The same OS-level writer lock ``AuditLog.record()`` takes (the file
    must exist). Holding it gives a consistent snapshot of the file."""
    return _FileLock(Path(path), timeout)


@dataclass(frozen=True)
class AuditSnapshot:
    """Read-only view of one audit file: its well-formed records (file order,
    up to the first unparseable line) and the structured verification."""

    records: tuple[AuditRecord, ...]
    verification: AuditVerification


def inspect_audit_file(path: str | Path) -> AuditSnapshot:
    """Read-only, deterministic, never raises, never creates anything."""
    scan = _scan(Path(path))
    return AuditSnapshot(tuple(scan.records), scan.verification)


def _fsync_dir(directory: Path) -> None:
    """Persist a new directory entry (POSIX; best effort, as in reporting.store)."""
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


# --- the log --------------------------------------------------------------------------


class AuditLog:
    """One append-only JSONL audit log, identified by its file path."""

    def __init__(self, path: str | Path, *,
                 lock_timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS) -> None:
        if not 0 < lock_timeout <= 300:
            raise ValueError("lock_timeout must be in (0, 300] seconds")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_timeout = lock_timeout
        self._lock = _lock_for(self.path)

    def _ensure_file(self) -> None:
        """Create the log if missing (empty append; never truncates)."""
        if self.path.exists():
            return
        try:
            with self.path.open("a", encoding="utf-8"):
                pass
        except OSError as exc:
            raise AuditWriteError(f"cannot create the audit log ({type(exc).__name__})") from None
        _fsync_dir(self.path.parent)

    def record(self, event: str, data: dict[str, Any] | None = None) -> AuditRecord:
        data = data or {}
        if not self._lock.acquire(timeout=self.lock_timeout):
            raise AuditLockTimeout(
                f"audit log is busy in this process (waited {self.lock_timeout:g}s); "
                "nothing was recorded")
        try:
            self._ensure_file()
            with _FileLock(self.path, self.lock_timeout):
                scan = _scan(self.path)
                if not scan.verification.ok:
                    if scan.verification.status is AuditStatus.UNREADABLE:
                        raise AuditWriteError(scan.verification.describe())
                    raise AuditCorruptError(scan.verification)  # never extend a damaged log
                seq = scan.verification.last_seq + 1
                prev_hash = scan.verification.head_hash
                ts = datetime.now(UTC).isoformat()
                digest = _record_hash(seq, ts, event, data, prev_hash)
                rec = AuditRecord(
                    seq=seq, ts=ts, event=event, data=data, prev_hash=prev_hash, hash=digest
                )
                line = json.dumps(asdict(rec), sort_keys=True) + "\n"
                try:
                    # Text mode on purpose: identical bytes to every historical
                    # record (CRLF on Windows); the hash never covers line endings.
                    with self.path.open("a", encoding="utf-8") as fh:
                        fh.write(line)
                        fh.flush()
                        _fsync(fh.fileno())
                except OSError as exc:
                    raise AuditWriteError(
                        f"audit append failed ({type(exc).__name__}); treat the action "
                        "as NOT recorded") from None
        finally:
            self._lock.release()
        return rec

    def verify_detailed(self) -> AuditVerification:
        """Structured, deterministic integrity check. Never raises."""
        return _scan(self.path).verification

    def read_all(self) -> list[AuditRecord]:
        """Every record in file order. Raises ``AuditCorruptError`` if any line
        is not a well-formed record, ``AuditUnreadableError`` on I/O errors.
        Records with a broken chain are still returned (check ``verify()``)."""
        scan = _scan(self.path)
        if scan.verification.status is AuditStatus.UNREADABLE:
            raise AuditUnreadableError(scan.verification.describe())
        if scan.format_problem is not None:
            raise AuditCorruptError(scan.format_problem)
        return scan.records

    def verify(self) -> bool:
        """Check the hash chain end to end. False means tampering, damage or
        an unreadable file; it never raises."""
        return self.verify_detailed().ok
