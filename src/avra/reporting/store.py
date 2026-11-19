"""Attested, immutable report storage (M7.9.1 — fixes D2 and D6).

A research report is written once, as exact bytes, and bound to the
session's hash-chained audit log. Steps, in this order:

1. Find the run's audit anchor: the chain must verify, the last record must
   be ``research_stopped``, and the run's ``research_started`` (whose ``seq``
   names the file) must not already have a report.
2. Serialize the report deterministically (sorted keys, UTF-8, LF only) and
   hash those exact bytes — the hash always matches the file on disk, on
   every OS (D6: text-mode writes on Windows turned LF into CRLF).
3. Write the bytes to a private temp file in the same directory with
   exclusive create, fsync it, and re-read it to confirm the hash.
4. Append ``report_generated`` (hash, size, verdict, reasons, anchor) to the
   audit log. From here the report is ATTESTED.
5. Publish: hard-link the temp file to the final name. ``os.link`` never
   replaces an existing file (NTFS and POSIX), so no report is overwritten.
   Then confirm the published bytes and drop the temp name (the data stays
   under the final name).

Crash consistency: a failure before step 4 leaves no audit claim and no
published file — at most a temp file, which is kept, never presented as a
report, and never deleted silently. A failure after step 4 leaves an
attested report whose bytes still sit in the fsynced temp file; the
``report_states`` / ``complete_publication`` pair detects that and finishes
publication after re-checking the hash. Nothing here ever deletes a report,
an evidence file or an audit record.

Untrusted audit data: the chain detects *edits*, but it is not keyed — anyone
who can write the sessions directory can append a well-formed event. So
every field of a ``report_generated`` event is treated as untrusted input:
file names are never taken from the event; they are rebuilt from the
session UUID (the audit log's own name) and a validated run sequence number,
and the event's strings must equal them exactly. Every file is inspected
with ``lstat`` first; symlinks, junctions/reparse points, non-regular files
and extra hard links are never read through or acted on.

Historical reports (``<session>.report.json``, written before M7.9.1) are
never touched: new reports use a different, run-scoped name.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from avra.reporting import ResearchReport, ValidationResult
from avra.storage.audit import AuditLog, AuditRecord

EVENT_GENERATED = "report_generated"
EVENT_PUBLISH_FAILED = "report_publish_failed"
EVENT_PUBLICATION_COMPLETED = "report_publication_completed"
STORE_FORMAT = 1
SERIALIZATION = "json; utf-8; LF; sort_keys; indent=2; trailing LF"

# Indirections so tests can inject faults without touching the real os module.
_open = os.open
_write = os.write
_fsync = os.fsync
_close = os.close
_link = os.link

_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) \
    | getattr(os, "O_NOINHERIT", 0)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_TEMP_SUFFIX = re.compile(r"[0-9a-f]{32}\.tmp", re.ASCII)


class ReportStoreError(Exception):
    """The report could not be stored as an attested, published file.

    The message always says whether the report is attested (has an audit
    event) and where any leftover temp file is."""


@dataclass(frozen=True)
class RunAnchor:
    started_seq: int
    stopped_seq: int
    stopped_hash: str


@dataclass(frozen=True)
class StoredReport:
    path: Path
    sha256: str
    size: int
    audit_seq: int
    temp_left: Path | None = None  # set only if dropping the temp name failed


class PublicationState(str, Enum):
    PUBLISHED = "published"          # final file present, hash matches the event
    RECOVERABLE = "recoverable"      # final missing; private temp file holds the attested bytes
    CONFLICT = "conflict"            # final name holds different bytes
    MISSING = "missing"              # neither a matching final nor a matching temp
    INVALID_EVENT = "invalid_event"  # event fields fail validation; never acted on
    UNSAFE_PATH = "unsafe_path"      # a named entry is a link/reparse point/not a plain file
    # Final file present with the attested bytes, BUT a recovery authorization
    # for this report has no matching completion/failure record: the
    # publication itself is not fully audited (M7.9.2R). Never "published".
    PUBLISHED_RECOVERY_UNAUDITED = "published_recovery_unaudited"


@dataclass(frozen=True)
class ReportStatus:
    event_seq: int
    state: PublicationState
    report_file: str = ""  # only set once validated
    temp_file: str = ""
    sha256: str = ""
    detail: str = ""


def serialize_report(report: ResearchReport) -> bytes:
    """Deterministic bytes: same report -> same bytes on every OS. Uses the
    schema-aware dict (M7.9.3) so older-schema reports keep their exact bytes."""
    text = json.dumps(report.canonical_dict(), sort_keys=True, ensure_ascii=False,
                      indent=2, separators=(",", ": "))
    return (text + "\n").encode("utf-8")


def report_filename(session_id: uuid.UUID, started_seq: int) -> str:
    if not isinstance(session_id, uuid.UUID) or type(started_seq) is not int \
            or started_seq < 1:
        raise ReportStoreError("report names come only from a session UUID and a positive seq")
    return f"{session_id}.run{started_seq}.report.json"


# --- trusted inputs -------------------------------------------------------------

def _read_records(audit: AuditLog) -> list[AuditRecord]:
    try:
        return audit.read_all()
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ReportStoreError(f"session audit log is unreadable ({type(exc).__name__})") from None


def _chain_ok(audit: AuditLog) -> bool:
    try:
        return audit.verify()
    except (ValueError, TypeError, KeyError):
        return False


def _session_of(audit: AuditLog) -> uuid.UUID | None:
    """The session UUID from the audit log's OWN file name (canonical form only)."""
    name = Path(audit.path).name
    if not name.endswith(".jsonl"):
        return None
    stem = name[: -len(".jsonl")]
    try:
        sid = uuid.UUID(stem)
    except ValueError:
        return None
    return sid if str(sid) == stem else None


def _require_dir(audit: AuditLog, directory: Path) -> Path:
    """Reports live next to their session audit log, nowhere else."""
    resolved = Path(directory).resolve()
    if resolved != Path(audit.path).parent.resolve():
        raise ReportStoreError("report directory must be the session audit log's directory")
    return resolved


def run_anchor(audit: AuditLog) -> RunAnchor:
    """The just-finished run, read from the VERIFIED chain (fail closed)."""
    if not _chain_ok(audit):
        raise ReportStoreError("session audit chain does not verify; report not stored")
    records = _read_records(audit)
    if not records or records[-1].event != "research_stopped":
        raise ReportStoreError("last audit record is not research_stopped; report not stored")
    started = next((r for r in reversed(records) if r.event == "research_started"), None)
    if started is None:
        raise ReportStoreError("no research_started record for this run; report not stored")
    for r in records:
        if r.event == EVENT_GENERATED and isinstance(r.data, dict) \
                and r.data.get("research_started_seq") == started.seq:
            raise ReportStoreError(f"a report was already generated for run seq {started.seq}")
    stopped = records[-1]
    return RunAnchor(started_seq=started.seq, stopped_seq=stopped.seq, stopped_hash=stopped.hash)


# --- filesystem inspection (never follows links) -------------------------------

@dataclass(frozen=True)
class _Entry:
    kind: str  # "absent" | "regular" | "unsafe"
    sha256: str | None = None
    nlink: int = 0
    why: str = ""


def _inspect(path: Path) -> _Entry:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return _Entry("absent")
    except OSError as exc:
        return _Entry("unsafe", why=f"cannot lstat ({type(exc).__name__})")
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        return _Entry("unsafe", why="symlink or reparse point (e.g. junction)")
    if not stat.S_ISREG(st.st_mode):
        return _Entry("unsafe", why="not a regular file")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return _Entry("unsafe", why=f"cannot read ({type(exc).__name__})")
    return _Entry("regular", sha256=digest, nlink=st.st_nlink)


def _sha256_file(path: Path) -> str | None:
    entry = _inspect(path)
    return entry.sha256 if entry.kind == "regular" else None


def _fsync_dir(directory: Path) -> None:
    """Persist the directory entry (POSIX). Windows has no directory fsync."""
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


# --- writing ---------------------------------------------------------------------

def _write_temp(temp: Path, data: bytes) -> None:
    try:
        fd = _open(temp, _OPEN_FLAGS, 0o600)
    except OSError as exc:
        raise ReportStoreError(f"cannot create temp report file ({type(exc).__name__}); "
                               "report NOT attested, nothing published") from None
    try:
        view = memoryview(data)
        while view:
            n = _write(fd, view)
            if n <= 0:
                raise OSError("short write")
            view = view[n:]
        _fsync(fd)
    except OSError as exc:
        raise ReportStoreError(f"writing temp report failed ({type(exc).__name__}); report NOT "
                               f"attested, nothing published; temp file kept: {temp}") from None
    finally:
        try:
            _close(fd)
        except OSError:
            pass


def store_report(report: ResearchReport, validation: ValidationResult, *, audit: AuditLog,
                 session_id: uuid.UUID, directory: Path) -> StoredReport:
    """Write ``report`` once, attest it in ``audit``, then publish it."""
    if report.session_id != str(session_id) or _session_of(audit) != session_id:
        raise ReportStoreError("report session_id does not match the session audit log; "
                               "report not stored")
    directory = _require_dir(audit, directory)
    anchor = run_anchor(audit)
    final = directory / report_filename(session_id, anchor.started_seq)
    if os.path.lexists(final):  # also catches a dangling symlink
        raise ReportStoreError(f"report already exists, not overwritten: {final.name}")

    data = serialize_report(report)
    digest = hashlib.sha256(data).hexdigest()
    temp = directory / f".{final.name}.{uuid.uuid4().hex}.tmp"
    _write_temp(temp, data)
    if _sha256_file(temp) != digest:
        raise ReportStoreError(f"temp report does not read back as written; report NOT attested, "
                               f"nothing published; temp file kept: {temp}")

    event = {
        "report_file": final.name, "temp_file": temp.name, "sha256": digest, "size": len(data),
        "store_format": STORE_FORMAT, "serialization": SERIALIZATION,
        "verdict": validation.verdict.value, "reasons": list(validation.reasons),
        "research_started_seq": anchor.started_seq,
        "research_stopped_seq": anchor.stopped_seq,
        "research_stopped_hash": anchor.stopped_hash,
    }
    try:
        rec = audit.record(EVENT_GENERATED, event)
    # Deliberately broad: ANY failure to append (I/O, serialization, ...) must
    # be reported as "not attested" and must stop publication.
    except Exception as exc:  # noqa: BLE001
        raise ReportStoreError(f"audit append failed ({type(exc).__name__}); report NOT attested, "
                               f"nothing published; temp file kept: {temp}") from None

    try:
        _link(temp, final)
    except OSError as exc:
        try:
            audit.record(EVENT_PUBLISH_FAILED, {"report_generated_seq": rec.seq,
                                                "report_file": final.name, "temp_file": temp.name,
                                                "error": type(exc).__name__})
        # Best effort only: it must never mask the publication error raised
        # below, and the report_generated event already names the temp file.
        except Exception:  # noqa: BLE001, S110
            pass
        raise ReportStoreError(f"report attested (audit seq {rec.seq}) but NOT published "
                               f"({type(exc).__name__}); bytes kept in {temp} for recovery") from None

    if _sha256_file(final) != digest:
        raise ReportStoreError(f"published report does not match its attested hash: {final}")
    _fsync_dir(directory)
    temp_left: Path | None = None
    try:
        temp.unlink()  # drops only the temp NAME; the data lives on under `final`
        _fsync_dir(directory)
    except OSError:
        temp_left = temp
    return StoredReport(path=final, sha256=digest, size=len(data), audit_seq=rec.seq,
                        temp_left=temp_left)


# --- status and recovery (all event fields untrusted) ------------------------------

class _Invalid(Exception):
    pass


def _field(data: dict, key: str, typ: type):
    value = data.get(key)
    if type(value) is not typ:  # exact type: rejects bool-as-int, None, lists, ...
        raise _Invalid(f"field {key!r} missing or not {typ.__name__}")
    return value


def _validated(rec: AuditRecord, session: uuid.UUID | None,
               by_seq: dict[int, AuditRecord]) -> tuple[str, str, str, int]:
    """Return (report_file, temp_file, sha256, started_seq) or raise _Invalid.
    The names returned are rebuilt by this code; the event's strings are only
    compared against them, never used to build a path."""
    data = rec.data
    if not isinstance(data, dict):
        raise _Invalid("event data is not an object")
    report_file = _field(data, "report_file", str)
    temp_file = _field(data, "temp_file", str)
    sha = _field(data, "sha256", str)
    size = _field(data, "size", int)
    started_seq = _field(data, "research_started_seq", int)
    stopped_seq = _field(data, "research_stopped_seq", int)
    stopped_hash = _field(data, "research_stopped_hash", str)
    if session is None:
        raise _Invalid("audit log name is not a canonical session UUID")
    if not _HEX64.fullmatch(sha) or not _HEX64.fullmatch(stopped_hash):
        raise _Invalid("sha256 / research_stopped_hash is not 64 lowercase hex characters")
    if size < 0:
        raise _Invalid("size is negative")
    if not 1 <= started_seq < stopped_seq < rec.seq:
        raise _Invalid("inconsistent audit sequence references")
    started, stopped = by_seq.get(started_seq), by_seq.get(stopped_seq)
    if started is None or started.event != "research_started":
        raise _Invalid("research_started_seq does not point to a research_started record")
    if stopped is None or stopped.event != "research_stopped" or stopped.hash != stopped_hash:
        raise _Invalid("research_stopped_seq/hash does not match a research_stopped record")
    if any(by_seq[s].event == "research_started" for s in range(started_seq + 1, stopped_seq)
           if s in by_seq):
        raise _Invalid("research_stopped belongs to a later run")
    expected = report_filename(session, started_seq)
    if report_file != expected:
        raise _Invalid("report_file is not this session's expected report name")
    prefix = f".{expected}."
    if not (temp_file.startswith(prefix) and _TEMP_SUFFIX.fullmatch(temp_file[len(prefix):])):
        raise _Invalid("temp_file does not match the expected temp name pattern")
    # Rebuild from validated parts only (no event string reaches a path).
    rebuilt_temp = prefix + temp_file[len(prefix):]
    return expected, rebuilt_temp, sha, started_seq


def report_states(audit: AuditLog, directory: Path) -> list[ReportStatus]:
    """Read-only: the publication state of every ``report_generated`` event.
    Never follows links, never writes, never raises on a malformed event."""
    directory = _require_dir(audit, directory)
    records = _read_records(audit)
    if not _chain_ok(audit):
        return [ReportStatus(event_seq=r.seq, state=PublicationState.INVALID_EVENT,
                             detail="session audit chain does not verify")
                for r in records if r.event == EVENT_GENERATED]
    session = _session_of(audit)
    by_seq = {r.seq: r for r in records}
    open_auth = _unresolved_authorizations(records)
    seen_runs: set[int] = set()
    out = []
    for rec in records:
        if rec.event != EVENT_GENERATED:
            continue
        try:
            report_file, temp_file, sha, started_seq = _validated(rec, session, by_seq)
            if started_seq in seen_runs:
                raise _Invalid("duplicate report_generated for the same run")
        except _Invalid as exc:
            out.append(ReportStatus(event_seq=rec.seq, state=PublicationState.INVALID_EVENT,
                                    detail=str(exc)))
            continue
        seen_runs.add(started_seq)
        final_e, temp_e = _inspect(directory / report_file), _inspect(directory / temp_file)
        detail = ""
        if final_e.kind == "unsafe":
            state, detail = PublicationState.UNSAFE_PATH, f"report_file: {final_e.why}"
        elif final_e.kind == "regular":
            state = (PublicationState.PUBLISHED if final_e.sha256 == sha
                     else PublicationState.CONFLICT)
        elif temp_e.kind == "unsafe":
            state, detail = PublicationState.UNSAFE_PATH, f"temp_file: {temp_e.why}"
        elif temp_e.kind == "regular" and temp_e.nlink != 1:
            state, detail = PublicationState.UNSAFE_PATH, "temp_file has extra hard links"
        elif temp_e.kind == "regular" and temp_e.sha256 == sha:
            state = PublicationState.RECOVERABLE
        else:
            state = PublicationState.MISSING
        pending = [a for a, report_seq in open_auth.items() if report_seq == rec.seq]
        if state is PublicationState.PUBLISHED and pending:
            state = PublicationState.PUBLISHED_RECOVERY_UNAUDITED
            detail = (f"recovery authorized at audit seq {', '.join(map(str, pending))} "
                      "has no matching completion or failure record")
        out.append(ReportStatus(event_seq=rec.seq, state=state, report_file=report_file,
                                temp_file=temp_file, sha256=sha, detail=detail))
    return out


def _unresolved_authorizations(records: list[AuditRecord]) -> dict[int, int | None]:
    """Recovery authorizations (seq -> report_generated seq) that no LATER,
    MATCHING completion/failure record closes. A closing record must name this
    authorization seq, the same report seq and (for completion) the same
    SHA-256 — a forged or mismatched record cannot close it. A malformed
    authorization stays open (with report seq None)."""
    auths: dict[int, tuple[int | None, str | None]] = {}
    closed: set[int] = set()
    for r in records:
        d = r.data if isinstance(r.data, dict) else {}
        if r.event == EVENT_RECOVERY_AUTHORIZED:
            seq, sha = d.get("report_generated_seq"), d.get("sha256")
            auths[r.seq] = (seq if type(seq) is int else None,
                            sha if isinstance(sha, str) else None)
        elif r.event in (EVENT_PUBLICATION_COMPLETED, EVENT_RECOVERY_FAILED):
            a = d.get("recovery_authorized_seq")
            if type(a) is not int or a not in auths or a >= r.seq:
                continue
            report_seq, sha = auths[a]
            if report_seq is None or d.get("report_generated_seq") != report_seq:
                continue
            if r.event == EVENT_PUBLICATION_COMPLETED and d.get("sha256") != sha:
                continue
            closed.add(a)
    return {a: report_seq for a, (report_seq, _) in auths.items() if a not in closed}


# --- controlled recovery (M7.9.2R) ---------------------------------------------------
#
# Recovery publishes an attested-but-unpublished report ONLY for exact
# (event_seq, sha256) pairs the owner approved. Per report, immediately before
# acting: re-verify the chain, re-validate the event, open the temp file and
# check (through the open handle) that it is the same plain, single-link file
# with exactly the attested bytes, check the final name is absent, audit the
# authorization, link without overwrite, then prove the published name is the
# SAME file as the open handle with the same bytes, and audit completion.
#
# Remaining threat model. Linux: the link is made through /proc/self/fd/N,
# i.e. from the open, verified file itself, so the temp NAME cannot be swapped
# underneath it. Windows: there is no link-by-handle, but the verified source
# is held open without delete sharing, so its name cannot be renamed or
# removed until the link is done (tested). On every platform the one window
# left is an in-place rewrite of the held file by someone with write access to
# the sessions directory; the post-link proof (same file identity AND the
# attested bytes) detects it and fails closed: audited as failed, never
# reported as recovered, nothing deleted (verify then shows CONFLICT).

EVENT_RECOVERY_AUTHORIZED = "report_recovery_authorized"
EVENT_RECOVERY_FAILED = "report_recovery_failed"

_READ_FLAGS = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) \
    | getattr(os, "O_NOINHERIT", 0)
_PROC_FD = Path("/proc/self/fd")


class RecoveryStatus(str, Enum):
    PUBLISHED = "published"                      # linked, verified, completion audited
    PUBLISHED_UNAUDITED = "published_unaudited"  # linked + verified; completion NOT audited
    REFUSED = "refused"                          # changed since approval; nothing done
    FAILED = "failed"                            # attempted, did not publish (fail closed)
    NOT_ATTEMPTED = "not_attempted"              # an earlier entry stopped the run


@dataclass(frozen=True)
class RecoveryOutcome:
    event_seq: int
    sha256: str
    status: RecoveryStatus
    report_file: str = ""
    detail: str = ""
    authorization_seq: int | None = None
    completion_seq: int | None = None


class _Changed(Exception):
    pass


def _identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _plain(st: os.stat_result) -> bool:
    return stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) \
        and not getattr(st, "st_file_attributes", 0) & _REPARSE


def _open_verified(path: Path, sha256: str, *, single_link: bool) -> tuple[int, os.stat_result]:
    """Open ``path`` and prove, through the handle, that it is the plain file
    the path named a moment ago, with exactly ``sha256``. Returns (fd, fstat);
    the caller closes fd. Raises _Changed on any doubt."""
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise _Changed(f"{path.name}: {type(exc).__name__}") from None
    if not _plain(before):
        raise _Changed(f"{path.name}: not a plain file (link, junction or special file)")
    try:
        fd = os.open(path, _READ_FLAGS)
    except OSError as exc:
        raise _Changed(f"{path.name}: cannot open without following links "
                       f"({type(exc).__name__})") from None
    try:
        st = os.fstat(fd)
        if _identity(st) != _identity(before) or not _plain(st):
            raise _Changed(f"{path.name}: replaced between check and open")
        if single_link and st.st_nlink != 1:
            raise _Changed(f"{path.name}: has extra hard links")
        chunks, digest = [], hashlib.sha256()
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(fd)
        if digest.hexdigest() != sha256:
            raise _Changed(f"{path.name}: bytes do not match the attested SHA-256")
        if (after.st_size, after.st_mtime_ns) != (st.st_size, st.st_mtime_ns):
            raise _Changed(f"{path.name}: modified while being read")
        return fd, st
    except BaseException:
        os.close(fd)
        raise


def _link_from_handle(fd: int, temp: Path, final: Path) -> None:
    """No-overwrite publication. Linux: link the OPEN file itself through the
    /proc/self/fd magic link (linkat AT_SYMLINK_FOLLOW, the documented
    O_TMPFILE technique; same directory, so same filesystem). Elsewhere by
    path. Either way the caller re-proves identity and bytes afterwards, so a
    platform where this does not work can only FAIL, never mis-publish."""
    if sys.platform.startswith("linux") and _PROC_FD.is_dir():
        _link(f"{_PROC_FD}/{fd}", final, follow_symlinks=True)
    else:
        _link(temp, final)


def _authorization_set(authorized: object) -> dict[int, str]:
    if type(authorized) is not frozenset:
        raise ReportStoreError("authorization must be a frozenset of (event_seq, sha256) pairs")
    out: dict[int, str] = {}
    for item in authorized:
        if type(item) is not tuple or len(item) != 2 or type(item[0]) is not int \
                or type(item[1]) is not str or item[0] < 1 or not _HEX64.fullmatch(item[1]):
            raise ReportStoreError("malformed authorization entry (need (int seq, sha256 hex))")
        if item[0] in out:
            raise ReportStoreError(f"conflicting authorizations for event seq {item[0]}")
        out[item[0]] = item[1]
    return out


def recovery_candidates(audit: AuditLog, directory: Path) -> list[ReportStatus]:
    """Read-only: the entries an owner may be asked about (RECOVERABLE only)."""
    return [st for st in report_states(audit, directory)
            if st.state is PublicationState.RECOVERABLE]


def unfinished_recoveries(audit: AuditLog) -> list[int]:
    """Read-only: seqs of recovery authorizations with no completion/failure
    record (e.g. the process died, or the completion append failed)."""
    return sorted(_unresolved_authorizations(_read_records(audit)))


def complete_publication(audit: AuditLog, directory: Path, *, authorized: frozenset,
                         confirmation: str) -> list[RecoveryOutcome]:
    """Publish ONLY the attested reports named by ``authorized`` — exact
    ``(event_seq, sha256)`` pairs the owner approved. Fails closed: invalid or
    unknown authorizations abort before anything happens; a change since
    approval refuses that entry; the first refusal or failure stops the run
    (later entries are NOT_ATTEMPTED). Never overwrites, never deletes
    anything but the temp NAME of a verified, audited publication."""
    if not isinstance(confirmation, str) or not confirmation.strip():
        raise ReportStoreError("recovery needs a recorded owner confirmation")
    wanted = _authorization_set(authorized)
    directory = _require_dir(audit, directory)
    if not _chain_ok(audit):
        raise ReportStoreError("session audit chain does not verify; nothing recovered")
    events = {st.event_seq: st for st in report_states(audit, directory)}
    for seq, sha in wanted.items():
        st = events.get(seq)
        if st is None:
            raise ReportStoreError(f"authorization names unknown report event seq {seq}")
        if st.state is PublicationState.INVALID_EVENT or st.sha256 != sha:
            raise ReportStoreError(f"authorization for seq {seq} does not match the "
                                   "attested report")

    outcomes: list[RecoveryOutcome] = []
    stop = False
    for seq in sorted(wanted):
        sha = wanted[seq]
        if stop:
            outcomes.append(RecoveryOutcome(seq, sha, RecoveryStatus.NOT_ATTEMPTED))
            continue
        outcome = _recover_one(audit, directory, seq, sha, confirmation)
        outcomes.append(outcome)
        stop = outcome.status is not RecoveryStatus.PUBLISHED
    return outcomes


def _recover_one(audit: AuditLog, directory: Path, seq: int, sha: str,
                 confirmation: str) -> RecoveryOutcome:
    # 1. Re-verify the chain and THIS event right now.
    if not _chain_ok(audit):
        return RecoveryOutcome(seq, sha, RecoveryStatus.REFUSED,
                               detail="audit chain no longer verifies")
    st = next((s for s in report_states(audit, directory) if s.event_seq == seq), None)
    if st is None or st.sha256 != sha or st.state is not PublicationState.RECOVERABLE:
        state = st.state.value if st is not None else "missing event"
        return RecoveryOutcome(seq, sha, RecoveryStatus.REFUSED, report_file=st.report_file
                               if st else "", detail=f"changed since approval (now {state})")
    temp, final = directory / st.temp_file, directory / st.report_file

    # 2. Hold the source open; prove identity, single link and exact bytes.
    try:
        fd, src = _open_verified(temp, sha, single_link=True)
    except _Changed as exc:
        return RecoveryOutcome(seq, sha, RecoveryStatus.REFUSED, st.report_file, str(exc))
    try:
        if os.path.lexists(final):
            return RecoveryOutcome(seq, sha, RecoveryStatus.REFUSED, st.report_file,
                                   "final name already exists; never overwritten")
        # 3. Audit the owner's authorization BEFORE acting (fail closed).
        try:
            auth = audit.record(EVENT_RECOVERY_AUTHORIZED, {
                "report_generated_seq": seq, "report_file": st.report_file, "sha256": sha,
                "owner_confirmed": True, "confirmation": confirmation[:200]})
        except Exception as exc:  # noqa: BLE001 - any failure means: do not act
            return RecoveryOutcome(seq, sha, RecoveryStatus.FAILED, st.report_file,
                                   f"could not audit the authorization ({type(exc).__name__}); "
                                   "nothing published")

        def failed(stage: str, why: str) -> RecoveryOutcome:
            try:
                audit.record(EVENT_RECOVERY_FAILED, {"report_generated_seq": seq,
                                                     "recovery_authorized_seq": auth.seq,
                                                     "stage": stage, "detail": why[:300]})
            # Best effort: the outcome below already reports the failure.
            except Exception:  # noqa: BLE001, S110
                pass
            return RecoveryOutcome(seq, sha, RecoveryStatus.FAILED, st.report_file, why,
                                   authorization_seq=auth.seq)

        # 4. No-overwrite publication.
        try:
            _link_from_handle(fd, temp, final)
        except OSError as exc:
            return failed("link", f"publication failed ({type(exc).__name__}); "
                                  "nothing overwritten, temp kept")
        # 5. Prove the published name IS the file we verified, with the same bytes.
        try:
            pfd, pub = _open_verified(final, sha, single_link=False)
            os.close(pfd)
        except _Changed as exc:
            return failed("verify", f"published name does not hold the attested file "
                                    f"({exc}); left in place, not deleted")
        if _identity(pub) != _identity(src):
            return failed("verify", "published name is not the verified temp file "
                                    "(possible swap); left in place, not deleted")
        _fsync_dir(directory)
    finally:
        os.close(fd)

    # 6. Audit completion; only then is it an audited recovery.
    try:
        done = audit.record(EVENT_PUBLICATION_COMPLETED, {
            "report_generated_seq": seq, "report_file": st.report_file, "sha256": sha,
            "recovery_authorized_seq": auth.seq})
    except Exception as exc:  # noqa: BLE001
        return RecoveryOutcome(seq, sha, RecoveryStatus.PUBLISHED_UNAUDITED, st.report_file,
                               f"published and verified, but the completion record could not "
                               f"be written ({type(exc).__name__}); authorization is at seq "
                               f"{auth.seq}", authorization_seq=auth.seq)
    if not _chain_ok(audit):
        return RecoveryOutcome(seq, sha, RecoveryStatus.PUBLISHED_UNAUDITED, st.report_file,
                               "published, but the audit chain does not verify after the "
                               "completion record", authorization_seq=auth.seq)
    # 7. Drop the temp NAME only if it is still the same file as the published one.
    try:
        if _identity(os.lstat(temp)) == _identity(src):
            temp.unlink()
            _fsync_dir(directory)
    except OSError:
        pass
    return RecoveryOutcome(seq, sha, RecoveryStatus.PUBLISHED, st.report_file,
                           authorization_seq=auth.seq, completion_seq=done.seq)
