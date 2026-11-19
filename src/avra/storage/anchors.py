"""HMAC-authenticated audit anchors (ADR 0012 Stage 2).

An *anchor* is a small, keyed statement: "audit log L had exactly N valid
records and record N's hash was H" — plus a link to the previous anchor and
the key id. Anchors live outside the audit directories, in an append-only
JSONL store (``<state>/anchors/anchors.jsonl``; ``<state>`` =
``AVRA_STATE_DIR`` or ``%LOCALAPPDATA%\\AVRA``). Audit logs are never written
or modified here.

What an anchor lets ``verify_log`` detect, for every sealed log:

- removal of records at or below an anchored ``seq`` (TRUNCATED),
- any change to an anchored record or its predecessors, incl. a complete,
  self-consistent rewrite of the log (HASH_MISMATCH),
- records added after the last anchor (UNANCHORED_TAIL — reported, never
  presented as protected),
- forged/edited/reordered/duplicated anchors or a broken anchor chain
  (ANCHOR_CORRUPT — needs the key to forge),
- missing/undecryptable keys (KEY_UNAVAILABLE) or wrong keys (KEY_INVALID).

Deletion / rollback of the anchor store: a keyed *head witness*
(``<state>/keys/anchor-head.json``, next to the key ring, separate from the
anchors directory) records the latest anchor. Deleting or rolling back the
anchors directory while the keys directory survives is ANCHOR_CORRUPT; a
key ring without its witness is ANCHOR_CORRUPT. **Limit:** someone who can
delete or roll back BOTH directories (any code running as this Windows
user) makes the machine look never-initialized: logs then show
LEGACY_UNANCHORED — never VERIFIED, but not detected as an attack either.
Detecting that needs a copy of the head outside this account (e.g. the
proposed cross-anchor to Kali, not built).

Serialization (v1): canonical JSON — sorted keys, no whitespace, ASCII —
one record per LF-terminated line; a stored line must equal the canonical
re-serialization of what it parses to. MAC = HMAC-SHA256(key,
domain || canonical(record without "mac")). ``prev_anchor_hash`` =
SHA-256 of the previous stored line (without its newline). Log identity =
``os.path.normcase(os.path.realpath(path))`` with ``/`` separators (resolves
links, 8.3 names and case), plus the log's first record hash
(``log_genesis_hash``) so a different log at the same path never matches.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from avra.storage.audit import (
    AuditStatus,
    AuditVerification,
    audit_file_lock,
    inspect_audit_file,
)
from avra.storage.keys import (
    KeyInvalidError,
    KeySource,
    KeyUnavailableError,
    keys_dir,
)

ANCHOR_VERSION = 1
ANCHORS_NAME = "anchors.jsonl"
WITNESS_NAME = "anchor-head.json"
GENESIS_ANCHOR_HASH = "0" * 64
_MAC_DOMAIN = b"AVRA-audit-anchor-v1\x00"
_WITNESS_DOMAIN = b"AVRA-anchor-head-v1\x00"
_ANCHOR_FIELDS = frozenset({"v", "anchor_seq", "prev_anchor_hash", "log_id", "log_genesis_hash",
                            "audit_seq", "audit_head_hash", "sealed_at", "key_id", "mac"})
_WITNESS_FIELDS = frozenset({"v", "anchor_seq", "anchor_hash", "key_id", "updated_at", "mac"})


def state_dir() -> Path:
    """Where AVRA keeps machine-local trust state (never inside ``data/``)."""
    override = os.environ.get("AVRA_STATE_DIR")
    if override:
        return Path(override)
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "AVRA"
    return Path.home() / ".local" / "state" / "avra"


def log_identity(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(path)).replace("\\", "/")


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _mac(key: bytes, domain: bytes, obj: dict[str, Any]) -> str:
    body = {k: v for k, v in obj.items() if k != "mac"}
    return hmac.new(key, domain + _canonical(body), hashlib.sha256).hexdigest()


def _is_hex(value: object, n: int) -> bool:
    return isinstance(value, str) and len(value) == n and all(c in "0123456789abcdef" for c in value)


# --- outcomes -----------------------------------------------------------------------------


class AnchorStatus(str, Enum):
    VERIFIED = "VERIFIED"
    LEGACY_UNANCHORED = "LEGACY_UNANCHORED"
    UNANCHORED_TAIL = "UNANCHORED_TAIL"
    TRUNCATED = "TRUNCATED"
    HASH_MISMATCH = "HASH_MISMATCH"
    ANCHOR_CORRUPT = "ANCHOR_CORRUPT"
    KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
    KEY_INVALID = "KEY_INVALID"
    UNREADABLE = "UNREADABLE"


class Severity(str, Enum):
    OK = "ok"  # cryptographically anchored, nothing outside the anchor
    WARNING = "warning"  # not (fully) protected, no evidence of tampering
    FAILURE = "failure"  # tampering, damage, or verification impossible


SEVERITY = {
    AnchorStatus.VERIFIED: Severity.OK,
    AnchorStatus.LEGACY_UNANCHORED: Severity.WARNING,
    AnchorStatus.UNANCHORED_TAIL: Severity.WARNING,
}
EXIT_CODES = {Severity.OK: 0, Severity.FAILURE: 1, Severity.WARNING: 2}


def severity(status: AnchorStatus) -> Severity:
    return SEVERITY.get(status, Severity.FAILURE)


class AnchorError(Exception):
    """Sealing or key setup refused. Messages never contain key material."""

    def __init__(self, message: str, status: AnchorStatus = AnchorStatus.ANCHOR_CORRUPT) -> None:
        super().__init__(message)
        self.status = status


class AnchorWriteError(AnchorError, OSError):
    """An anchor or the head witness could not be durably written."""


@dataclass(frozen=True)
class Anchor:
    anchor_seq: int
    prev_anchor_hash: str
    log_id: str
    log_genesis_hash: str
    audit_seq: int
    audit_head_hash: str
    sealed_at: str
    key_id: str
    mac: str
    line_hash: str  # SHA-256 of the stored canonical line


@dataclass(frozen=True)
class StoreState:
    status: AnchorStatus  # VERIFIED (store sound), LEGACY_UNANCHORED (not initialized) or a failure
    detail: str
    anchors: tuple[Anchor, ...] = ()
    witness_seq: int | None = None
    notes: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return self.status in (AnchorStatus.VERIFIED, AnchorStatus.LEGACY_UNANCHORED)

    @property
    def head(self) -> tuple[int, str]:
        if not self.anchors:
            return 0, GENESIS_ANCHOR_HASH
        return self.anchors[-1].anchor_seq, self.anchors[-1].line_hash


@dataclass(frozen=True)
class LogVerification:
    status: AnchorStatus
    detail: str
    chain: AuditVerification  # basic (unkeyed) hash-chain result, Stage 1
    log_id: str
    record_count: int = 0
    anchored_seq: int = 0
    anchors_checked: int = 0
    notes: tuple[str, ...] = ()

    @property
    def severity(self) -> Severity:
        sev = severity(self.status)
        if not self.chain.ok and sev is not Severity.FAILURE:
            return Severity.FAILURE  # a damaged chain is never just a warning
        return sev

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.severity]


@dataclass(frozen=True)
class SealResult:
    anchor: Anchor | None  # None: already sealed at this exact head
    audit_seq: int
    notes: tuple[str, ...] = field(default_factory=tuple)


# --- the store ----------------------------------------------------------------------------


class _Corrupt(Exception):
    pass


class AnchorStore:
    def __init__(self, state: Path, keys: KeySource | None, *,
                 lock_timeout: float = 10.0) -> None:
        self.state = Path(state)
        self.keys = keys
        self.anchors_path = self.state / "anchors" / ANCHORS_NAME
        self.witness_path = keys_dir(self.state) / WITNESS_NAME
        self.lock_timeout = lock_timeout

    # -- reading ---------------------------------------------------------------------------

    def _parse_anchors(self, raw: bytes) -> list[Anchor]:
        if raw and not raw.endswith(b"\n"):
            raise _Corrupt("anchor store ends with an incomplete record (interrupted write?)")
        out: list[Anchor] = []
        prev = GENESIS_ANCHOR_HASH
        last_seq_by_log: dict[str, int] = {}
        genesis_by_log: dict[str, str] = {}
        for n, line in enumerate(raw.split(b"\n")[:-1], start=1):
            try:
                obj = json.loads(line.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                raise _Corrupt(f"anchor line {n} is not valid JSON") from None
            if not isinstance(obj, dict) or set(obj) != _ANCHOR_FIELDS:
                raise _Corrupt(f"anchor line {n} has unexpected fields")
            if _canonical(obj) != line:
                raise _Corrupt(f"anchor line {n} is not in canonical form")
            if obj["v"] != ANCHOR_VERSION:
                raise _Corrupt(f"anchor line {n} has unsupported version")
            if type(obj["anchor_seq"]) is not int or obj["anchor_seq"] != n:
                raise _Corrupt(f"anchor line {n}: anchor_seq is not {n} (gap, duplicate or reorder)")
            if obj["prev_anchor_hash"] != prev:
                raise _Corrupt(f"anchor {n} does not link to anchor {n - 1}")
            if type(obj["audit_seq"]) is not int or obj["audit_seq"] < 1:
                raise _Corrupt(f"anchor {n}: invalid audit_seq")
            if not all(_is_hex(obj[k], 64) for k in ("log_genesis_hash", "audit_head_hash", "mac")) \
                    or not _is_hex(obj["key_id"], 32) or not isinstance(obj["log_id"], str) \
                    or not obj["log_id"] or not isinstance(obj["sealed_at"], str):
                raise _Corrupt(f"anchor {n} has malformed fields")
            log_id = obj["log_id"]
            if obj["audit_seq"] <= last_seq_by_log.get(log_id, 0):
                raise _Corrupt(f"anchor {n}: audit_seq does not increase for its log")
            if genesis_by_log.setdefault(log_id, obj["log_genesis_hash"]) != obj["log_genesis_hash"]:
                raise _Corrupt(f"anchor {n}: genesis hash differs from earlier anchors of its log")
            last_seq_by_log[log_id] = obj["audit_seq"]
            line_hash = hashlib.sha256(line).hexdigest()
            out.append(Anchor(n, obj["prev_anchor_hash"], log_id, obj["log_genesis_hash"],
                              obj["audit_seq"], obj["audit_head_hash"], obj["sealed_at"],
                              obj["key_id"], obj["mac"], line_hash))
            prev = line_hash
        return out

    @staticmethod
    def _anchor_dict(a: Anchor) -> dict[str, Any]:
        return {"v": ANCHOR_VERSION, "anchor_seq": a.anchor_seq,
                "prev_anchor_hash": a.prev_anchor_hash, "log_id": a.log_id,
                "log_genesis_hash": a.log_genesis_hash, "audit_seq": a.audit_seq,
                "audit_head_hash": a.audit_head_hash, "sealed_at": a.sealed_at,
                "key_id": a.key_id, "mac": a.mac}

    def _read_witness(self) -> dict[str, Any] | None:
        try:
            raw = self.witness_path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            raise _Corrupt("anchor head witness is not readable") from None
        try:
            obj = json.loads(raw.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            raise _Corrupt("anchor head witness is malformed") from None
        if not isinstance(obj, dict) or set(obj) != _WITNESS_FIELDS or obj.get("v") != 1 \
                or type(obj["anchor_seq"]) is not int or obj["anchor_seq"] < 0 \
                or not _is_hex(obj["anchor_hash"], 64) or not _is_hex(obj["key_id"], 32) \
                or not _is_hex(obj["mac"], 64):
            raise _Corrupt("anchor head witness is malformed")
        return obj

    def _key(self, key_id: str) -> bytes:
        if self.keys is None:
            raise KeyUnavailableError("no key source configured")
        return self.keys.key(key_id)

    def _keyring_exists(self) -> bool:
        exists = getattr(self.keys, "exists", None)
        return bool(exists) if exists is not None else self.keys is not None

    def _load_unlocked(self) -> StoreState:
        try:
            raw = self.anchors_path.read_bytes()
        except FileNotFoundError:
            raw = b""
        except OSError as exc:
            return StoreState(AnchorStatus.UNREADABLE,
                              f"anchor store is not readable ({type(exc).__name__})")
        try:
            anchors = self._parse_anchors(raw)
            witness = self._read_witness()
        except _Corrupt as exc:
            return StoreState(AnchorStatus.ANCHOR_CORRUPT, str(exc))

        keyring = self._keyring_exists()
        if not keyring and not anchors and witness is None:
            return StoreState(AnchorStatus.LEGACY_UNANCHORED,
                              "audit anchoring is not initialized (no key, no anchors)")
        if keyring and witness is None:
            return StoreState(AnchorStatus.ANCHOR_CORRUPT,
                              "anchor head witness is missing although a key exists "
                              "(deleted or rolled back?)", tuple(anchors))
        try:
            for a in anchors:
                if not hmac.compare_digest(_mac(self._key(a.key_id), _MAC_DOMAIN,
                                                self._anchor_dict(a)), a.mac):
                    return StoreState(AnchorStatus.ANCHOR_CORRUPT,
                                      f"anchor {a.anchor_seq} fails authentication "
                                      "(forged or edited)", tuple(anchors))
            if witness is None:  # no key ring but anchors exist
                raise KeyUnavailableError("anchors exist but no audit anchor key is available")
            if not hmac.compare_digest(_mac(self._key(witness["key_id"]), _WITNESS_DOMAIN,
                                            witness), witness["mac"]):
                return StoreState(AnchorStatus.ANCHOR_CORRUPT,
                                  "anchor head witness fails authentication", tuple(anchors))
        except KeyUnavailableError as exc:
            return StoreState(AnchorStatus.KEY_UNAVAILABLE, str(exc), tuple(anchors))
        except KeyInvalidError as exc:
            return StoreState(AnchorStatus.KEY_INVALID, str(exc), tuple(anchors))

        w_seq = witness["anchor_seq"]
        if w_seq > len(anchors):
            return StoreState(AnchorStatus.ANCHOR_CORRUPT,
                              f"anchor store holds {len(anchors)} anchors but the head witness "
                              f"records {w_seq} (store deleted, truncated or rolled back)",
                              tuple(anchors), w_seq)
        expected = anchors[w_seq - 1].line_hash if w_seq else GENESIS_ANCHOR_HASH
        if witness["anchor_hash"] != expected:
            return StoreState(AnchorStatus.ANCHOR_CORRUPT,
                              f"anchor {w_seq} does not match the head witness (store replaced?)",
                              tuple(anchors), w_seq)
        notes = ()
        if len(anchors) > w_seq:
            notes = ((f"head witness is {len(anchors) - w_seq} anchor(s) behind the store "
                     "(interrupted seal); those anchors are authenticated; the next seal "
                     "updates the witness"),)
        return StoreState(AnchorStatus.VERIFIED, f"anchor store sound ({len(anchors)} anchors)",
                          tuple(anchors), w_seq, notes)

    def load(self) -> StoreState:
        """Read-only check of the whole store (consistent snapshot under its lock)."""
        if not self.anchors_path.exists():
            return self._load_unlocked()
        try:
            with audit_file_lock(self.anchors_path, self.lock_timeout):
                return self._load_unlocked()
        except OSError as exc:
            return StoreState(AnchorStatus.UNREADABLE,
                              f"anchor store could not be locked for reading ({type(exc).__name__})")

    # -- verifying one log -----------------------------------------------------------------

    def verify_log(self, log_path: str | Path, state: StoreState | None = None) -> LogVerification:
        """Read-only. Never modifies the log, the store or anything else."""
        path = Path(log_path)
        log_id = log_identity(path)
        if path.exists():
            try:
                with audit_file_lock(path, self.lock_timeout):
                    snap = inspect_audit_file(path)
            except OSError:
                snap = inspect_audit_file(path)  # e.g. a directory: reported as unreadable
        else:
            snap = inspect_audit_file(path)
        return self._judge(log_id, snap, state or self.load())

    def _judge(self, log_id: str, snap, state: StoreState) -> LogVerification:
        chain, records = snap.verification, snap.records

        def out(status: AnchorStatus, detail: str, **kw) -> LogVerification:
            return LogVerification(status, detail, chain, log_id, len(records), **kw)

        if not state.usable:
            return out(state.status, f"anchor verification impossible: {state.detail}")
        if chain.status is AuditStatus.UNREADABLE:
            return out(AnchorStatus.UNREADABLE, chain.describe())
        mine = [a for a in state.anchors if a.log_id == log_id]
        if not mine:
            if not chain.exists:
                return out(AnchorStatus.UNREADABLE, "no audit log at this path")
            notes = ()
            if records and any(a.log_genesis_hash == records[0].hash for a in state.anchors):
                notes = ("a log with the same first record is anchored under another path",)
            why = ("anchoring not initialized" if state.status is AnchorStatus.LEGACY_UNANCHORED
                   else "this log was never sealed")
            return out(AnchorStatus.LEGACY_UNANCHORED,
                       f"{why}; only the unkeyed hash chain is checked", notes=notes)

        valid_prefix = chain.last_seq if not chain.ok else len(records)
        for a in mine:
            k = a.audit_seq
            if k > len(records):
                what = "the audit log is missing" if not chain.exists else \
                    f"the log has {len(records)} readable records"
                return out(AnchorStatus.TRUNCATED,
                           f"anchor {a.anchor_seq} covers record {k}, but {what}",
                           anchored_seq=k, anchors_checked=len(mine))
            if k > valid_prefix or records[k - 1].hash != a.audit_head_hash \
                    or records[0].hash != a.log_genesis_hash:
                return out(AnchorStatus.HASH_MISMATCH,
                           f"records up to {k} differ from what anchor {a.anchor_seq} sealed "
                           "(edited or rewritten)", anchored_seq=k, anchors_checked=len(mine))
        k = mine[-1].audit_seq
        if len(records) > k or not chain.ok:
            return out(AnchorStatus.UNANCHORED_TAIL,
                       f"records 1..{k} anchored; {max(len(records) - k, 0)} later record(s) are "
                       "NOT protected by an anchor", anchored_seq=k, anchors_checked=len(mine),
                       notes=state.notes)
        return out(AnchorStatus.VERIFIED, f"all {k} records anchored (anchor {mine[-1].anchor_seq})",
                   anchored_seq=k, anchors_checked=len(mine), notes=state.notes)

    # -- writing ---------------------------------------------------------------------------

    def _witness_doc(self, anchor_seq: int, anchor_hash: str, key_id: str, key: bytes) -> bytes:
        doc = {"v": 1, "anchor_seq": anchor_seq, "anchor_hash": anchor_hash, "key_id": key_id,
               "updated_at": datetime.now(UTC).isoformat()}
        doc["mac"] = _mac(key, _WITNESS_DOMAIN, doc)
        return _canonical(doc) + b"\n"

    def _write_witness(self, anchor_seq: int, anchor_hash: str, key_id: str, key: bytes) -> None:
        data = self._witness_doc(anchor_seq, anchor_hash, key_id, key)
        tmp = self.witness_path.with_name(f".{WITNESS_NAME}.{secrets.token_hex(8)}.tmp")
        try:
            self.witness_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                         0o600)
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self.witness_path)
        except OSError as exc:
            raise AnchorWriteError(f"anchor head witness could not be written "
                                   f"({type(exc).__name__})") from None

    def _ensure_store_file(self) -> None:
        try:
            self.anchors_path.parent.mkdir(parents=True, exist_ok=True)
            with self.anchors_path.open("ab"):
                pass
        except OSError as exc:
            raise AnchorWriteError(f"anchor store could not be created ({type(exc).__name__})") \
                from None

    def initialize_witness(self, key_id: str, key: bytes) -> None:
        """First keygen only (before the key ring is committed): the store
        must hold no anchors; writes a witness for the empty store."""
        self._ensure_store_file()
        with audit_file_lock(self.anchors_path, self.lock_timeout):
            if self.anchors_path.read_bytes():
                raise AnchorError("anchors already exist; refusing to start a new key over them "
                                  "(see ADR 0012 key-loss procedure)")
            self._write_witness(0, GENESIS_ANCHOR_HASH, key_id, key)

    def resign_witness(self) -> None:
        """After a rotation: re-sign the current head with the new active key."""
        self._ensure_store_file()
        with audit_file_lock(self.anchors_path, self.lock_timeout):
            state = self._load_unlocked()
            if state.status is not AnchorStatus.VERIFIED:
                raise AnchorError(f"anchor store not sound: {state.detail}", state.status)
            seq, head = state.head
            active = self.keys.active_key_id()
            self._write_witness(seq, head, active, self._key(active))

    def seal(self, log_path: str | Path) -> SealResult:
        """Explicit owner action: anchor the log's current valid head."""
        path = Path(log_path)
        if not path.is_file():
            raise AnchorError("audit log not found or not a regular file", AnchorStatus.UNREADABLE)
        try:
            active = self.keys.active_key_id() if self.keys is not None else None
            if active is None:
                raise KeyUnavailableError("no audit anchor key (run `avra audit keygen`)")
            key = self._key(active)
        except KeyUnavailableError as exc:
            raise AnchorError(str(exc), AnchorStatus.KEY_UNAVAILABLE) from None
        except KeyInvalidError as exc:
            raise AnchorError(str(exc), AnchorStatus.KEY_INVALID) from None
        self._ensure_store_file()
        try:
            with audit_file_lock(path, self.lock_timeout), \
                    audit_file_lock(self.anchors_path, self.lock_timeout):
                return self._seal_locked(path, active, key)
        except AnchorError:
            raise
        except OSError as exc:  # lock timeout / lock failure
            raise AnchorWriteError(f"could not lock for sealing ({type(exc).__name__}: {exc})") \
                from None

    def _seal_locked(self, path: Path, active: str, key: bytes) -> SealResult:
        state = self._load_unlocked()
        if state.status is not AnchorStatus.VERIFIED:
            raise AnchorError(f"refusing to seal: {state.detail}", state.status)
        snap = inspect_audit_file(path)
        if not snap.verification.ok:
            raise AnchorError(f"refusing to seal a damaged audit log: "
                              f"{snap.verification.describe()}", AnchorStatus.HASH_MISMATCH)
        if not snap.records:
            raise AnchorError("refusing to seal an empty audit log", AnchorStatus.UNREADABLE)
        current = self._judge(log_identity(path), snap, state)
        if current.status not in (AnchorStatus.LEGACY_UNANCHORED, AnchorStatus.UNANCHORED_TAIL,
                                  AnchorStatus.VERIFIED):
            raise AnchorError(f"refusing to seal: {current.detail}", current.status)
        records = snap.records
        seq, head = state.head
        if current.status is AnchorStatus.VERIFIED:
            if state.witness_seq != seq:  # repair a lagging witness only
                self._write_witness(seq, head, active, key)
            return SealResult(None, len(records), ("already sealed at this head",))
        anchor = {"v": ANCHOR_VERSION, "anchor_seq": seq + 1, "prev_anchor_hash": head,
                  "log_id": log_identity(path), "log_genesis_hash": records[0].hash,
                  "audit_seq": len(records), "audit_head_hash": records[-1].hash,
                  "sealed_at": datetime.now(UTC).isoformat(), "key_id": active}
        anchor["mac"] = _mac(key, _MAC_DOMAIN, anchor)
        line = _canonical(anchor)
        try:
            with self.anchors_path.open("ab") as fh:
                fh.write(line + b"\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise AnchorWriteError(f"anchor could not be written ({type(exc).__name__}); the "
                                   "log is NOT sealed") from None
        line_hash = hashlib.sha256(line).hexdigest()
        self._write_witness(seq + 1, line_hash, active, key)
        return SealResult(Anchor(seq + 1, head, anchor["log_id"], anchor["log_genesis_hash"],
                                 anchor["audit_seq"], anchor["audit_head_hash"],
                                 anchor["sealed_at"], active, anchor["mac"], line_hash),
                          len(records))


def create_key(state: Path, keyring, store: AnchorStore, *, rotate: bool, **generate_kw) -> str:
    """The only way an operational key comes into existence (``avra audit
    keygen``). Crash-safe ordering:

    - first key: refuse if any anchor exists (key-loss case, see ADR 0012);
      write the head witness for the empty store BEFORE committing the key
      ring, so "key ring exists" always implies "witness was written";
    - rotation: the store must verify; commit the ring (old key retired, still
      usable), THEN re-sign the witness with the new key — a crash between
      leaves a witness signed by a key that is still in the ring.
    """
    if not rotate:
        if keyring.exists:
            raise AnchorError("an audit anchor key already exists; use --rotate",
                              AnchorStatus.KEY_INVALID)
        return keyring.generate(rotate=False, before_commit=store.initialize_witness,
                                **generate_kw)
    current = store.load()
    if current.status is not AnchorStatus.VERIFIED:
        raise AnchorError(f"refusing to rotate: {current.detail}", current.status)
    new_id = keyring.generate(rotate=True, **generate_kw)
    store.resign_witness()
    return new_id
