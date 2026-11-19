"""Audit-anchor HMAC keys, protected at rest with Windows DPAPI (ADR 0012
Stage 2).

Trust model, stated plainly: the key ring protects the anchor key against
*other* Windows users and against copying the files to another machine or
account (DPAPI, CurrentUser scope, app-specific entropy) and against casual
reading. It does NOT protect against code running as the same Windows user:
that code can ask DPAPI to decrypt the key exactly as AVRA does.

Rules:

- A key is created ONLY by an explicit owner command (``avra audit
  keygen``); a missing key is never regenerated silently.
- Raw key bytes never leave this module's objects: never printed, logged,
  audited or put into exception messages. Only the non-secret ``key_id``
  (HMAC-SHA256(key, label), first 128 bits) is shown.
- Every key ever created stays in the ring (``active`` / ``retired``), so
  anchors made before a rotation keep verifying.
- Errors: ``KeyUnavailableError`` (missing ring/key, DPAPI unavailable or
  refuses — e.g. another Windows user's blob) and ``KeyInvalidError``
  (present but wrong: malformed ring, machine-scoped blob, wrong length,
  id mismatch).

File: ``<state>/keys/keyring.json`` (``<state>`` = ``AVRA_STATE_DIR`` or
``%LOCALAPPDATA%\\AVRA``). ``keygen`` restricts the ``keys`` directory ACL
to the current user and SYSTEM (``icacls``, fixed argv, no shell) before
any key is written.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

KEY_BYTES = 32
KEYRING_VERSION = 1
KEYRING_NAME = "keyring.json"
SCOPE_DPAPI_USER = "dpapi-current-user"
_KEY_ID_LABEL = b"AVRA-audit-anchor-key-id-v1"
_DPAPI_ENTROPY = b"AVRA-audit-anchor-key-v1"
# DPAPI blob header: dwVersion, guidProvider, dwMasterKeyVersion, guidMasterKey, dwFlags.
_DPAPI_PROVIDER = bytes.fromhex("d08c9ddf0115d1118c7a00c04fc297eb")  # {df9d8cd0-1501-11d1-...}
_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_CRYPTPROTECT_LOCAL_MACHINE = 0x4


class AnchorKeyError(Exception):
    """Base class. Messages never contain key material."""


class KeyUnavailableError(AnchorKeyError):
    """No usable key: missing, not decryptable by this user, or no DPAPI."""


class KeyInvalidError(AnchorKeyError):
    """A key or key ring is present but malformed or wrongly scoped."""


def key_id_for(key: bytes) -> str:
    """Stable, non-secret identifier (one-way; reveals nothing about the key)."""
    return hmac.new(key, _KEY_ID_LABEL, hashlib.sha256).hexdigest()[:32]


class KeySource(Protocol):
    """What the anchor store needs: look up keys by id, and the active one."""

    def key(self, key_id: str) -> bytes: ...

    def active_key_id(self) -> str: ...

    def key_ids(self) -> list[str]: ...


class StaticKeys:
    """In-memory keys (tests and isolated tools). The first key is active."""

    def __init__(self, keys: list[bytes]) -> None:
        if not keys:
            raise KeyUnavailableError("no keys given")
        for k in keys:
            if not isinstance(k, bytes) or len(k) != KEY_BYTES:
                raise KeyInvalidError("test key must be 32 bytes")
        self._keys = {key_id_for(k): k for k in keys}
        self._active = key_id_for(keys[0])

    def key(self, key_id: str) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise KeyUnavailableError(f"key {key_id[:32]} is not available") from None

    def active_key_id(self) -> str:
        return self._active

    def key_ids(self) -> list[str]:
        return list(self._keys)

    def __repr__(self) -> str:
        return f"StaticKeys(<{len(self._keys)} redacted>)"


# --- DPAPI --------------------------------------------------------------------------


class Protector(Protocol):
    def protect(self, data: bytes) -> bytes: ...

    def unprotect(self, blob: bytes) -> bytes: ...


def dpapi_available() -> bool:
    return os.name == "nt"


class DpapiProtector:
    """Windows DPAPI, CurrentUser scope, app entropy, no UI (ctypes; stdlib)."""

    def __init__(self, entropy: bytes = _DPAPI_ENTROPY) -> None:
        if not dpapi_available():
            raise KeyUnavailableError("Windows DPAPI is not available on this platform")
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        self._ct, self._Blob, self._entropy = ctypes, Blob, entropy
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        p = ctypes.POINTER(Blob)
        self._protect = crypt32.CryptProtectData
        self._protect.argtypes = [p, wintypes.LPCWSTR, p, ctypes.c_void_p, ctypes.c_void_p,
                                  wintypes.DWORD, p]
        self._protect.restype = wintypes.BOOL
        self._unprotect = crypt32.CryptUnprotectData
        self._unprotect.argtypes = [p, ctypes.c_void_p, p, ctypes.c_void_p, ctypes.c_void_p,
                                    wintypes.DWORD, p]
        self._unprotect.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self._kernel32.LocalFree.restype = ctypes.c_void_p

    def _blob(self, data: bytes):
        buf = self._ct.create_string_buffer(data, len(data))
        return self._Blob(len(data), self._ct.cast(buf, self._ct.POINTER(self._ct.c_char))), buf

    def _take(self, out) -> bytes:
        try:
            return self._ct.string_at(out.pbData, out.cbData)
        finally:
            self._kernel32.LocalFree(self._ct.cast(out.pbData, self._ct.c_void_p))

    def protect(self, data: bytes, *, flags: int = _CRYPTPROTECT_UI_FORBIDDEN) -> bytes:
        inp, _b1 = self._blob(data)
        ent, _b2 = self._blob(self._entropy)
        out = self._Blob()
        ok = self._protect(self._ct.byref(inp), "AVRA audit anchor key", self._ct.byref(ent),
                           None, None, flags, self._ct.byref(out))
        if not ok:
            raise KeyUnavailableError("DPAPI could not protect the key")
        return self._take(out)

    def unprotect(self, blob: bytes) -> bytes:
        check_dpapi_blob(blob)
        inp, _b1 = self._blob(blob)
        ent, _b2 = self._blob(self._entropy)
        out = self._Blob()
        ok = self._unprotect(self._ct.byref(inp), None, self._ct.byref(ent), None, None,
                             _CRYPTPROTECT_UI_FORBIDDEN, self._ct.byref(out))
        if not ok:
            raise KeyUnavailableError(
                "DPAPI refused to decrypt the key (corrupted, or protected for another "
                "Windows user/profile)")
        return self._take(out)


def check_dpapi_blob(blob: bytes) -> None:
    """Header sanity + scope: only CurrentUser-scoped blobs are acceptable
    (a LOCAL_MACHINE blob is decryptable by every account on the machine)."""
    if len(blob) < 44:
        raise KeyInvalidError("key blob is too short to be a DPAPI blob")
    version = struct.unpack_from("<I", blob, 0)[0]
    if version != 1 or blob[4:20] != _DPAPI_PROVIDER:
        raise KeyInvalidError("key blob is not a DPAPI blob")
    flags = struct.unpack_from("<I", blob, 40)[0]
    if flags & _CRYPTPROTECT_LOCAL_MACHINE:
        raise KeyInvalidError("key blob is machine-scoped; only current-user scope is accepted")


# --- the key ring ---------------------------------------------------------------------


@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    created_at: str
    status: str  # "active" | "retired"
    scope: str
    blob: bytes


def keys_dir(state_dir: Path) -> Path:
    return Path(state_dir) / "keys"


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


AclFn = Callable[[Path], None]


def restrict_windows_acl(directory: Path) -> None:
    """Owner-only ACL on ``directory``: remove inherited entries, grant full
    control to the current user's SID and SYSTEM only. Fixed argv, no shell.
    Raises KeyUnavailableError on any failure (keygen then writes nothing)."""
    if os.name != "nt":
        os.chmod(directory, 0o700)
        return
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    who = subprocess.run([str(system32 / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, check=False, timeout=30)
    sid = who.stdout.strip().rsplit(",", 1)[-1].strip('"') if who.returncode == 0 else ""
    if not sid.startswith("S-1-"):
        raise KeyUnavailableError("could not determine the current user's SID")
    acl = subprocess.run([str(system32 / "icacls.exe"), str(directory), "/inheritance:r",
                          "/grant:r", f"*{sid}:(OI)(CI)F", "/grant:r", "*S-1-5-18:(OI)(CI)F"],
                         capture_output=True, text=True, check=False, timeout=30)
    if acl.returncode != 0:
        raise KeyUnavailableError("could not restrict the key directory ACL (icacls failed)")


class Keyring:
    """DPAPI-protected key ring on disk. Implements ``KeySource``."""

    def __init__(self, state_dir: Path, *, protector: Protector | None = None,
                 acl: AclFn | None = None) -> None:
        self.path = keys_dir(state_dir) / KEYRING_NAME
        self._protector = protector
        self._acl = acl
        self._cache: dict[str, bytes] = {}

    def __repr__(self) -> str:
        return f"Keyring({self.path})"

    def _prot(self) -> Protector:
        if self._protector is None:
            self._protector = DpapiProtector()
        return self._protector

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def entries(self) -> list[KeyEntry]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            raise KeyUnavailableError("no audit anchor key exists (run `avra audit keygen`)") \
                from None
        except OSError as exc:
            raise KeyUnavailableError(f"key ring is not readable ({type(exc).__name__})") \
                from None
        try:
            doc = json.loads(raw.decode("utf-8"))
            if not isinstance(doc, dict) or doc.get("v") != KEYRING_VERSION \
                    or not isinstance(doc.get("keys"), list) or not doc["keys"]:
                raise ValueError
            out = []
            for e in doc["keys"]:
                if set(e) != {"key_id", "created_at", "status", "scope", "blob"}:
                    raise ValueError
                if e["status"] not in ("active", "retired") or e["scope"] != SCOPE_DPAPI_USER:
                    raise ValueError
                if not (isinstance(e["key_id"], str) and len(e["key_id"]) == 32):
                    raise ValueError
                out.append(KeyEntry(e["key_id"], str(e["created_at"]), e["status"], e["scope"],
                                    base64.b64decode(e["blob"], validate=True)))
        except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
            raise KeyInvalidError("key ring file is malformed") from None
        ids = [e.key_id for e in out]
        if len(set(ids)) != len(ids) or sum(e.status == "active" for e in out) != 1:
            raise KeyInvalidError("key ring must hold unique ids and exactly one active key")
        return out

    def key_ids(self) -> list[str]:
        return [e.key_id for e in self.entries()]

    def active_key_id(self) -> str:
        return next(e.key_id for e in self.entries() if e.status == "active")

    def key(self, key_id: str) -> bytes:
        if key_id in self._cache:
            return self._cache[key_id]
        entry = next((e for e in self.entries() if e.key_id == key_id), None)
        if entry is None:
            raise KeyUnavailableError(f"key {key_id[:32]} is not in the key ring")
        key = self._prot().unprotect(entry.blob)
        if len(key) != KEY_BYTES:
            raise KeyInvalidError(f"key {key_id} has the wrong length")
        if not hmac.compare_digest(key_id_for(key), key_id):
            raise KeyInvalidError(f"key {key_id} does not match its identifier")
        self._cache[key_id] = key
        return key

    def generate(self, *, rotate: bool, acl: AclFn | None = None,
                 random: Callable[[int], bytes] = secrets.token_bytes,
                 before_commit: Callable[[str, bytes], None] | None = None) -> str:
        """Explicit owner action only. Creates the first key, or (``rotate``)
        adds a new active key and retires the old one. Returns the key id.
        ``before_commit(key_id, key)`` runs after the key is protected and
        round-trip checked, before the ring file is written (used to write the
        anchor head witness first)."""
        existing: list[KeyEntry] = []
        if self.exists:
            if not rotate:
                raise KeyInvalidError("a key ring already exists; use --rotate to add a key")
            existing = self.entries()
            self.key(self.active_key_id())  # current key must still be usable
        elif rotate:
            raise KeyUnavailableError("no key ring to rotate; run keygen first")
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        (acl or self._acl or restrict_windows_acl)(directory)  # before any key material
        key = random(KEY_BYTES)
        if len(key) != KEY_BYTES:
            raise KeyInvalidError("random source returned the wrong length")
        blob = self._prot().protect(key)
        new_id = key_id_for(key)
        if new_id in {e.key_id for e in existing}:
            raise KeyInvalidError("generated key collides with an existing key id")
        if not hmac.compare_digest(self._prot().unprotect(blob), key):
            raise KeyInvalidError("protected key does not round-trip; nothing written")
        if before_commit is not None:
            before_commit(new_id, key)
        entries = [{"key_id": e.key_id, "created_at": e.created_at, "status": "retired",
                    "scope": e.scope, "blob": base64.b64encode(e.blob).decode("ascii")}
                   for e in existing]
        entries.append({"key_id": new_id, "created_at": datetime.now(UTC).isoformat(),
                        "status": "active", "scope": SCOPE_DPAPI_USER,
                        "blob": base64.b64encode(blob).decode("ascii")})
        _atomic_write(self.path, json.dumps({"v": KEYRING_VERSION, "keys": entries},
                                            sort_keys=True, indent=2).encode("utf-8") + b"\n")
        self._cache[new_id] = key
        return new_id


def key_source_map(source: KeySource) -> Mapping[str, str]:
    """Non-secret summary (ids -> active/retired) for status displays."""
    active = source.active_key_id()
    return {k: ("active" if k == active else "retired") for k in source.key_ids()}
