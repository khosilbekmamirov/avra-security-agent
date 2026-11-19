"""Runner configuration — strict, fail-closed (ADR 0003, M3.1).

Read once at startup from the Runner's own environment on the Kali VM.
Any missing or unacceptable value raises ``RunnerConfigError`` and the
Runner must not start. Nothing here comes from a request.

Environment variables:

=============================  ==========================================
``AVRA_RUNNER_SCOPE_FILE``     trusted scope YAML (absolute path)
``AVRA_RUNNER_TOKEN_FILE``     bearer token file (absolute, 0600 on Linux)
``AVRA_RUNNER_AUDIT_LOG``      audit JSONL path (absolute; parent exists)
``AVRA_RUNNER_BIND_HOST``      IPv4 literal; never a wildcard
``AVRA_RUNNER_PORT``           1024-65535 (default 8765)
``AVRA_RUNNER_EXEC_<NAME>``    absolute path for each registry executable,
                               e.g. ``AVRA_RUNNER_EXEC_NMAP``
=============================  ==========================================

Linux-only checks (skipped on the Windows dev host, where the Runner is
never deployed): token file must be owned by the Runner user and not
group/world accessible; executables must not be writable by the Runner
user; the audit directory must not be world-writable.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from avra.runner.policy import SCOPE_FILE_ENV, RunnerPolicy, RunnerScopeError
from avra.runner.registry import get_tool, registered_tools
from avra.storage.audit import AuditLog

IS_POSIX = os.name == "posix"

TOKEN_FILE_ENV = "AVRA_RUNNER_TOKEN_FILE"
AUDIT_LOG_ENV = "AVRA_RUNNER_AUDIT_LOG"
BIND_HOST_ENV = "AVRA_RUNNER_BIND_HOST"
PORT_ENV = "AVRA_RUNNER_PORT"
EXEC_ENV_PREFIX = "AVRA_RUNNER_EXEC_"

DEFAULT_PORT = 8765
MIN_TOKEN_CHARS = 32
MAX_TOKEN_CHARS = 512


class RunnerConfigError(Exception):
    """Runner configuration is missing or unsafe. Never includes secrets."""


class BearerToken:
    """Holds the Runner token. Never printed; compared in constant time."""

    __slots__ = ("_digest",)

    def __init__(self, value: str) -> None:
        # Only a digest is kept. Comparing fixed-length digests means the
        # comparison time doesn't depend on the candidate's length either.
        self._digest = hashlib.sha256(value.encode("ascii")).digest()

    def matches(self, candidate: str | bytes) -> bool:
        # Length cap first: never hash attacker-sized input.
        if not isinstance(candidate, (str, bytes)) or len(candidate) > MAX_TOKEN_CHARS:
            return False
        if isinstance(candidate, str):
            try:
                candidate = candidate.encode("ascii")
            except UnicodeEncodeError:
                return False
        return hmac.compare_digest(self._digest, hashlib.sha256(candidate).digest())

    def __repr__(self) -> str:
        return "BearerToken(***)"

    __str__ = __repr__


@dataclass(frozen=True)
class RunnerConfig:
    scope_file: Path
    policy: RunnerPolicy = field(repr=False)
    token: BearerToken = field(repr=False)
    audit_path: Path
    bind_host: str
    port: int
    executables: Mapping[str, str]


def _require(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value.strip():
        raise RunnerConfigError(f"{name} is not set")
    if value != value.strip():
        raise RunnerConfigError(f"{name} has leading/trailing whitespace")
    return value


def _absolute(name: str, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise RunnerConfigError(f"{name} must be an absolute path")
    return path


def _load_scope(env: Mapping[str, str]) -> tuple[Path, RunnerPolicy]:
    path = _absolute(SCOPE_FILE_ENV, _require(env, SCOPE_FILE_ENV))
    try:
        return path, RunnerPolicy.from_scope_file(path)
    except RunnerScopeError as exc:
        raise RunnerConfigError(f"scope rejected: {exc}") from None


def _open_token_file(path: Path) -> int:
    """Open the token file so that every check applies to the very file
    that is read (no check-then-open race).

    POSIX: ``O_NOFOLLOW`` refuses a symlink at open time, ``O_NONBLOCK``
    keeps a FIFO from blocking startup; all checks then use ``fstat`` on
    the open descriptor. Windows (dev host only): no ``O_NOFOLLOW``, so
    ``lstat`` before and ``fstat`` after must name the same file.
    """
    if IS_POSIX:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            return os.open(path, flags)
        except OSError as exc:
            if os.path.islink(path):
                raise RunnerConfigError(f"{TOKEN_FILE_ENV}: must not be a symlink") from None
            raise RunnerConfigError(
                f"{TOKEN_FILE_ENV}: cannot open ({exc.strerror})"
            ) from None
    try:
        before = path.lstat()
    except OSError:
        raise RunnerConfigError(f"{TOKEN_FILE_ENV}: file not found") from None
    if stat.S_ISLNK(before.st_mode):
        raise RunnerConfigError(f"{TOKEN_FILE_ENV}: must not be a symlink")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except OSError as exc:
        raise RunnerConfigError(f"{TOKEN_FILE_ENV}: cannot open ({exc.strerror})") from None
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd)
        raise RunnerConfigError(f"{TOKEN_FILE_ENV}: file changed while opening")
    return fd


def _load_token(env: Mapping[str, str]) -> BearerToken:
    path = _absolute(TOKEN_FILE_ENV, _require(env, TOKEN_FILE_ENV))
    fd = _open_token_file(path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise RunnerConfigError(f"{TOKEN_FILE_ENV}: must be a regular file")
        if IS_POSIX:
            if st.st_mode & 0o077:
                raise RunnerConfigError(
                    f"{TOKEN_FILE_ENV}: permissions too open (must be 0600 or stricter)"
                )
            if st.st_uid != os.geteuid():
                raise RunnerConfigError(
                    f"{TOKEN_FILE_ENV}: must be owned by the Runner user"
                )
        # Bounded read: never pull an arbitrarily large file into memory.
        data = os.read(fd, MAX_TOKEN_CHARS + 3)
        if os.read(fd, 1):
            raise RunnerConfigError(
                f"{TOKEN_FILE_ENV}: token must be {MIN_TOKEN_CHARS}-{MAX_TOKEN_CHARS} characters"
            )
    finally:
        os.close(fd)
    try:
        raw = data.decode("ascii")
    except UnicodeDecodeError:
        raise RunnerConfigError(f"{TOKEN_FILE_ENV}: unreadable or not ASCII") from None
    token = raw.rstrip("\r\n")
    # Deliberately never include the token (or its length) in errors.
    if not MIN_TOKEN_CHARS <= len(token) <= MAX_TOKEN_CHARS:
        raise RunnerConfigError(
            f"{TOKEN_FILE_ENV}: token must be {MIN_TOKEN_CHARS}-{MAX_TOKEN_CHARS} characters"
        )
    if not all(33 <= ord(c) <= 126 for c in token):
        raise RunnerConfigError(
            f"{TOKEN_FILE_ENV}: token must be printable ASCII without whitespace"
        )
    return BearerToken(token)


def _load_audit_path(env: Mapping[str, str]) -> Path:
    path = _absolute(AUDIT_LOG_ENV, _require(env, AUDIT_LOG_ENV))
    parent = path.parent
    if not parent.is_dir():
        raise RunnerConfigError(f"{AUDIT_LOG_ENV}: parent directory does not exist")
    if IS_POSIX and parent.stat().st_mode & stat.S_IWOTH:
        raise RunnerConfigError(f"{AUDIT_LOG_ENV}: directory must not be world-writable")
    if path.is_symlink():
        raise RunnerConfigError(f"{AUDIT_LOG_ENV}: must not be a symlink")
    if path.exists():
        if not path.is_file():
            raise RunnerConfigError(f"{AUDIT_LOG_ENV}: must be a regular file")
        try:
            intact = AuditLog(path).verify()
        except (OSError, ValueError, KeyError, TypeError):
            intact = False
        if not intact:
            raise RunnerConfigError(
                f"{AUDIT_LOG_ENV}: existing audit log fails hash-chain verification"
            )
    return path


def _load_bind_host(env: Mapping[str, str]) -> str:
    value = _require(env, BIND_HOST_ENV)
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        raise RunnerConfigError(
            f"{BIND_HOST_ENV} must be a literal IPv4 address (no hostnames, no IPv6)"
        ) from None
    if str(addr) != value:
        raise RunnerConfigError(f"{BIND_HOST_ENV} must be in canonical form")
    if addr.is_unspecified:
        raise RunnerConfigError(f"{BIND_HOST_ENV}: wildcard addresses are not allowed")
    if addr.is_multicast or addr.is_reserved or addr.is_link_local or (
        addr == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise RunnerConfigError(f"{BIND_HOST_ENV}: not a bindable unicast address")
    return value


def _load_port(env: Mapping[str, str]) -> int:
    value = env.get(PORT_ENV, "")
    if value == "":
        return DEFAULT_PORT
    if not value.isascii() or not value.isdigit() or value.startswith("0"):
        raise RunnerConfigError(f"{PORT_ENV} must be a plain decimal number")
    port = int(value)
    if not 1024 <= port <= 65535:
        raise RunnerConfigError(f"{PORT_ENV} must be between 1024 and 65535")
    return port


def _load_executables(env: Mapping[str, str]) -> Mapping[str, str]:
    names = sorted({get_tool(t).executable for t in registered_tools()})
    resolved: dict[str, str] = {}
    for name in names:
        var = EXEC_ENV_PREFIX + name.upper()
        path = _absolute(var, _require(env, var))
        real = Path(os.path.realpath(path))
        if not real.is_file():
            raise RunnerConfigError(f"{var}: not found or not a regular file")
        if not os.access(real, os.X_OK):
            raise RunnerConfigError(f"{var}: not executable")
        if IS_POSIX and (os.access(real, os.W_OK) or os.access(real.parent, os.W_OK)):
            raise RunnerConfigError(
                f"{var}: executable or its directory is writable by the Runner user"
            )
        resolved[name] = str(real)
    return MappingProxyType(resolved)


def load_runner_config(env: Mapping[str, str] | None = None) -> RunnerConfig:
    """Load and validate everything; raise RunnerConfigError on any problem."""
    env = os.environ if env is None else env
    scope_file, policy = _load_scope(env)
    return RunnerConfig(
        scope_file=scope_file,
        policy=policy,
        token=_load_token(env),
        audit_path=_load_audit_path(env),
        bind_host=_load_bind_host(env),
        port=_load_port(env),
        executables=_load_executables(env),
    )
