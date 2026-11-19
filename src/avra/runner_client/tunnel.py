"""The restricted SSH tunnel to the Runner (ADR 0003, M6.1).

Opens ``ssh -N -L 127.0.0.1:<free port>:127.0.0.1:8765 avra-tunnel@<kali>``
with the dedicated runtime key and a fixed set of options — the same ones
proven live in M4.5 by ``runner/deploy/verify_tunnel.py`` (which stays a
standalone stdlib script so it runs without the package installed).

Nothing here is model-controlled: the remote end is a constant, the local
end is loopback only, and the only inputs are the owner's own settings
(Kali address, key path). The server side restricts the account anyway
(``permitopen="127.0.0.1:8765"``, ``from=``, ``restrict``, ``nologin``).
"""

from __future__ import annotations

import atexit
import contextlib
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

REMOTE_RUNNER = "127.0.0.1:8765"  # fixed: the only destination sshd permits
TUNNEL_USER = "avra-tunnel"
DEFAULT_KALI = "192.168.56.104"
DEFAULT_KEY = Path.home() / ".ssh" / "avra_runtime_ed25519"
READY_TIMEOUT = 20.0

_READY = re.compile(r"Local forwarding listening on 127\.0\.0\.1 port (\d+)")
_AUTH_DENIED = re.compile(r"Permission denied \(")
_FORWARD_FAILED = re.compile(r"Could not request local forwarding|bind \[.*\]: ")
_MAX_LOG_CHARS = 200_000


class TunnelError(Exception):
    """The tunnel could not be opened (or died). The message never contains
    secrets; it may quote a few ssh diagnostic lines."""


def ssh_executable() -> str:
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH" / "ssh.exe"
    if system.is_file():
        return str(system)
    found = shutil.which("ssh")
    if not found:
        raise TunnelError("ssh client not found")
    return found


def free_loopback_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass(frozen=True)
class TunnelConfig:
    kali_host: str = DEFAULT_KALI
    key_path: Path = DEFAULT_KEY
    ssh_path: str | None = None  # None: Windows OpenSSH, else PATH
    ready_timeout: float = READY_TIMEOUT

    def __post_init__(self) -> None:
        try:
            ipaddress.IPv4Address(self.kali_host)
        except ValueError:
            raise TunnelError("kali_host must be an IPv4 literal") from None
        if not 0 < self.ready_timeout <= 120:
            raise TunnelError("ready_timeout must be in (0, 120]")


def build_ssh_argv(cfg: TunnelConfig, ssh: str, local_port: int) -> list[str]:
    """The complete, fixed ssh command line. No shell, no user config, only
    the runtime key, no agent, pinned host key, one local forward."""
    if not 1024 <= local_port <= 65535:
        raise TunnelError("local port out of range")
    return [
        ssh, "-v", "-N",
        "-F", "none",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-i", str(cfg.key_path),
        "-L", f"127.0.0.1:{local_port}:{REMOTE_RUNNER}",
        f"{TUNNEL_USER}@{cfg.kali_host}",
    ]


@dataclass
class _Log:
    lines: list[str] = field(default_factory=list)
    size: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, line: str) -> None:
        with self.lock:
            if self.size < _MAX_LOG_CHARS:
                self.lines.append(line.rstrip("\r\n"))
                self.size += len(line)

    def text(self) -> str:
        with self.lock:
            return "\n".join(self.lines)


PopenFactory = Callable[[list[str]], subprocess.Popen]


def _default_popen(argv: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        argv, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True, errors="replace",
    )


# M8.8 (F-4): ssh children not yet confirmed stopped, keyed by object identity. An
# interrupt delivered as close() is entered skipped the whole cleanup and left
# ssh (and its local forward) running after AVRA moved on or exited. Entries
# leave only once the child has exited; the atexit net below terminates the
# rest when the interpreter exits (also after an unhandled KeyboardInterrupt).
_LIVE_CHILDREN: dict[int, subprocess.Popen] = {}
_LIVE_LOCK = threading.Lock()


def _stop_child(proc: subprocess.Popen | None) -> None:
    """Terminate (then kill) one ssh child; never raises."""
    if proc is None:
        return
    with contextlib.suppress(Exception):  # cleanup must never raise
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    if proc.poll() is not None:
        with _LIVE_LOCK:
            _LIVE_CHILDREN.pop(id(proc), None)


def _terminate_leftover_tunnels() -> None:
    with _LIVE_LOCK:
        leftovers = list(_LIVE_CHILDREN.values())
    for proc in leftovers:
        _stop_child(proc)


atexit.register(_terminate_leftover_tunnels)


class SshTunnel:
    """Context manager: opens the tunnel, yields the local base URL, closes it.

    >>> with SshTunnel(TunnelConfig()) as base_url:  # doctest: +SKIP
    ...     RunnerClient(base_url, token).health()
    """

    def __init__(self, cfg: TunnelConfig, *, popen: PopenFactory | None = None) -> None:
        self._cfg = cfg
        # Resolved at construction, not at import: lets the test suite forbid
        # real ssh launches globally (tests/conftest.py).
        self._popen = popen if popen is not None else _default_popen
        self._proc: subprocess.Popen | None = None
        self._child: subprocess.Popen | None = None  # owned until confirmed exited (F-4)
        self._log = _Log()
        self._reader: threading.Thread | None = None
        self.local_port: int | None = None

    @property
    def base_url(self) -> str:
        if self.local_port is None:
            raise TunnelError("tunnel is not open")
        return f"http://127.0.0.1:{self.local_port}"

    def diagnostics(self) -> str:
        """Relevant ssh -v lines (auth, forwarding, errors) — no secrets."""
        keep = re.compile(r"Authenticated to|Permission denied|Local forwarding|open failed|"
                          r"Could not request|Host key verification|Connection (refused|timed out)")
        return "\n".join(ln for ln in self._log.text().splitlines() if keep.search(ln))

    def open(self) -> str:
        if self._proc is not None:
            raise TunnelError("tunnel already open")
        if not Path(self._cfg.key_path).is_file():
            raise TunnelError(f"runtime key not found: {self._cfg.key_path}")
        ssh = self._cfg.ssh_path or ssh_executable()
        port = free_loopback_port()
        self._proc = self._popen(build_ssh_argv(self._cfg, ssh, port))
        self._child = self._proc
        with _LIVE_LOCK:
            _LIVE_CHILDREN[id(self._proc)] = self._proc
        try:
            stream = self._proc.stderr
            self._reader = threading.Thread(
                target=lambda: [self._log.add(ln) for ln in iter(stream.readline, "")], daemon=True
            )
            self._reader.start()
            deadline = time.monotonic() + self._cfg.ready_timeout
            while time.monotonic() < deadline:
                text = self._log.text()
                m = _READY.search(text)
                if m and int(m.group(1)) == port:
                    self.local_port = port
                    return self.base_url
                if _AUTH_DENIED.search(text) or _FORWARD_FAILED.search(text) or self._proc.poll() is not None:
                    break
                time.sleep(0.05)
        except BaseException:
            # M8.8 (F-6, Phase 1C): an interrupt or error while waiting for the
            # forward. `with` never calls __exit__ when __enter__ (open) raises, so
            # without this the ssh child and its forward lived until interpreter
            # exit (atexit net) - or for good after a hard kill. Stop it now
            # (_stop_child never raises), mark the tunnel closed, re-raise.
            self._proc, self.local_port = None, None
            _stop_child(self._child)
            raise
        self.close()
        raise TunnelError("SSH tunnel did not come up:\n" + (self.diagnostics() or "(no ssh output)"))

    def alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def close(self) -> None:
        proc, self._proc = self._proc, None
        self.local_port = None
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        with _LIVE_LOCK:
            _LIVE_CHILDREN.pop(id(proc), None)
        if self._reader is not None:
            self._reader.join(timeout=5)

    def __enter__(self) -> str:
        return self.open()

    def __exit__(self, *exc) -> None:
        try:
            self.close()
        except BaseException:
            # F-4: an interrupt (or error) at/inside close() must not leave ssh
            # and its local forward running. Then let the interrupt continue.
            _stop_child(self._child)
            raise
