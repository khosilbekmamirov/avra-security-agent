"""Live verification of the avra-tunnel SSH account (ADR 0003, M4.4/M4.5).

Run by the owner on Windows AFTER install-tunnel.sh succeeded on Kali:

    python runner/deploy/verify_tunnel.py [--bridged-ip 10.x.x.x]

It never changes anything on either machine, reads no token, runs no scan.
Each check starts the Windows OpenSSH client with ``-v`` and the dedicated
runtime key, then — for forwarding checks — actually CONNECTS to the local
listener so the client sends the forwarding request to sshd. A local
listener appearing proves nothing about the server; only the client's
debug log after a real connection does. Every check reports four layers:

  auth      Authenticated to … using "publickey"   | Permission denied
  listener  Local forwarding listening on …         | (absent)
  request   Connection to port N forwarding … requested (proves it was sent)
  verdict   administratively prohibited             -> server refused
            open failed: connect failed: …          -> server allowed it,
                                                       nothing listening behind it
            no "open failed" after a request        -> server allowed it,
                                                       backend accepted

Standard library only. Exit code 0 only if every check matched its
expectation.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

KALI = "192.168.56.104"
TUNNEL_USER = "avra-tunnel"
DEV_USER = "kali"
RUNNER_PORT = 8765
JUICE_SHOP = ("192.168.56.103", 3000)
DEFAULT_KEY = Path.home() / ".ssh" / "avra_runtime_ed25519"
SETTLE_SECONDS = 2.0
AUTH_TIMEOUT = 20.0


class Auth(str, Enum):
    OK = "ok"
    DENIED = "denied"
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    PROHIBITED = "prohibited"  # sshd refused the forwarding request
    ALLOWED_BACKEND_DOWN = "allowed-backend-down"  # allowed; nothing behind it
    ALLOWED_BACKEND_UP = "allowed-backend-up"  # allowed; backend accepted
    REMOTE_FORWARD_DENIED = "remote-forward-denied"
    # sshd's generic channel-open failure ("connect failed: open failed"):
    # OpenSSH sends exactly this both when it REFUSES a direct-streamlocal
    # (Unix socket) forward and when connecting to the path fails, so the
    # client log alone can't tell them apart. Never counts as allowed.
    GENERIC_OPEN_FAILED = "generic-open-failed"
    NOT_REQUESTED = "not-requested"  # no request reached the server: inconclusive
    UNKNOWN = "unknown"


@dataclass
class Layers:
    auth: Auth
    listener: bool
    requested: bool
    verdict: Verdict
    evidence: list[str] = field(default_factory=list)


_AUTH_OK = re.compile(r'Authenticated to .* using "publickey"')
_AUTH_DENIED = re.compile(r"Permission denied \(")
_LISTENER = re.compile(r"Local forwarding listening on|Local connections to .* forwarded to")
_REQUESTED = re.compile(r"Connection to port \d+ forwarding to .* requested")
_PROHIBITED = re.compile(r"open failed: administratively prohibited")
_GENERIC_OPEN_FAILED = re.compile(r"open failed: connect failed: open failed\s*$", re.MULTILINE)
_BACKEND_DOWN = re.compile(r"open failed: connect failed: ")
_OPEN_FAILED = re.compile(r"open failed:")
_REMOTE_DENIED = re.compile(r"remote port forwarding failed")
_EVIDENCE = re.compile(
    "|".join(
        p.pattern
        for p in (_AUTH_OK, _AUTH_DENIED, _LISTENER, _REQUESTED, _OPEN_FAILED, _REMOTE_DENIED)
    )
)


def classify(log: str, *, triggered: bool) -> Layers:
    """Turn an ``ssh -v`` stderr log into the four layers. Pure function."""
    auth = Auth.UNKNOWN
    if _AUTH_OK.search(log):
        auth = Auth.OK
    elif _AUTH_DENIED.search(log):
        auth = Auth.DENIED
    listener = bool(_LISTENER.search(log))
    requested = bool(_REQUESTED.search(log))
    if _REMOTE_DENIED.search(log):
        verdict = Verdict.REMOTE_FORWARD_DENIED
    elif _PROHIBITED.search(log):
        verdict = Verdict.PROHIBITED
    elif _GENERIC_OPEN_FAILED.search(log):
        verdict = Verdict.GENERIC_OPEN_FAILED
    elif _BACKEND_DOWN.search(log):
        verdict = Verdict.ALLOWED_BACKEND_DOWN
    elif _OPEN_FAILED.search(log):
        verdict = Verdict.UNKNOWN  # some other refusal reason: don't guess
    elif triggered and requested and auth is Auth.OK:
        verdict = Verdict.ALLOWED_BACKEND_UP
    else:
        verdict = Verdict.NOT_REQUESTED
    evidence = [ln.strip() for ln in log.splitlines() if _EVIDENCE.search(ln)]
    return Layers(auth, listener, requested, verdict, evidence)


def socks5_connect_request(host: str, port: int) -> bytes:
    """SOCKS5 CONNECT for an IPv4 address (RFC 1928)."""
    return b"\x05\x01\x00\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")


def free_local_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ssh_binary(name: str = "ssh") -> str:
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "OpenSSH"
    exe = system / f"{name}.exe"
    if exe.is_file():
        return str(exe)
    found = shutil.which(name)
    if not found:
        raise SystemExit(f"{name} not found")
    return found


def tunnel_args(key: Path, *, batch_only: bool = False) -> list[str]:
    """Options common to every runtime-key connection: only this key, no
    agent, no user ssh_config, pinned host key, fail on forward errors."""
    args = [
        "-F", "none",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ConnectTimeout=10",
        "-i", str(key),
    ]
    if not batch_only:
        args += ["-o", "ExitOnForwardFailure=yes"]
    return args


class _Drain(threading.Thread):
    def __init__(self, stream):
        super().__init__(daemon=True)
        self.stream, self.chunks = stream, []

    def run(self):
        for line in iter(self.stream.readline, ""):
            self.chunks.append(line)

    @property
    def text(self) -> str:
        return "".join(self.chunks)


def _wait_for(drain: _Drain, proc: subprocess.Popen, pattern: re.Pattern, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pattern.search(drain.text):
            return True
        if proc.poll() is not None:
            return bool(pattern.search(drain.text))
        time.sleep(0.1)
    return False


def run_forward(key: Path, host: str, forward: list[str], trigger) -> Layers:
    """Start ``ssh -N`` with one forward, wait for auth + listener, call
    ``trigger()`` (which connects to the local side), then collect the log."""
    cmd = [ssh_binary(), "-v", "-N", *tunnel_args(key), *forward, f"{TUNNEL_USER}@{host}"]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True, errors="replace",
    )
    drain = _Drain(proc.stderr)
    drain.start()
    triggered = False
    try:
        if _wait_for(drain, proc, _AUTH_OK, AUTH_TIMEOUT) and proc.poll() is None:
            _wait_for(drain, proc, _LISTENER, 5.0)
            time.sleep(0.5)  # let a -R refusal arrive before we trigger
            if trigger is not None and proc.poll() is None:
                triggered = trigger()
            time.sleep(SETTLE_SECONDS)
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        drain.join(timeout=5)
    return classify(drain.text, triggered=triggered)


def tcp_trigger(port: int, payload: bytes = b""):
    def go() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                if payload:
                    s.sendall(payload)
                s.settimeout(SETTLE_SECONDS)
                try:
                    s.recv(64)
                except (TimeoutError, OSError):
                    pass
            return True
        except OSError:
            return False
    return go


def socks_trigger(port: int, target: tuple[str, int]):
    def go() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.settimeout(5)
                s.sendall(b"\x05\x01\x00")  # greeting: no auth
                if s.recv(2) != b"\x05\x00":
                    return False
                s.sendall(socks5_connect_request(*target))
                try:
                    s.recv(10)
                except (TimeoutError, OSError):
                    pass
            return True
        except OSError:
            return False
    return go


def run_command(cmd: list[str], stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, check=False, input=stdin, capture_output=True, text=True, errors="replace", timeout=60
    )


# --- checks -----------------------------------------------------------------

@dataclass
class Result:
    name: str
    passed: bool
    detail: str
    evidence: list[str] = field(default_factory=list)
    # True when the client-side evidence can't decide; `hint` says how to
    # settle it (e.g. which server log line to look for).
    inconclusive: bool = False
    hint: str = ""

    @property
    def status(self) -> str:
        if self.passed:
            return "PASS"
        return "INCONCLUSIVE" if self.inconclusive else "FAIL"


def _forward_check(name, layers: Layers, want: set[Verdict]) -> Result:
    ok = layers.auth is Auth.OK and layers.requested and layers.verdict in want
    detail = (
        f"auth={layers.auth.value} listener={layers.listener} "
        f"requested={layers.requested} verdict={layers.verdict.value} "
        f"(expected {'/'.join(v.value for v in want)}, auth=ok, requested=True)"
    )
    return Result(name, ok, detail, layers.evidence)


def check_allowed(key: Path) -> Result:
    port = free_local_port()
    layers = run_forward(
        key, KALI, ["-L", f"127.0.0.1:{port}:127.0.0.1:{RUNNER_PORT}"], tcp_trigger(port)
    )
    return _forward_check(
        "allowed: -L to 127.0.0.1:8765", layers,
        {Verdict.ALLOWED_BACKEND_DOWN, Verdict.ALLOWED_BACKEND_UP},
    )


def check_denied_local(key: Path, name: str, remote: str) -> Result:
    port = free_local_port()
    layers = run_forward(key, KALI, ["-L", f"127.0.0.1:{port}:{remote}"], tcp_trigger(port))
    return _forward_check(name, layers, {Verdict.PROHIBITED})


STREAMLOCAL_HINT = (
    "client can't distinguish refusal from a failed connect for Unix sockets; "
    "confirm on Kali: journalctl --since '-10 min' | grep 'refused streamlocal port forward'"
)


def check_unix_socket(key: Path, path: str = "/var/run/docker.sock") -> Result:
    """-L to a Unix socket. sshd answers a refused direct-streamlocal with
    the generic "connect failed: open failed" (not "administratively
    prohibited"), so that answer is INCONCLUSIVE from the client side and
    must be confirmed in the server log; anything else is decisive."""
    name = f"denied: -L to Unix socket {path}"
    port = free_local_port()
    layers = run_forward(key, KALI, ["-L", f"127.0.0.1:{port}:{path}"], tcp_trigger(port))
    res = _forward_check(name, layers, {Verdict.PROHIBITED})
    if (not res.passed and layers.auth is Auth.OK and layers.requested
            and layers.verdict is Verdict.GENERIC_OPEN_FAILED):
        res.inconclusive = True
        res.hint = STREAMLOCAL_HINT
    return res


def check_socks(key: Path) -> Result:
    port = free_local_port()
    layers = run_forward(key, KALI, ["-D", f"127.0.0.1:{port}"], socks_trigger(port, JUICE_SHOP))
    return _forward_check("denied: -D SOCKS to Juice Shop", layers, {Verdict.PROHIBITED})


def check_reverse(key: Path) -> Result:
    layers = run_forward(key, KALI, ["-R", "127.0.0.1:18765:127.0.0.1:22"], None)
    ok = layers.auth is Auth.OK and layers.verdict is Verdict.REMOTE_FORWARD_DENIED
    return Result(
        "denied: -R reverse forward", ok,
        f"auth={layers.auth.value} verdict={layers.verdict.value} "
        "(expected auth=ok, remote-forward-denied)",
        layers.evidence,
    )


def check_shell(key: Path) -> Result:
    r = run_command([ssh_binary(), *tunnel_args(key, batch_only=True),
                     f"{TUNNEL_USER}@{KALI}", "id"])
    ran = "uid=" in r.stdout
    ok = not ran and "currently not available" in (r.stdout + r.stderr) and r.returncode != 0
    return Result("denied: remote command / shell", ok,
                  f"exit={r.returncode} command_ran={ran} (expected nologin message, nonzero)")


def check_pty(key: Path) -> Result:
    r = run_command([ssh_binary(), "-tt", *tunnel_args(key, batch_only=True),
                     f"{TUNNEL_USER}@{KALI}"])
    ok = "PTY allocation request failed" in r.stderr and "uid=" not in r.stdout
    return Result("denied: PTY", ok, f"exit={r.returncode} (expected 'PTY allocation request failed')")


def check_sftp(key: Path) -> Result:
    r = run_command([ssh_binary("sftp"), "-b", "-", *tunnel_args(key, batch_only=True),
                     f"{TUNNEL_USER}@{KALI}"], stdin="pwd\n")
    ok = r.returncode != 0 and "Remote working directory" not in r.stdout
    return Result("denied: SFTP", ok, f"exit={r.returncode} (expected nonzero, no working directory)")


def check_runtime_key_not_for_kali(key: Path) -> Result:
    r = run_command([ssh_binary(), "-v", *tunnel_args(key, batch_only=True),
                     f"{DEV_USER}@{KALI}", "true"])
    ok = r.returncode != 0 and bool(_AUTH_DENIED.search(r.stderr))
    return Result("denied: runtime key as kali", ok, f"exit={r.returncode} (expected Permission denied)")


def check_bridged(key: Path, ip: str) -> Result:
    # No -N: if the key were (wrongly) accepted, nologin ends the session
    # instead of leaving a tunnel open; the auth layer decides the result.
    # HostKeyAlias: same sshd and host key as 192.168.56.104, so strict
    # host-key checking still applies (without it the run stops at "Host
    # key verification failed" before authentication — not a from= test).
    r = run_command([ssh_binary(), "-v", *tunnel_args(key, batch_only=True),
                     "-o", f"HostKeyAlias={KALI}", f"{TUNNEL_USER}@{ip}", "true"])
    ok = bool(_AUTH_DENIED.search(r.stderr)) and not _AUTH_OK.search(r.stderr)
    reached_auth = "Authenticating to" in r.stderr
    host_key_failed = "Host key verification failed" in r.stderr
    if not ok and (host_key_failed or not reached_auth):
        # Never reached the authentication layer (unreachable / host key):
        # says nothing about from=.
        line = next((ln for ln in r.stderr.splitlines()
                     if "verification failed" in ln or "timed out" in ln
                     or "Connection refused" in ln or "No route" in ln), "")
        return Result(f"denied: via Bridged IP {ip} (from=)", False,
                      f"exit={r.returncode}: did not reach authentication",
                      [line] if line else [], inconclusive=True,
                      hint="check that Windows can reach the Bridged IP on port 22")
    return Result(f"denied: via Bridged IP {ip} (from=)", ok,
                  f"exit={r.returncode} (expected Permission denied)")


def check_dev_ssh() -> Result:
    # The owner's normal dev access: user's own config/agent, nothing special.
    r = run_command([ssh_binary(), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                     f"{DEV_USER}@{KALI}", "echo dev-ssh-ok"])
    ok = r.returncode == 0 and "dev-ssh-ok" in r.stdout
    return Result("unchanged: kali dev SSH", ok, f"exit={r.returncode}")


def all_checks(key: Path, bridged_ip: str | None):
    yield check_dev_ssh
    yield lambda: check_allowed(key)
    yield lambda: check_denied_local(key, "denied: -L to SSH port 22", "127.0.0.1:22")
    yield lambda: check_denied_local(key, "denied: -L direct to Juice Shop",
                                     f"{JUICE_SHOP[0]}:{JUICE_SHOP[1]}")
    yield lambda: check_denied_local(key, "denied: -L to localhost:8765 (alt name)",
                                     f"localhost:{RUNNER_PORT}")
    yield lambda: check_denied_local(key, "denied: -L to [::1]:8765 (alt address)",
                                     f"[::1]:{RUNNER_PORT}")
    yield lambda: check_unix_socket(key)
    yield lambda: check_socks(key)
    yield lambda: check_reverse(key)
    yield lambda: check_shell(key)
    yield lambda: check_pty(key)
    yield lambda: check_sftp(key)
    yield lambda: check_runtime_key_not_for_kali(key)
    if bridged_ip:
        yield lambda: check_bridged(key, bridged_ip)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", type=Path, default=DEFAULT_KEY)
    ap.add_argument("--bridged-ip", help="Kali's Bridged-adapter IP (optional extra check)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print ssh evidence lines")
    args = ap.parse_args(argv)
    if not args.key.is_file():
        print(f"runtime key not found: {args.key}", file=sys.stderr)
        return 2
    failed = inconclusive = 0
    for check in all_checks(args.key, args.bridged_ip):
        try:
            res = check()
        except (OSError, subprocess.SubprocessError) as exc:
            res = Result(getattr(check, "__name__", "check"), False, f"error: {exc}")
        failed += res.status == "FAIL"
        inconclusive += res.status == "INCONCLUSIVE"
        print(f"[{res.status}] {res.name}: {res.detail}")
        if res.hint:
            print(f"         > {res.hint}")
        if args.verbose or not res.passed:
            for line in res.evidence:
                print(f"         | {line}")
    if failed:
        print(f"{failed} CHECK(S) FAILED, {inconclusive} INCONCLUSIVE")
        return 1
    if inconclusive:
        print(f"NO FAILURES, {inconclusive} INCONCLUSIVE — confirm as hinted above")
        return 2
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
