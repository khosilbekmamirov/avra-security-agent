"""M8.8 Phase 1C (finding F-6): an interrupt or error DURING SshTunnel.open() must
not leave the ssh child running.

Phase 1C (disposable Kali Runner, real ssh.exe, trial T2n): a non-console
interrupt while open() waited for the forward left the ssh child alive after the
pipeline had returned; only the atexit net removed it at interpreter exit (and a
hard kill would have left it for good). `with` never calls __exit__ when
__enter__ (open) raises, so the F-4 fix in __exit__ did not cover this window.

These tests use the REAL SshTunnel with a real child process: a stdlib stand-in
for ssh that never reports the forward as ready (so open() keeps waiting); no
network. The child must be gone right after open() raises - BEFORE any atexit.
"""

from __future__ import annotations

import _thread
import subprocess
import sys
import textwrap
import threading
import time
import types

import pytest

from avra.runner_client import tunnel as tunnel_mod
from avra.runner_client.tunnel import SshTunnel, TunnelConfig, TunnelError

# See test_m88_tunnel_cleanup.py: run the stand-in on the base interpreter, not
# the venv launcher (terminating a launcher would not end its child).
PY = getattr(sys, "_base_executable", sys.executable)
NEVER_READY_SSH = textwrap.dedent("""
    import sys, time
    sys.stderr.write("debug1: Connecting to 192.168.56.104 port 22.\\n")
    sys.stderr.flush()
    time.sleep(120)
""")
READY_SSH = textwrap.dedent("""
    import sys, time
    a = sys.argv[1:]
    port = int(a[a.index("-L") + 1].split(":")[1])
    sys.stderr.write(f"debug1: Local forwarding listening on 127.0.0.1 port {port}.\\n")
    sys.stderr.flush()
    time.sleep(120)
""")


def _popen_factory(spawned: list, script: str):
    def popen(argv):
        p = subprocess.Popen([PY, "-c", script, *argv[1:]], shell=False,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, text=True, errors="replace")
        spawned.append(p)
        return p
    return popen


@pytest.fixture
def cfg(tmp_path):
    key = tmp_path / "key"
    key.write_text("dummy")
    return TunnelConfig(kali_host="192.168.56.104", key_path=key, ssh_path="ssh", ready_timeout=30)


@pytest.fixture(autouse=True)
def spawned():
    """Never leave a test child behind, whatever happens."""
    procs: list = []
    yield procs
    for p in procs:
        if p.poll() is None:
            p.kill()


def _gone(proc, timeout=10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            return True
        time.sleep(0.05)
    return False


def _registered(proc) -> bool:
    with tunnel_mod._LIVE_LOCK:
        return id(proc) in tunnel_mod._LIVE_CHILDREN


def _raise_on_nth_wait(monkeypatch, exc: BaseException, n: int = 3) -> None:
    """Deterministic: open()'s wait loop raises on its n-th short sleep (the child
    is running and registered by then). Only the tunnel module's view of `time`
    is replaced; monotonic stays real."""
    calls = {"n": 0}

    def sleep(seconds):
        calls["n"] += 1
        if calls["n"] == n:
            raise exc
        time.sleep(seconds)
    monkeypatch.setattr(tunnel_mod, "time", types.SimpleNamespace(monotonic=time.monotonic,
                                                                  sleep=sleep))


def test_interrupt_while_waiting_for_the_forward_stops_the_child(cfg, spawned, monkeypatch):
    _raise_on_nth_wait(monkeypatch, KeyboardInterrupt())
    t = SshTunnel(cfg, popen=_popen_factory(spawned, NEVER_READY_SSH))
    with pytest.raises(KeyboardInterrupt):
        t.open()
    assert len(spawned) == 1
    assert _gone(spawned[0], timeout=1.0), "ssh child still running after an interrupt in open()"
    assert not _registered(spawned[0])
    assert not t.alive()
    with pytest.raises(TunnelError):
        _ = t.base_url  # the tunnel is not open
    t.close()  # harmless no-op afterwards


def test_interrupt_in_with_statement_open_stops_the_child(cfg, spawned, monkeypatch):
    """The pipeline shape: `with tunnel_factory(cfg) as base_url:` - __exit__ never runs."""
    _raise_on_nth_wait(monkeypatch, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt), SshTunnel(cfg, popen=_popen_factory(spawned, NEVER_READY_SSH)):
        pytest.fail("the body must not run")
    assert _gone(spawned[0], timeout=1.0)
    assert not _registered(spawned[0])


def test_non_console_interrupt_main_during_open_stops_the_child(cfg, spawned):
    """Phase 1C trial T2n, offline: a real `_thread.interrupt_main()` from a timer
    while open() waits. The child must be gone right after - not at interpreter exit."""
    timer = threading.Timer(0.3, _thread.interrupt_main)
    timer.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            SshTunnel(cfg, popen=_popen_factory(spawned, NEVER_READY_SSH)).open()
    finally:
        timer.cancel()
    assert len(spawned) == 1
    assert _gone(spawned[0], timeout=1.0), "ssh child alive after open() was interrupted"
    assert not _registered(spawned[0])


def test_error_while_waiting_for_the_forward_stops_the_child(cfg, spawned, monkeypatch):
    _raise_on_nth_wait(monkeypatch, RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):  # propagated unchanged
        SshTunnel(cfg, popen=_popen_factory(spawned, NEVER_READY_SSH)).open()
    assert _gone(spawned[0], timeout=1.0)
    assert not _registered(spawned[0])


def test_successful_open_is_unchanged(cfg, spawned):
    t = SshTunnel(cfg, popen=_popen_factory(spawned, READY_SSH))
    url = t.open()
    assert url == f"http://127.0.0.1:{t.local_port}" and t.alive()
    assert spawned[0].poll() is None and _registered(spawned[0])
    t.close()
    assert _gone(spawned[0]) and not _registered(spawned[0])


def test_forward_never_ready_still_raises_tunnel_error_and_stops_the_child(cfg, spawned):
    """The pre-existing failure path (timeout -> close() -> TunnelError) is unchanged."""
    quick = TunnelConfig(kali_host=cfg.kali_host, key_path=cfg.key_path, ssh_path="ssh",
                         ready_timeout=0.5)
    with pytest.raises(TunnelError, match="did not come up"):
        SshTunnel(quick, popen=_popen_factory(spawned, NEVER_READY_SSH)).open()
    assert _gone(spawned[0]) and not _registered(spawned[0])
