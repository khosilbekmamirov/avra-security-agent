"""M8.8 Phase 1B (finding F-4): the tunnel's ssh child must not outlive an interrupt.

Phase 1A: a non-console interrupt arriving as ``SshTunnel.close()`` is entered
left the ssh child running (12/12), holding the local port forward. These
tests use the REAL SshTunnel with a real child process (a stdlib stand-in for
ssh that prints ssh's readiness line and sleeps; no network) and require:

* an interrupt at close() still terminates the child;
* a tunnel that was never closed is terminated when the interpreter exits
  (also after an unhandled KeyboardInterrupt);
* the ssh command line is unchanged (no new options, same single forward).
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from avra.runner_client import tunnel as tunnel_mod
from avra.runner_client.tunnel import SshTunnel, TunnelConfig, build_ssh_argv

# The venv's python.exe on Windows is a launcher that spawns the real
# interpreter as a CHILD; terminating the launcher would not end it. Real ssh
# has no launcher, so the stand-in runs on the base interpreter (stdlib only).
PY = getattr(sys, "_base_executable", sys.executable)
FAKE_SSH = textwrap.dedent("""
    import sys, time
    a = sys.argv[1:]
    port = int(a[a.index("-L") + 1].split(":")[1])
    sys.stderr.write(f"debug1: Local forwarding listening on 127.0.0.1 port {port}.\\n")
    sys.stderr.flush()
    time.sleep(120)
""")


def _popen_factory(spawned: list):
    def popen(argv):
        p = subprocess.Popen([PY, "-c", FAKE_SSH, *argv[1:]], shell=False,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, text=True, errors="replace")
        spawned.append(p)
        return p
    return popen


@pytest.fixture
def cfg(tmp_path):
    key = tmp_path / "key"
    key.write_text("dummy")
    return TunnelConfig(kali_host="192.168.56.104", key_path=key, ssh_path="ssh", ready_timeout=15)


def _gone(proc, timeout=10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if proc.poll() is not None:
            return True
        time.sleep(0.05)
    return False


@pytest.fixture(autouse=True)
def _kill_strays():
    """Never leave a test child behind, whatever happens."""
    spawned: list = []
    yield spawned
    for p in spawned:
        if p.poll() is None:
            p.kill()


def test_interrupt_at_close_entry_still_terminates_the_child(cfg, _kill_strays):
    class InterruptedAtClose(SshTunnel):
        def close(self):
            if not getattr(self, "_hit", False):
                self._hit = True
                raise KeyboardInterrupt  # = interrupt delivered as close() is entered
            super().close()

    with pytest.raises(KeyboardInterrupt), InterruptedAtClose(cfg, popen=_popen_factory(_kill_strays)):
        pass
    assert len(_kill_strays) == 1
    assert _gone(_kill_strays[0]), "ssh child still running after an interrupt at close()"


def test_never_closed_tunnel_is_terminated_by_the_exit_safety_net(cfg, _kill_strays):
    t = SshTunnel(cfg, popen=_popen_factory(_kill_strays))
    t.open()  # deliberately never closed (e.g. the frame was torn down by an interrupt)
    assert _kill_strays[0].poll() is None
    tunnel_mod._terminate_leftover_tunnels()  # what atexit runs
    assert _gone(_kill_strays[0])


def test_unhandled_ctrl_c_in_a_real_process_leaves_no_ssh_child(cfg, tmp_path):
    """End to end in a separate interpreter: open a tunnel, die of an unhandled
    KeyboardInterrupt without closing it; the ssh child must be gone afterwards."""
    pid_file = tmp_path / "child.pid"
    script = tmp_path / "victim.py"
    script.write_text(textwrap.dedent(f"""
        import subprocess, sys
        sys.path.insert(0, {str(Path(tunnel_mod.__file__).resolve().parents[2])!r})
        from avra.runner_client.tunnel import SshTunnel, TunnelConfig
        from pathlib import Path
        FAKE = {FAKE_SSH!r}
        def popen(argv):
            p = subprocess.Popen([{PY!r}, "-c", FAKE, *argv[1:]], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            Path({str(pid_file)!r}).write_text(str(p.pid))
            return p
        cfg = TunnelConfig(kali_host="192.168.56.104", key_path=Path({str(cfg.key_path)!r}),
                           ssh_path="ssh", ready_timeout=15)
        t = SshTunnel(cfg, popen=popen)
        t.open()
        raise KeyboardInterrupt  # unhandled; the tunnel is never closed
    """))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=60, env=env,
                       check=False)
    assert "KeyboardInterrupt" in r.stderr, r.stderr[-500:]
    pid = int(pid_file.read_text())
    end = time.monotonic() + 10
    while time.monotonic() < end and _alive(pid):
        time.sleep(0.05)
    alive = _alive(pid)
    if alive:  # do not leak it from the test either
        subprocess.run(["taskkill", "/F", "/PID", str(pid)] if os.name == "nt" else ["kill", "-9", str(pid)],
                       capture_output=True, check=False)
    assert not alive, "ssh child outlived the interpreter after an unhandled Ctrl+C"


def _alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes
        k = ctypes.WinDLL("kernel32")
        h = k.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        code = ctypes.c_ulong()
        k.GetExitCodeProcess(h, ctypes.byref(code))
        k.CloseHandle(h)
        return code.value == 259
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def test_ssh_command_line_is_unchanged():
    argv = build_ssh_argv(TunnelConfig(), "ssh", 40000)
    assert argv.count("-L") == 1 and "127.0.0.1:40000:127.0.0.1:8765" in argv
    assert argv[:3] == ["ssh", "-v", "-N"] and "BatchMode=yes" in argv and "StrictHostKeyChecking=yes" in argv
    assert not any(a in argv for a in ("-R", "-D", "-g", "-A", "-X"))
