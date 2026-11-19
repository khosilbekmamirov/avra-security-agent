"""M8.7 Stage 6 (ADR 0012): Linux/POSIX-only checks of Runner cancellation.

Skipped on Windows. Run on Linux (Kali) as an UNPRIVILEGED user in an
isolated workspace: harmless local Python children only, no network, no
nmap, no operational Runner state."""

from __future__ import annotations

import os
import signal
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from avra.runner.emergency import LatchState, RunnerLatch
from avra.runner.execution import (
    IS_POSIX,
    ExecutionLimits,
    ProcessOutcome,
    SubprocessRunner,
)
from avra.storage.audit import AuditLog

pytestmark = pytest.mark.skipif(not IS_POSIX, reason="POSIX/Linux semantics only")

PYTHON = sys.executable


@pytest.fixture
def sub():
    return SubprocessRunner({"py": PYTHON})


def _limits(**kw):
    kw.setdefault("timeout_seconds", 30)
    kw.setdefault("kill_grace_seconds", 1)
    return ExecutionLimits(**kw)


def _cancel_after(seconds):
    ev = threading.Event()
    threading.Timer(seconds, ev.set).start()
    return ev


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie still "exists" for kill(0): treat it as gone but report it
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split(")")[-1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def _zombie_children() -> list[int]:
    me, out = os.getpid(), []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as fh:
                fields = fh.read().split(")")[-1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if fields[0] == "Z" and int(fields[1]) == me:
            out.append(int(entry))
    return out


def _wait_gone(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


GRANDCHILD = (
    "import subprocess, sys, time\n"
    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
    "open(sys.argv[1], 'w').write(str(p.pid))\n"
    "print('ready', flush=True)\n"
    "time.sleep(120)\n"
)


def test_cancel_reaps_child_and_grandchild_and_leaves_no_zombies(sub, tmp_path):
    pidfile = tmp_path / "gc.pid"
    res = sub.run(["py", "-c", GRANDCHILD, str(pidfile)], _limits(), cancel=_cancel_after(1.0))
    assert res.outcome is ProcessOutcome.CANCELLED
    assert _wait_gone(int(pidfile.read_text())), "grandchild in the job's group survived"
    assert _zombie_children() == []  # the direct child was reaped (waitpid)


def test_sigterm_ignoring_job_is_killed_after_the_grace_period(sub, tmp_path):
    code = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(120)")
    t0 = time.monotonic()
    res = sub.run(["py", "-c", code], _limits(kill_grace_seconds=1), cancel=_cancel_after(0.5))
    elapsed = time.monotonic() - t0
    assert res.outcome is ProcessOutcome.CANCELLED and res.exit_code == -signal.SIGKILL
    assert 1.0 <= elapsed < 8, elapsed  # waited the grace period, then SIGKILL


def test_graceful_job_ends_with_sigterm(sub):
    res = sub.run(["py", "-c", "import time; print('ready', flush=True); time.sleep(120)"],
                  _limits(kill_grace_seconds=3), cancel=_cancel_after(0.5))
    assert res.outcome is ProcessOutcome.CANCELLED and res.exit_code == -signal.SIGTERM


def test_descendant_that_escapes_with_setsid_survives_a_cancel(sub, tmp_path):
    """RESIDUAL RISK, documented (ADR 0012): a descendant that calls setsid()
    leaves the job's process group, so the group kill cannot reach it.
    Under systemd, KillMode=control-group removes it when the service stops.
    nmap and avra-http-probe do not do this. The test cleans up after itself."""
    pidfile = tmp_path / "escaped.pid"
    code = ("import os, subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],"
            " start_new_session=True)\n"
            "open(sys.argv[1], 'w').write(str(p.pid))\n"
            "time.sleep(120)\n")
    t0 = time.monotonic()
    res = sub.run(["py", "-c", code, str(pidfile)], _limits(), cancel=_cancel_after(1.0))
    elapsed = time.monotonic() - t0
    escaped = int(pidfile.read_text())
    try:
        assert res.outcome is ProcessOutcome.CANCELLED
        assert _alive(escaped), "expected the setsid() escapee to survive (documented limit)"
        assert os.getpgid(escaped) != os.getpgid(0)
        # Stage 6 fix: the escapee keeps the job's output pipe open, but run()
        # still returns promptly instead of waiting for it to exit.
        assert elapsed < 10, f"run() blocked {elapsed:.1f}s on an escaped descendant"
        assert "outside the job's process group" in res.cleanup_error
    finally:
        os.kill(escaped, signal.SIGKILL)
        _wait_gone(escaped)


def test_escaped_pipe_holder_cannot_stretch_a_timeout(sub, tmp_path):
    """Same defect class via the timeout path: bounded by timeout + grace."""
    pidfile = tmp_path / "escaped.pid"
    code = ("import subprocess, sys, time\n"
            "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'],"
            " start_new_session=True)\n"
            "open(sys.argv[1], 'w').write(str(p.pid))\n"
            "time.sleep(120)\n")
    t0 = time.monotonic()
    res = sub.run(["py", "-c", code, str(pidfile)], _limits(timeout_seconds=1))
    elapsed = time.monotonic() - t0
    try:
        assert res.outcome is ProcessOutcome.TIMED_OUT and elapsed < 10, elapsed
    finally:
        try:
            os.kill(int(pidfile.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_unrelated_process_in_our_own_session_is_untouched(sub):
    import subprocess

    bystander = subprocess.Popen([PYTHON, "-c", "import time; time.sleep(60)"])
    try:
        res = sub.run(["py", "-c", "import time; time.sleep(60)"], _limits(),
                      cancel=_cancel_after(0.3))
        assert res.outcome is ProcessOutcome.CANCELLED
        assert _alive(bystander.pid) and os.getpgid(bystander.pid) == os.getpgid(0)
    finally:
        bystander.kill()
        bystander.wait()


def test_cancel_wins_over_output_limit_in_the_same_poll(sub):
    class AlreadySet(threading.Event):
        def is_set(self):  # set before the first poll, while output floods in
            return True

    code = "import sys, time\nsys.stdout.write('x' * 5_000_000)\nsys.stdout.flush()\ntime.sleep(5)"
    res = sub.run(["py", "-c", code], _limits(max_stdout_bytes=1000), cancel=AlreadySet())
    assert res.outcome is ProcessOutcome.CANCELLED  # never started: checked before Popen


def test_output_limit_still_wins_when_no_cancel(sub):
    res = sub.run(["py", "-c", "import sys; sys.stdout.write('x' * 5_000_000)"],
                  _limits(max_stdout_bytes=1000), cancel=threading.Event())
    assert res.outcome is ProcessOutcome.OUTPUT_LIMIT


def test_job_runs_in_its_own_session_and_group(sub, tmp_path):
    out = tmp_path / "ids"
    code = (f"import os; open(r'{out}', 'w').write(f'{{os.getpid()}} {{os.getpgid(0)}} "
            f"{{os.getsid(0)}}')")
    sub.run(["py", "-c", code], _limits())
    pid, pgid, sid = map(int, out.read_text().split())
    assert pid == pgid == sid  # start_new_session: leader of its own session/group
    assert pgid != os.getpgid(0)  # never our (the Runner's) group


# --- filesystem semantics under POSIX ----------------------------------------------------


def test_latch_symlink_is_rejected(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    latch = RunnerLatch.beside(audit)
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    os.symlink(target, latch.path)
    st = latch.load()
    assert st.state is LatchState.CORRUPT and "symlink" in st.detail
    assert latch.engage("operator_emergency_stop", by="t").durable is False
    assert target.read_text() == "{}"  # nothing written through the link


def test_unreadable_latch_fails_closed(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    audit = AuditLog(tmp_path / "audit.jsonl")
    latch = RunnerLatch.beside(audit)
    latch.engage("operator_emergency_stop", by="t")
    os.chmod(latch.path, 0)
    try:
        assert latch.load().state is LatchState.UNREADABLE
    finally:
        os.chmod(latch.path, stat.S_IRUSR | stat.S_IWUSR)
    assert latch.load().state is LatchState.STOPPED


def test_unwritable_audit_directory_fails_closed(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    from avra.storage.audit import AuditWriteError

    d = tmp_path / "ro"
    d.mkdir()
    log = AuditLog(d / "audit.jsonl")
    log.record("first")
    os.chmod(d / "audit.jsonl", stat.S_IRUSR)
    try:
        with pytest.raises(AuditWriteError):
            log.record("second")
    finally:
        os.chmod(d / "audit.jsonl", stat.S_IRUSR | stat.S_IWUSR)
    assert log.verify() and len(log.read_all()) == 1


def test_latch_file_is_private_and_atomically_replaced(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    latch = RunnerLatch.beside(audit)
    latch.engage("operator_emergency_stop", by="t")
    st = os.stat(latch.path)
    assert stat.S_IMODE(st.st_mode) & 0o077 == 0  # 0600
    assert st.st_uid == os.geteuid()
    assert not list(Path(tmp_path).glob(".emergency-stop.json.*.tmp"))  # no temp left
