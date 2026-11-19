"""SubprocessRunner — security properties (ADR 0003, M2.2b Part 1).

Harmless local Python child processes only; no network, no nmap.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

import avra.runner.execution as execution
from avra.runner.execution import (
    IS_POSIX,
    ExecutionLimits,
    ProcessOutcome,
    SubprocessRunner,
)

PYTHON = getattr(sys, "_base_executable", sys.executable) or sys.executable


@pytest.fixture
def runner():
    return SubprocessRunner({"py": PYTHON})


def _limits(**kw):
    kw.setdefault("timeout_seconds", 20)
    kw.setdefault("kill_grace_seconds", 1)
    return ExecutionLimits(**kw)


# --- Executable configuration: fixed, trusted, absolute ------------------


@pytest.mark.parametrize(
    "mapping",
    [
        {},
        {"py": "python"},  # relative -> would be a PATH lookup
        {"py": "./python"},
        {"py": os.path.join(os.sep, "definitely", "not", "here", "nmap")},
        {"../py": PYTHON},  # name must be a plain logical name
        {"": PYTHON},
    ],
)
def test_untrusted_executable_config_rejected(mapping):
    with pytest.raises(ValueError):
        SubprocessRunner(mapping)


def test_directory_is_not_an_executable(tmp_path):
    with pytest.raises(ValueError):
        SubprocessRunner({"py": str(tmp_path)})


def test_executables_mapping_is_read_only(runner):
    with pytest.raises(TypeError):
        runner.executables["sh"] = "/bin/sh"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        "py -c print(1)",  # a command string, not argv
        ["sh", "-c", "id"],  # not a configured executable
        ["bash"],
        [PYTHON, "-c", "print(1)"],  # raw path instead of logical name
        ["py", 123],
        ["py", "-c", "print(1)\x00"],
    ],
)
def test_bad_argv_rejected_before_anything_runs(runner, argv, monkeypatch):
    started = []
    monkeypatch.setattr(
        execution.subprocess, "Popen", lambda *a, **k: started.append(a)
    )
    with pytest.raises(ValueError):
        runner.run(argv, _limits())
    assert started == []


# --- No shell, no secrets ------------------------------------------------


@pytest.mark.parametrize(
    "arg", ["; echo hacked", "$(id)", "`id`", "a && b", "| cat /etc/passwd"]
)
def test_shell_metacharacters_passed_literally(runner, arg):
    res = runner.run(["py", "-c", "import sys; print(sys.argv[1])", arg], _limits())
    assert res.ok
    assert res.stdout.decode().strip() == arg


def test_popen_called_with_shell_false(runner, monkeypatch):
    seen = {}
    real_popen = subprocess.Popen

    def spy(cmd, **kw):
        seen.update(kw)
        return real_popen(cmd, **kw)

    monkeypatch.setattr(execution.subprocess, "Popen", spy)
    runner.run(["py", "-c", "pass"], _limits())
    assert seen["shell"] is False
    assert seen["stdin"] is subprocess.DEVNULL


def test_runner_environment_not_leaked(runner, monkeypatch):
    monkeypatch.setenv("AVRA_RUNNER_TOKEN", "super-secret-token")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
    code = "import os; print(sorted(os.environ))"
    res = runner.run(["py", "-c", code], _limits())
    out = res.stdout.decode()
    assert "AVRA_RUNNER_TOKEN" not in out
    assert "ANTHROPIC_API_KEY" not in out
    assert "super-secret" not in out


def test_child_env_is_minimal(runner):
    code = "import os; print(','.join(sorted(os.environ)))"
    res = runner.run(["py", "-c", code], _limits())
    keys = set(res.stdout.decode().strip().split(","))
    # The OS/interpreter may add a few vars of its own, but nothing from
    # the parent beyond the allowlist.
    allowed = set(execution.default_child_env()) | {
        "__CF_USER_TEXT_ENCODING", "LC_CTYPE", "PYTHONHASHSEED", "",
    }
    assert keys <= allowed


# --- Timeouts and output limits ------------------------------------------


def test_timeout_kills_process(runner):
    t0 = time.monotonic()
    res = runner.run(
        ["py", "-c", "import time; time.sleep(60)"], _limits(timeout_seconds=1)
    )
    assert res.outcome is ProcessOutcome.TIMED_OUT
    assert not res.ok
    assert time.monotonic() - t0 < 10
    assert res.exit_code is not None  # reaped


def test_timeout_kills_process_ignoring_sigterm(runner):
    code = (
        "import signal, time\n"
        "if hasattr(signal, 'SIGTERM'): signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(60)"
    )
    t0 = time.monotonic()
    res = runner.run(["py", "-c", code], _limits(timeout_seconds=1))
    assert res.outcome is ProcessOutcome.TIMED_OUT
    assert time.monotonic() - t0 < 10


def test_stdout_flood_is_capped_and_killed(runner):
    code = "import sys\nwhile True: sys.stdout.write('x' * 65536)"
    res = runner.run(["py", "-c", code], _limits(max_stdout_bytes=10_000))
    assert res.outcome is ProcessOutcome.OUTPUT_LIMIT
    assert not res.ok
    assert res.stdout_truncated
    assert len(res.stdout) == 10_000


def test_stderr_flood_is_capped_and_killed(runner):
    code = "import sys\nwhile True: sys.stderr.write('e' * 65536)"
    res = runner.run(["py", "-c", code], _limits(max_stderr_bytes=5_000))
    assert res.outcome is ProcessOutcome.OUTPUT_LIMIT
    assert res.stderr_truncated
    assert len(res.stderr) == 5_000


def test_overflow_before_exit_is_still_a_failure(runner):
    code = "import sys; sys.stdout.write('x' * 50_000)"
    res = runner.run(["py", "-c", code], _limits(max_stdout_bytes=1_000))
    assert res.outcome is ProcessOutcome.OUTPUT_LIMIT
    assert len(res.stdout) == 1_000


def test_large_output_on_both_pipes_does_not_deadlock(runner):
    # A naive wait()-then-read would deadlock once a pipe buffer fills.
    code = (
        "import sys\n"
        "sys.stderr.write('e' * 300_000); sys.stderr.flush()\n"
        "sys.stdout.write('o' * 300_000)"
    )
    t0 = time.monotonic()
    res = runner.run(
        ["py", "-c", code],
        _limits(timeout_seconds=15, max_stdout_bytes=400_000, max_stderr_bytes=400_000),
    )
    assert res.ok
    assert len(res.stdout) == 300_000 and len(res.stderr) == 300_000
    assert time.monotonic() - t0 < 15


@pytest.mark.skipif(not IS_POSIX, reason="process groups are POSIX-only")
def test_timeout_kills_descendants_on_posix(runner):
    code = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "print(p.pid, flush=True)\n"
        "time.sleep(60)"
    )
    res = runner.run(["py", "-c", code], _limits(timeout_seconds=2))
    assert res.outcome is ProcessOutcome.TIMED_OUT
    grandchild = int(res.stdout.split()[0])
    for _ in range(40):
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("grandchild process survived the timeout")


@pytest.mark.skipif(IS_POSIX, reason="documents the Windows-only limitation")
def test_windows_limitation_documented():
    assert "Windows" in execution.__doc__
    assert "descendants" in execution.__doc__


# --- Startup and cleanup failures ----------------------------------------


def test_startup_failure_is_structured_and_cleans_up(runner, monkeypatch):
    made = []
    real_mkdtemp = execution.tempfile.mkdtemp

    def tracking_mkdtemp(**kw):
        path = real_mkdtemp(**kw)
        made.append(path)
        return path

    def boom(*a, **k):
        raise OSError("exec format error")

    monkeypatch.setattr(execution.tempfile, "mkdtemp", tracking_mkdtemp)
    monkeypatch.setattr(execution.subprocess, "Popen", boom)
    res = runner.run(["py", "-c", "pass"], _limits())
    assert res.outcome is ProcessOutcome.START_FAILED
    assert not res.ok
    assert "exec format error" in res.error
    assert res.exit_code is None
    assert made and not os.path.exists(made[0])


def test_cleanup_failure_is_reported_not_raised(runner, monkeypatch):
    real_rmtree = execution.shutil.rmtree
    leaked = []

    def failing_rmtree(path):
        leaked.append(path)
        raise OSError("device busy")

    monkeypatch.setattr(execution.shutil, "rmtree", failing_rmtree)
    res = runner.run(["py", "-c", "print(1)"], _limits())
    assert res.ok
    assert "workdir cleanup failed" in res.cleanup_error
    for path in leaked:  # the test caused the leak, so the test cleans it up
        real_rmtree(path, ignore_errors=True)
