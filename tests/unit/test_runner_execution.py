"""SubprocessRunner — normal behaviour (ADR 0003, M2.2b Part 1).

All child processes here are harmless local Python one-liners; nothing
touches the network and nmap is never run.
"""

from __future__ import annotations

import sys

import pytest

from avra.runner.execution import (
    ExecutionLimits,
    ProcessOutcome,
    SubprocessRunner,
)

# Under a venv on Windows, sys.executable can be a launcher that spawns
# the real interpreter as a grandchild; use the real interpreter.
PYTHON = getattr(sys, "_base_executable", sys.executable) or sys.executable


@pytest.fixture
def runner():
    return SubprocessRunner({"py": PYTHON})


def _limits(**kw):
    kw.setdefault("timeout_seconds", 20)
    return ExecutionLimits(**kw)


def test_successful_run_returns_structured_result(runner):
    res = runner.run(["py", "-c", "print('hello')"], _limits())
    assert res.outcome is ProcessOutcome.EXITED
    assert res.ok
    assert res.exit_code == 0
    assert res.stdout.strip() == b"hello"
    assert res.stderr == b""
    assert not res.stdout_truncated and not res.stderr_truncated
    assert res.duration_seconds >= 0
    assert res.cleanup_error == ""


def test_nonzero_exit_and_stderr_captured(runner):
    code = "import sys; sys.stderr.write('bad'); sys.exit(3)"
    res = runner.run(["py", "-c", code], _limits())
    assert res.outcome is ProcessOutcome.EXITED
    assert res.exit_code == 3
    assert res.stderr == b"bad"


def test_stdin_is_closed(runner):
    code = "import sys; print(repr(sys.stdin.read()))"
    res = runner.run(["py", "-c", code], _limits())
    assert res.stdout.strip() == b"''"


def test_runs_in_fresh_temp_dir_that_is_removed(runner):
    code = "import os; print(os.getcwd()); open('scratch.txt','w').write('x')"
    res = runner.run(["py", "-c", code], _limits())
    workdir = res.stdout.decode().strip()
    assert "avra-run-" in workdir
    import os

    assert not os.path.exists(workdir)


def test_output_exactly_at_limit_is_not_truncated(runner):
    code = "import sys; sys.stdout.write('a' * 1000)"
    res = runner.run(["py", "-c", code], _limits(max_stdout_bytes=1000))
    assert res.ok
    assert len(res.stdout) == 1000
    assert not res.stdout_truncated


@pytest.mark.parametrize(
    "kw",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": 601},
        {"timeout_seconds": 5, "max_stdout_bytes": 0},
        {"timeout_seconds": 5, "max_stderr_bytes": -1},
        {"timeout_seconds": 5, "kill_grace_seconds": 0},
    ],
)
def test_invalid_limits_rejected(kw):
    with pytest.raises(ValueError):
        ExecutionLimits(**kw)
