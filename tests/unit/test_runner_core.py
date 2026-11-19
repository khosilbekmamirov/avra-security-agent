"""Runner core — allowed paths with a fake executor (ADR 0003, M2.2b
Part 2). No process is started, nothing touches the network."""

from __future__ import annotations

import hashlib
import uuid

import pytest

from avra.runner.core import PROCESS_TIMEOUT_GRACE_SECONDS, Runner
from avra.runner.execution import ProcessOutcome, ProcessResult
from avra.runner.policy import RunnerPolicy
from avra.runner.schemas import ToolRunResult, ToolRunStatus
from avra.storage.audit import AuditLog

SCOPE_YAML = """\
session_name: "core-test"
expires_at: "2099-01-01T00:00:00Z"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["active-safe"]
    allowed_tools: ["nmap_connect_scan"]
"""


class FakeExecutor:
    def __init__(self, result=None, exc=None):
        self.executables = {"nmap": "/usr/bin/nmap",
                            "http_probe": "/opt/avra-runner/venv/bin/avra-http-probe"}
        self.calls = []
        self._result = result
        self._exc = exc

    def run(self, argv, limits, cancel=None):
        self.calls.append((tuple(argv), limits))
        if self._exc:
            raise self._exc
        return self._result or proc_result()


def proc_result(outcome=ProcessOutcome.EXITED, exit_code=0, stdout=b"<nmaprun/>", **kw):
    return ProcessResult(
        outcome=outcome,
        exit_code=exit_code,
        stdout=stdout,
        stderr=kw.get("stderr", b""),
        stdout_truncated=kw.get("stdout_truncated", False),
        stderr_truncated=False,
        duration_seconds=0.5,
        error=kw.get("error", ""),
    )


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "runner.scope.yaml"
    path.write_text(SCOPE_YAML, encoding="utf-8")
    return RunnerPolicy.from_scope_file(path)


@pytest.fixture
def audit(tmp_path):
    return AuditLog(tmp_path / "runner-audit.jsonl")


def payload(**overrides):
    data = {
        "tool": "nmap_connect_scan",
        "request_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "host": "10.66.7.103",
        "ports": [3000],
        "timeout_seconds": 30,
    }
    data.update(overrides)
    return data


def test_authorized_request_runs_once_and_completes(policy, audit):
    ex = FakeExecutor()
    p = payload()
    res = Runner(policy, ex, audit).handle(p)

    assert isinstance(res, ToolRunResult)
    assert res.status is ToolRunStatus.COMPLETED
    assert str(res.request_id) == p["request_id"]
    assert res.exit_code == 0
    assert res.raw_output == "<nmaprun/>"
    assert res.output_sha256 == hashlib.sha256(b"<nmaprun/>").hexdigest()

    assert len(ex.calls) == 1
    argv, limits = ex.calls[0]
    assert argv[0] == "nmap" and argv[-1] == "10.66.7.103"
    assert limits.timeout_seconds == 30 + PROCESS_TIMEOUT_GRACE_SECONDS
    assert limits.max_stdout_bytes == 1_000_000
    assert limits.max_stderr_bytes == 64_000


def test_audit_trail_for_completed_run(policy, audit):
    Runner(policy, FakeExecutor(), audit).handle(payload())
    events = [r.event for r in audit.read_all()]
    assert events == ["request_received", "execution_started", "execution_finished"]
    assert audit.verify()
    finished = audit.read_all()[-1].data
    assert finished["status"] == "completed"
    assert finished["stdout_sha256"] == hashlib.sha256(b"<nmaprun/>").hexdigest()


@pytest.mark.parametrize(
    "proc,status",
    [
        (proc_result(exit_code=1), ToolRunStatus.COMPLETED),
        (proc_result(ProcessOutcome.TIMED_OUT, exit_code=-9), ToolRunStatus.TIMED_OUT),
        (
            proc_result(ProcessOutcome.OUTPUT_LIMIT, exit_code=-9, stdout_truncated=True),
            ToolRunStatus.FAILED,
        ),
        (
            proc_result(ProcessOutcome.START_FAILED, exit_code=None, stdout=b"",
                        error="OSError: no such file"),
            ToolRunStatus.FAILED,
        ),
    ],
)
def test_process_outcomes_map_to_statuses(policy, audit, proc, status):
    res = Runner(policy, FakeExecutor(result=proc), audit).handle(payload())
    assert isinstance(res, ToolRunResult)
    assert res.status is status
    assert [r.event for r in audit.read_all()][-1] == "execution_finished"


def test_non_utf8_output_is_handled(policy, audit):
    res = Runner(policy, FakeExecutor(result=proc_result(stdout=b"\xff\xfe<x>")), audit).handle(
        payload()
    )
    assert res.status is ToolRunStatus.COMPLETED
    assert res.output_sha256 == hashlib.sha256(b"\xff\xfe<x>").hexdigest()
