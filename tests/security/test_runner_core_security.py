"""Runner core — fail-closed behaviour, denied requests never execute,
audit hygiene (ADR 0003, M2.2b Part 2). Fake executor only."""

from __future__ import annotations

import uuid

import pytest

from avra.runner.core import Runner
from avra.runner.policy import RunnerPolicy
from avra.runner.schemas import (
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.storage.audit import AuditLog
from tests.unit.test_runner_core import SCOPE_YAML, FakeExecutor, payload, proc_result


@pytest.fixture
def policy(tmp_path):
    path = tmp_path / "runner.scope.yaml"
    path.write_text(SCOPE_YAML, encoding="utf-8")
    return RunnerPolicy.from_scope_file(path)


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "runner-audit.jsonl"


class FailingAudit:
    """Real AuditLog that raises on chosen events."""

    def __init__(self, path, fail_on):
        self._log = AuditLog(path)
        self._fail_on = set(fail_on)

    def record(self, event, data=None):
        if event in self._fail_on:
            raise OSError("disk full")
        return self._log.record(event, data)

    def read_all(self):
        return self._log.read_all()


# --- Denied / invalid requests never reach execution --------------------


@pytest.mark.parametrize(
    "p,stage",
    [
        (payload(host="192.168.56.104"), RejectionStage.SCOPE),
        (payload(ports=[22]), RejectionStage.SCOPE),
        (payload(tool="bash"), RejectionStage.UNKNOWN_TOOL),
        ({"ports": [3000]}, RejectionStage.UNKNOWN_TOOL),
        ("nmap -A 10.66.7.103", RejectionStage.UNKNOWN_TOOL),
        (None, RejectionStage.UNKNOWN_TOOL),
        (payload(host="10.66.7.103; rm -rf /"), RejectionStage.INVALID_REQUEST),
        (payload(executable="/bin/sh"), RejectionStage.INVALID_REQUEST),
        (payload(command="nmap -A 10.66.7.103"), RejectionStage.INVALID_REQUEST),
        (payload(args=["-sS", "-O"]), RejectionStage.INVALID_REQUEST),
        (
            payload(scope={"targets": [{"host": "192.168.56.1", "ports": [22]}]}),
            RejectionStage.INVALID_REQUEST,
        ),
        (payload(tier="passive"), RejectionStage.INVALID_REQUEST),
    ],
)
def test_rejected_requests_never_execute(policy, audit_path, p, stage):
    ex = FakeExecutor()
    audit = AuditLog(audit_path)
    res = Runner(policy, ex, audit).handle(p)
    assert isinstance(res, RunnerRejection)
    assert res.stage is stage
    assert ex.calls == []
    assert [r.event for r in audit.read_all()] == ["request_received", "request_denied"]
    assert audit.verify()


# --- Fail closed on audit failure ---------------------------------------


@pytest.mark.parametrize("event", ["request_received", "execution_started"])
def test_pre_execution_audit_failure_blocks_execution(policy, audit_path, event):
    ex = FakeExecutor()
    res = Runner(policy, ex, FailingAudit(audit_path, {event})).handle(payload())
    assert isinstance(res, RunnerRejection)
    assert res.stage is RejectionStage.AUDIT_UNAVAILABLE
    assert ex.calls == []


def test_post_execution_audit_failure_withholds_result(policy, audit_path):
    ex = FakeExecutor()
    res = Runner(policy, ex, FailingAudit(audit_path, {"execution_finished"})).handle(
        payload()
    )
    assert isinstance(res, ToolRunResult)
    assert res.status is ToolRunStatus.FAILED
    assert res.raw_output is None
    assert "withheld" in res.reason


# --- Safe exception handling --------------------------------------------


def test_executor_exception_becomes_failed_result(policy, audit_path):
    audit = AuditLog(audit_path)
    res = Runner(policy, FakeExecutor(exc=RuntimeError("boom")), audit).handle(payload())
    assert isinstance(res, ToolRunResult)
    assert res.status is ToolRunStatus.FAILED
    assert [r.event for r in audit.read_all()][-1] == "execution_finished"


def test_policy_exception_fails_closed(policy, audit_path, monkeypatch):
    ex = FakeExecutor()

    def broken(_payload):
        raise RuntimeError("policy bug")

    monkeypatch.setattr(policy, "authorize_request", broken)
    res = Runner(policy, ex, AuditLog(audit_path)).handle(payload())
    assert isinstance(res, RunnerRejection)
    assert res.stage is RejectionStage.INTERNAL_ERROR
    assert ex.calls == []


def test_runner_refuses_executor_without_trusted_paths(policy, audit_path):
    ex = FakeExecutor()
    ex.executables = {}
    with pytest.raises(ValueError):
        Runner(policy, ex, AuditLog(audit_path))


# --- Audit hygiene: no raw output, no requester-supplied junk -----------


def test_audit_has_no_raw_output(policy, audit_path):
    marker = b"RAW-TOOL-OUTPUT-MARKER-7f3a"
    ex = FakeExecutor(result=proc_result(stdout=b"<x>" + marker, stderr=marker))
    res = Runner(policy, ex, AuditLog(audit_path)).handle(payload())
    assert marker.decode() in res.raw_output  # caller gets it...
    assert marker.decode() not in audit_path.read_text(encoding="utf-8")  # ...log doesn't


@pytest.mark.parametrize(
    "p",
    [
        payload(api_token="SECRET-abc123-should-not-be-logged"),
        payload(tool="SECRET-abc123-should-not-be-logged"),
        {"tool": "nmap_connect_scan", "note": "SECRET-abc123-should-not-be-logged"},
    ],
)
def test_audit_does_not_echo_request_content(policy, audit_path, p):
    Runner(policy, FakeExecutor(), AuditLog(audit_path)).handle(p)
    assert "SECRET-abc123" not in audit_path.read_text(encoding="utf-8")


def test_request_id_preserved_on_rejection(policy, audit_path):
    rid = str(uuid.uuid4())
    res = Runner(policy, FakeExecutor(), AuditLog(audit_path)).handle(
        payload(request_id=rid, ports=[22])
    )
    assert isinstance(res, RunnerRejection)
    assert str(res.request_id) == rid
