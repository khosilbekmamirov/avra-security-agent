"""Runner scope enforcement — default-deny, fail-closed, and denied
requests never reach an executor (ADR 0003, M2.2a)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from avra.runner.policy import (
    SCOPE_FILE_ENV,
    Authorized,
    Denied,
    RunnerPolicy,
    RunnerScopeError,
)
from avra.runner.registry import ToolSpec
from avra.schemas.scope import Scope

BASE_TARGET = """\
  - host: "{host}"
    ports: {ports}
    allowed_tiers: {tiers}
    allowed_tools: {tools}
"""


def _scope_text(
    host="10.66.7.103",
    ports="[3000]",
    tiers='["active-safe"]',
    tools='["nmap_connect_scan"]',
    expires="2099-01-01T00:00:00Z",
):
    return (
        f'session_name: "t"\nexpires_at: "{expires}"\ntargets:\n'
        + BASE_TARGET.format(host=host, ports=ports, tiers=tiers, tools=tools)
    )


def _policy(tmp_path, **kw):
    path = tmp_path / "s.yaml"
    path.write_text(_scope_text(**kw), encoding="utf-8")
    return RunnerPolicy.from_scope_file(path)


def _payload(**overrides):
    data = {
        "tool": "nmap_connect_scan",
        "request_id": str(uuid.uuid4()),
        "session_id": str(uuid.uuid4()),
        "host": "10.66.7.103",
        "ports": [3000],
    }
    data.update(overrides)
    return data


@pytest.fixture
def executor_calls(monkeypatch):
    """Record every attempt to build a command (i.e. reach an executor)."""
    calls = []
    original = ToolSpec.build_command

    def spy(self, request):
        calls.append(request)
        return original(self, request)

    monkeypatch.setattr(ToolSpec, "build_command", spy)
    return calls


# --- Fail closed: the Runner's own scope configuration -------------------


@pytest.mark.parametrize("env", [{}, {SCOPE_FILE_ENV: ""}, {SCOPE_FILE_ENV: "  "}])
def test_no_configured_scope_fails_closed(env):
    with pytest.raises(RunnerScopeError):
        RunnerPolicy.from_env(env)


def test_missing_scope_file_fails_closed(tmp_path):
    with pytest.raises(RunnerScopeError):
        RunnerPolicy.from_scope_file(tmp_path / "nope.yaml")


def test_invalid_yaml_fails_closed(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("targets: [unclosed", encoding="utf-8")
    with pytest.raises(RunnerScopeError):
        RunnerPolicy.from_scope_file(path)


def test_expired_scope_file_fails_closed(tmp_path):
    with pytest.raises(RunnerScopeError):
        _policy(tmp_path, expires="2000-01-01T00:00:00Z")


@pytest.mark.parametrize(
    "kw",
    [
        {"ports": "[]"},  # ScopeChecker would read this as "any port"
        {"tools": "[]"},  # ...and this as "any tool"
        {"host": "juice-shop.local"},
        {"host": "192.168.56.0/24"},
        {"host": "0.0.0.0"},
        {"tiers": '["destructive"]'},
    ],
)
def test_unacceptable_runner_scope_rejected(tmp_path, kw):
    with pytest.raises(RunnerScopeError):
        _policy(tmp_path, **kw)


# --- Default-deny: requests vs. the Runner's scope ----------------------


@pytest.mark.parametrize(
    "scope_kw,payload_kw",
    [
        ({}, {"host": "192.168.56.104"}),  # different host
        ({}, {"host": "172.31.99.135"}),  # another address of the same VM (synthetic)
        ({}, {"ports": [22]}),  # port not in scope
        ({}, {"ports": [3000, 22]}),  # one bad port denies the whole request
        ({"tools": '["http_probe"]'}, {}),  # tool not allowed for target
        ({"tiers": '["passive"]'}, {}),  # active-safe tier not allowed
    ],
)
def test_out_of_scope_denied_and_executor_not_called(
    tmp_path, executor_calls, scope_kw, payload_kw
):
    result = _policy(tmp_path, **scope_kw).authorize_request(_payload(**payload_kw))
    assert isinstance(result, Denied)
    assert result.stage == "scope"
    assert executor_calls == []


@pytest.mark.parametrize(
    "payload,stage",
    [
        (_payload(tool="bash"), "unknown_tool"),
        ({"ports": [3000]}, "unknown_tool"),
        ("nmap -A 10.66.7.103", "unknown_tool"),
        (_payload(host="10.66.7.103;id"), "invalid_request"),
        (_payload(ports=["3000"]), "invalid_request"),
        # The requester can't widen authorization by sending its own scope
        # or tier — rejected before the scope check even runs.
        (_payload(scope={"targets": [{"host": "192.168.56.1"}]}), "invalid_request"),
        (_payload(tier="passive"), "invalid_request"),
    ],
)
def test_bad_requests_denied_and_executor_not_called(
    tmp_path, executor_calls, payload, stage
):
    result = _policy(tmp_path).authorize_request(payload)
    assert isinstance(result, Denied)
    assert result.stage == stage
    assert executor_calls == []


def test_scope_expiring_after_load_denies(executor_calls):
    scope = Scope.model_validate(
        {
            "session_name": "t",
            "expires_at": datetime.now(UTC) - timedelta(seconds=1),
            "targets": [
                {
                    "host": "10.66.7.103",
                    "ports": [3000],
                    "allowed_tiers": ["active-safe"],
                    "allowed_tools": ["nmap_connect_scan"],
                }
            ],
        }
    )
    result = RunnerPolicy(scope).authorize_request(_payload())
    assert isinstance(result, Denied)
    assert "expired" in result.reason
    assert executor_calls == []


def test_allowed_request_reaches_executor_exactly_once(tmp_path, executor_calls):
    result = _policy(tmp_path).authorize_request(_payload())
    assert isinstance(result, Authorized)
    assert len(executor_calls) == 1


def test_deny_reason_is_bounded(tmp_path):
    result = _policy(tmp_path).authorize_request(_payload(host="x" * 10_000))
    assert isinstance(result, Denied)
    assert len(result.reason) <= 600
