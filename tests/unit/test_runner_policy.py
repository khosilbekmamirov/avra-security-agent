"""Runner scope enforcement — allowed paths (ADR 0003, M2.2a)."""

from __future__ import annotations

import uuid

from avra.runner.policy import SCOPE_FILE_ENV, Authorized, RunnerPolicy

SCOPE_YAML = """\
session_name: "runner-test"
expires_at: "2099-01-01T00:00:00Z"
targets:
  - host: "10.66.7.103"
    ports: [22, 3000]
    allowed_tiers: ["passive", "active-safe"]
    allowed_tools: ["nmap_connect_scan"]
"""


def _scope_file(tmp_path, text=SCOPE_YAML):
    path = tmp_path / "runner.scope.yaml"
    path.write_text(text, encoding="utf-8")
    return path


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


def test_in_scope_request_authorized_with_command(tmp_path):
    policy = RunnerPolicy.from_scope_file(_scope_file(tmp_path))
    result = policy.authorize_request(_payload())
    assert isinstance(result, Authorized)
    assert result.command.argv[0] == "nmap"
    assert result.command.argv[-1] == "10.66.7.103"


def test_all_ports_in_scope_authorized(tmp_path):
    policy = RunnerPolicy.from_scope_file(_scope_file(tmp_path))
    assert isinstance(policy.authorize_request(_payload(ports=[22, 3000])), Authorized)


def test_from_env_loads_runner_scope(tmp_path):
    path = _scope_file(tmp_path)
    policy = RunnerPolicy.from_env({SCOPE_FILE_ENV: str(path)})
    assert isinstance(policy.authorize_request(_payload()), Authorized)
