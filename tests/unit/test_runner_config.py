"""RunnerConfig — valid configuration (ADR 0003, M3.1)."""

from __future__ import annotations

import os
import sys

import pytest

from avra.runner.config import DEFAULT_PORT, RunnerConfig, load_runner_config

PYTHON = os.path.realpath(getattr(sys, "_base_executable", sys.executable) or sys.executable)
TOKEN = "A" * 20 + "b9-_x" * 4  # 40 printable chars, no whitespace

SCOPE_YAML = """\
session_name: "cfg-test"
expires_at: "2099-01-01T00:00:00Z"
targets:
  - host: "10.66.7.103"
    ports: [3000]
    allowed_tiers: ["active-safe"]
    allowed_tools: ["nmap_connect_scan"]
"""


def make_env(tmp_path, **overrides):
    """A complete, valid Runner environment under tmp_path."""
    scope = tmp_path / "runner.scope.yaml"
    scope.write_text(SCOPE_YAML, encoding="utf-8")
    token = tmp_path / "runner.token"
    token.write_text(TOKEN + "\n", encoding="ascii")
    os.chmod(token, 0o600)
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(mode=0o700, exist_ok=True)
    env = {
        "AVRA_RUNNER_SCOPE_FILE": str(scope),
        "AVRA_RUNNER_TOKEN_FILE": str(token),
        "AVRA_RUNNER_AUDIT_LOG": str(audit_dir / "runner-audit.jsonl"),
        "AVRA_RUNNER_BIND_HOST": "192.168.56.104",
        "AVRA_RUNNER_EXEC_NMAP": PYTHON,  # stand-in binary; never executed here
        "AVRA_RUNNER_EXEC_HTTP_PROBE": PYTHON,  # stand-in (ADR 0007); never executed
    }
    env.update({k: v for k, v in overrides.items() if v is not None})
    for k, v in overrides.items():
        if v is None:
            env.pop(k, None)
    return env


@pytest.mark.skipif(
    os.name == "posix" and os.access(os.path.dirname(PYTHON), os.W_OK),
    reason="interpreter dir is writable by this user; config would rightly refuse it",
)
def test_valid_config_loads(tmp_path):
    cfg = load_runner_config(make_env(tmp_path))
    assert isinstance(cfg, RunnerConfig)
    assert cfg.bind_host == "192.168.56.104"
    assert cfg.port == DEFAULT_PORT
    assert cfg.executables["nmap"] == PYTHON
    assert cfg.token.matches(TOKEN)
    assert not cfg.token.matches(TOKEN + "x")
    assert not cfg.token.matches("")


@pytest.mark.skipif(
    os.name == "posix" and os.access(os.path.dirname(PYTHON), os.W_OK),
    reason="interpreter dir is writable by this user",
)
def test_explicit_port_and_loopback_bind(tmp_path):
    cfg = load_runner_config(
        make_env(tmp_path, AVRA_RUNNER_PORT="9000", AVRA_RUNNER_BIND_HOST="127.0.0.1")
    )
    assert cfg.port == 9000
    assert cfg.bind_host == "127.0.0.1"
