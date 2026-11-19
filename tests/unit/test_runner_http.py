"""Runner HTTP layer — authenticated happy paths (ADR 0003, M3.2).
In-process Starlette TestClient only: no server, no port, no network."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from avra.runner.config import BearerToken
from avra.runner.core import Runner
from avra.runner.http_app import create_app
from avra.runner.policy import RunnerPolicy
from avra.storage.audit import AuditLog
from tests.unit.test_runner_core import SCOPE_YAML, FakeExecutor, payload

TOKEN = "T" * 24 + "-runner-test-token-0123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


class Env:
    def __init__(self, tmp_path, audit=None, health=None, executor=None):
        scope = tmp_path / "scope.yaml"
        scope.write_text(SCOPE_YAML, encoding="utf-8")
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = audit or AuditLog(self.audit_path)
        self.executor = executor or FakeExecutor()
        self.runner = Runner(RunnerPolicy.from_scope_file(scope), self.executor, self.audit)
        self.health = health or (lambda: {"scope": True, "audit": True, "executables": True})
        self.clock = [0.0]
        self.app = create_app(
            runner=self.runner,
            token=BearerToken(TOKEN),
            audit=self.audit,
            health_checks=lambda: self.health(),
            clock=lambda: self.clock[0],
        )
        self.client = TestClient(self.app, raise_server_exceptions=False)

    def events(self):
        return [(r.event, r.data) for r in AuditLog(self.audit_path).read_all()]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_health_ok(env):
    r = env.client.get("/v1/health", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "tools": ["nmap_connect_scan", "http_probe",
                                                   "http_get_path"]}  # M10.5
    assert r.headers["cache-control"] == "no-store"


def test_run_authorized_request(env):
    r = env.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["raw_output"] == "<nmaprun/>"
    assert len(env.executor.calls) == 1


def test_lowercase_bearer_scheme_accepted(env):
    r = env.client.get("/v1/health", headers={"Authorization": f"bearer {TOKEN}"})
    assert r.status_code == 200


def test_json_content_type_with_charset_accepted(env):
    import json

    r = env.client.post(
        "/v1/tools/run",
        content=json.dumps(payload()),
        headers={**AUTH, "Content-Type": "application/json; charset=utf-8"},
    )
    assert r.status_code == 200
