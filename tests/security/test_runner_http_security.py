"""Runner HTTP layer — authentication, size limits, error hygiene,
audit integration (ADR 0003, M3.2). In-process TestClient only."""

from __future__ import annotations

import asyncio
import json

import pytest
from starlette.requests import Request

import avra.runner.http_app as http_app
from avra.runner.http_app import MAX_BODY_BYTES, default_health_checks
from tests.security.test_runner_core_security import FailingAudit
from tests.unit.test_runner_core import payload
from tests.unit.test_runner_http import AUTH, TOKEN, Env


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# --- Authentication: every path, before anything else -------------------


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/v1/health"),
        ("POST", "/v1/tools/run"),
        ("GET", "/v1/tools/run"),
        ("GET", "/"),
        ("GET", "/docs"),
        ("GET", "/openapi.json"),
        ("DELETE", "/v1/health"),
    ],
)
def test_no_token_is_401_everywhere(env, method, path):
    r = env.client.request(method, path, json=payload())
    assert r.status_code == 401
    assert r.json() == {"error": "unauthorized"}
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.headers["connection"] == "close"
    assert env.executor.calls == []


@pytest.mark.parametrize(
    "value",
    [
        f"Bearer {TOKEN}x",
        f"Bearer {TOKEN[:-1]}",
        "Bearer ",
        "Bearer",
        f"Basic {TOKEN}",
        f"Token {TOKEN}",
        f"Bearer  {TOKEN}",  # two spaces
        f"Bearer {TOKEN} extra",
        f"{TOKEN}",
        "Bearer " + "A" * 600,  # oversized token (header still under the cap)
    ],
)
def test_bad_credentials_rejected(env, value):
    r = env.client.post("/v1/tools/run", json=payload(), headers={"Authorization": value})
    assert r.status_code == 401
    assert env.executor.calls == []


def test_non_ascii_authorization_rejected(env):
    r = env.client.get(
        "/v1/health", headers=[(b"authorization", "Bearer ü".encode("latin-1"))]
    )
    assert r.status_code == 401


def test_duplicate_authorization_headers_rejected(env):
    r = env.client.get(
        "/v1/health",
        headers=[("Authorization", f"Bearer {TOKEN}"), ("Authorization", f"Bearer {TOKEN}")],
    )
    assert r.status_code == 401


def test_oversized_headers_431_before_auth(env, monkeypatch):
    from avra.runner.config import BearerToken

    compared = []
    monkeypatch.setattr(BearerToken, "matches", lambda self, c: compared.append(c) or True)
    r = env.client.get("/v1/health", headers={**AUTH, "X-Big": "a" * 20_000})
    assert r.status_code == 431
    r = env.client.post(
        "/v1/tools/run", json=payload(), headers={"Authorization": "Bearer " + "A" * 100_000}
    )
    assert r.status_code == 431
    assert compared == []
    assert env.executor.calls == []


def test_token_in_query_string_not_accepted(env):
    r = env.client.get(f"/v1/health?token={TOKEN}&access_token={TOKEN}")
    assert r.status_code == 401


def test_oversized_auth_header_never_reaches_token_compare(env, monkeypatch):
    from avra.runner.config import BearerToken

    compared = []
    monkeypatch.setattr(BearerToken, "matches", lambda self, c: compared.append(c) or False)
    r = env.client.get("/v1/health", headers={"Authorization": "Bearer " + "A" * 5000})
    assert r.status_code == 401
    assert compared == []


def test_auth_failures_are_audited_but_throttled(env):
    for _ in range(5):
        env.client.get("/v1/health")
    env.clock[0] = 11.0
    env.client.get("/v1/health")
    rejected = [d for e, d in env.events() if e == "http_rejected"]
    assert len(rejected) == 2
    assert rejected[0]["reason"] == "auth_failed"
    assert rejected[1]["suppressed_since_last"] == 4


def test_audit_never_contains_token_or_bad_credentials(env):
    env.client.get("/v1/health", headers={"Authorization": "Bearer WRONG-SECRET-123"})
    env.client.post("/v1/tools/run", json=payload(ports=[22]), headers=AUTH)
    text = env.audit_path.read_text(encoding="utf-8")
    assert TOKEN not in text and "WRONG-SECRET-123" not in text


# --- Request bounds -----------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Type": "text/plain"},
        {"Content-Type": "application/x-www-form-urlencoded"},
        {"Content-Type": "application/jsonx"},
        {},
    ],
)
def test_non_json_content_type_415(env, headers):
    r = env.client.post(
        "/v1/tools/run", content=json.dumps(payload()), headers={**AUTH, **headers}
    )
    assert r.status_code == 415
    assert env.executor.calls == []


def test_oversized_content_length_413(env):
    big = json.dumps(payload(pad="x" * (MAX_BODY_BYTES + 10)))
    r = env.client.post(
        "/v1/tools/run", content=big, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert r.status_code == 413
    assert r.headers["connection"] == "close"
    assert env.executor.calls == []


@pytest.mark.parametrize("value", ["9" * 5000, "9" * 30, "0" * 40 + "99999"])
def test_huge_or_padded_content_length_is_413_not_500(env, value):
    # audit 2026-11-10: > 4300 digits made int() raise -> generic 500
    r = env.client.post("/v1/tools/run", content=b"{}",
                        headers={**AUTH, "Content-Type": "application/json",
                                 "Content-Length": value})
    assert r.status_code == 413 and r.json() == {"error": "too_large"}
    assert env.executor.calls == []


def test_leading_zeros_do_not_change_a_small_length(env):
    body = json.dumps(payload()).encode()
    r = env.client.post("/v1/tools/run", content=body,
                        headers={**AUTH, "Content-Type": "application/json",
                                 "Content-Length": "000" + str(len(body))})
    assert r.status_code != 413


def test_oversized_chunked_body_413(env):
    def gen():
        yield b'{"tool": "nmap_connect_scan", "pad": "'
        for _ in range(40):
            yield b"x" * 1024
        yield b'"}'

    r = env.client.post(
        "/v1/tools/run", content=gen(), headers={**AUTH, "Content-Type": "application/json"}
    )
    assert r.status_code == 413
    assert env.executor.calls == []


@pytest.mark.parametrize("value", ["abc", "-1", "1e3", "１０"])
def test_bad_content_length_400(env, value):
    async def run():
        sent = []
        scope = {
            "type": "http", "method": "POST", "path": "/v1/tools/run",
            "headers": [
                (b"authorization", f"Bearer {TOKEN}".encode()),
                (b"content-type", b"application/json"),
                (b"content-length", value.encode()),
            ],
            "query_string": b"", "client": ("127.0.0.1", 1), "server": ("x", 1),
            "scheme": "http", "root_path": "", "http_version": "1.1",
        }

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(msg):
            sent.append(msg)

        await env.app(scope, receive, send)
        return sent[0]["status"]

    assert asyncio.run(run()) == 400


def test_slow_body_times_out(monkeypatch):
    monkeypatch.setattr(http_app, "BODY_READ_TIMEOUT_SECONDS", 0.2)

    async def run():
        async def receive():
            await asyncio.sleep(5)
            return {"type": "http.request", "body": b"{}", "more_body": False}

        scope = {"type": "http", "method": "POST", "headers": [], "path": "/"}
        with pytest.raises(http_app._BodyError) as info:
            await http_app._read_bounded_body(Request(scope, receive))
        return info.value

    err = asyncio.run(run())
    assert err.status == 408 and err.close


@pytest.mark.parametrize(
    "body",
    [b"{not json", b"", b"\xff\xfe", b'{"a": NaN'],
)
def test_malformed_json_400(env, body):
    r = env.client.post(
        "/v1/tools/run", content=body, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert r.status_code == 400
    assert r.json() == {"error": "malformed_json"}
    assert env.executor.calls == []


def test_deeply_nested_json_is_rejected_400_on_every_python(env):
    """Deep nesting (under the 16 KiB cap, so it reaches the parser).
    Python 3.12's json raises RecursionError -> ``malformed_json``; 3.14
    (stack-based recursion limit, seen on Kali M8.2) parses it, and the
    Runner then rejects the non-object payload as ``unknown_tool``. Only
    these two exact rejections are acceptable; nothing may run."""
    body = b"[" * 8000 + b"]" * 8000
    r = env.client.post(
        "/v1/tools/run", content=body, headers={**AUTH, "Content-Type": "application/json"}
    )
    assert r.status_code == 400
    assert r.json() in (
        {"error": "malformed_json"},
        {"stage": "unknown_tool", "reason": "unknown or missing tool name",
         "request_id": None},
    )
    assert env.executor.calls == []


# --- Runner outcomes map to safe status codes ---------------------------


@pytest.mark.parametrize(
    "p,status,stage",
    [
        (payload(ports=[22]), 403, "scope"),
        (payload(tool="bash"), 400, "unknown_tool"),
        (payload(executable="/bin/sh"), 400, "invalid_request"),
        (payload(scope={"targets": []}), 400, "invalid_request"),
        ("nmap -A 10.66.7.103", 400, "unknown_tool"),
        ([1, 2, 3], 400, "unknown_tool"),
    ],
)
def test_rejections_map_to_status(env, p, status, stage):
    r = env.client.post("/v1/tools/run", json=p, headers=AUTH)
    assert r.status_code == status
    assert r.json()["stage"] == stage
    assert env.executor.calls == []


def test_unavailable_audit_storage_503(tmp_path):
    env = Env(tmp_path, audit=FailingAudit(tmp_path / "audit.jsonl", {"request_received"}))
    r = env.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    assert r.status_code == 503
    assert r.json()["stage"] == "audit_unavailable"
    assert env.executor.calls == []


def test_busy_runner_429_without_running(env):
    env.runner._lock.acquire()
    try:
        r = env.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    finally:
        env.runner._lock.release()
    assert r.status_code == 429
    assert r.headers["retry-after"] == "5"
    assert env.executor.calls == []
    assert ("http_rejected", {"reason": "busy", "client": "testclient"}) in env.events()


def test_internal_error_is_generic(env, monkeypatch):
    def boom(_payload):
        raise RuntimeError(r"secret path C:\internal\runner.py token=abc")

    monkeypatch.setattr(env.runner, "try_handle", boom)
    r = env.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    assert r.status_code == 500
    assert r.json() == {"error": "internal_error"}
    assert "internal" not in r.text.replace("internal_error", "")
    assert "Traceback" not in r.text


def test_unknown_path_and_method_generic_with_auth(env):
    r = env.client.get("/v1/nope", headers=AUTH)
    assert (r.status_code, r.json()) == (404, {"error": "not_found"})
    r = env.client.get("/v1/tools/run", headers=AUTH)
    assert (r.status_code, r.json()) == (405, {"error": "method_not_allowed"})


def test_no_server_banner_or_debug_info(env):
    r = env.client.get("/v1/nope", headers=AUTH)
    assert "server" not in r.headers
    assert "starlette" not in r.text.lower()


# --- Health -------------------------------------------------------------


def test_health_unavailable_reports_booleans_only(tmp_path):
    env = Env(tmp_path, health=lambda: {"scope": False, "audit": True, "executables": True})
    r = env.client.get("/v1/health", headers=AUTH)
    assert r.status_code == 503
    assert r.json() == {
        "status": "unavailable",
        "checks": {"scope": False, "audit": True, "executables": True},
    }


def test_health_check_exception_is_503_not_500(tmp_path):
    def broken():
        raise OSError(r"C:\secret\path")

    env = Env(tmp_path, health=broken)
    r = env.client.get("/v1/health", headers=AUTH)
    assert r.status_code == 503
    assert "secret" not in r.text


def test_default_health_checks(tmp_path):
    env = Env(tmp_path)
    import sys

    checks = default_health_checks(
        env.runner._policy, env.audit_path, {"py": sys.executable}
    )()
    assert checks == {"scope": True, "audit": True, "executables": True}
    bad = default_health_checks(
        env.runner._policy, tmp_path / "missing-dir" / "a.jsonl", {"nmap": str(tmp_path / "x"), "http_probe": str(tmp_path / "y")}
    )()
    assert bad["audit"] is False and bad["executables"] is False
