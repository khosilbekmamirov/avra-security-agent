"""Runner server — startup, shutdown, real HTTP behaviour on loopback
(ADR 0003, M3.3).

These tests start the real uvicorn server bound to 127.0.0.1 on a free
ephemeral port, in a background thread, and talk to it over loopback
only. No request here is authorized to run a tool, so no process is
ever spawned; nothing leaves the machine.
"""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest

from avra.runner.audit_owner import AuditOwnerLock
from avra.runner.config import load_runner_config
from avra.runner.server import (
    EXIT_AUDIT_OWNED,
    EXIT_CONFIG,
    EXIT_OK,
    EXIT_START_FAILED,
    UVICORN_SETTINGS,
    RunnerServer,
    main,
)
from avra.storage.audit import AuditLog
from tests.unit.test_runner_config import TOKEN, make_env

LOOPBACK = "127.0.0.1"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind((LOOPBACK, 0))
        return s.getsockname()[1]


class Running:
    def __init__(self, env):
        self.env = env
        self.cfg = load_runner_config(env)
        self.server = RunnerServer(self.cfg, log_level="warning")
        self.exit_code = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        self.exit_code = self.server.run()

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if not self.thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError(f"server did not start (exit={self.exit_code})")
            time.sleep(0.05)
        self.base = f"http://{LOOPBACK}:{self.cfg.port}"
        return self

    def __exit__(self, *exc):
        self.server.stop()
        self.thread.join(timeout=20)
        assert not self.thread.is_alive(), "server did not shut down"

    def audit_events(self):
        return [(r.event, r.data) for r in AuditLog(self.cfg.audit_path).read_all()]


@pytest.fixture
def env(tmp_path):
    return make_env(tmp_path, AVRA_RUNNER_BIND_HOST=LOOPBACK, AVRA_RUNNER_PORT=str(_free_port()))


def _raw(port: int, data: bytes, timeout: float = 5.0) -> bytes:
    """Send raw bytes over loopback and return whatever comes back."""
    with socket.create_connection((LOOPBACK, port), timeout=timeout) as s:
        s.sendall(data)
        chunks = []
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except (TimeoutError, ConnectionResetError):
            pass
        return b"".join(chunks)


# --- Settings -----------------------------------------------------------


def test_hardened_uvicorn_settings():
    assert UVICORN_SETTINGS["proxy_headers"] is False
    assert UVICORN_SETTINGS["server_header"] is False
    assert UVICORN_SETTINGS["access_log"] is False
    assert UVICORN_SETTINGS["ws"] == "none"
    assert UVICORN_SETTINGS["h11_max_incomplete_event_size"] == 16384
    assert UVICORN_SETTINGS["limit_concurrency"] == 4


# --- Startup / shutdown lifecycle ---------------------------------------


def test_start_serve_and_clean_shutdown(env):
    with Running(env) as srv:
        r = httpx.get(f"{srv.base}/v1/health", headers=AUTH, timeout=5)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
        # Lock is held while serving.
        with pytest.raises(Exception):
            AuditOwnerLock(srv.cfg.audit_path).acquire()
    assert srv.exit_code == EXIT_OK
    events = [e for e, _ in srv.audit_events()]
    assert events[0] == "runner_started" and events[-1] == "runner_stopped"
    assert AuditLog(srv.cfg.audit_path).verify()
    # Lock released after shutdown.
    with AuditOwnerLock(srv.cfg.audit_path) as lock:
        assert lock.held


def test_second_runner_on_same_audit_log_refuses(env, tmp_path):
    with Running(env) as srv:
        other_env = dict(env, AVRA_RUNNER_PORT=str(_free_port()))
        code = RunnerServer(load_runner_config(other_env), log_level="warning").run()
        assert code == EXIT_AUDIT_OWNED
        # The first one is unaffected.
        assert httpx.get(f"{srv.base}/v1/health", headers=AUTH, timeout=5).status_code == 200


def test_bind_failure_releases_lock(env):
    # Occupy the port first, so binding fails; nothing is sent anywhere.
    port = int(env["AVRA_RUNNER_PORT"])
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    blocker.bind((LOOPBACK, port))
    blocker.listen(1)
    try:
        cfg = load_runner_config(env)
        code = RunnerServer(cfg, log_level="critical").run()
    finally:
        blocker.close()
    assert code == EXIT_START_FAILED
    with AuditOwnerLock(cfg.audit_path) as lock:
        assert lock.held
    events = [r.event for r in AuditLog(cfg.audit_path).read_all()]
    assert events[-1] == "runner_stopped"


def test_tampered_audit_log_refuses_start(env):
    log = AuditLog(env["AVRA_RUNNER_AUDIT_LOG"])
    log.record("a", {"x": 1})
    cfg = load_runner_config(env)
    path = env["AVRA_RUNNER_AUDIT_LOG"]
    text = open(path, encoding="utf-8").read().replace('"x": 1', '"x": 2')
    open(path, "w", encoding="utf-8").write(text)  # tamper after validation
    assert RunnerServer(cfg, log_level="critical").run() == EXIT_START_FAILED


@pytest.mark.parametrize(
    "override",
    [
        {"AVRA_RUNNER_BIND_HOST": "0.0.0.0"},
        {"AVRA_RUNNER_BIND_HOST": None},
        {"AVRA_RUNNER_TOKEN_FILE": None},
        {"AVRA_RUNNER_SCOPE_FILE": None},
    ],
)
def test_main_rejects_bad_config_without_leaking_token(tmp_path, capsys, override):
    env = make_env(tmp_path, AVRA_RUNNER_PORT=str(_free_port()), **override)
    assert main(env) == EXIT_CONFIG
    err = capsys.readouterr().err
    assert "configuration rejected" in err
    assert TOKEN not in err


# --- --check mode -------------------------------------------------------


def test_check_mode_validates_without_binding_or_writing(env, capsys):
    port = int(env["AVRA_RUNNER_PORT"])
    assert main(env, ["--check"]) == EXIT_OK
    out = capsys.readouterr()
    assert "configuration OK" in out.out
    assert TOKEN not in out.out + out.err
    # Nothing written to the audit log, nothing left listening.
    assert AuditLog(env["AVRA_RUNNER_AUDIT_LOG"]).read_all() == []
    with socket.socket() as s:
        s.bind((LOOPBACK, port))


def test_check_mode_reports_running_owner(env):
    with AuditOwnerLock(env["AVRA_RUNNER_AUDIT_LOG"]):
        assert main(env, ["--check"]) == EXIT_AUDIT_OWNED


def test_check_mode_fails_closed_on_bad_config(tmp_path):
    env = make_env(tmp_path, AVRA_RUNNER_BIND_HOST="0.0.0.0")
    assert main(env, ["--check"]) == EXIT_CONFIG


@pytest.mark.parametrize(
    "argv",
    [["--host", "0.0.0.0"], ["--check", "--port", "80"], ["--help"], ["check"], ["--CHECK"]],
)
def test_no_other_command_line_options(env, argv, capsys):
    assert main(env, argv) == EXIT_CONFIG
    assert "usage" in capsys.readouterr().err


# --- Real HTTP behaviour over loopback ----------------------------------


def test_real_http_auth_and_headers(env):
    with Running(env) as srv:
        r = httpx.get(f"{srv.base}/v1/health", timeout=5)
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"
        assert "server" not in r.headers  # no banner
        r = httpx.get(f"{srv.base}/v1/health?token={TOKEN}", timeout=5)
        assert r.status_code == 401


def test_real_http_scope_denial_runs_nothing(env):
    payload = {
        "tool": "nmap_connect_scan",
        "request_id": "00000000-0000-4000-8000-000000000001",
        "session_id": "00000000-0000-4000-8000-000000000002",
        "host": "10.66.7.103",
        "ports": [22],  # not in scope
    }
    with Running(env) as srv:
        r = httpx.post(f"{srv.base}/v1/tools/run", json=payload, headers=AUTH, timeout=5)
        assert r.status_code == 403
        events = [e for e, _ in srv.audit_events()]
    assert "request_denied" in events
    assert "execution_started" not in events


def test_forwarded_headers_are_not_trusted(env):
    with Running(env) as srv:
        httpx.get(
            f"{srv.base}/v1/health",
            headers={"X-Forwarded-For": "6.6.6.6", "Forwarded": "for=6.6.6.6"},
            timeout=5,
        )
        clients = [d.get("client") for e, d in srv.audit_events() if e == "http_rejected"]
    assert clients == [LOOPBACK]


@pytest.mark.parametrize("with_token", [False, True])
def test_oversized_headers_rejected_431(env, with_token):
    # Sent in one burst, so h11's incomplete-event cap does NOT catch it;
    # the app-level cap must.
    with Running(env) as srv:
        auth = f"Authorization: Bearer {TOKEN}\r\n".encode() if with_token else b""
        req = (
            b"GET /v1/health HTTP/1.1\r\nHost: x\r\n" + auth
            + b"X-Big: " + b"a" * 40_000 + b"\r\n\r\n"
        )
        resp = _raw(srv.cfg.port, req)
        reasons = [d["reason"] for e, d in srv.audit_events() if e == "http_rejected"]
    head = resp.split(b"\r\n\r\n", 1)[0].lower()
    assert head.startswith(b"http/1.1 431")
    assert b"connection: close" in head
    assert reasons == ["headers_too_large"]


def test_request_smuggling_cl_te_rejected(env):
    with Running(env) as srv:
        req = (
            b"POST /v1/tools/run HTTP/1.1\r\nHost: x\r\n"
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + b"Content-Type: application/json\r\n"
            b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
        )
        resp = _raw(srv.cfg.port, req)
        events = [e for e, _ in srv.audit_events()]
    assert resp.startswith(b"HTTP/1.1 400")  # rejected by h11 before the app
    assert "request_received" not in events


def test_oversized_body_closed_without_reading(env):
    with Running(env) as srv:
        req = (
            b"POST /v1/tools/run HTTP/1.1\r\nHost: x\r\n"
            + f"Authorization: Bearer {TOKEN}\r\n".encode()
            + b"Content-Type: application/json\r\nContent-Length: 10000000\r\n\r\n"
            + b"{" * 1000
        )
        resp = _raw(srv.cfg.port, req)
    head = resp.split(b"\r\n\r\n", 1)[0].lower()
    assert head.startswith(b"http/1.1 413")
    assert b"connection: close" in head


def test_unauthenticated_body_never_parsed(env):
    with Running(env) as srv:
        r = httpx.post(
            f"{srv.base}/v1/tools/run",
            content=b"{" * 10_000,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        assert r.status_code == 401
        reasons = [d["reason"] for e, d in srv.audit_events() if e == "http_rejected"]
    assert reasons == ["auth_failed"]  # not malformed_json: body was never read


# --- Signal shutdown (M4.5 regression) ------------------------------------
# Live on Kali, `systemctl stop` (SIGTERM) left no `runner_stopped` record:
# uvicorn 0.54 re-raises the captured signal after its graceful shutdown,
# and with the default handler restored that killed the process before
# RunnerServer.run()'s `finally`. Runs in a child process so the old
# behaviour kills only the child, never the test session.

SIGNAL_CHILD = r"""
import os, signal, sys, threading, time
from avra.runner.config import load_runner_config
from avra.runner.server import RunnerServer

server = RunnerServer(load_runner_config(os.environ), log_level="warning")

def deliver():
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    signal.raise_signal(getattr(signal, sys.argv[1]))  # like systemctl stop / Ctrl+C

threading.Thread(target=deliver, daemon=True).start()
rc = server.run()
print("RUN_RETURNED", rc, flush=True)
sys.exit(rc)
"""


@pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT"])
def test_signal_stop_records_runner_stopped_and_releases_lock(env, tmp_path, signame):
    import os
    import subprocess
    import sys

    child_env = {**os.environ, **env, "PYTHONPATH": os.pathsep.join(sys.path)}
    r = subprocess.run(
        [sys.executable, "-c", SIGNAL_CHILD, signame],
        env=child_env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert "RUN_RETURNED 0" in r.stdout, (r.returncode, r.stdout, r.stderr[-2000:])
    assert r.returncode == EXIT_OK
    cfg = load_runner_config(env)
    events = [rec.event for rec in AuditLog(cfg.audit_path).read_all()]
    assert events[0] == "runner_started"
    assert events[-1] == "runner_stopped"
    assert AuditLog(cfg.audit_path).verify()
    with AuditOwnerLock(cfg.audit_path) as lock:
        assert lock.held
