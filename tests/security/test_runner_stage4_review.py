"""M8.7 Stage 4 security review (ADR 0012): regression tests for the
findings R1-R6. Each test failed on commit 6ef9dd8 (see the review record
in ADR 0012) and passes after the fix. Offline only: fake executors, the
in-process app, real uvicorn on 127.0.0.1 only."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.request
import uuid

import pytest

from avra.runner import emergency
from avra.runner.emergency import LatchState, RunnerLatch
from avra.runner.http_app import STOP_RATE_MAX
from avra.runner.schemas import CancelOutcome, RejectionStage, ToolRunStatus
from avra.storage.audit import AuditLog
from tests.security.test_runner_cancellation import (
    AUTH,
    TOKEN,
    BlockingExecutor,
    Http,
    World,
    _cancel,
)
from tests.unit.test_runner_core import payload


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


@pytest.fixture
def http(w):
    return Http(w)


def _scope(body: bytes) -> dict:
    return {"type": "http", "method": "POST", "path": "/v1/tools/run",
            "raw_path": b"/v1/tools/run", "root_path": "", "scheme": "http",
            "query_string": b"", "http_version": "1.1", "client": ("127.0.0.1", 5),
            "server": ("127.0.0.1", 8765),
            "headers": [(b"authorization", f"Bearer {TOKEN}".encode()),
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())]}


# --- R1: disconnect-cancel must only touch the job THIS connection started --------------


def test_r1_disconnect_of_a_duplicate_request_does_not_cancel_the_running_job(http):
    """A second connection that re-sends the SAME ids (a client retry or a
    replay) is refused as busy; if it then disconnects, the original job must
    keep running. Before the fix the watcher cancelled by payload ids."""
    w = http.world
    p = payload()
    first = w.start(p)  # job A runs (via the core, as connection 1)

    real = w.runner.try_handle

    def slow_try_handle(*a, **k):
        time.sleep(0.3)  # connection 2's busy answer is not instant
        return real(*a, **k)

    w.runner.try_handle = slow_try_handle
    body = json.dumps(p).encode()

    async def second_connection():
        sent = {"body": False}

        async def receive():
            if not sent["body"]:
                sent["body"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}  # gone right after sending

        async def send(message):
            pass

        await asyncio.wait_for(http.app(_scope(body), receive, send), 10)

    asyncio.run(second_connection())
    assert not w.events("cancel_handled"), "a foreign disconnect cancelled job A"
    w.executor.release.set()
    first.join(5)
    assert w.results[0].status is ToolRunStatus.COMPLETED


# --- R2: cancel traffic must not starve the emergency stop -------------------------------


def test_r2_cancel_flood_cannot_block_an_emergency_stop(http):
    body = {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
            "reason": "operator_request"}
    for _ in range(STOP_RATE_MAX + 5):
        http.client.post("/v1/tools/cancel", json=body, headers=AUTH)
    r = http.client.post("/v1/emergency-stop", json={"reason": "operator_emergency_stop"},
                         headers=AUTH)
    assert r.status_code == 200, r.text
    assert http.world.latch.load().state is LatchState.STOPPED


# --- R3: a stopping Runner cancels its job and records it before runner_stopped ----------


def test_r3_shutdown_cancels_the_active_job_before_runner_stopped(tmp_path, monkeypatch):
    from avra.runner import server as server_mod
    from tests.security.test_runner_server import AUTH as SERVER_AUTH
    from tests.security.test_runner_server import Running, _free_port
    from tests.unit.test_runner_config import make_env

    executor = BlockingExecutor()
    monkeypatch.setattr(server_mod, "SubprocessRunner", lambda executables: executor)
    env = make_env(tmp_path, AVRA_RUNNER_BIND_HOST="127.0.0.1",
                   AVRA_RUNNER_PORT=str(_free_port()))
    running = Running(env)
    with running:
        def call():
            req = urllib.request.Request(
                running.base + "/v1/tools/run", data=json.dumps(payload()).encode(),
                headers={**SERVER_AUTH, "Content-Type": "application/json"}, method="POST")
            try:
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30)
            except Exception:  # noqa: BLE001, S110 - the connection may be closed on shutdown
                pass

        client = threading.Thread(target=call, daemon=True)
        client.start()
        assert executor.started.wait(10)
        t0 = time.monotonic()
    elapsed = time.monotonic() - t0
    events = [e for e, _ in running.audit_events()]
    assert "execution_finished" in events, events
    assert events.index("execution_finished") < events.index("runner_stopped"), events
    fin = [d for e, d in running.audit_events() if e == "execution_finished"][-1]
    assert fin["outcome"] == "cancelled" and fin["cancel_reason"] == "runner_shutdown"
    assert elapsed < 9, f"shutdown waited {elapsed:.1f}s for the job"


def test_r3b_server_exit_without_stop_still_finishes_the_job_first(tmp_path, monkeypatch):
    """The safety net: uvicorn exits WITHOUT RunnerServer.stop() (e.g. after
    its graceful-shutdown wait); the job must still be cancelled and its
    execution_finished recorded before runner_stopped."""
    from avra.runner import server as server_mod
    from tests.security.test_runner_server import AUTH as SERVER_AUTH
    from tests.security.test_runner_server import Running, _free_port
    from tests.unit.test_runner_config import make_env

    executor = BlockingExecutor()
    monkeypatch.setattr(server_mod, "SubprocessRunner", lambda executables: executor)
    monkeypatch.setitem(server_mod.UVICORN_SETTINGS, "timeout_graceful_shutdown", 1)
    env = make_env(tmp_path, AVRA_RUNNER_BIND_HOST="127.0.0.1",
                   AVRA_RUNNER_PORT=str(_free_port()))
    running = Running(env)
    running.__enter__()

    def call():
        req = urllib.request.Request(
            running.base + "/v1/tools/run", data=json.dumps(payload()).encode(),
            headers={**SERVER_AUTH, "Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30)
        except Exception:  # noqa: BLE001, S110 - the connection is dropped on shutdown
            pass

    threading.Thread(target=call, daemon=True).start()
    assert executor.started.wait(10)
    running.server._server.should_exit = True  # bypass stop(): no early cancel
    running.thread.join(30)
    assert not running.thread.is_alive()
    events = [e for e, _ in running.audit_events()]
    assert events.index("execution_finished") < events.index("runner_stopped"), events
    fin = [d for e, d in running.audit_events() if e == "execution_finished"][-1]
    assert fin["outcome"] == "cancelled" and fin["cancel_reason"] == "runner_shutdown"


# --- R4: emergency stop must persist even when the audit log is damaged -----------------


def test_r4_emergency_stop_is_written_even_if_the_audit_is_damaged(w):
    with open(w.audit_path, "ab") as fh:  # e.g. a torn tail after a crash
        fh.write(b'{"torn')
    res = w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    assert res.durable, res  # the STOPPED latch file is on disk and reads back
    assert json.loads(w.latch.path.read_bytes())["state"] == "stopped"
    assert res.audit_recorded is False and res.latch == "CORRUPT"


def test_r4_a_valid_ready_latch_is_replaced_by_stopped_under_audit_damage(w):
    w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    # simulate an earlier owner reset (ready latch backed by its record)
    w.latch.reset("maintenance", by="test")
    with open(w.audit_path, "ab") as fh:
        fh.write(b'{"torn')
    runner = w.restart()
    res = runner.emergency_stop({"reason": "operator_emergency_stop"})
    assert res.durable
    # Once the audit damage is repaired by the owner, STOPPED is still there:
    assert json.loads(w.latch.path.read_bytes())["state"] == "stopped"


def test_r4_a_malformed_latch_file_is_still_kept(w):
    w.latch.path.write_bytes(b"{garbage")
    res = w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    assert not res.durable and w.latch.path.read_bytes() == b"{garbage"


# --- R5: unexpected internal errors in stop paths are contained and audited -------------


@pytest.mark.parametrize("method,body", [
    ("cancel", {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                "reason": "operator_request"}),
    ("emergency_stop", {"reason": "operator_emergency_stop"}),
])
def test_r5_unexpected_errors_are_contained(w, monkeypatch, method, body):
    def boom(*a, **k):
        raise RuntimeError("secret detail /etc/avra-runner/token")

    target = "_decide_cancel" if method == "cancel" else "_cancel_active_job"
    monkeypatch.setattr(type(w.runner), target, boom)
    res = getattr(w.runner, method)(body)
    assert res.stage is RejectionStage.INTERNAL_ERROR
    assert "secret" not in res.reason and "/etc" not in res.reason
    assert w.events("internal_error")[-1].data == {"error_type": "RuntimeError",
                                                   "operation": method}


def test_r5_emergency_stop_keeps_new_runs_blocked_after_an_internal_error(w, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(type(w.runner), "_cancel_active_job", boom)
    w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    w.executor.release.set()
    assert w.runner.handle(payload()).stage is RejectionStage.EMERGENCY_STOP


# --- R6: the REAL Windows pipeline (shared schemas) never treats CANCELLED as success ----


def test_r6_real_scan_pipeline_treats_cancelled_as_failure(tmp_path):
    from datetime import UTC, datetime

    from avra.core.research import classify_result
    from avra.policy.scope import ScopeChecker
    from avra.runner.schemas import ToolRunResult
    from avra.runner_client.client import RunnerToken, RunOutcome
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import TunnelConfig
    from avra.schemas.scope import ActionTier, Scope, Target

    class Tunnel:
        def __init__(self, cfg):
            pass

        def __enter__(self):
            return "http://127.0.0.1:1"

        def __exit__(self, *a):
            return False

    class Client:
        def __init__(self, base, token):
            pass

        def health(self):
            return {"status": "ok"}

        def run(self, request):
            res = ToolRunResult(request_id=request.request_id, tool="nmap_connect_scan",
                                status=ToolRunStatus.CANCELLED, reason="cancelled",
                                started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
                                exit_code=-15)
            return RunOutcome(200, result=res)

    scope = Scope(session_name="t", expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                  targets=[Target(host="10.66.7.103", ports=[3000],
                                  allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                  allowed_tools=["nmap_connect_scan"])])
    audit = AuditLog(tmp_path / "s.jsonl")
    out = run_nmap_connect_scan(checker=ScopeChecker(scope), audit=audit,
                                session_id=uuid.uuid4(), host="10.66.7.103", ports=[3000],
                                timeout_seconds=30, token=RunnerToken("t" * 43),
                                evidence_root=tmp_path / "ev", tunnel_cfg=TunnelConfig(),
                                tunnel_factory=Tunnel, client_factory=Client)
    assert not out.ok and out.evidence is None and out.report is None
    # Stage 5 names it precisely; before Stage 5 it was "failed". Never success.
    assert classify_result(out)[0] == "cancelled"
    assert any("not evidence" in e for e in out.errors)
    assert not (tmp_path / "ev").exists() or not any((tmp_path / "ev").rglob("*"))
    rec = audit.read_all()[-1]
    assert rec.event == "tool_result_received" and rec.data["status"] == "cancelled"


@pytest.mark.parametrize("status,stage", [(503, "emergency_stop"), (409, "cancelled")])
def test_r6_real_client_never_accepts_new_rejections_as_success(status, stage):
    """The current Windows RunnerClient: 503 emergency_stop -> rejection;
    409 cancelled -> RunnerClientError (not in its accepted list). Both fail
    closed. (Accepting 409 explicitly is Stage 5.)"""
    from avra.runner.schemas import NmapConnectScanRequest
    from avra.runner_client.client import RunnerClient, RunnerClientError, RunnerToken

    req = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                 host="10.66.7.103", ports=[3000], timeout_seconds=30)
    client = RunnerClient("http://127.0.0.1:1", RunnerToken("t" * 43))
    body = {"stage": stage, "reason": "r", "request_id": str(req.request_id)}
    client._call = lambda *a, **k: (status, body)
    try:
        out = client.run(req)
    except RunnerClientError:
        return
    assert out.result is None and out.rejection is not None
    assert out.rejection.stage is RejectionStage(stage)


# --- concurrency between cancel and emergency stop ------------------------------------------


def test_concurrent_cancel_and_emergency_stop(w):
    p = payload()
    t = w.start(p)
    out = {}
    a = threading.Thread(target=lambda: out.setdefault("c", w.runner.cancel(_cancel(p))))
    b = threading.Thread(target=lambda: out.setdefault(
        "e", w.runner.emergency_stop({"reason": "operator_emergency_stop"})))
    a.start()
    b.start()
    a.join(10)
    b.join(10)
    t.join(5)
    assert w.results[0].status is ToolRunStatus.CANCELLED
    assert out["c"].outcome in (CancelOutcome.APPLIED, CancelOutcome.ALREADY_CANCELLED,
                                CancelOutcome.ALREADY_FINISHED)
    assert out["e"].durable and out["e"].active_job in ("cancelled", "already_finished",
                                                        "none")
    fin = w.events("execution_finished")
    assert len(fin) == 1 and fin[0].data["outcome"] == "cancelled"
    assert AuditLog(w.audit_path).verify()


def test_cancel_racing_natural_completion_never_relabels(w):
    p = payload()
    t = w.start(p)
    w.executor.release.set()  # the job completes...
    res = w.runner.cancel(_cancel(p))  # ...while the cancel arrives
    t.join(5)
    final = w.results[0].status
    if final is ToolRunStatus.COMPLETED:
        assert res.outcome in (CancelOutcome.ALREADY_FINISHED,)
    else:
        assert final is ToolRunStatus.CANCELLED and res.outcome is CancelOutcome.APPLIED


def test_corrupted_latch_after_restart_blocks_and_health_says_so(w):
    w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    w.latch.path.write_bytes(b'{"v": 1}')
    runner = w.restart()
    assert runner.emergency_blocked() and "CORRUPT" in runner.emergency_blocked()
    assert RunnerLatch.beside(AuditLog(w.audit_path)).load().state is LatchState.CORRUPT


def test_replace_failure_never_reports_success(w, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk")

    monkeypatch.setattr(emergency, "_replace", boom)
    res = w.runner.emergency_stop({"reason": "operator_emergency_stop"})
    assert res.outcome == "not_durable" and not res.durable
