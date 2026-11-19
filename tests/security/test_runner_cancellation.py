"""M8.7 Stage 4 (ADR 0012): Runner cancellation and emergency stop.

Offline only: fake executors, harmless local Python child processes, the
in-process Starlette app, and one real uvicorn server bound to 127.0.0.1 on
a free port (the same pattern as test_runner_server.py). No Kali, no nmap,
no target traffic."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from avra.runner import emergency
from avra.runner.config import BearerToken
from avra.runner.core import Runner
from avra.runner.emergency import EV_ENGAGED, LatchState, RunnerLatch
from avra.runner.execution import (
    IS_POSIX,
    ExecutionLimits,
    ProcessOutcome,
    ProcessResult,
    SubprocessRunner,
)
from avra.runner.http_app import STOP_RATE_MAX, create_app
from avra.runner.policy import RunnerPolicy
from avra.runner.schemas import (
    CancelOutcome,
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.storage.audit import AuditLog
from tests.unit.test_runner_core import SCOPE_YAML, payload, proc_result

TOKEN = "T" * 24 + "-runner-test-token-0123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
PYTHON = getattr(sys, "_base_executable", sys.executable) or sys.executable


class BlockingExecutor:
    """Runs until cancelled or released; mirrors SubprocessRunner's contract."""

    def __init__(self, final=None):
        self.executables = {"nmap": "/usr/bin/nmap",
                            "http_probe": "/opt/avra-runner/venv/bin/avra-http-probe"}
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self.final = final  # force an outcome (e.g. TIMED_OUT) regardless of cancel

    def run(self, argv, limits, cancel=None):
        self.calls += 1
        self.started.set()
        give_up = time.monotonic() + 15  # a missing cancel fails a test, never hangs it
        while not self.release.is_set() and time.monotonic() < give_up:
            if cancel is not None and cancel.is_set() and self.final is None:
                return proc_result(ProcessOutcome.CANCELLED, exit_code=-15, stdout=b"partial")
            time.sleep(0.01)
        return self.final or proc_result()


class World:
    def __init__(self, tmp_path, *, executor=None, audit=None, latch=True, wait=2.0):
        scope = tmp_path / "scope.yaml"
        scope.write_text(SCOPE_YAML, encoding="utf-8")
        self.policy = RunnerPolicy.from_scope_file(scope)
        self.audit_path = tmp_path / "runner-audit.jsonl"
        self.audit = audit or AuditLog(self.audit_path)
        self.executor = executor or BlockingExecutor()
        self.latch = RunnerLatch.beside(AuditLog(self.audit_path)) if latch else None
        self.runner = Runner(self.policy, self.executor, self.audit, latch=self.latch,
                             cancel_wait_seconds=wait)
        self.results: list = []

    def start(self, p):
        t = threading.Thread(target=lambda: self.results.append(self.runner.handle(p)))
        t.start()
        assert self.executor.started.wait(5), "job did not start"
        return t

    def events(self, name=None):
        recs = AuditLog(self.audit_path).read_all()
        return [r for r in recs if name is None or r.event == name]

    def restart(self):
        return Runner(self.policy, BlockingExecutor(), AuditLog(self.audit_path),
                      latch=RunnerLatch.beside(AuditLog(self.audit_path)))


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _cancel(p, reason="operator_request", **over):
    return {"request_id": p["request_id"], "session_id": p["session_id"], "reason": reason,
            **over}


# --- cancellation ------------------------------------------------------------------------------


def test_cancel_active_job(w):
    p = payload()
    t = w.start(p)
    res = w.runner.cancel(_cancel(p))
    t.join(5)
    assert res.outcome is CancelOutcome.APPLIED and res.audit_recorded
    [result] = w.results
    assert isinstance(result, ToolRunResult) and result.status is ToolRunStatus.CANCELLED
    assert result.raw_output is None and result.output_sha256 is None  # no evidence
    fin = w.events("execution_finished")[-1].data
    assert fin["outcome"] == "cancelled" and fin["cancel_requested"] is True
    assert fin["cancel_reason"] == "operator_request"
    assert w.events("cancel_handled")[-1].data["outcome"] == "cancellation_applied"


def test_wrong_request_id_does_not_touch_the_job(w):
    p = payload()
    t = w.start(p)
    res = w.runner.cancel(_cancel(p, request_id=str(uuid.uuid4())))
    assert res.outcome is CancelOutcome.NOT_ACTIVE
    w.executor.release.set()
    t.join(5)
    assert w.results[0].status is ToolRunStatus.COMPLETED


def test_wrong_session_id_is_a_mismatch(w):
    p = payload()
    t = w.start(p)
    res = w.runner.cancel(_cancel(p, session_id=str(uuid.uuid4())))
    assert res.outcome is CancelOutcome.MISMATCH
    w.executor.release.set()
    t.join(5)
    assert w.results[0].status is ToolRunStatus.COMPLETED


def test_same_session_other_request_does_not_touch_the_job(w):
    p = payload()
    t = w.start(p)
    other = payload(session_id=p["session_id"])
    assert w.runner.cancel(_cancel(other)).outcome is CancelOutcome.NOT_ACTIVE
    w.executor.release.set()
    t.join(5)
    assert w.results[0].status is ToolRunStatus.COMPLETED


def test_cancel_before_registration_refuses_the_run_and_its_retries(w):
    p = payload()
    assert w.runner.cancel(_cancel(p)).outcome is CancelOutcome.NOT_ACTIVE
    w.executor.release.set()
    for _ in range(2):  # the original and a retried copy
        res = w.runner.handle(p)
        assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.CANCELLED
    assert w.executor.calls == 0
    assert w.runner.cancel(_cancel(p)).outcome is CancelOutcome.ALREADY_CANCELLED
    other = payload()  # an unrelated job is unaffected
    assert isinstance(w.runner.handle(other), ToolRunResult)


def test_tombstones_expire_and_are_bounded(tmp_path):
    clock = [0.0]
    world = World(tmp_path)
    world.runner._clock = lambda: clock[0]
    world.executor.release.set()
    p = payload()
    world.runner.cancel(_cancel(p))
    clock[0] += 901
    assert isinstance(world.runner.handle(p), ToolRunResult)  # expired: runs
    for _ in range(300):
        world.runner.cancel(_cancel(payload()))
    assert len(world.runner._tombstones) == 256


def test_cancel_after_completion(w):
    w.executor.release.set()
    p = payload()
    w.runner.handle(p)
    assert w.runner.cancel(_cancel(p)).outcome is CancelOutcome.ALREADY_FINISHED
    assert w.runner.cancel(_cancel(p, session_id=str(uuid.uuid4()))).outcome \
        is CancelOutcome.MISMATCH


def test_duplicate_cancel(w):
    p = payload()
    t = w.start(p)
    assert w.runner.cancel(_cancel(p)).outcome is CancelOutcome.APPLIED
    t.join(5)
    assert w.runner.cancel(_cancel(p)).outcome is CancelOutcome.ALREADY_CANCELLED


def test_cancel_racing_a_timeout_reports_the_real_outcome(tmp_path):
    ex = BlockingExecutor(final=proc_result(ProcessOutcome.TIMED_OUT, exit_code=-9))
    world = World(tmp_path, executor=ex, wait=0.3)
    p = payload()
    t = world.start(p)
    first = world.runner.cancel(_cancel(p))  # the timeout "wins": job not done yet
    assert first.outcome is CancelOutcome.REQUESTED
    ex.release.set()
    t.join(5)
    assert world.results[0].status is ToolRunStatus.TIMED_OUT  # never re-labelled
    assert world.runner.cancel(_cancel(p)).outcome is CancelOutcome.ALREADY_FINISHED


def test_concurrent_cancels_signal_once(w):
    p = payload()
    t = w.start(p)
    outcomes: list = []
    threads = [threading.Thread(target=lambda: outcomes.append(
        w.runner.cancel(_cancel(p)).outcome)) for _ in range(10)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(10)
    t.join(5)
    assert outcomes.count(CancelOutcome.APPLIED) == 1
    assert set(outcomes) <= {CancelOutcome.APPLIED, CancelOutcome.ALREADY_CANCELLED}
    assert len(w.events("cancel_handled")) == 10 and AuditLog(w.audit_path).verify()


@pytest.mark.parametrize("bad", [
    {},
    {"request_id": "x", "session_id": "y", "reason": "operator_request"},
    {"request_id": str(uuid.uuid4()).upper(), "session_id": str(uuid.uuid4()),
     "reason": "operator_request"},
    {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()), "reason": "because"},
    {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
     "reason": "operator_request", "pid": 1},
    {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
     "reason": "operator_request", "signal": "SIGKILL"},
    {"request_id": 1, "session_id": 2, "reason": 3},
    ["not", "an", "object"],
])
def test_invalid_cancel_requests_are_rejected_and_audited(w, bad):
    res = w.runner.cancel(bad)
    assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.INVALID_REQUEST
    assert w.events("cancel_rejected")


def test_cancel_still_applies_if_its_audit_record_fails(tmp_path):
    class NoCancelRecord(AuditLog):
        def record(self, event, data=None):
            if event == "cancel_handled":
                raise OSError("disk full")
            return super().record(event, data)

    world = World(tmp_path, audit=NoCancelRecord(tmp_path / "runner-audit.jsonl"))
    p = payload()
    t = world.start(p)
    res = world.runner.cancel(_cancel(p))
    t.join(5)
    assert res.outcome is CancelOutcome.APPLIED and res.audit_recorded is False


# --- emergency stop ------------------------------------------------------------------------------


def _stop(runner, reason="operator_emergency_stop"):
    return runner.emergency_stop({"reason": reason})


def test_emergency_stop_while_idle_blocks_new_runs(w):
    res = _stop(w.runner)
    assert res.outcome == "engaged" and res.durable and res.audit_recorded
    assert res.latch == "STOPPED" and res.active_job == "none"
    w.executor.release.set()
    run = w.runner.handle(payload())
    assert isinstance(run, RunnerRejection) and run.stage is RejectionStage.EMERGENCY_STOP
    assert w.executor.calls == 0
    events = [r.event for r in w.events()]
    assert events.index("emergency_stop_requested") < events.index(EV_ENGAGED)


def test_emergency_stop_during_execution_cancels_the_job(w):
    p = payload()
    t = w.start(p)
    res = _stop(w.runner)
    t.join(5)
    assert res.active_job == "cancelled" and w.results[0].status is ToolRunStatus.CANCELLED
    assert w.events("execution_finished")[-1].data["cancel_reason"] == "emergency_stop"
    assert w.events("emergency_stop_cancelled_job")[-1].data["request_id"] == p["request_id"]


def test_latch_is_written_before_the_job_is_cancelled(w, monkeypatch):
    seen = {}
    real = RunnerLatch.engage

    def spy(self, reason, *, by):
        seen["job_cancelled_at_engage"] = w.runner._active.cancel_event.is_set()
        return real(self, reason, by=by)

    monkeypatch.setattr(RunnerLatch, "engage", spy)
    t = w.start(payload())
    _stop(w.runner)
    t.join(5)
    assert seen == {"job_cancelled_at_engage": False}


def test_repeated_emergency_stop_is_idempotent(w):
    first = _stop(w.runner)
    second = _stop(w.runner)
    assert first.outcome == "engaged" and second.outcome == "already_engaged"
    assert second.durable and json.loads(w.latch.path.read_bytes())["state"] == "stopped"


def test_emergency_state_survives_restart(w):
    _stop(w.runner)
    fresh = w.restart()
    fresh._executor.release.set()
    res = fresh.handle(payload())
    assert isinstance(res, RunnerRejection) and res.stage is RejectionStage.EMERGENCY_STOP


def test_fresh_install_is_ready(w):
    assert w.latch.load().state is LatchState.READY
    w.executor.release.set()
    assert isinstance(w.runner.handle(payload()), ToolRunResult)


@pytest.mark.parametrize("content", [b"{garbage", b"[]", b'{"v": 1, "state": "ready"}',
                                     b" " * 5000])
def test_corrupted_latch_blocks_and_is_kept(w, content):
    _stop(w.runner)
    w.latch.path.write_bytes(content)
    fresh = w.restart()
    fresh._executor.release.set()
    assert fresh.handle(payload()).stage is RejectionStage.EMERGENCY_STOP
    res = _stop(fresh)
    assert res.outcome == "not_durable" and res.latch == "CORRUPT"
    assert w.latch.path.read_bytes() == content  # evidence never overwritten


def test_deleted_latch_still_blocks(w):
    _stop(w.runner)
    w.latch.path.unlink()
    st = w.latch.load()
    assert st.state is LatchState.CORRUPT and "deleted" in st.detail
    fresh = w.restart()
    fresh._executor.release.set()
    assert fresh.handle(payload()).stage is RejectionStage.EMERGENCY_STOP


def test_unreadable_latch_blocks(w, monkeypatch):
    def denied(self):
        raise PermissionError("denied")

    monkeypatch.setattr(RunnerLatch, "_read", denied)
    w.executor.release.set()
    assert w.runner.handle(payload()).stage is RejectionStage.EMERGENCY_STOP


@pytest.mark.parametrize("target", ["_replace", "_fsync"])
def test_latch_write_failure_is_not_reported_as_durable(w, monkeypatch, target):
    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(emergency, target, boom)
    res = _stop(w.runner)
    assert res.outcome == "not_durable" and not res.durable
    w.executor.release.set()
    # Still refuses for the rest of this process's life (in-memory latch).
    assert w.runner.handle(payload()).stage is RejectionStage.EMERGENCY_STOP
    assert w.events("emergency_stop_engage_failed")


def test_emergency_audit_failure_is_reported_but_latch_holds(tmp_path):
    class NoEngagedRecord(AuditLog):
        def record(self, event, data=None):
            if event == EV_ENGAGED:
                raise OSError("disk full")
            return super().record(event, data)

    path = tmp_path / "runner-audit.jsonl"
    world = World(tmp_path, audit=NoEngagedRecord(path))
    world.latch = RunnerLatch.beside(NoEngagedRecord(path))
    world.runner._latch = world.latch
    res = _stop(world.runner)
    assert res.durable and res.audit_recorded is False
    assert world.latch.load().state is LatchState.STOPPED


def test_run_arriving_during_engagement_is_refused(w, monkeypatch):
    """The in-memory flag is set before the (slow) disk write."""
    real = RunnerLatch.engage
    gate, result = threading.Event(), {}

    def slow(self, reason, *, by):
        gate.set()
        time.sleep(0.3)
        return real(self, reason, by=by)

    monkeypatch.setattr(RunnerLatch, "engage", slow)
    t = threading.Thread(target=lambda: _stop(w.runner))
    t.start()
    gate.wait(5)
    w.executor.release.set()
    result["run"] = w.runner.handle(payload())
    t.join(5)
    assert result["run"].stage is RejectionStage.EMERGENCY_STOP and w.executor.calls == 0


def test_invalid_emergency_request(w):
    for bad in ({}, {"reason": "please"}, {"reason": "operator_emergency_stop", "x": 1}):
        res = w.runner.emergency_stop(bad)
        assert isinstance(res, RunnerRejection)
    assert w.latch.load().state is LatchState.READY


# --- local reset (never HTTP) ----------------------------------------------------------------------


def _cfg(tmp_path, world):
    class Cfg:
        audit_path = world.audit_path
    return Cfg()


def test_local_reset_flow(tmp_path, w):
    from avra.runner.server import EXIT_OK, EXIT_RESET_REFUSED, reset_emergency_stop

    cfg = _cfg(tmp_path, w)
    assert reset_emergency_stop(cfg, interactive=True, ask=lambda q: "x") == EXIT_RESET_REFUSED
    _stop(w.runner)
    assert reset_emergency_stop(cfg, interactive=False) == EXIT_RESET_REFUSED
    answers = iter(["", "RESET"])
    assert reset_emergency_stop(cfg, interactive=True, ask=lambda q: next(answers)) \
        == EXIT_RESET_REFUSED  # empty reason
    answers = iter(["done", "reset"])
    assert reset_emergency_stop(cfg, interactive=True, ask=lambda q: next(answers)) \
        == EXIT_RESET_REFUSED  # wrong word
    assert w.latch.load().state is LatchState.STOPPED
    answers = iter(["maintenance complete", "RESET"])
    assert reset_emergency_stop(cfg, interactive=True, ask=lambda q: next(answers)) == EXIT_OK
    assert w.latch.load().state is LatchState.READY
    assert [r.event for r in w.events()][-1] == "emergency_stop_reset"
    fresh = w.restart()
    fresh._executor.release.set()
    assert isinstance(fresh.handle(payload()), ToolRunResult)  # explicit new work only


def test_local_reset_refused_while_a_runner_owns_the_audit(tmp_path, w):
    from avra.runner.audit_owner import AuditOwnerLock
    from avra.runner.server import EXIT_AUDIT_OWNED, reset_emergency_stop

    _stop(w.runner)
    with AuditOwnerLock(w.audit_path):
        assert reset_emergency_stop(_cfg(tmp_path, w), interactive=True,
                                    ask=lambda q: "RESET") == EXIT_AUDIT_OWNED
    assert w.latch.load().state is LatchState.STOPPED


def test_local_reset_refuses_corrupt_latch(tmp_path, w):
    from avra.runner.server import EXIT_RESET_REFUSED, reset_emergency_stop

    _stop(w.runner)
    w.latch.path.write_bytes(b"junk")
    assert reset_emergency_stop(_cfg(tmp_path, w), interactive=True,
                                ask=lambda q: "RESET") == EXIT_RESET_REFUSED
    assert w.latch.path.read_bytes() == b"junk"


def test_reset_audit_failure_keeps_stopped(w, monkeypatch):
    _stop(w.runner)

    def boom(self, event, data=None):
        raise OSError("disk full")

    monkeypatch.setattr(AuditLog, "record", boom)
    with pytest.raises(emergency.LatchError, match="still STOPPED"):
        w.latch.reset("done", by="t")
    monkeypatch.undo()
    assert w.latch.load().state is LatchState.STOPPED


# --- HTTP layer ------------------------------------------------------------------------------------


class Http:
    def __init__(self, world: World):
        self.world = world
        self.clock = [0.0]
        self.app = create_app(runner=world.runner, token=BearerToken(TOKEN), audit=world.audit,
                              health_checks=lambda: {"emergency_stop_clear":
                                                     world.runner.emergency_blocked() is None},
                              clock=lambda: self.clock[0])
        self.client = TestClient(self.app, raise_server_exceptions=False)


@pytest.fixture
def http(w):
    return Http(w)


@pytest.mark.parametrize("path,body", [
    ("/v1/tools/cancel", {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                          "reason": "operator_request"}),
    ("/v1/emergency-stop", {"reason": "operator_emergency_stop"}),
])
@pytest.mark.parametrize("headers", [
    {}, {"Authorization": "Bearer wrong-token"}, {"Authorization": f"Basic {TOKEN}"},
    {"Authorization": f"Bearer  {TOKEN}"}, {"Authorization": TOKEN},
])
def test_stop_endpoints_require_the_bearer_token(http, path, body, headers):
    r = http.client.post(path, json=body, headers=headers)
    assert r.status_code == 401
    assert http.world.latch.load().state is LatchState.READY
    assert not http.world.events("cancel_handled")


def test_cancel_endpoint_happy_path_and_validation(http):
    body = {"request_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
            "reason": "client_interrupt"}
    r = http.client.post("/v1/tools/cancel", json=body, headers=AUTH)
    assert r.status_code == 200 and r.json()["outcome"] == "not_active"
    assert set(r.json()) == {"outcome", "request_id", "session_id", "audit_recorded"}
    r = http.client.post("/v1/tools/cancel", json={**body, "pid": 1}, headers=AUTH)
    assert r.status_code == 400
    r = http.client.post("/v1/tools/cancel", content=b"{}", headers={**AUTH,
                         "Content-Type": "text/plain"})
    assert r.status_code == 415
    r = http.client.post("/v1/tools/cancel", content=b"x" * 20000,
                         headers={**AUTH, "Content-Type": "application/json"})
    assert r.status_code == 413


def test_emergency_endpoint_and_no_reset_route(http):
    r = http.client.post("/v1/emergency-stop", json={"reason": "operator_emergency_stop"},
                         headers=AUTH)
    assert r.status_code == 200 and r.json()["outcome"] == "engaged"
    for method, path in [("POST", "/v1/emergency-stop/reset"), ("POST", "/v1/emergency-reset"),
                         ("POST", "/v1/reset"), ("DELETE", "/v1/emergency-stop"),
                         ("PUT", "/v1/emergency-stop"), ("GET", "/v1/emergency-stop")]:
        resp = http.client.request(method, path, headers=AUTH)
        assert resp.status_code in (404, 405), (method, path)
    assert http.world.latch.load().state is LatchState.STOPPED
    r = http.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    assert r.status_code == 503 and r.json()["stage"] == "emergency_stop"
    health = http.client.get("/v1/health", headers=AUTH)
    assert health.status_code == 503 and health.json()["checks"]["emergency_stop_clear"] is False


def test_partial_emergency_stop_is_503(http, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(emergency, "_replace", boom)
    r = http.client.post("/v1/emergency-stop", json={"reason": "operator_emergency_stop"},
                         headers=AUTH)
    assert r.status_code == 503 and r.json()["durable"] is False


def test_stop_requests_are_rate_limited(http):
    body = {"reason": "operator_emergency_stop"}
    codes = [http.client.post("/v1/emergency-stop", json=body, headers=AUTH).status_code
             for _ in range(STOP_RATE_MAX + 3)]
    assert codes.count(429) == 3
    http.clock[0] += 61
    assert http.client.post("/v1/emergency-stop", json=body, headers=AUTH).status_code == 200


def test_responses_disclose_no_pid_path_or_token(http):
    p = payload()
    t = http.world.start(p)
    r = http.client.post("/v1/tools/cancel", json=_cancel(p), headers=AUTH)
    t.join(5)
    text = r.text + json.dumps([rec.data for rec in http.world.events()])
    assert TOKEN not in text and "/usr/bin/nmap" not in r.text and "pid" not in r.text


def test_completed_response_is_not_treated_as_a_disconnect(http):
    http.world.executor.release.set()
    r = http.client.post("/v1/tools/run", json=payload(), headers=AUTH)
    assert r.status_code == 200 and r.json()["status"] == "completed"
    assert not http.world.events("cancel_handled")


def test_disconnect_cancels_the_job_with_a_fake_transport(http):
    import asyncio

    p = payload()
    body = json.dumps(p).encode()
    sent: list = []

    async def scenario():
        disconnect = asyncio.Event()

        async def receive():
            if not hasattr(receive, "done"):
                receive.done = True
                return {"type": "http.request", "body": body, "more_body": False}
            await disconnect.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "POST", "path": "/v1/tools/run",
                 "raw_path": b"/v1/tools/run", "root_path": "", "scheme": "http",
                 "query_string": b"", "http_version": "1.1", "client": ("127.0.0.1", 5),
                 "server": ("127.0.0.1", 8765),
                 "headers": [(b"authorization", f"Bearer {TOKEN}".encode()),
                             (b"content-type", b"application/json"),
                             (b"content-length", str(len(body)).encode())]}
        task = asyncio.ensure_future(http.app(scope, receive, send))
        while not http.world.executor.started.is_set():
            await asyncio.sleep(0.01)
        disconnect.set()  # the client goes away mid-job
        await asyncio.wait_for(task, 10)

    asyncio.run(scenario())
    handled = http.world.events("cancel_handled")
    assert handled and handled[-1].data["reason"] == "client_disconnected"
    fin = http.world.events("execution_finished")[-1].data
    assert fin["outcome"] == "cancelled" and fin["cancel_reason"] == "client_disconnected"


def test_disconnect_on_the_real_uvicorn_stack(http):
    """Real uvicorn on 127.0.0.1 (free port); the socket is closed mid-job."""
    import uvicorn

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(http.app, host="127.0.0.1", port=port,
                                           log_level="error", lifespan="off", http="h11",
                                           ws="none"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        body = json.dumps(payload()).encode()
        req = (b"POST /v1/tools/run HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               + f"Authorization: Bearer {TOKEN}\r\n".encode()
               + b"Content-Type: application/json\r\n"
               + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(req)
        assert http.world.executor.started.wait(5)
        sock.close()  # client vanishes
        deadline = time.monotonic() + 10
        while not http.world.events("execution_finished") and time.monotonic() < deadline:
            time.sleep(0.05)
        fin = http.world.events("execution_finished")[-1].data
        assert fin["outcome"] == "cancelled" and fin["cancel_reason"] == "client_disconnected"
    finally:
        http.world.executor.release.set()
        server.should_exit = True
        th.join(10)


# --- real subprocesses ------------------------------------------------------------------------------


@pytest.fixture
def sub():
    return SubprocessRunner({"py": PYTHON})


def _limits(**kw):
    kw.setdefault("timeout_seconds", 30)
    kw.setdefault("kill_grace_seconds", 1)
    return ExecutionLimits(**kw)


def _cancel_after(event, seconds):
    threading.Timer(seconds, event.set).start()


def test_real_process_is_cancelled_promptly(sub):
    cancel = threading.Event()
    _cancel_after(cancel, 0.5)
    t0 = time.monotonic()
    res = sub.run(["py", "-c", "import time; print('x', flush=True); time.sleep(60)"], _limits(),
                  cancel=cancel)
    assert res.outcome is ProcessOutcome.CANCELLED and time.monotonic() - t0 < 10


def test_cancel_before_start_never_starts_the_process(sub, tmp_path):
    marker = tmp_path / "ran"
    cancel = threading.Event()
    cancel.set()
    res = sub.run(["py", "-c", f"open(r'{marker}', 'w').write('x')"], _limits(), cancel=cancel)
    assert res.outcome is ProcessOutcome.CANCELLED and not marker.exists()


def test_cancel_takes_precedence_over_a_timeout_in_the_same_poll(sub):
    class LateCancel(threading.Event):
        """Becomes set exactly when the deadline has also passed."""

        def __init__(self):
            super().__init__()
            self.at = time.monotonic() + 0.4

        def is_set(self):
            return time.monotonic() >= self.at

    res = sub.run(["py", "-c", "import time; time.sleep(60)"],
                  _limits(timeout_seconds=0.4), cancel=LateCancel())
    assert res.outcome is ProcessOutcome.CANCELLED


def test_unrelated_process_survives_a_cancel(sub):
    bystander = subprocess.Popen([PYTHON, "-c", "import time; time.sleep(60)"])
    try:
        cancel = threading.Event()
        _cancel_after(cancel, 0.3)
        res = sub.run(["py", "-c", "import time; time.sleep(60)"], _limits(), cancel=cancel)
        assert res.outcome is ProcessOutcome.CANCELLED
        assert bystander.poll() is None  # untouched
    finally:
        bystander.kill()
        bystander.wait()


def test_output_limit_still_applies_with_a_cancel_event(sub):
    res = sub.run(["py", "-c", "import sys; sys.stdout.write('x' * 5_000_000)"],
                  _limits(max_stdout_bytes=1000), cancel=threading.Event())
    assert res.outcome is ProcessOutcome.OUTPUT_LIMIT and len(res.stdout) == 1000


@pytest.mark.skipif(not IS_POSIX, reason="needs POSIX signals (verify on Linux/Kali)")
def test_sigterm_ignoring_child_is_killed_after_grace(sub):
    cancel = threading.Event()
    _cancel_after(cancel, 0.5)
    code = ("import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)")
    t0 = time.monotonic()
    res = sub.run(["py", "-c", code], _limits(kill_grace_seconds=1), cancel=cancel)
    assert res.outcome is ProcessOutcome.CANCELLED and time.monotonic() - t0 < 10
    assert res.exit_code == -9


@pytest.mark.skipif(not IS_POSIX, reason="process groups are POSIX-only (verify on Linux/Kali)")
def test_cancel_kills_grandchildren_on_posix(sub, tmp_path):
    pidfile = tmp_path / "gc.pid"
    code = (f"import subprocess, sys, time; p = subprocess.Popen([sys.executable, '-c', "
            f"'import time; time.sleep(60)']); open(r'{pidfile}', 'w').write(str(p.pid)); "
            f"time.sleep(60)")
    cancel = threading.Event()
    _cancel_after(cancel, 1.0)
    res = sub.run(["py", "-c", code], _limits(), cancel=cancel)
    assert res.outcome is ProcessOutcome.CANCELLED
    grandchild = int(pidfile.read_text())
    time.sleep(0.2)
    with pytest.raises(ProcessLookupError):
        os.kill(grandchild, 0)


def test_process_result_contract_for_cancelled(sub):
    r = ProcessResult(outcome=ProcessOutcome.CANCELLED, exit_code=None, stdout=b"",
                      stderr=b"", stdout_truncated=False, stderr_truncated=False,
                      duration_seconds=0.0)
    assert not r.ok  # never "completed"


# --- compatibility ------------------------------------------------------------------------------------


def test_old_client_schema_would_reject_cancelled(tmp_path):
    """A pre-Stage-4 Windows client validates with a status enum that has no
    'cancelled': simulate it and check it fails closed (never success)."""
    from enum import Enum

    from pydantic import BaseModel, ValidationError

    class OldStatus(str, Enum):
        COMPLETED = "completed"
        DENIED = "denied"
        TIMED_OUT = "timed_out"
        FAILED = "failed"

    class OldResult(BaseModel):
        status: OldStatus

    with pytest.raises(ValidationError):
        OldResult.model_validate({"status": "cancelled"})


def test_cancelled_result_schema_carries_no_evidence():
    from datetime import UTC, datetime

    from pydantic import ValidationError

    base = {"request_id": uuid.uuid4(), "tool": "nmap_connect_scan",
            "status": "cancelled", "started_at": datetime.now(UTC)}
    ToolRunResult.model_validate({**base, "reason": "cancelled"})
    for extra in ({"raw_output": "x"}, {"output_sha256": "a" * 64}, {"reason": ""}):
        with pytest.raises(ValidationError):
            ToolRunResult.model_validate({**base, "reason": "cancelled", **extra})


def test_historical_runner_records_are_unchanged():
    # Runner audit semantics for existing events are unchanged: the fixture
    # sessions (Windows side) still verify byte-identically.
    root = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic-sessions" / "sessions"
    for p in root.glob("*.jsonl"):
        assert AuditLog(p).verify()
