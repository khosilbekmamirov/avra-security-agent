"""M8.7 Stage 5 (ADR 0012): Windows <-> Runner cancellation and emergency stop.

Offline only: fake HTTP openers, fake tunnels/clients, isolated state, and
one real Stage 4 Runner app served by uvicorn on 127.0.0.1. tests/conftest.py
additionally forbids real ssh and the real .env token for every test."""

from __future__ import annotations

import io
import json
import socket
import threading
import time
import urllib.error
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.control.killswitch import KillSwitch, KillSwitchEngaged, Latch
from avra.runner.schemas import (
    CancelOutcome,
    CancelReason,
    CancelResponse,
    EmergencyReason,
    EmergencyStopResponse,
    NmapConnectScanRequest,
    ToolRunStatus,
)
from avra.runner_client.client import (
    MAX_STOP_RESPONSE_BYTES,
    STOP_ONLY_PATHS,
    RunnerClient,
    RunnerToken,
    StopCallResult,
)
from avra.runner_client.stop import (
    REMOTE_UNCONFIRMED,
    StopOnlyClient,
    remote_emergency_stop,
)
from avra.runner_client.tunnel import TunnelConfig, TunnelError
from avra.storage.audit import AuditLog, inspect_audit_file

TOKEN_TEXT = "S" * 40 + "-stage5-secret-token"
TOKEN = RunnerToken(TOKEN_TEXT)
RID, SID = uuid.uuid4(), uuid.uuid4()


# --- fake HTTP transport for RunnerClient -------------------------------------------------


class _Resp:
    def __init__(self, status: int, body: bytes):
        self.status, self._body = status, io.BytesIO(body)

    def read(self, n=-1):
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeOpener:
    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def open(self, req, timeout=None):
        self.calls.append({"url": req.full_url, "method": req.get_method(),
                           "body": json.loads(req.data) if req.data else None,
                           "headers": dict(req.header_items()), "timeout": timeout})
        a = self.answers.pop(0)
        if isinstance(a, BaseException):
            raise a
        status, body = a
        return _Resp(status, body if isinstance(body, bytes) else json.dumps(body).encode())


def _client(*answers, killswitch=None):
    c = RunnerClient("http://127.0.0.1:18765", TOKEN, killswitch=killswitch)
    c._opener = FakeOpener(*answers)
    return c


def _cancel_body(outcome: str, rid=RID, sid=SID, audit=True):
    return {"outcome": outcome, "request_id": str(rid), "session_id": str(sid),
            "audit_recorded": audit}


def _stop_body(outcome="engaged", latch="STOPPED", durable=True, audit=True, job="none"):
    return {"outcome": outcome, "latch": latch, "durable": durable, "audit_recorded": audit,
            "active_job": job}


# --- RunnerClient.cancel ------------------------------------------------------------------


@pytest.mark.parametrize("outcome,confirmed", [
    ("cancellation_applied", True), ("already_cancelled", True), ("already_finished", True),
    ("not_active", True), ("cancellation_requested", False), ("identifier_mismatch", False),
])
def test_cancel_outcomes(outcome, confirmed):
    c = _client((200, _cancel_body(outcome)))
    res = c.cancel(RID, SID, CancelReason.CLIENT_INTERRUPT)
    assert res.category == "ok" and res.cancel.outcome is CancelOutcome(outcome)
    assert res.cancel_confirmed is confirmed
    call = c._opener.calls[0]
    assert call["url"].endswith("/v1/tools/cancel") and call["method"] == "POST"
    assert call["body"] == {"request_id": str(RID), "session_id": str(SID),
                            "reason": "client_interrupt"}  # exactly these three fields
    assert call["headers"]["Authorization"] == f"Bearer {TOKEN_TEXT}"
    assert call["timeout"] == 15.0


def test_cancel_unavailable_is_unconfirmed():
    res = _client((503, _cancel_body("cancellation_unavailable"))).cancel(
        RID, SID, CancelReason.OPERATOR_REQUEST)
    assert res.category == "ok" and not res.cancel_confirmed


@pytest.mark.parametrize("answer,category", [
    ((401, {"error": "unauthorized"}), "auth_failed"),
    ((404, {"error": "not_found"}), "unsupported"),       # Runner older than Stage 4
    ((405, {"error": "method_not_allowed"}), "unsupported"),
    ((400, {"stage": "invalid_request", "reason": "x"}), "rejected"),
    ((429, {"error": "rate_limited"}), "rate_limited"),
    ((503, {"error": "busy"}), "unavailable"),
    ((500, {"error": "internal_error"}), "unavailable"),
    ((409, {"stage": "cancelled", "reason": "x"}), "invalid_response"),
    ((200, b"not json"), "invalid_response"),
    ((200, [1, 2]), "invalid_response"),
    ((200, {**_cancel_body("cancellation_applied"), "extra": 1}), "invalid_response"),
    ((200, _cancel_body("cancellation_applied", rid=uuid.uuid4())), "invalid_response"),
    ((200, _cancel_body("cancellation_unavailable")), "invalid_response"),  # 200 vs 503 rule
    ((200, _cancel_body("made_up")), "invalid_response"),
    ((200, b"{" + b" " * (MAX_STOP_RESPONSE_BYTES + 10) + b"}"), "invalid_response"),
    (TimeoutError("timed out"), "transport"),
    (ConnectionResetError("reset"), "transport"),
    (urllib.error.URLError("refused"), "transport"),
])
def test_cancel_failures_never_confirm_and_never_retry(answer, category):
    c = _client(answer)
    res = c.cancel(RID, SID, CancelReason.OPERATOR_REQUEST)
    assert res.category == category and not res.cancel_confirmed
    assert len(c._opener.calls) == 1  # no retry
    assert TOKEN_TEXT not in repr(res) and TOKEN_TEXT not in res.detail


# --- RunnerClient.emergency_stop -----------------------------------------------------------


def test_emergency_stop_confirmed():
    c = _client((200, _stop_body()))
    res = c.emergency_stop(EmergencyReason.LOCAL_KILL_SWITCH)
    assert res.category == "ok" and res.emergency_confirmed
    call = c._opener.calls[0]
    assert call["url"].endswith("/v1/emergency-stop") and call["body"] == {
        "reason": "local_kill_switch"} and call["timeout"] == 20.0


@pytest.mark.parametrize("status,body,category,confirmed", [
    (503, _stop_body("not_durable", "CORRUPT", False, False), "ok", False),
    (503, _stop_body("engaged", "STOPPED", True, False), "ok", True),  # durable, audit failed
    # Latch reads STOPPED but the Runner says the write was NOT durable:
    # never "confirmed" (mutation testing found this case missing).
    (503, _stop_body("not_durable", "STOPPED", False, True), "ok", False),
    (200, _stop_body("not_durable", "READY", False, True), "invalid_response", False),
    (503, _stop_body("engaged", "STOPPED", True, True), "invalid_response", False),
    (200, {**_stop_body(), "reset": True}, "invalid_response", False),
    (404, {"error": "not_found"}, "unsupported", False),
    (503, {"stage": "internal_error", "reason": "x"}, "unavailable", False),
])
def test_emergency_stop_strict(status, body, category, confirmed):
    res = _client((status, body)).emergency_stop(EmergencyReason.OPERATOR_EMERGENCY_STOP)
    assert res.category == category and res.emergency_confirmed is confirmed


def test_stop_calls_only_reach_the_two_stop_endpoints():
    assert STOP_ONLY_PATHS == {"/v1/tools/cancel", "/v1/emergency-stop"}
    c = _client()
    for path in ("/v1/tools/run", "/v1/health", "/v1/emergency-stop/reset", "/v1/reset"):
        with pytest.raises(ValueError):
            c._stop_call(path, {}, 1.0)
    assert not [n for n in dir(RunnerClient) if "reset" in n.lower()]


# --- the stop-only transport and the kill switch -------------------------------------------


class Tunnels:
    def __init__(self, fail=None):
        self.opened = self.closed = 0
        self.cfgs: list = []
        self.fail = fail

    def __call__(self, cfg):
        outer = self
        outer.cfgs.append(cfg)

        class T:
            def __enter__(self):
                if outer.fail:
                    raise outer.fail
                outer.opened += 1
                return "http://127.0.0.1:18765"

            def __exit__(self, *a):
                outer.closed += 1
                return False

        return T()


class StopClient:
    """Fake Runner client for the stop path; records every call."""

    def __init__(self, cancel=None, emergency=None):
        self.cancel_answer, self.emergency_answer = cancel, emergency
        self.calls: list = []

    def __call__(self, base_url, token):
        return self

    def cancel(self, request_id, session_id, reason):
        self.calls.append(("cancel", request_id, session_id, reason))
        if isinstance(self.cancel_answer, BaseException):
            raise self.cancel_answer
        return self.cancel_answer

    def emergency_stop(self, reason):
        self.calls.append(("emergency_stop", reason))
        return self.emergency_answer

    def run(self, request):  # must never be reached on the stop path
        self.calls.append(("run",))
        raise AssertionError("run() on the stop path")

    def health(self):
        self.calls.append(("health",))
        return {"status": "ok"}


def _ok_cancel(outcome="cancellation_applied", rid=RID, sid=SID):
    return StopCallResult("ok", 200, cancel=CancelResponse.model_validate(
        _cancel_body(outcome, rid, sid)))


def _ok_stop(**kw):
    status = 200 if kw.get("durable", True) and kw.get("audit", True) else 503
    return StopCallResult("ok", status, emergency=EmergencyStopResponse.model_validate(
        _stop_body(**kw)))


@pytest.fixture
def engaged():
    ks = KillSwitch()
    ks.engage("stage5 test")
    return ks


def test_stop_only_client_exposes_only_stop_methods():
    assert StopOnlyClient.__slots__ == ("_client",)
    public = {n for n in dir(StopOnlyClient) if not n.startswith("_")}
    assert public == {"cancel", "emergency_stop"}
    s = StopOnlyClient(_client())
    for name in ("run", "health", "reset", "_call"):
        assert not hasattr(s, name)


def test_remote_stop_works_while_the_latch_blocks_and_never_runs(engaged):
    tunnels, client = Tunnels(), StopClient(emergency=_ok_stop())
    res = remote_emergency_stop(reason=EmergencyReason.LOCAL_KILL_SWITCH, token=TOKEN,
                                tunnel_cfg=TunnelConfig(), tunnel_factory=tunnels,
                                client_factory=client)
    assert res.emergency_confirmed and client.calls == [("emergency_stop",
                                                         EmergencyReason.LOCAL_KILL_SWITCH)]
    assert tunnels.opened == tunnels.closed == 1
    assert tunnels.cfgs[0].ready_timeout <= 15  # bounded
    assert engaged.status().latch is Latch.ENGAGED  # never disengaged to send it


def test_execution_stays_blocked_while_engaged(engaged, tmp_path):
    # 1. the scan pipeline: no tunnel, nothing sent
    from avra.policy.scope import ScopeChecker
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.schemas.scope import ActionTier, Scope, Target

    scope = Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                  targets=[Target(host="10.66.7.103", ports=[3000],
                                  allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                  allowed_tools=["nmap_connect_scan"])])
    tunnels = Tunnels()
    out = run_nmap_connect_scan(checker=ScopeChecker(scope), audit=AuditLog(tmp_path / "a.jsonl"),
                                session_id=SID, host="10.66.7.103", ports=[3000],
                                timeout_seconds=30, token=TOKEN, evidence_root=tmp_path / "ev",
                                tunnel_cfg=TunnelConfig(), tunnel_factory=tunnels,
                                client_factory=StopClient())
    assert not out.allowed_locally and tunnels.opened == 0
    # 2. the client itself refuses to send an execution request
    c = _client((200, {}))
    req = NmapConnectScanRequest(request_id=RID, session_id=SID, host="10.66.7.103",
                                 ports=[3000], timeout_seconds=30)
    with pytest.raises(KillSwitchEngaged):
        c.run(req)
    assert c._opener.calls == []
    # 3. model calls stay blocked
    from avra.llm.config import LLMConfig
    from avra.llm.provider import ApiKey, ClaudeProvider, LLMProviderError
    from tests.unit.test_llm_research import FakeClient, _sdk_message

    fake = FakeClient(_sdk_message())
    with pytest.raises(LLMProviderError):
        ClaudeProvider(LLMConfig(), ApiKey("sk-ant-" + "x" * 40), client=fake).complete(
            system=[], messages=[], tools=[])
    assert fake.messages.calls == []


def test_remote_stop_tunnel_failure_is_transport():
    res = remote_emergency_stop(reason=EmergencyReason.LOCAL_KILL_SWITCH, token=TOKEN,
                                tunnel_cfg=TunnelConfig(),
                                tunnel_factory=Tunnels(fail=TunnelError("no route")),
                                client_factory=StopClient())
    assert res.category == "transport" and not res.emergency_confirmed


def test_real_ssh_is_impossible_in_tests():
    from avra.runner_client.tunnel import SshTunnel

    with pytest.raises(TunnelError, match="disabled in the test suite"):
        SshTunnel(TunnelConfig(key_path=Path(__file__))).open()


# --- Ctrl+C in the scan and probe pipelines -------------------------------------------------


class PipelineClient:
    """Run-path fake: raises KeyboardInterrupt at a chosen point."""

    def __init__(self, interrupt_at="run"):
        self.interrupt_at, self.calls = interrupt_at, []

    def __call__(self, base_url, token):
        return self

    def health(self):
        self.calls.append("health")
        if self.interrupt_at == "health":
            raise KeyboardInterrupt

    def run(self, request):
        self.calls.append("run")
        self.request = request
        raise KeyboardInterrupt


class Combined:
    """client_factory used for BOTH the run and the later cancel tunnel."""

    def __init__(self, run_client, stop_client):
        self.run_client, self.stop_client, self.n = run_client, stop_client, 0

    def __call__(self, base_url, token):
        self.n += 1
        return self.run_client if self.n == 1 else self.stop_client


def _scope():
    from avra.policy.scope import ScopeChecker
    from avra.schemas.scope import ActionTier, Scope, Target

    return ScopeChecker(Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host="10.66.7.103", ports=[3000],
                                              allowed_tiers=[ActionTier.ACTIVE_SAFE,
                                                             ActionTier.PASSIVE],
                                              allowed_tools=["nmap_connect_scan",
                                                             "http_probe"])]))


def _scan(tmp_path, client_factory, tunnels, audit=None, notes=None):
    from avra.runner_client.scan import run_nmap_connect_scan

    return run_nmap_connect_scan(checker=_scope(), audit=audit or AuditLog(tmp_path / "s.jsonl"),
                                 session_id=SID, host="10.66.7.103", ports=[3000],
                                 timeout_seconds=30, token=TOKEN, evidence_root=tmp_path / "ev",
                                 tunnel_cfg=TunnelConfig(), tunnel_factory=tunnels,
                                 client_factory=client_factory,
                                 notify=(notes.append if notes is not None else None))


def _events(path):
    return [(r.event, r.data) for r in AuditLog(path).read_all()]


def test_interrupt_during_execution_cancels_this_job(tmp_path):
    run_c = PipelineClient("run")
    stop_c = StopClient(cancel=None)
    combined = Combined(run_c, stop_c)
    tunnels, notes = Tunnels(), []

    def answer(request_id, session_id, reason):  # Runner confirms for these exact ids
        return _ok_cancel(rid=request_id, sid=session_id)

    stop_c.cancel = lambda r, s, why: (stop_c.calls.append(("cancel", r, s, why)),
                                       answer(r, s, why))[1]
    with pytest.raises(KeyboardInterrupt):  # never swallowed
        _scan(tmp_path, combined, tunnels, notes=notes)
    [(_, rid, sid, why)] = stop_c.calls
    assert rid == run_c.request.request_id and sid == SID
    assert why is CancelReason.CLIENT_INTERRUPT
    events = [e for e, _ in _events(tmp_path / "s.jsonl")]
    assert events == ["tool_request_sent", "tool_request_interrupted", "remote_cancel_requested",
                      "remote_cancel_confirmed"]
    assert "tool_result_received" not in events  # nothing fabricated
    assert tunnels.opened == tunnels.closed == 2  # run tunnel + one fresh stop tunnel
    assert not (tmp_path / "ev").exists()  # no evidence
    assert any("confirmed" in n for n in notes)
    assert KillSwitch().active_work() == []  # gate marker released


def test_ctrl_c_is_not_held_back_by_a_blocking_socket_read(tmp_path):
    """Stage 7 finding: on Windows a KeyboardInterrupt waits until a blocking
    C-level socket read returns (measured live: 67 s, the job's own timeout),
    so the cancel came too late. The run call is now interruptible."""
    import _thread

    a, b = socket.socketpair()

    class BlockedInRecv(PipelineClient):
        def run(self, request):
            self.request = request
            a.recv(1)  # blocks in C, like urllib waiting for the Runner's answer

    stop_c = StopClient(cancel=_ok_cancel())
    threading.Timer(1.0, _thread.interrupt_main).start()
    release = threading.Timer(12.0, lambda: b.send(b"x"))  # old code: only here
    release.start()
    t0 = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            _scan(tmp_path, Combined(BlockedInRecv("none"), stop_c), Tunnels())
        elapsed = time.monotonic() - t0
        assert elapsed < 6, f"Ctrl+C held back {elapsed:.1f}s by a blocking read"
        assert [c[0] for c in stop_c.calls] == ["cancel"]  # sent while the job runs
    finally:
        release.cancel()
        b.send(b"x")  # let the abandoned worker thread finish
        a.close()
        b.close()


def test_interrupt_before_submission_cancels_nothing(tmp_path):
    run_c = PipelineClient("health")
    tunnels = Tunnels()
    with pytest.raises(KeyboardInterrupt):
        _scan(tmp_path, Combined(run_c, StopClient()), tunnels)
    ev = _events(tmp_path / "s.jsonl")
    assert [e for e, _ in ev] == ["tool_request_sent", "tool_request_interrupted"]
    assert ev[1][1]["submitted"] is False and tunnels.opened == 1


@pytest.mark.parametrize("answer,confirmed", [
    (_ok_cancel("already_cancelled"), True),       # disconnect-cancel already did it (race)
    (_ok_cancel("already_finished"), True),        # it finished as Ctrl+C arrived
    (_ok_cancel("cancellation_requested"), False),
    (StopCallResult("transport", detail="tunnel: refused"), False),
    (StopCallResult("unsupported", 404), False),   # old Runner
])
def test_interrupt_outcomes_are_recorded_honestly(tmp_path, answer, confirmed):
    run_c = PipelineClient("run")
    stop_c = StopClient(cancel=answer)
    notes: list = []
    with pytest.raises(KeyboardInterrupt):
        _scan(tmp_path, Combined(run_c, stop_c), Tunnels(), notes=notes)
    last_event = _events(tmp_path / "s.jsonl")[-1][0]
    assert last_event == ("remote_cancel_confirmed" if confirmed else "remote_cancel_unconfirmed")
    if not confirmed:
        assert any(REMOTE_UNCONFIRMED in n and "may still be running" in n for n in notes)


def test_second_interrupt_during_cancel_is_unconfirmed(tmp_path):
    stop_c = StopClient(cancel=KeyboardInterrupt())
    notes: list = []
    with pytest.raises(KeyboardInterrupt):
        _scan(tmp_path, Combined(PipelineClient("run"), stop_c), Tunnels(), notes=notes)
    event, data = _events(tmp_path / "s.jsonl")[-1]
    assert event == "remote_cancel_unconfirmed" and data["category"] == "interrupted"


def test_audit_failure_never_skips_the_cancel(tmp_path):
    class NoInterruptRecords(AuditLog):
        def record(self, event, data=None):
            if event in ("tool_request_interrupted", "remote_cancel_requested"):
                raise OSError("disk full")
            return super().record(event, data)

    stop_c = StopClient(cancel=_ok_cancel())
    with pytest.raises(KeyboardInterrupt):
        _scan(tmp_path, Combined(PipelineClient("run"), stop_c), Tunnels(),
              audit=NoInterruptRecords(tmp_path / "s.jsonl"))
    assert [c[0] for c in stop_c.calls] == ["cancel"]


def test_http_probe_interrupt_is_cancelled_too(tmp_path):
    from avra.runner_client import http_probe as pipeline

    stop_c = StopClient(cancel=_ok_cancel())
    with pytest.raises(KeyboardInterrupt):
        pipeline.run_http_probe(checker=_scope(), audit=AuditLog(tmp_path / "p.jsonl"),
                                session_id=SID, host="10.66.7.103", port=3000,
                                timeout_seconds=5, token=TOKEN, evidence_root=tmp_path / "ev",
                                tunnel_cfg=TunnelConfig(),
                                approval=pipeline.APPROVAL_INTERACTIVE_TTY,
                                tunnel_factory=Tunnels(),
                                client_factory=Combined(PipelineClient("run"), stop_c))
    assert [c[0] for c in stop_c.calls] == ["cancel"]
    assert _events(tmp_path / "p.jsonl")[-1][0] == "remote_cancel_confirmed"


def test_research_interrupted_mid_scan_aborts_and_replays(tmp_path):
    from avra.core.research import ResearchSession, StopReason
    from avra.llm.config import SessionLimits
    from avra.llm.tools import PROPOSE_SCAN
    from avra.reporting.replay import find_runs, replay_result
    from tests.unit.test_llm_research import PROPOSAL, FakeProvider, _resp, _use

    audit = AuditLog(tmp_path / "r.jsonl")
    stop_c = StopClient(cancel=_ok_cancel())

    def execute(p):
        from avra.runner_client.scan import run_nmap_connect_scan

        return run_nmap_connect_scan(checker=_scope(), audit=audit, session_id=SID,
                                     host=p.host, ports=list(p.ports),
                                     timeout_seconds=p.timeout_seconds, token=TOKEN,
                                     evidence_root=tmp_path / "ev", tunnel_cfg=TunnelConfig(),
                                     tunnel_factory=Tunnels(),
                                     client_factory=Combined(PipelineClient("run"), stop_c))

    session = ResearchSession(provider=FakeProvider([_resp("tool_use",
                                                           [_use(PROPOSE_SCAN, 1, **PROPOSAL)])]),
                              checker=_scope(), audit=audit, session_id=SID,
                              limits=SessionLimits(), approve=lambda v: True, execute=execute)
    result = session.run("check the web port")
    assert result.stop_reason is StopReason.ABORTED and result.outcomes == []
    events = [r.event for r in audit.read_all()]
    assert events[-2:] == ["remote_cancel_confirmed", "research_stopped"]
    replayed, _checks = replay_result(find_runs(audit.read_all())[-1], SID, tmp_path / "ev")
    assert replayed.stop_reason is StopReason.ABORTED  # reports still rebuild
    assert audit.verify()


def test_cancelled_runner_result_is_never_evidence(tmp_path):
    from avra.core.research import classify_result
    from avra.runner.schemas import ToolRunResult
    from avra.runner_client.client import RunOutcome

    class Cancelled(PipelineClient):
        def run(self, request):
            return RunOutcome(200, result=ToolRunResult(
                request_id=request.request_id, tool="nmap_connect_scan",
                status=ToolRunStatus.CANCELLED, reason="cancelled (operator_request)",
                started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=-15))

    out = _scan(tmp_path, Cancelled("none"), Tunnels())
    assert not out.ok and out.evidence is None and classify_result(out)[0] == "cancelled"
    assert classify_result(out)[0] != "timed_out"


# --- avra kill: local + remote --------------------------------------------------------------


@pytest.fixture
def cli(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from avra.cli import main

    calls: list = []
    answer = {"res": _ok_stop()}

    def fake_remote(kali, key):
        calls.append(KillSwitch().status().latch)  # local state AT the remote call
        a = answer["res"]
        if isinstance(a, BaseException):
            raise a
        return a

    monkeypatch.setattr(main, "_remote_emergency_stop", fake_remote)
    monkeypatch.setattr(main, "_killswitch", lambda: KillSwitch())
    return CliRunner(), main, calls, answer


def _control_events():
    ks = KillSwitch()
    return [r.event for r in inspect_audit_file(ks.audit_path).records]


def test_kill_case_a_both_confirmed(cli):
    runner, main, calls, _a = cli
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 0, r.output
    assert "LOCAL STOP ENGAGED" in r.output and "REMOTE EMERGENCY STOP CONFIRMED" in r.output
    assert calls == [Latch.ENGAGED]  # the local latch was engaged FIRST
    assert _control_events() == ["kill_switch_engaged", "remote_emergency_stop_requested",
                                 "remote_emergency_stop_confirmed"]


@pytest.mark.parametrize("res,text", [
    (StopCallResult("transport", detail="tunnel: no route"), "REMOTE EMERGENCY STOP UNCONFIRMED"),
    (StopCallResult("invalid_response", 200), "REMOTE EMERGENCY STOP UNCONFIRMED"),
    (StopCallResult("auth_failed", 401), "REMOTE EMERGENCY STOP UNCONFIRMED"),
    (StopCallResult("rate_limited", 429), "REMOTE EMERGENCY STOP UNCONFIRMED"),
    (StopCallResult("config", detail="AVRA_RUNNER_TOKEN is not set"),
     "REMOTE EMERGENCY STOP UNCONFIRMED"),
    (StopCallResult("unsupported", 404), "REMOTE STOP UNSUPPORTED OR UNCONFIRMED"),
])
def test_kill_remote_failures_are_never_success(cli, res, text):
    runner, main, _calls, answer = cli
    answer["res"] = res
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 4 and "LOCAL STOP ENGAGED" in r.output and text in r.output
    assert "REMOTE EMERGENCY STOP CONFIRMED" not in r.output
    assert KillSwitch().status().latch is Latch.ENGAGED


@pytest.mark.parametrize("res", [_ok_stop(outcome="not_durable", latch="CORRUPT", durable=False,
                                          audit=False),
                                 _ok_stop(outcome="not_durable", latch="STOPPED", durable=False),
                                 _ok_stop(audit=False)])
def test_kill_case_c_not_durably_confirmed(cli, res):
    runner, main, _calls, answer = cli
    answer["res"] = res
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 4 and "REMOTE EMERGENCY STOP NOT DURABLY CONFIRMED" in r.output


def test_kill_case_d_local_failure_still_tries_remote_but_fails(cli, monkeypatch):
    from avra.control import killswitch as ks_mod

    runner, main, calls, _a = cli

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(ks_mod, "_replace", boom)
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 1 and "LOCAL STOP FAILED" in r.output
    assert "it can only stop work" in r.output and len(calls) == 1
    assert "LOCAL STOP ENGAGED" not in r.output


def test_kill_interrupted_remote_is_unconfirmed(cli):
    runner, main, _calls, answer = cli
    answer["res"] = KeyboardInterrupt()
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 4 and "UNCONFIRMED (interrupted" in r.output


def test_kill_local_audit_failure_still_sends_remote(cli, monkeypatch):
    runner, main, calls, _a = cli
    real = AuditLog.record

    def no_engage_record(self, event, data=None):
        if event == "kill_switch_engaged":
            raise OSError("disk full")
        return real(self, event, data)

    monkeypatch.setattr(AuditLog, "record", no_engage_record)
    r = runner.invoke(main.app, ["kill"])
    assert r.exit_code == 1 and len(calls) == 1 and "REMOTE EMERGENCY STOP CONFIRMED" in r.output


def test_kill_local_only_never_contacts_the_runner(cli):
    runner, main, calls, _a = cli
    r = runner.invoke(main.app, ["kill", "--local-only"])
    assert r.exit_code == 0 and calls == [] and "REMOTE: not attempted" in r.output


def test_repeated_and_concurrent_kill(cli):
    import typer

    runner, main, calls, _a = cli
    assert runner.invoke(main.app, ["kill"]).exit_code == 0
    assert runner.invoke(main.app, ["kill"]).exit_code == 0  # idempotent, remote asked again
    codes: list = []

    def one():
        try:
            main.kill(status=False, reset=False, reason="concurrent", local_only=False,
                      kali="192.168.56.104", key=None)
            codes.append(0)
        except typer.Exit as exc:  # anything else must fail the test loudly
            codes.append(exc.exit_code)

    threads = [threading.Thread(target=one) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert codes == [0, 0, 0, 0] and len(calls) == 6
    assert inspect_audit_file(KillSwitch().audit_path).verification.ok


def test_reset_is_local_only_and_keeps_the_remote_history(cli, monkeypatch):
    runner, main, calls, answer = cli
    answer["res"] = StopCallResult("transport", detail="tunnel: no route")
    runner.invoke(main.app, ["kill"])
    monkeypatch.setattr(main, "_interactive", lambda: True)
    r = runner.invoke(main.app, ["kill", "--reset"], input="maintenance\nRESET\n")
    assert r.exit_code == 0 and len(calls) == 1  # reset never contacted the Runner
    assert "does NOT reset the Kali Runner" in r.output
    st = runner.invoke(main.app, ["kill", "--status"])
    assert "remote_emergency_stop_unconfirmed" in st.output  # not hidden by the reset
    assert runner.invoke(main.app, ["kill", "--reset", "--local-only"]).exit_code == 1


def test_record_event_only_accepts_remote_stop_events():
    ks = KillSwitch()
    with pytest.raises(ValueError):
        ks.record_event("kill_switch_reset", {})


# --- end to end against the real Stage 4 Runner app (loopback only) ------------------------


@pytest.fixture
def live_runner(tmp_path):
    import uvicorn

    from tests.security.test_runner_cancellation import TOKEN as RUNNER_TOKEN
    from tests.security.test_runner_cancellation import Http, World

    world = World(tmp_path)
    http = Http(world)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(http.app, host="127.0.0.1", port=port,
                                           log_level="error", lifespan="off", http="h11",
                                           ws="none"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    client = RunnerClient(f"http://127.0.0.1:{port}", RunnerToken(RUNNER_TOKEN))
    try:
        yield world, client
    finally:
        world.executor.release.set()
        server.should_exit = True
        th.join(10)


def test_real_client_against_real_stage4_runner(live_runner):
    world, client = live_runner
    req = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                 host="10.66.7.103", ports=[3000], timeout_seconds=30)
    box: dict = {}
    t = threading.Thread(target=lambda: box.setdefault("run", client.run(req)))
    t.start()
    assert world.executor.started.wait(10)
    res = client.cancel(req.request_id, req.session_id, CancelReason.CLIENT_INTERRUPT)
    t.join(10)
    assert res.category == "ok" and res.cancel.outcome is CancelOutcome.APPLIED
    assert box["run"].result.status is ToolRunStatus.CANCELLED  # client parses it
    again = client.cancel(req.request_id, req.session_id, CancelReason.CLIENT_INTERRUPT)
    assert again.cancel.outcome is CancelOutcome.ALREADY_CANCELLED and again.cancel_confirmed
    stop = client.emergency_stop(EmergencyReason.LOCAL_KILL_SWITCH)
    assert stop.category == "ok" and stop.emergency_confirmed
    nxt = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                 host="10.66.7.103", ports=[3000], timeout_seconds=30)
    out = client.run(nxt)  # local latch is disengaged in this test; the Runner refuses
    assert out.rejection is not None and out.rejection.stage.value == "emergency_stop"


def test_real_client_with_wrong_token_is_auth_failed(live_runner):
    _world, client = live_runner
    bad = RunnerClient(client._base, RunnerToken("W" * 40))
    assert bad.emergency_stop(EmergencyReason.LOCAL_KILL_SWITCH).category == "auth_failed"
    assert bad.cancel(RID, SID, CancelReason.OPERATOR_REQUEST).category == "auth_failed"
