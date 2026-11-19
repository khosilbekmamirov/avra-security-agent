"""M14.2 (ADR 0022 Option A): research controller, end to end and OFFLINE.

The real planner, engine, evidence store and audited http_probe/http_get_path pipeline run
against a SIMULATED-FIXTURE target (192.168.56.250:8080) through the stand-in tunnel/Runner
in conftest. No network, no model, no Runner, no lab VM."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import HOST, PORT, _client, _Sock, _Tunnel, http_response

from avra.chat import knowledge as kb
from avra.control.killswitch import KillSwitch
from avra.policy.scope import ScopeChecker
from avra.research.controller import (
    DEFER,
    DENY,
    Controller,
    Decision,
    Ports,
    analyze_session,
    evidence_verifier,
)
from avra.research.investigation import (
    ActionStatus,
    Investigation,
    InvestigationError,
    InvState,
    RunLockBusy,
    run_lock,
)
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerToken
from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
from avra.runner_client.tunnel import TunnelConfig
from avra.schemas.scope import ActionTier, Scope, Target

ROOT = http_response(body=(b'<script src="/main.js"></script><a href="/app/page">p</a>'
                           b'<a href="/admin/panel">a</a>'))
MAIN = http_response(headers=(("Content-Type", "application/javascript"),),
                     body=b'fetch("/rest/products/search");fetch("/api/Users")')
PAGE = http_response(body=b"<html><title>page</title></html>")
BODIES = {"/main.js": MAIN, "/app/page": PAGE}


def scope(paths=("/main.js", "/app/")):
    return ScopeChecker(Scope(session_name="SIMULATED-FIXTURE",
                              expires_at=datetime.now(UTC) + timedelta(days=1),
                              targets=[Target(host=HOST, ports=[PORT],
                                              allowed_tiers=[ActionTier.PASSIVE],
                                              allowed_tools=["http_probe", "http_get_path"],
                                              http_paths=list(paths))]))


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)

    def __call__(self):
        return self.t


class Approver:
    """Approves by quoting the fingerprint (the CLI's typed-prefix + confirm, simulated)."""

    def __init__(self, answers=None):
        self.answers = list(answers or [])
        self.seen = []

    def __call__(self, act, explanation):
        self.seen.append((act, explanation))
        ans = self.answers.pop(0) if self.answers else "approve"
        if ans == "approve":
            return Decision.approve(act.fingerprint)
        return {"deny": DENY, "defer": DEFER}.get(ans, Decision.approve(ans))


class Runner:
    """Runs the REAL audited pipeline with the investigation's request id."""

    def __init__(self, lab, sid, checker, *, body=None):
        self.lab, self.sid, self.checker, self.body = lab, sid, checker, body
        self.calls = []

    def __call__(self, act, rid):
        self.calls.append((act.key, rid))
        from avra.storage.audit import AuditLog

        audit = AuditLog(self.lab.sessions / f"{self.sid}.jsonl")
        path = act.path or None
        body = self.body or BODIES.get(act.path, PAGE)
        env = child.probe(HOST, PORT, 5, socket_factory=lambda: _Sock([body]), path=path)
        out = run_http_probe(checker=self.checker, audit=audit, session_id=uuid.UUID(self.sid),
                             host=act.host, port=act.port, timeout_seconds=5,
                             token=RunnerToken("t" * 43), evidence_root=self.lab.evidence_root,
                             tunnel_cfg=TunnelConfig(), approval=APPROVAL_INTERACTIVE_TTY,
                             tunnel_factory=_Tunnel,
                             client_factory=_client(child.encode_envelope(env), act.tool),
                             path=path, request_id=uuid.UUID(rid))
        return {"ok": out.ok, "request_id": str(out.request.request_id), "errors": out.errors,
                "evidence_sha256": out.evidence.sha256 if out.evidence else None}


@pytest.fixture
def env(lab, monkeypatch):
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    sid = lab.http_session(ROOT)
    return lab, sid


def make(lab, sid, *, checker=None, decide=None, runner=None, kill=None, explain=None,
         clock=None, verify=None, max_actions=3, inv=None):
    checker = checker or scope()
    inv = inv or Investigation.create(lab.root / "inv", objective="map the app's API",
                                      session_id=sid, scope_name="SIMULATED-FIXTURE",
                                      clock=clock or Clock())
    runner = runner or Runner(lab, sid, checker)
    ports = Ports(analyze=lambda: analyze_session(sid, checker),
                  scope_check=lambda t, h, p, pa: kb.scope_allows(checker, t, h, p, pa),
                  decide=decide or Approver(), execute=runner,
                  verify_evidence=verify or evidence_verifier(lab.sessions, lab.evidence_root,
                                                              sid),
                  kill_reason=kill or (lambda: None), explain=explain)
    return Controller(inv, ports, max_actions=max_actions), inv, runner


def statuses(inv):
    return [(a.path, a.status) for a in inv.actions.values()]


# --- the happy path --------------------------------------------------------------------------

def test_planner_chooses_owner_approves_engine_reanalyses(env):
    lab, sid = env
    ctl, inv, runner = make(lab, sid)
    res = ctl.run()
    # the planner's best step comes first: the first-party bundle while no API is known
    assert runner.calls[0][0] == ("http_get_path", HOST, PORT, "/main.js")
    assert [k[3] for k, _ in runner.calls] == ["/main.js", "/app/page"]
    assert res.state in (InvState.COMPLETED, InvState.INCONCLUSIVE) and not res.paused
    assert all(a.status is ActionStatus.SUCCEEDED for a in inv.actions.values())
    # every executed request id is the one recorded BEFORE sending, and it is in the
    # session audit with a hash-checked evidence file
    from avra.storage.audit import AuditLog

    sent = {r.data["request_id"] for r in AuditLog(lab.sessions / f"{sid}.jsonl").read_all()
            if r.event == "tool_request_sent"}
    refs = lab.evidence(sid).refs()
    for a in inv.actions.values():
        assert a.request_id in sent and refs[a.request_id].sha256 == a.evidence_sha256
    assert [n["data"]["evidence_verified"] for n in inv.notes if n["kind"] == "verification"] \
        == [True, True]
    # /admin/panel and the API routes are outside the scope prefixes: never proposed
    assert all(a.path in ("/main.js", "/app/page") for a in inv.actions.values())
    # the phases the brief asks for, in order
    seq = [to for _f, to, _w in inv.history]
    assert seq[:6] == ["OBSERVING", "ANALYZING", "PLANNING", "WAITING_APPROVAL", "EXECUTING",
                       "VERIFYING"]
    assert inv.verify()
    again = Investigation.load(lab.root / "inv", inv.investigation_id)
    assert again.snapshot() == inv.snapshot()


def test_action_limit_stops_inconclusive(env):
    lab, sid = env
    ctl, _inv, runner = make(lab, sid, max_actions=1)
    res = ctl.run()
    assert len(runner.calls) == 1
    assert res.state is InvState.INCONCLUSIVE and "action limit" in res.message


# --- owner decisions -----------------------------------------------------------------------

def test_non_interactive_defers_and_resume_continues(env):
    lab, sid = env
    ctl, inv, runner = make(lab, sid, decide=Approver(["defer"]))
    res = ctl.run()
    assert res.paused and inv.state is InvState.WAITING_APPROVAL and runner.calls == []
    inv2 = Investigation.load(lab.root / "inv", inv.investigation_id, clock=Clock())
    ctl2, _, runner2 = make(lab, sid, inv=inv2)
    ctl2.run()
    assert runner2.calls[0][0][3] == "/main.js"


def test_denied_action_is_never_reproposed(env):
    lab, sid = env
    ctl, inv, runner = make(lab, sid, decide=Approver(["deny"]))
    ctl.run()
    assert statuses(inv)[0] == ("/main.js", ActionStatus.DENIED)
    assert [k[3] for k, _ in runner.calls] == ["/app/page"]
    assert sum(1 for p, _ in statuses(inv) if p == "/main.js") == 1


def test_wrong_fingerprint_is_refused_and_nothing_runs(env):
    lab, sid = env
    ctl, inv, runner = make(lab, sid, decide=Approver(["0" * 64, "deny"]))
    ctl.run()
    assert statuses(inv)[:2] == [("/main.js", ActionStatus.DENIED),
                                 ("/app/page", ActionStatus.DENIED)]
    assert runner.calls == []


def test_expired_approval_is_reproposed_with_a_new_fingerprint(env):
    lab, sid = env
    clock = Clock()

    class Slow(Approver):
        def __call__(self, act, explanation):
            if len(self.seen) == 0:
                clock.t += timedelta(minutes=16)  # the owner answered too late
            return super().__call__(act, explanation)

    ctl, inv, runner = make(lab, sid, decide=Slow(), clock=clock, max_actions=1)
    ctl.run()
    first, second = list(inv.actions.values())[:2]
    assert first.status is ActionStatus.EXPIRED and first.path == "/main.js"
    assert second.path == "/main.js" and second.status is ActionStatus.SUCCEEDED
    assert first.fingerprint != second.fingerprint
    assert len(runner.calls) == 1


def test_scope_narrowed_after_proposal_is_refused_at_approval(env):
    lab, sid = env
    allowed = {"on": True}
    checker = scope()

    def decide(act, explanation):
        allowed["on"] = False  # the scope changes while the owner is deciding
        return Decision.approve(act.fingerprint)

    ctl, inv, runner = make(lab, sid, checker=checker, decide=decide)
    ctl.p.scope_check = lambda t, h, p, pa: allowed["on"] and kb.scope_allows(checker, t, h, p,
                                                                              pa)
    ctl.run()
    assert runner.calls == []
    assert statuses(inv)[0] == ("/main.js", ActionStatus.DENIED)


# --- kill switch ---------------------------------------------------------------------------

def test_kill_switch_mid_loop_cancels_without_another_request(env):
    lab, sid = env
    ks = KillSwitch()
    runner_box = {}

    def kill():
        st = ks.status()
        return st.detail if st.blocking else None

    class EngageAfterFirst(Runner):
        def __call__(self, act, rid):
            out = super().__call__(act, rid)
            ks.engage("test: stop after the first action")
            return out

    checker = scope()
    runner_box["r"] = EngageAfterFirst(lab, sid, checker)
    ctl, _inv, runner = make(lab, sid, checker=checker, runner=runner_box["r"], kill=kill)
    res = ctl.run()
    assert res.state is InvState.CANCELLED and "kill switch" in res.message
    assert len(runner.calls) == 1


def test_kill_switch_between_approval_and_start_sends_nothing(env):
    lab, sid = env
    flag = {"on": False}

    def decide(act, explanation):
        flag["on"] = True
        return Decision.approve(act.fingerprint)

    ctl, inv, runner = make(lab, sid, decide=decide,
                            kill=lambda: "ENGAGED" if flag["on"] else None)
    res = ctl.run()
    assert res.state is InvState.CANCELLED and runner.calls == []
    act = next(iter(inv.actions.values()))
    assert act.status is ActionStatus.DENIED and act.request_id is None
    assert not any(r.event == "action_started" for r in inv._log.read_all())


def test_pipeline_kill_switch_is_still_enforced(env):
    """Even if the controller's own check were bypassed, the pipeline refuses."""
    lab, sid = env
    KillSwitch().engage("test")
    ctl, inv, _runner = make(lab, sid)  # controller's kill check stubbed to "not blocking"
    ctl.run()
    acts = list(inv.actions.values())
    assert acts and all(a.status is ActionStatus.FAILED for a in acts)
    from avra.storage.audit import AuditLog

    recs = AuditLog(lab.sessions / f"{sid}.jsonl").read_all()
    denied = [r for r in recs if r.event == "tool_request_denied_locally"]
    assert denied and all(r.data["reason"] == "kill switch engaged" for r in denied)


# --- at most once: interruption and recovery -----------------------------------------------

def test_interrupted_execution_is_never_rerun(env):
    lab, sid = env

    class Crash(Runner):
        def __call__(self, act, rid):
            self.calls.append((act.key, rid))
            raise KeyboardInterrupt  # power cut / Ctrl+C while the request may be in flight

    checker = scope()
    ctl, inv, runner = make(lab, sid, checker=checker, runner=Crash(lab, sid, checker))
    with pytest.raises(KeyboardInterrupt):
        ctl.run()
    assert inv.state is InvState.EXECUTING  # nothing more was written
    view = Investigation.load(lab.root / "inv", inv.investigation_id, reconcile=False)
    assert view.state is InvState.EXECUTING  # read-only view writes nothing
    recovered = Investigation.load(lab.root / "inv", inv.investigation_id)
    act = next(iter(recovered.actions.values()))
    assert act.status is ActionStatus.INTERRUPTED and recovered.state is InvState.FAILED
    ctl2, _, runner2 = make(lab, sid, inv=recovered)
    res = ctl2.run()
    assert res.state is InvState.FAILED and runner2.calls == [] and len(runner.calls) == 1
    assert recovered.verify()


def test_approved_but_unstarted_action_lapses_on_resume(env):
    lab, sid = env
    ctl, inv, _runner = make(lab, sid, decide=Approver(["defer"]))
    ctl.run()
    act = inv.pending()[0]
    inv.approve(act.action_id, act.fingerprint, scope_check=ctl.p.scope_check)
    # the process dies here, before begin_execution
    inv2 = Investigation.load(lab.root / "inv", inv.investigation_id, clock=Clock())
    ctl2, _, runner2 = make(lab, sid, inv=inv2, max_actions=1)
    ctl2.run()
    assert inv2.actions[act.action_id].status is ActionStatus.EXPIRED  # never reused
    assert len(runner2.calls) == 1  # it ran once, after a FRESH proposal and approval
    fresh = next(a for a in inv2.actions.values() if a.action_id != act.action_id)
    assert fresh.path == act.path and fresh.fingerprint != act.fingerprint


def test_run_lock_is_exclusive(env, tmp_path):
    _lab, sid = env
    inv = Investigation.create(tmp_path, objective="x", session_id=sid)
    with run_lock(tmp_path, inv.investigation_id), pytest.raises(RunLockBusy), \
            run_lock(tmp_path, inv.investigation_id, timeout=0.1):
        pass
    with run_lock(tmp_path, inv.investigation_id):
        pass  # released


# --- execution results ---------------------------------------------------------------------

def test_executor_exception_fails_the_action_and_the_loop_moves_on(env):
    lab, sid = env

    class Boom(Runner):
        def __call__(self, act, rid):
            self.calls.append((act.key, rid))
            if act.path == "/main.js":
                raise OSError("token sk-ant-api03-SECRETSECRETSECRET leaked?")
            return super().__call__(act, rid)

    checker = scope()
    ctl, inv, runner = make(lab, sid, checker=checker, runner=Boom(lab, sid, checker))
    ctl.run()
    first = next(iter(inv.actions.values()))
    assert first.status is ActionStatus.FAILED and first.errors == ["OSError"]
    assert "SECRET" not in inv._log.path.read_text(encoding="utf-8")
    assert [k[3] for k, _ in runner.calls].count("/main.js") == 1


def test_success_without_evidence_or_with_foreign_request_id_is_failed(env):
    lab, sid = env
    answers = [{"ok": True, "evidence_sha256": None},
               {"ok": True, "request_id": str(uuid.uuid4()), "evidence_sha256": "a" * 64}]

    def runner(act, rid):
        runner.calls.append((act.key, rid))
        r = answers.pop(0)
        return {"request_id": rid, **r}
    runner.calls = []
    ctl, inv, _ = make(lab, sid, runner=runner)
    ctl.run()
    a, b = list(inv.actions.values())[:2]
    assert a.status is ActionStatus.FAILED and "no evidence recorded" in a.errors
    assert b.status is ActionStatus.FAILED and "result request id does not match" in b.errors


def test_unverifiable_evidence_fails_the_investigation(env):
    lab, sid = env
    ctl, _inv, runner = make(lab, sid, verify=lambda rid, sha: False)
    res = ctl.run()
    assert res.state is InvState.FAILED and "did not verify" in res.message
    assert len(runner.calls) == 1


def test_evidence_verifier_checks_hash_and_request_id(env):
    lab, sid = env
    ctl, inv, _runner = make(lab, sid, max_actions=1)
    ctl.run()
    a = next(iter(inv.actions.values()))
    v = evidence_verifier(lab.sessions, lab.evidence_root, sid)
    assert v(a.request_id, a.evidence_sha256)
    assert not v(a.request_id, "0" * 64)
    assert not v(str(uuid.uuid4()), a.evidence_sha256)


def test_terminal_investigation_cannot_be_driven(env):
    lab, sid = env
    ctl, inv, _ = make(lab, sid, max_actions=1)
    ctl.run()
    assert inv.terminal
    with pytest.raises(InvestigationError):
        inv.transition(InvState.PLANNING)
    assert ctl.run().message == "investigation already ended"
