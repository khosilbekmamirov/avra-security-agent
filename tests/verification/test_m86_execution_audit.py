"""M8.6 — Safe Tool Execution & Audit: acceptance regression tests (offline).

Covers G3b (refused verify_hypothesis requests are audited), G3 (hash of
every model-facing payload actually sent), Windows-side audit-write
failures failing closed, replayed Runner requests being re-checked and
re-audited, audit-chain integrity limits, and the reporting clarifications
G1/G2/G4. Real AVRA components; fakes only for the model, tunnel and Runner.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import HOST, PORT, http_response, nmap_xml
from test_research_loop import FakeModel, Session, _resp

from avra.llm.tools import FINISH, PROPOSE_SCAN, VERIFY_HYPOTHESIS
from avra.policy.scope import ScopeChecker
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.audit import AuditLog
from avra.verification.cycle import RuleBasedProposer
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.report import render_text, run_verification

NOSNIFF = "http.missing_x_content_type_options"


def _events(audit):
    return [r for r in audit.read_all()]


def _of(audit, name):
    return [r.data for r in audit.read_all() if r.event == name]


# --- G3b: refused verify_hypothesis requests are audited --------------------------------------

@pytest.mark.parametrize("call,status", [
    ({"rule_id": NOSNIFF, "host": "10.66.7.103", "port": 3000}, "out_of_scope"),
    ({"rule_id": NOSNIFF, "host": HOST, "port": 9999}, "out_of_scope"),
    ({"rule_id": "NoDotRuleId", "host": HOST, "port": PORT}, "invalid"),
])
def test_refused_verify_requests_are_audited(lab, call, status):
    s = Session(lab)
    s.probe(http_response())
    seq = iter([_resp((VERIFY_HYPOTHESIS, {**call, "rationale": "SECRET-RATIONALE"})),
                _resp((FINISH, {"summary": "done"}))])
    _, model, loop = s.run(lambda st, n: next(seq))
    assert model.seen[1]["status"] == status
    (rec,) = _of(s.audit, "verification_request_refused")
    assert (rec["status"], rec["rule_id"], rec["host"], rec["port"], rec["step"]) == (
        status, call["rule_id"], call["host"], call["port"], 1)
    assert "SECRET-RATIONALE" not in json.dumps(rec)  # no free text stored
    assert all(e.hypothesis.origin.value != "model" for e in loop.entries.values())


def test_budget_exhausted_verify_request_is_audited(lab):
    s = Session(lab)
    s.probe(http_response())  # the rules use up the whole budget at session start
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": "net.tcp_port_open", "host": HOST,
                                           "port": PORT, "rationale": "x"})),
                _resp((FINISH, {"summary": "done"}))])
    model = FakeModel(lambda st, n: next(seq))
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root, max_verifications=2))
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    ResearchSession(provider=model, checker=lab.checker, audit=s.audit,
                    session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=4),
                    approve=lambda v: False, execute=s.execute,
                    verification=loop).run("check")
    (rec,) = _of(s.audit, "verification_request_refused")
    assert rec["status"] == "budget" and rec["verifications_used"] == 2
    assert model.seen[1]["status"] == "budget"


def test_refusals_appear_in_the_verification_report(lab):
    s = Session(lab)
    s.probe(http_response())
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": "10.66.7.103",
                                           "port": 3000, "rationale": "x"})),
                _resp((FINISH, {"summary": "done"}))])
    s.run(lambda st, n: next(seq))
    rep = s.report().report
    (r,) = rep["research_loop"]["refused_requests"]
    assert (r["status"], r["host"]) == ("out_of_scope", "10.66.7.103")
    assert any("refused model request" in line for line in render_text(rep))


# --- G3: model-facing payloads are hashed exactly when sent -----------------------------------

class Capture(FakeModel):
    def __init__(self, policy):
        super().__init__(policy)
        self.requests = []

    def complete(self, *, system, messages, tools):
        self.requests.append((system, [dict(m) for m in messages], tools))
        return super().complete(system=system, messages=messages, tools=tools)


def _sent_payloads(model):
    """Every payload of every request, in first-sent order (deduplicated)."""
    seen, out = set(), []
    for _system, messages, _tools in model.requests:
        for i, m in enumerate(messages):
            if m["role"] != "user":
                continue
            items = [(f"m{i}", None, m["content"])] if isinstance(m["content"], str) else [
                (f"m{i}b{j}", b["tool_use_id"], b["content"])
                for j, b in enumerate(m["content"]) if b.get("type") == "tool_result"]
            for key, tid, text in items:
                if key not in seen:
                    seen.add(key)
                    out.append((tid, text))
    return out


@pytest.mark.parametrize("verification", [True, False])
def test_every_sent_payload_has_a_matching_hash_record(lab, verification):
    s = Session(lab)
    s.probe(http_response())
    script = iter([
        _resp((VERIFY_HYPOTHESIS, {"rule_id": "net.tcp_port_open", "host": HOST, "port": PORT,
                                   "rationale": "x"})) if verification else
        _resp(("record_observation", {"summary": "HTTP answered.",
                                      "evidence_request_id": None})),
        _resp((PROPOSE_SCAN, {"host": HOST, "ports": [PORT], "timeout_seconds": 30,
                              "explanation": "Check whether the port is open."})),
        _resp((FINISH, {"summary": "done"})),
    ])
    model = Capture(lambda st, n: next(script))
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root)) if verification else None
    ResearchSession(provider=model, checker=lab.checker, audit=s.audit,
                    session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=5),
                    approve=lambda v: True, execute=s.execute, verification=loop).run("x")
    recs = _of(s.audit, "model_feedback")
    sent = _sent_payloads(model)
    assert len(recs) == len(sent) == 3  # first message + 2 tool results (finish's never sent)
    for rec, (tid, text) in zip(recs, sent, strict=True):
        data = text.encode("utf-8")
        assert rec["sha256"] == hashlib.sha256(data).hexdigest() and rec["bytes"] == len(data)
        assert rec["tool_use_id"] == tid
    first = recs[0]
    assert first["kind"] == "first_message" and first["step"] == 1
    system = model.requests[0][0][0]["text"]
    assert first["system_sha256"] == hashlib.sha256(system.encode("utf-8")).hexdigest()
    assert [r["tool"] for r in recs[1:]] == [
        "verify_hypothesis" if verification else "record_observation",
        "propose_nmap_connect_scan"]
    assert [r["step"] for r in recs] == [1, 2, 3]  # recorded right before the call that sent it


def test_feedback_audit_failure_means_no_api_call(lab):
    s = Session(lab)

    class FailingFeedbackAudit(AuditLog):
        def record(self, event, data=None):
            if event == "model_feedback":
                raise OSError("disk full")
            return super().record(event, data)

    audit = FailingFeedbackAudit(s.audit.path)
    model = Capture(lambda st, n: pytest.fail("the model must not be called"))
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    with pytest.raises(OSError):
        ResearchSession(provider=model, checker=lab.checker, audit=audit,
                        session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=3),
                        approve=lambda v: True, execute=s.execute).run("x")
    assert model.requests == []


# --- Windows-side audit-write failures fail closed -------------------------------------------

def test_scan_pipeline_audit_failure_opens_no_tunnel(lab):
    from conftest import _client, _Tunnel

    from avra.runner_client.client import RunnerToken
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import TunnelConfig

    sid, audit = lab.new_session()
    opened = []

    class CountingTunnel(_Tunnel):
        def __enter__(self):
            opened.append(1)
            return super().__enter__()

    class FailOnSend(AuditLog):
        def record(self, event, data=None):
            if event == "tool_request_sent":
                raise OSError("disk full")
            return super().record(event, data)

    with pytest.raises(OSError):
        run_nmap_connect_scan(checker=lab.checker, audit=FailOnSend(audit.path),
                              session_id=uuid.UUID(sid), host=HOST, ports=[PORT],
                              timeout_seconds=30, token=RunnerToken("t" * 43),
                              evidence_root=lab.evidence_root, tunnel_cfg=TunnelConfig(),
                              tunnel_factory=CountingTunnel,
                              client_factory=_client(nmap_xml("open"), "nmap_connect_scan"))
    assert opened == []


@pytest.mark.parametrize("fail_on", ["llm_proposal", "owner_decision"])
def test_research_audit_failure_before_execution_runs_nothing(lab, fail_on):
    s = Session(lab)

    class Failing(AuditLog):
        def record(self, event, data=None):
            if event == fail_on:
                raise OSError("disk full")
            return super().record(event, data)

    model = FakeModel(lambda st, n: _resp((PROPOSE_SCAN, {
        "host": HOST, "ports": [PORT], "timeout_seconds": 30,
        "explanation": "Check whether the port is open."})))
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    with pytest.raises(OSError):
        ResearchSession(provider=model, checker=lab.checker, audit=Failing(s.audit.path),
                        session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=3),
                        approve=lambda v: True, execute=s.execute).run("x")
    assert s.executed == 0


def test_zero_tool_budget_never_reaches_approval_or_execution(lab):
    s = Session(lab)
    model = FakeModel(lambda st, n: _resp((PROPOSE_SCAN, {
        "host": HOST, "ports": [PORT], "timeout_seconds": 30,
        "explanation": "Check whether the port is open."})))
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    ResearchSession(provider=model, checker=lab.checker, audit=s.audit,
                    session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=2,
                                                                      max_tool_runs=0),
                    approve=lambda v: pytest.fail("no approval prompt"),
                    execute=s.execute).run("x")
    assert s.executed == 0
    reasons = [d["reason"] for d in _of(s.audit, "llm_proposal_rejected")]
    assert reasons and set(reasons) == {"tool_run_limit"}  # one per attempt, each audited


# --- replayed Runner requests are re-checked and re-audited (never silent) ---------------------

def test_replayed_runner_request_is_authorized_and_audited_again(tmp_path):
    from avra.runner.core import Runner
    from avra.runner.policy import RunnerPolicy
    from tests.unit.test_runner_core import (
        SCOPE_YAML,
        FakeExecutor,
        payload,
        proc_result,
    )

    scope = tmp_path / "scope.yaml"
    scope.write_text(SCOPE_YAML, encoding="utf-8")
    audit = AuditLog(tmp_path / "runner-audit.jsonl")
    executor = FakeExecutor(result=proc_result())
    runner = Runner(RunnerPolicy.from_scope_file(scope), executor, audit)
    good = payload()
    runner.handle(good)
    runner.handle(dict(good))  # exact replay, same request_id
    events = [r.event for r in audit.read_all()]
    assert events.count("request_received") == 2 and events.count("execution_started") == 2
    bad = payload(host="192.168.56.104")
    runner.handle(bad)
    runner.handle(dict(bad))
    assert len(executor.calls) == 2  # the out-of-scope replay never executed
    assert [r.event for r in audit.read_all()].count("request_denied") == 2
    assert audit.verify()


# --- audit-chain integrity and its documented limits -----------------------------------------

def _chain(tmp_path, n=5):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(n):
        log.record("e", {"i": i})
    return log


def _rewrite(log, lines):
    log.path.write_text("".join(lines), encoding="utf-8")


def test_chain_detects_edit_reorder_gap_and_insertion(tmp_path):
    log = _chain(tmp_path)
    lines = log.path.read_text(encoding="utf-8").splitlines(keepends=True)
    for mutated in (
        [*lines[:2], lines[2].replace('"i": 2', '"i": 9'), *lines[3:]],  # edit
        [lines[0], lines[2], lines[1], *lines[3:]],                    # reorder
        [*lines[:2], *lines[3:]],                                      # gap
        [*lines[:2], lines[1], *lines[2:]],                            # duplicate/insert
    ):
        _rewrite(log, mutated)
        assert not log.verify()


def test_tail_truncation_is_not_detected_by_the_chain_alone(tmp_path):
    """Documented limit (docs/threat-model.md T8): an unsigned hash chain
    cannot tell that its LAST records were removed; only an external anchor
    (an attested report, a copy elsewhere) can."""
    log = _chain(tmp_path)
    lines = log.path.read_text(encoding="utf-8").splitlines(keepends=True)
    _rewrite(log, lines[:-2])
    assert log.verify() is True


def test_truncating_an_attested_session_fails_report_verification(lab, monkeypatch):
    from test_prior_evidence import _run_and_publish, _verified

    s = Session(lab)
    s.probe(http_response())
    _run_and_publish(lab, s, "Nothing to add.", monkeypatch)
    assert _verified(lab, s).verified
    lines = s.audit.path.read_text(encoding="utf-8").splitlines(keepends=True)
    s.audit.path.write_text("".join(lines[:-1]), encoding="utf-8")  # drop report_generated
    assert s.audit.verify() is True
    assert not _verified(lab, s).verified  # the published report is no longer attested


# --- G4 / G2 / G1 ---------------------------------------------------------------------------

def test_report_distinguishes_session_scope_from_run_scope(lab):
    s = Session(lab)          # session created under SIMULATED-FIXTURE
    s.probe(http_response())
    lab.checker = ScopeChecker(Scope(
        session_name="research-run-scope", expires_at=datetime.now(UTC) + timedelta(days=1),
        targets=[Target(host=HOST, ports=[PORT], allowed_tiers=[ActionTier.ACTIVE_SAFE],
                        allowed_tools=["nmap_connect_scan"])]))
    s.run(lambda st, n: _resp((FINISH, {"summary": "done"})))
    rep = s.report().report
    sess = rep["session"]
    assert (sess["scope_session_name"], sess["scope_label_source"]) == (
        "SIMULATED-FIXTURE", "session_created")
    (run_scope,) = sess["research_run_scopes"]
    assert run_scope["scope_session_name"] == "research-run-scope"
    assert run_scope["snapshot_verified"] and len(run_scope["scope_snapshot_sha256"]) == 64
    assert rep["research_loop"]["runs"][0]["scope"] == run_scope
    text = "\n".join(render_text(rep))
    assert "created under scope 'SIMULATED-FIXTURE'" in text
    assert "used scope 'research-run-scope'" in text


@pytest.mark.parametrize("tool_runs,actionable", [(0, 0), (2, 1)])
def test_next_action_counts_separate_proposed_from_executable(lab, tool_runs, actionable):
    s = Session(lab)
    s.probe(http_response())
    from avra.core.research import ResearchSession
    from avra.llm.config import SessionLimits
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": "net.tcp_port_open", "host": HOST,
                                           "port": PORT, "rationale": "x"})),
                _resp((FINISH, {"summary": "done"}))])
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root))
    result = ResearchSession(
        provider=FakeModel(lambda st, n: next(seq)), checker=lab.checker, audit=s.audit,
        session_id=uuid.UUID(s.sid), limits=SessionLimits(max_steps=3, max_tool_runs=tool_runs),
        approve=lambda v: False, execute=s.execute, verification=loop).run("x")
    v = result.verification
    assert v["proposed_next_actions"] == 1 and v["agent_actionable_next_actions"] == actionable
    rep = run_verification(sessions_dir=lab.sessions, evidence_root=lab.evidence_root,
                           verification_root=lab.root / "data" / "verification",
                           session_id=s.sid, proposers=[RuleBasedProposer()]).report
    assert len(rep["proposed_next_actions"]) == v["proposed_next_actions"]
    assert any("executable by the agent with the remaining budget "
               f"{actionable}" in line for line in render_text(rep))


def test_cli_explains_earlier_evidence_is_not_counted_in_coverage(lab, monkeypatch, capsys):
    from test_prior_evidence import _run_and_publish

    s = Session(lab)
    probe = s.probe(http_response())
    report, _ = _run_and_publish(lab, s, f"See {probe}.", monkeypatch)
    out = capsys.readouterr().out
    assert report["prior_session_evidence"] and report["coverage"] == "not_evaluated"
    assert "earlier evidence of this session: 1 item(s) the model may cite; NOT counted" in out


def test_http_probe_pipeline_audit_failure_opens_no_tunnel(lab):
    from conftest import _Tunnel

    from avra.runner_client.client import RunnerToken
    from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
    from avra.runner_client.tunnel import TunnelConfig

    sid, audit = lab.new_session()
    opened = []

    class CountingTunnel(_Tunnel):
        def __enter__(self):
            opened.append(1)
            return super().__enter__()

    class FailOnSend(AuditLog):
        def record(self, event, data=None):
            if event == "tool_request_sent":
                raise OSError("disk full")
            return super().record(event, data)

    with pytest.raises(OSError):
        run_http_probe(checker=lab.checker, audit=FailOnSend(audit.path),
                       session_id=uuid.UUID(sid), host=HOST, port=PORT, timeout_seconds=5,
                       token=RunnerToken("t" * 43), evidence_root=lab.evidence_root,
                       tunnel_cfg=TunnelConfig(), approval=APPROVAL_INTERACTIVE_TTY,
                       tunnel_factory=CountingTunnel,
                       client_factory=lambda *a: pytest.fail("no client may be built"))
    assert opened == []
