"""M8.5: the Verification Engine inside the live research loop (offline).

These tests drive the REAL ``ResearchSession`` (M7 loop) with a
``VerificationLoop``. Scans run through the real nmap pipeline (fake tunnel /
Runner) into the session's own audit + evidence; owner HTTP probes are
recorded the same way. The "model" is a fake provider. ``Analyst`` is a
generic feedback-reading policy (it parses the verification state AVRA sends
back and acts on it) - it is not a per-scenario script, so different
evidence leads it to different decisions (Scenario E).

Simulated autonomy only: no real LLM, no lab, no network.
"""

from __future__ import annotations

import json
import re
import uuid

import pytest
from conftest import HOST, PORT, http_response, nmap_xml

from avra.core.research import ResearchSession, StopReason
from avra.llm.config import LLMConfig, SessionLimits, TokenUsage
from avra.llm.prompts import PROMPT_VERSION_VERIFY
from avra.llm.provider import LLMResponse, ToolUse
from avra.llm.tools import FINISH, PROPOSE_SCAN, VERIFY_HYPOTHESIS
from avra.reporting import build_report, validate_report
from avra.reporting.replay import trusted_report_inputs
from avra.runner_client.client import RunnerToken
from avra.runner_client.scan import run_nmap_connect_scan
from avra.runner_client.tunnel import TunnelConfig
from avra.storage.audit import AuditLog
from avra.verification.cycle import RuleBasedProposer
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.report import check_verification, run_verification

NOSNIFF = "http.missing_x_content_type_options"
TARGET = f"{HOST}:{PORT}"
# tool results: <untrusted_tool_output>; first message (m8.5-v2): <avra_verification_state>
_WRAPPED = re.compile(r"<(untrusted_tool_output|avra_verification_state)>\n(.*?)\n</\1>",
                      re.DOTALL)


# --- fake model ------------------------------------------------------------------------

def _resp(*uses, stop="tool_use", text=""):
    return LLMResponse(stop_reason=stop, text=text, model="claude-opus-5-5", request_id="req",
                       tool_uses=tuple(ToolUse(id=f"t{i}", name=n, input=d)
                                       for i, (n, d) in enumerate(uses)),
                       usage=TokenUsage(input_tokens=1000, output_tokens=100),
                       history_content=[{"type": "text", "text": "..."}])


def latest_state(messages) -> dict:
    """The most recent verification state AVRA sent (tool result or first message)."""
    for msg in reversed(messages):
        blocks = msg["content"] if isinstance(msg["content"], list) else [
            {"content": msg["content"]}]
        for b in reversed(blocks):
            for _tag, body in reversed(_WRAPPED.findall(str(b.get("content", "")))):
                data = json.loads(body)
                if "verification" in data:
                    return data
    return {}


class FakeModel:
    def __init__(self, policy):
        self.config, self.policy = LLMConfig(), policy
        self.seen: list[dict] = []
        self.tools_offered: list[str] = []

    def count_input_tokens(self, *, system, messages, tools):
        return 3000

    def complete(self, *, system, messages, tools):
        self.tools_offered = [t["name"] for t in tools]
        state = latest_state(messages)
        self.seen.append(state)
        return self.policy(state, len(self.seen))


class Analyst:
    """Generic policy: get port evidence if there is none, then verify every
    (rule, target) that has no verdict yet, never re-proposing a decided or
    rejected one; finish when nothing is left, naming owner-only actions."""

    def __init__(self):
        self.scanned = False
        self.decisions: list[str] = []

    def __call__(self, state, n):
        v = state.get("verification", {})
        rules = [r["rule_id"] for r in state.get("rules", [])] or self.rules
        self.rules = rules
        known = {(i["rule_id"], i["target"]) for k in ("verified_observations",
                                                       "confirmed_findings", "rejected",
                                                       "inconclusive") for i in v.get(k, [])}
        has_port_evidence = any(i["rule_id"] == "net.tcp_port_open"
                                for k in ("verified_observations", "rejected")
                                for i in v.get(k, []))
        if not has_port_evidence and not self.scanned:
            self.scanned = True
            self.decisions.append("scan")
            return _resp((PROPOSE_SCAN, {"host": HOST, "ports": [PORT], "timeout_seconds": 30,
                                         "explanation": "Find out whether the port is open."}))
        for rule in rules:
            if (rule, TARGET) not in known:
                self.decisions.append(f"verify {rule}")
                return _resp((VERIFY_HYPOTHESIS, {"rule_id": rule, "host": HOST, "port": PORT,
                                                  "rationale": f"Check {rule}."}))
        owner_only = [a["tool"] for a in v.get("next_actions", []) if a["executor"] == "owner_only"]
        findings = [f["rule_id"] for f in v.get("confirmed_findings", [])]
        self.decisions.append("finish")
        return _resp((FINISH, {"summary": f"Findings: {findings or 'none'}. "
                                          f"Owner-only next steps: {owner_only or 'none'}."}))


# --- harness -------------------------------------------------------------------------------

OPEN_XML = nmap_xml("open")


class Session:
    def __init__(self, lab, xml=OPEN_XML):
        self.lab, self.xml = lab, xml
        self.sid, self.audit = lab.new_session()
        self.executed = 0

    def probe(self, response: bytes) -> str:  # an owner-run `avra probe http`
        return self.lab.http(self.sid, self.audit, chunks=[response])

    def execute(self, p):
        self.executed += 1
        from conftest import _client, _Tunnel
        return run_nmap_connect_scan(
            checker=self.lab.checker, audit=self.audit, session_id=uuid.UUID(self.sid),
            host=p.host, ports=list(p.ports), timeout_seconds=p.timeout_seconds,
            token=RunnerToken("t" * 43), evidence_root=self.lab.evidence_root,
            tunnel_cfg=TunnelConfig(), tunnel_factory=_Tunnel,
            client_factory=_client(self.xml, "nmap_connect_scan"))

    def run(self, policy, *, verification=True, max_steps=10, no_progress=3, approve=True):
        model = FakeModel(policy)
        loop = (VerificationLoop(LoopConfig(evidence_root=self.lab.evidence_root,
                                            no_progress_steps=no_progress))
                if verification else None)
        result = ResearchSession(
            provider=model, checker=self.lab.checker, audit=self.audit,
            session_id=uuid.UUID(self.sid),
            limits=SessionLimits(budget_usd=1.0, max_steps=max_steps, max_tool_runs=3),
            approve=lambda view: approve, execute=self.execute,
            verification=loop).run("Assess the lab web service on port 8080.")
        return result, model, loop

    def events(self):
        return [r.event for r in self.audit.read_all()]

    def report(self):
        """What `avra research` does afterwards (_auto_verify) / `avra verify session`."""
        return run_verification(
            sessions_dir=self.lab.sessions, evidence_root=self.lab.evidence_root,
            verification_root=self.lab.root / "data" / "verification", session_id=self.sid,
            proposers=[RuleBasedProposer()])

    def research_report(self):
        result_audit = AuditLog(self.audit.path)
        scope, objective, metadata, schema = trusted_report_inputs(result_audit,
                                                                   uuid.UUID(self.sid))
        return scope, objective, metadata, schema


def _research_report_ok(s: Session, result):
    scope, objective, metadata, schema = s.research_report()
    report = build_report(result, session_id=uuid.UUID(s.sid), scope=scope, objective=objective,
                          metadata=metadata, schema_version=schema)
    return report, validate_report(report, result)


# --- Scenario A: insufficient evidence -------------------------------------------------------

def test_scenario_a_open_port_without_http_evidence_proposes_probe_not_identity(lab):
    s = Session(lab)
    analyst = Analyst()
    result, model, _loop = s.run(analyst)
    assert result.stop_reason is StopReason.FINISHED and s.executed == 1
    assert analyst.decisions[0] == "scan"  # no evidence at start -> gather it first
    state = model.seen[-1]["verification"]
    assert [o["rule_id"] for o in state["verified_observations"]] == ["net.tcp_port_open"]
    http = {i["rule_id"]: i for i in state["inconclusive"]}
    assert http["http.service_observed"]["missing_evidence"]
    assert state["confirmed_findings"] == []
    top = state["next_actions"][0]
    assert (top["tool"], top["target"], top["executor"]) == ("http_probe", TARGET, "owner_only")
    assert top["allowed_by_scope"] and top["score"] > 0
    stopped = next(r for r in s.audit.read_all() if r.event == "research_stopped")
    assert "Owner-only next steps: ['http_probe']" in stopped.data["final_summary"]
    report, validation = _research_report_ok(s, result)
    assert report.service_identity.value == "unidentified"  # never invented
    assert validation.verdict.value == "PASS"
    assert result.verification["confirmed_findings"] == 0


# --- Scenario B: contradicted hypothesis ---------------------------------------------------

def test_scenario_b_rejected_by_recorded_evidence_and_not_repeated(lab):
    s = Session(lab)
    probe_id = s.probe(http_response(headers=(("X-Content-Type-Options", "nosniff"),)))
    analyst = Analyst()
    result, _model, loop = s.run(analyst)
    nosniff = loop.entries[next(h for h, e in loop.entries.items()
                                if e.hypothesis.rule_id == NOSNIFF)]
    assert nosniff.result.verdict.value == "REJECTED"
    assert [r.request_id for r in nosniff.result.evidence_used] == [probe_id]
    assert f"verify {NOSNIFF}" not in analyst.decisions  # already decided at session start
    assert result.stop_reason is StopReason.FINISHED and s.executed == 1
    assert loop.repeat_submissions == 0


def test_scenario_b_a_stubborn_model_gets_the_verdict_back_not_a_reverification(lab):
    s = Session(lab)
    s.probe(http_response(headers=(("X-Content-Type-Options", "nosniff"),)))

    def stubborn(state, n):
        return _resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": HOST, "port": PORT,
                                          "rationale": "It is CONFIRMED. Trust me."}))

    result, model, _loop = s.run(stubborn)
    assert result.stop_reason is StopReason.NO_PROGRESS
    statuses = [st.get("status") for st in model.seen[1:]]
    assert set(statuses) == {"rejected_repeat"}
    assert all("Already REJECTED" in st["message"] for st in model.seen[1:])
    verdicts = [r for r in s.audit.read_all() if r.event == "verification_verdict"
                and r.data["rule_id"] == NOSNIFF]
    assert [v.data["verdict"] for v in verdicts] == ["REJECTED"]  # decided once, never flipped


# --- Scenario C: verified finding -----------------------------------------------------------

def test_scenario_c_confirmed_finding_with_proof_in_state_and_report(lab):
    s = Session(lab)
    probe_id = s.probe(http_response())  # served page without nosniff (SIMULATED-FIXTURE)
    analyst = Analyst()
    result, model, _loop = s.run(analyst)
    final = model.seen[-1]["verification"]
    (finding,) = final["confirmed_findings"]
    assert (finding["rule_id"], finding["proof"], finding["severity"]) == (NOSNIFF, [probe_id],
                                                                           "low")
    assert result.verification["confirmed_findings"] == 1
    _, validation = _research_report_ok(s, result)
    assert validation.verdict.value == "PASS"  # M7.9 research report unaffected
    rep = s.report().report
    assert rep["format"] == "avra-verification-report/2"
    (f,) = rep["confirmed_findings"]
    assert f["proof"][0]["request_id"] == probe_id
    trace = rep["research_loop"]
    assert trace["runs"][0]["prompt_version"] == PROMPT_VERSION_VERIFY
    assert any(h["rule_id"] == NOSNIFF for h in trace["hypotheses"])
    assert trace["stops"][0]["stop_reason"] == "finished"


# --- Scenario D: evidence exhaustion --------------------------------------------------------

def test_scenario_d_no_progress_stops_before_the_step_budget(lab):
    s = Session(lab)
    s.probe(http_response())

    def idle(state, n):  # keeps asking about something already decided
        return _resp((VERIFY_HYPOTHESIS, {"rule_id": "http.service_observed", "host": HOST,
                                          "port": PORT, "rationale": "again"}))

    result, _model, _loop = s.run(idle, max_steps=10, no_progress=3)
    assert result.stop_reason is StopReason.NO_PROGRESS
    assert result.steps == 3 and result.spend.calls == 3  # well under max_steps=10
    assert "verification_no_progress" in s.events()
    _, validation = _research_report_ok(s, result)
    assert validation.verdict.value == "PASS"
    assert s.report().report["research_loop"]["no_progress_stops"]


# --- Scenario E: feedback changes the model's next decision ---------------------------------

def test_scenario_e_same_model_different_verdicts_different_decisions(lab):
    runs = {}
    for name, headers in (("nosniff_present", (("X-Content-Type-Options", "nosniff"),)),
                          ("nosniff_absent", ())):
        s = Session(lab)
        s.probe(http_response(headers=headers))
        analyst = Analyst()
        _result, model, _ = s.run(analyst)
        runs[name] = (analyst.decisions, model)
    # identical policy, identical scope: only the verdicts differ, and so do the outcomes
    assert runs["nosniff_present"][1].seen[-1]["verification"]["confirmed_findings"] == []
    assert runs["nosniff_absent"][1].seen[-1]["verification"]["confirmed_findings"]


def _reactor(decisions):
    """Asks one question, then acts on the engine's answer: INCONCLUSIVE ->
    take the best agent-executable next action; anything else -> finish."""
    def policy(state, n):
        v = state.get("verification", {})
        if n == 1:
            decisions.append("verify")
            return _resp((VERIFY_HYPOTHESIS, {"rule_id": "net.tcp_port_open", "host": HOST,
                                              "port": PORT, "rationale": "Is the port open?"}))
        this = v.get("this_hypothesis")
        if this and this["verdict"] == "INCONCLUSIVE":
            for a in v["next_actions"]:
                if a["executor"] == "agent" and a["score"] > 0:
                    host, port = a["target"].rsplit(":", 1)
                    decisions.append(f"{a['tool']} (because {this['verdict']})")
                    return _resp((PROPOSE_SCAN, {"host": host, "ports": [int(port)],
                                                 "timeout_seconds": 30,
                                                 "explanation": "The engine needs port evidence."}))
        decisions.append("finish")
        return _resp((FINISH, {"summary": f"Port verdict: {this['verdict'] if this else 'n/a'}"}))
    return policy


def test_scenario_e_the_verdict_changes_the_next_decision(lab):
    with_evidence, without_evidence = [], []
    s1 = Session(lab)
    s1.lab.nmap(s1.sid, s1.audit, nmap_xml("open"))  # owner already scanned: evidence exists
    _r1, _, _ = s1.run(_reactor(with_evidence))
    s2 = Session(lab)                                   # no evidence yet
    _r2, _m2, _ = s2.run(_reactor(without_evidence))
    assert with_evidence == ["verify", "finish"] and s1.executed == 0
    assert without_evidence == ["verify", "nmap_connect_scan (because INCONCLUSIVE)", "finish"]
    assert s2.executed == 1
    # after the scan the same hypothesis was revised by the engine, not by the model
    hist = [r.data["verdict"] for r in s2.audit.read_all()
            if r.event == "verification_verdict" and r.data["rule_id"] == "net.tcp_port_open"]
    assert hist == ["INCONCLUSIVE", "CONFIRMED"]


def test_scenario_e_verdict_from_step_n_reaches_the_model_at_step_n_plus_1(lab):
    s = Session(lab)
    s.probe(http_response())
    seq = iter([
        _resp((VERIFY_HYPOTHESIS, {"rule_id": "sqli.union_based", "host": HOST, "port": PORT,
                                   "rationale": "maybe"})),
        _resp((FINISH, {"summary": "done"})),
    ])
    _result, model, _loop = s.run(lambda st, n: next(seq))
    second = model.seen[1]
    assert second["status"] == "verified"
    assert second["verification"]["this_hypothesis"]["verdict"] == "INCONCLUSIVE"
    assert second["message"].startswith("INCONCLUSIVE")  # missing rule -> never a finding
    assert "unsupported_rule" in json.dumps(second)


# --- guard rails -----------------------------------------------------------------------------

def test_model_cannot_fabricate_or_reach_outside_scope(lab):
    s = Session(lab)
    s.probe(http_response(headers=(("X-Content-Type-Options", "nosniff"),)))
    seq = iter([
        _resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": "10.66.7.103", "port": 3000,
                                   "rationale": "x"})),
        _resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": HOST, "port": PORT,
                                   "rationale": "x", "verdict": "CONFIRMED"})),
        _resp((FINISH, {"summary": "done"})),
    ])
    _result, model, loop = s.run(lambda st, n: next(seq))
    assert model.seen[1]["status"] == "out_of_scope"
    invalid = [r for r in s.audit.read_all() if r.event == "llm_tool_invalid"]
    assert len(invalid) == 1 and "verdict" in invalid[0].data["error"]
    assert all(e.result.verdict.value != "CONFIRMED" or e.hypothesis.rule_id != NOSNIFF
               for e in loop.entries.values())


def test_new_evidence_revises_earlier_verdicts(lab):
    s = Session(lab, xml=nmap_xml("open"))
    seq = iter([
        _resp((VERIFY_HYPOTHESIS, {"rule_id": "net.tcp_port_open", "host": HOST, "port": PORT,
                                   "rationale": "is it open?"})),
        _resp((PROPOSE_SCAN, {"host": HOST, "ports": [PORT], "timeout_seconds": 30,
                              "explanation": "Check whether the port is open."})),
        _resp((FINISH, {"summary": "done"})),
    ])
    _result, _model, _loop = s.run(lambda st, n: next(seq))
    hist = [(r.data["verdict"], r.data["revised_from"]) for r in s.audit.read_all()
            if r.event == "verification_verdict" and r.data["rule_id"] == "net.tcp_port_open"]
    assert hist == [("INCONCLUSIVE", None), ("CONFIRMED", "INCONCLUSIVE")]


def test_m7_mode_is_unchanged_and_has_no_verify_tool(lab):
    s = Session(lab)
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": HOST, "port": PORT,
                                           "rationale": "x"})),
                _resp((FINISH, {"summary": "done"}))])
    result, model, loop = s.run(lambda st, n: next(seq), verification=False)
    assert VERIFY_HYPOTHESIS not in model.tools_offered and loop is None
    assert result.verification is None
    invalid = [r for r in s.audit.read_all() if r.event == "llm_tool_invalid"]
    assert "unknown tool" in invalid[0].data["error"]
    assert not any(e.startswith("verification_") for e in s.events())
    started = next(r for r in s.audit.read_all() if r.event == "research_started")
    assert started.data["prompt_version"] == "m7-v2" and "verification_loop" not in started.data


def test_verification_report_of_a_loop_session_rechecks(lab):
    s = Session(lab)
    s.probe(http_response())
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": "sqli.union_based", "host": HOST,
                                           "port": PORT, "rationale": "worth a look"})),
                _resp((FINISH, {"summary": "done"}))])
    s.run(lambda st, n: next(seq))
    run = s.report()
    out = check_verification(sessions_dir=lab.sessions, evidence_root=lab.evidence_root,
                             verification_root=lab.root / "data" / "verification",
                             session_id=s.sid)
    assert out.status == "VERIFIED" and out.reproduced == len(run.report["results"])
    origins = {h["rule_id"]: (h["origin"], h["proposed_by"]) for h in run.report["hypotheses"]}
    assert origins["sqli.union_based"] == ("model", "research-loop")
    assert origins[NOSNIFF] == ("generator", "rules")
    (inc,) = [i for i in run.report["inconclusive"] if i["rule_id"] == "sqli.union_based"]
    assert inc["reason_code"] == "unsupported_rule"


@pytest.mark.parametrize("bad", [{"max_verifications": 0}, {"no_progress_steps": 0}])
def test_loop_config_limits(tmp_path, bad):
    with pytest.raises(ValueError):
        LoopConfig(evidence_root=tmp_path, **bad)


# --- the real CLI: `avra research --verification` end to end (fake model) --------------------

def test_cli_research_with_verification_end_to_end(lab, monkeypatch, tmp_path):
    from typer.testing import CliRunner

    import avra.cli.main as cli
    import avra.llm.provider as provider_mod

    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-" + "x" * 40)
    monkeypatch.setenv("AVRA_RUNNER_TOKEN", "t" * 43)
    s = Session(lab)
    probe_id = s.probe(http_response())  # owner probe earlier in this session
    seq = iter([_resp((VERIFY_HYPOTHESIS, {"rule_id": NOSNIFF, "host": HOST, "port": PORT,
                                           "rationale": "check the header"})),
                _resp((FINISH, {"summary": "One low-severity header finding."}))])
    model = FakeModel(lambda st, n: next(seq))
    monkeypatch.setattr(provider_mod, "ClaudeProvider", lambda cfg, key: model)
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "session_name: SIMULATED-FIXTURE\nexpires_at: \"2099-01-01T00:00:00Z\"\n"
        f"targets:\n  - host: \"{HOST}\"\n    ports: [{PORT}]\n"
        "    allowed_tiers: [\"passive\", \"active-safe\"]\n"
        "    allowed_tools: [\"http_probe\", \"nmap_connect_scan\"]\n", encoding="utf-8")
    r = CliRunner().invoke(cli.app, ["research", "--scope", str(scope), "--objective",
                                     "Assess the web service", "--session", s.sid,
                                     "--verification"], input="y\n")
    assert r.exit_code == 0, r.output
    assert "Verification: ON" in r.output and "Report validation: PASS" in r.output
    assert "Offline verification: 0 confirmed vulnerability(ies), 1 configuration weakness(es)" in r.output
    assert VERIFY_HYPOTHESIS in model.tools_offered
    rep = json.loads(next((lab.root / "data" / "verification" / s.sid).glob(
        "report-*.json")).read_bytes())
    (f,) = rep["confirmed_findings"]
    assert f["proof"][0]["request_id"] == probe_id
    assert rep["research_loop"]["runs"][0]["prompt_version"] == PROMPT_VERSION_VERIFY
    assert CliRunner().invoke(cli.app, ["verify", "check", s.sid]).exit_code == 0
