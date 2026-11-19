"""M9.1 (ADR 0016): the research loop can PROPOSE a passive HTTP probe as its next step.

Real ResearchSession + real run_http_probe pipeline (only the tunnel/Runner are
stand-ins, conftest.Lab) + real Verification Engine with the web rule pack + a
scripted model. SIMULATED-FIXTURE target 192.168.56.250:8080 - never a lab VM."""

from __future__ import annotations

import uuid

from conftest import HOST, PORT, _client, _Sock, _Tunnel, http_response, nmap_xml

from avra.core.research import ResearchSession, StopReason
from avra.llm.config import LLMConfig, SessionLimits, TokenUsage
from avra.llm.provider import LLMResponse, ToolUse
from avra.llm.tools import FINISH, PROPOSE_HTTP_PROBE, VERIFY_HYPOTHESIS
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerToken
from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
from avra.runner_client.tunnel import TunnelConfig
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.rules import web_registry

CSP = "http.missing_content_security_policy"
PAGE = http_response(headers=(("Content-Type", "text/html"), ("X-Frame-Options", "DENY")))


class ScriptedModel:
    def __init__(self, script):
        self.config = LLMConfig(provider="local-openai-compatible", model="scripted")
        self.script, self.seen = list(script), []

    def count_input_tokens(self, *, system, messages, tools):
        return 1000

    def complete(self, *, system, messages, tools):
        self.seen.append({"system": system, "tools": [t["name"] for t in tools],
                          "last": messages[-1]})
        stop, uses = self.script.pop(0)
        return LLMResponse(stop_reason=stop, text="", tool_uses=tuple(uses),
                           usage=TokenUsage(input_tokens=1000, output_tokens=50), model="scripted",
                           request_id=None,
                           history_content=[{"type": "tool_use", "id": u.id, "name": u.name,
                                             "input": u.input} for u in uses])


def _use(name, i, **inp):
    return ToolUse(id=f"call_{i}", name=name, input=inp)


PROBE = {"host": HOST, "port": PORT, "explanation": "The engine needs HTTP evidence for headers."}


def _session(lab, script, *, approve=lambda v: True, allow=True, max_tool_runs=3, checker=None):
    sid, audit = lab.new_session()
    lab.nmap(sid, audit, nmap_xml("open"))  # recorded evidence: the port is open
    approvals, runs = [], []

    def execute_http(p):
        runs.append(p)
        env = child.probe(HOST, p.port, 5, socket_factory=lambda: _Sock([PAGE], None))
        return run_http_probe(checker=lab.checker, audit=audit, session_id=uuid.UUID(sid),
                              host=p.host, port=p.port, timeout_seconds=5,
                              token=RunnerToken("t" * 43), evidence_root=lab.evidence_root,
                              tunnel_cfg=TunnelConfig(), approval=APPROVAL_INTERACTIVE_TTY,
                              tunnel_factory=_Tunnel,
                              client_factory=_client(child.encode_envelope(env), "http_probe"))

    model = ScriptedModel(script)
    s = ResearchSession(
        provider=model, checker=checker or lab.checker, audit=audit, session_id=uuid.UUID(sid),
        limits=SessionLimits(max_tool_runs=max_tool_runs),
        approve=lambda v: (approvals.append(v), approve(v))[1],
        execute=lambda p: (_ for _ in ()).throw(AssertionError("no nmap scan expected")),
        verification=VerificationLoop(LoopConfig(evidence_root=lab.evidence_root),
                                      registry=web_registry()),
        http_probe=execute_http if allow else None)
    return s, model, audit, approvals, runs


def test_loop_follows_the_engine_probe_then_verify_then_finish(lab):
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(VERIFY_HYPOTHESIS, 2, rule_id=CSP, host=HOST, port=PORT,
                                 rationale="No CSP header was seen in the recorded response.")]),
              ("tool_use", [_use(FINISH, 3, summary="CSP missing confirmed as a weakness.")])]
    s, model, audit, approvals, runs = _session(lab, script)
    result = s.run("Check the web service on the lab target.")
    assert result.stop_reason is StopReason.FINISHED
    # the model was offered the tool and told about it (prompt version suffix)
    assert PROPOSE_HTTP_PROBE in model.seen[0]["tools"]
    assert "Passive HTTP probe (enabled" in model.seen[0]["system"][0]["text"]
    started = next(r for r in audit.read_all() if r.event == "research_started")
    assert started.data["prompt_version"].endswith("+http")
    # owner approved exactly one probe; it ran through the real pipeline
    assert len(approvals) == 1 and approvals[0].tool == "http_probe" and len(runs) == 1
    events = [r.event for r in audit.read_all()]
    assert events.count("tool_result_received") == 2  # recorded nmap + the new probe
    # the probe's result reached the model as structured data with fresh engine state
    probe_result = model.seen[1]["last"]["content"][0]["content"]
    assert '"status_code": 200' in probe_result and '"verification"' in probe_result
    # and the engine, not the model, confirmed the weakness from the new evidence
    verdicts = [r.data for r in audit.read_all() if r.event == "verification_verdict"]
    # before the probe: HTTP was INCONCLUSIVE (no evidence); after it: CONFIRMED, and the
    # rule chain then decided the header rules from the new evidence by itself
    http = [v["verdict"] for v in verdicts if v["rule_id"] == "http.service_observed"]
    assert http == ["INCONCLUSIVE", "CONFIRMED"]
    assert any(v["rule_id"] == CSP and v["verdict"] == "CONFIRMED" for v in verdicts)
    assert any(v["rule_id"] == "http.missing_clickjacking_protection" and v["verdict"] == "REJECTED"
               for v in verdicts)  # X-Frame-Options: DENY in the fixture response
    assert audit.verify()


def test_out_of_scope_probe_is_denied_before_the_owner_is_asked(lab):
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **{**PROBE, "port": 9999})]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, model, audit, approvals, runs = _session(lab, script)
    s.run("x")
    assert approvals == [] and runs == []
    assert any(r.event == "llm_proposal_denied" for r in audit.read_all())
    assert "Denied by scope policy" in model.seen[1]["last"]["content"][0]["content"]


def test_scope_without_http_probe_tool_denies_it(lab):
    from datetime import UTC, datetime, timedelta

    from avra.policy.scope import ScopeChecker
    from avra.schemas.scope import ActionTier, Scope, Target

    nmap_only = ScopeChecker(Scope(session_name="nmap-only", expires_at=datetime.now(UTC) + timedelta(days=1),
                                   targets=[Target(host=HOST, ports=[PORT],
                                                   allowed_tiers=[ActionTier.ACTIVE_SAFE, ActionTier.PASSIVE],
                                                   allowed_tools=["nmap_connect_scan"])]))
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, _m, audit, approvals, runs = _session(lab, script, checker=nmap_only)
    s.run("x")
    assert approvals == [] and runs == []
    denied = next(r for r in audit.read_all() if r.event == "llm_proposal_denied")
    assert "http_probe" in denied.data["reason"]


def test_declined_duplicate_and_budget_are_enforced(lab):
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(PROPOSE_HTTP_PROBE, 2, **PROBE)]),
              ("tool_use", [_use(FINISH, 3, summary="done")])]
    s, _model, audit, approvals, runs = _session(lab, script, approve=lambda v: False)
    s.run("x")
    assert len(approvals) == 1 and runs == []  # declined once; the duplicate never reached the owner
    reasons = [r.data["reason"] for r in audit.read_all() if r.event == "llm_proposal_rejected"]
    assert reasons == ["duplicate"]

    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, _m, audit, approvals, runs = _session(lab, script, max_tool_runs=0)
    s.run("x")
    assert approvals == [] and runs == []
    assert [r.data["reason"] for r in audit.read_all()
            if r.event == "llm_proposal_rejected"] == ["tool_run_limit"]


def test_tool_is_unknown_unless_the_owner_enables_it(lab):
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, model, audit, approvals, runs = _session(lab, script, allow=False)
    s.run("x")
    assert PROPOSE_HTTP_PROBE not in model.seen[0]["tools"] and runs == [] and approvals == []
    invalid = next(r for r in audit.read_all() if r.event == "llm_tool_invalid")
    assert "unknown tool" in invalid.data["error"]


def test_m93_consolidated_research_report(lab):
    """M9.3: one Markdown report = engine verdicts + research trace + UNVERIFIED model text."""
    from avra import assessment as asm
    from avra.verification.cycle import RuleBasedProposer
    from avra.verification.report import run_verification

    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(VERIFY_HYPOTHESIS, 2, rule_id=CSP, host=HOST, port=PORT,
                                 rationale="No CSP header was seen in the recorded response.")]),
              ("tool_use", [_use(FINISH, 3, summary="CSP is missing; this is a hardening gap.")])]
    s, _model, audit, _a, _r = _session(lab, script)
    s.run("Check the web service on the lab target.")
    run = run_verification(sessions_dir=lab.sessions, evidence_root=lab.evidence_root,
                           verification_root=lab.root / "verification", session_id=str(s.session_id),
                           proposers=[RuleBasedProposer()], registry=web_registry())
    trace = asm.research_trace(audit.read_all())
    assert trace["calls"] == 3 and trace["finish"].startswith("CSP is missing")
    steps = " | ".join(trace["steps"])
    assert steps.index("proposed `http_probe`") < steps.index("Owner **approved**") \
        < steps.index("Ran `http_probe`") < steps.index("asked the engine to verify")
    meta = {"generated_at": "t", "verification_report": "r.json", "audit_file": "a.jsonl"}
    md = asm.render_research_markdown(meta, asm.build_facts(run.report, run.evidence,
                                                            lab.evidence_root), run.report, trace)
    assert "## Research trace" in md and "## Model's conclusions (UNVERIFIED)" in md
    assert "0 confirmed vulnerability(ies)" in md
    assert "Confirmed configuration weaknesses (not proven exploitable)" in md
    assert "Model's closing summary (unverified): CSP is missing" in md
    assert "prompt `m8.5-v2+http`" in md
    path = asm.write_research_report(lab.root / "assessments" / str(s.session_id), meta,
                                     asm.build_facts(run.report, run.evidence, lab.evidence_root),
                                     run.report, trace)
    assert path.read_text(encoding="utf-8") .startswith("# AVRA research report")


def test_m94_executable_tools_are_withheld_once_the_budget_is_spent(lab):
    """Bonsai benchmark T04: with no tool runs left a model still proposed a scan.
    The loop now stops OFFERING executable tools; a stray call is still rejected."""
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),  # stray call
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, model, audit, approvals, runs = _session(lab, script, max_tool_runs=0)
    s.run("x")
    offered = model.seen[0]["tools"]
    assert PROPOSE_HTTP_PROBE not in offered and "propose_nmap_connect_scan" not in offered
    assert FINISH in offered and VERIFY_HYPOTHESIS in offered
    assert approvals == [] and runs == []  # the stray proposal still went nowhere
    assert [r.data["reason"] for r in audit.read_all()
            if r.event == "llm_proposal_rejected"] == ["tool_run_limit"]
    call = next(r for r in audit.read_all() if r.event == "llm_call")
    assert PROPOSE_HTTP_PROBE not in call.data["tools_offered"]


def test_m94_tools_disappear_after_the_last_run(lab):
    script = [("tool_use", [_use(PROPOSE_HTTP_PROBE, 1, **PROBE)]),
              ("tool_use", [_use(FINISH, 2, summary="done")])]
    s, model, _audit, _a, runs = _session(lab, script, max_tool_runs=1)
    s.run("x")
    assert len(runs) == 1
    assert PROPOSE_HTTP_PROBE in model.seen[0]["tools"]       # offered while budget remains
    assert PROPOSE_HTTP_PROBE not in model.seen[1]["tools"]   # withheld after the last run


def test_planner_marks_http_probe_agent_proposable_when_offered(lab):
    """M10 sprint fix: with --allow-http-probe the planner must not tell the model that
    http_probe is owner-only while the same session offers propose_http_probe."""
    s, _m, _a, _ap, _r = _session(lab, [("tool_use", [_use(FINISH, 1, summary="done")])])
    s.run("x")
    nxt = s.verification.plan()
    probe = [p for p in nxt if p.action.tool == "http_probe"]
    assert probe and all(p.executor == "agent" for p in probe)
    assert probe[0].score > 0


def test_planner_keeps_http_probe_owner_only_without_the_flag(lab):
    s, _m, _a, _ap, _r = _session(lab, [("tool_use", [_use(FINISH, 1, summary="done")])],
                                  allow=False)
    s.run("x")
    probe = [p for p in s.verification.plan() if p.action.tool == "http_probe"]
    assert probe and all(p.executor == "owner_only" for p in probe)
