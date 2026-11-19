"""M10.2 (ADR 0017): structured research hypotheses whose state only the engine decides.

SIMULATED-FIXTURE sessions (192.168.56.250:8080) from the real pipelines, plus the real
recorded Juice Shop session for the ledger."""

from __future__ import annotations

import uuid

from conftest import HOST, PORT, REPO, http_response, nmap_xml

from avra.policy.scope import ScopeChecker
from avra.recon.web_surface import surfaces_from_evidence
from avra.research.hypotheses import PRIORITY_NOTE, HypothesisBoard, State
from avra.storage.audit import AuditLog
from avra.verification.loop import LoopConfig, VerificationLoop
from avra.verification.rules import default_registry, web_registry

PAGE = http_response(headers=(("Content-Type", "text/html"), ("X-Frame-Options", "DENY"),
                              ("Access-Control-Allow-Origin", "*")),
                     body=b'<a href="/rest/basket/1">b</a><script>fetch("/api/Users")</script>')


def _board(lab, *, http=True, nmap=False, registry=None, agent_tools=frozenset()):
    sid, audit = lab.new_session()
    if nmap:
        lab.nmap(sid, audit, nmap_xml("open"))
    if http:
        lab.http(sid, audit, chunks=[PAGE])
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root),
                            registry=registry or web_registry())
    loop.agent_tools = loop.agent_tools | agent_tools
    loop.bind(audit=audit, session_id=uuid.UUID(sid), checker=lab.checker, tool_runs_left=2)
    loop.start()
    surfaces, _ = surfaces_from_evidence(loop.evidence, lab.evidence_root)
    board = HypothesisBoard(loop=loop, audit=audit, surfaces=surfaces,
                            agent_tools=loop.agent_tools)
    board.sync(0)
    return board, loop, audit


def _propose(board, step=1, **kw):
    args = {"vuln_class": "cors_misconfiguration", "host": HOST, "port": PORT, "endpoint": "",
                "statement": "CORS may expose API responses.", "supporting_evidence": [],
                "confidence": "medium", "uncertainty": "Only GET / was recorded.",
                "required_evidence": ["http_probe of an API path"], "verification_rule": ""}
    args.update(kw)
    return board.propose(step=step, **args)


def _rid(loop):
    return loop.evidence.observations[-1].ref.request_id


def test_state_comes_from_the_engine_not_the_proposer(lab):
    board, loop, _a = _board(lab)
    p = _propose(board, verification_rule="http.cors_wildcard_origin",
                 statement="CONFIRMED critical vulnerability, verdict: confirmed",
                 supporting_evidence=[_rid(loop)], confidence="high")
    assert p.ok and p.entry.state is State.CONFIRMED
    assert p.entry.verdict["verdict"] == "CONFIRMED"
    assert p.entry.verdict["engine_hypothesis"] in loop.entries
    rej = _propose(board, vuln_class="missing_security_header",
                   verification_rule="http.missing_clickjacking_protection",
                   statement="Clickjacking is CONFIRMED", confidence="high")
    assert rej.entry.state is State.REJECTED  # X-Frame-Options: DENY in the evidence


def test_hallucinated_evidence_ids_support_nothing(lab):
    board, loop, audit = _board(lab)
    fake = str(uuid.uuid4())
    p = _propose(board, supporting_evidence=[_rid(loop), fake, "not-an-id"])
    h = p.entry.hypothesis
    assert h.evidence_refs == (_rid(loop),)
    assert set(h.unverified_refs) == {fake, "not-an-id"}
    assert "do not exist" in p.message
    rec = next(r for r in audit.read_all() if r.event == "research_hypothesis")
    assert len(rec.data["unverified_refs"]) == 2
    assert board.summary()["unverified_citations"] == 2


def test_model_cannot_introduce_an_endpoint_as_observed(lab):
    board, _l, _a = _board(lab)
    seen = _propose(board, vuln_class="broken_access_control", endpoint="/rest/basket/1",
                    statement="IDOR on basket ids")
    invented = _propose(board, vuln_class="broken_access_control", endpoint="/admin/secret",
                        statement="Hidden admin panel")
    assert seen.entry.hypothesis.endpoint_observed is True
    assert invented.entry.hypothesis.endpoint_observed is False
    assert "not an observed fact" in invented.message
    assert seen.entry.priority["evidence_quality"] > invented.entry.priority["evidence_quality"]


def test_endpoint_hypothesis_without_a_check_needs_capability(lab):
    board, _l, _a = _board(lab)
    p = _propose(board, vuln_class="broken_access_control", endpoint="/rest/basket/1",
                 statement="IDOR on basket ids")
    assert p.entry.state is State.NEEDS_CAPABILITY
    # M10.4: a fixture-only check exists for this class; live validation is refused
    assert p.entry.next_action.kind == "validation_check" and not p.entry.next_action.available
    assert p.entry.next_action.rule_id == "idor.cross_account_object_access"
    assert "authorization" in p.entry.next_action.reason
    assert p.entry.priority["score"] == 0.0


def test_refusals_are_audited(lab):
    board, _l, audit = _board(lab)
    cases = [{"host": "10.66.7.103"}, {"port": 9999}, {"vuln_class": "rce_now"},
             {"endpoint": "http://evil.example/x"}, {"endpoint": "/a b"},
             {"confidence": "certain"}, {"verification_rule": "http.not_a_rule"},
             {"verification_rule": "http.cors_wildcard_origin", "endpoint": "/api/x"}]
    for kw in cases:
        p = _propose(board, **kw)
        assert not p.ok, kw
    statuses = [r.data["status"] for r in audit.read_all()
                if r.event == "research_hypothesis_refused"]
    assert statuses.count("out_of_scope") == 2 and len(statuses) == len(cases)
    assert board.summary()["model_proposed"] == 0


def test_resolved_hypothesis_is_not_reexamined(lab):
    board, loop, audit = _board(lab)
    first = _propose(board, verification_rule="http.cors_wildcard_origin")
    engine_before = len(loop.entries)
    again = _propose(board, step=2, verification_rule="http.cors_wildcard_origin",
                     statement="different words, same hypothesis")
    assert again.status == "already_resolved" and again.entry is first.entry
    assert len(loop.entries) == engine_before
    assert any(r.event == "research_hypothesis_repeat" for r in audit.read_all())


def test_class_level_hypothesis_untested_then_needs_evidence(lab):
    # nmap-only session: no HTTP evidence, header rules not yet examined
    board, loop, _a = _board(lab, http=False, nmap=True, agent_tools=frozenset({"http_probe"}))
    p = _propose(board, statement="The app may send CORS *")
    assert p.entry.state is State.UNTESTED
    assert p.entry.next_action.kind == "verify_rule"
    assert p.entry.next_action.rule_id == "http.cors_wildcard_origin"
    loop.submit(step=2, rule_id="http.cors_wildcard_origin", host=HOST, port=PORT,
                rationale="check")
    board.sync(2)
    e = board.entries[p.entry.hypothesis.id]
    assert e.state is State.NEEDS_EVIDENCE
    assert e.next_action.kind == "http_probe" and e.next_action.available
    assert any("http_probe" in m for m in e.missing)
    assert e.priority["score"] > 0


def test_needs_evidence_without_agent_tool_is_not_available(lab):
    board, loop, _a = _board(lab, http=False, nmap=True)
    p = _propose(board, verification_rule="http.cors_wildcard_origin")
    loop.submit(step=2, rule_id="http.cors_wildcard_origin", host=HOST, port=PORT,
                rationale="check")
    board.sync(2)
    e = board.entries[p.entry.hypothesis.id]
    assert e.state is State.NEEDS_EVIDENCE and not e.next_action.available
    assert e.priority["score"] == 0.0


def test_new_evidence_revises_board_state(lab):
    board, loop, audit = _board(lab, http=False, nmap=True)
    p = _propose(board, verification_rule="http.cors_wildcard_origin")
    loop.submit(step=1, rule_id="http.cors_wildcard_origin", host=HOST, port=PORT,
                rationale="check")
    board.sync(1)
    assert board.entries[p.entry.hypothesis.id].state is State.NEEDS_EVIDENCE
    lab.http(loop.session_id, audit, chunks=[PAGE])  # new trusted evidence arrives
    loop.refresh(2, tool_runs_left=1)
    board.sync(2)
    e = board.entries[p.entry.hypothesis.id]
    assert e.state is State.CONFIRMED
    assert [s for _, s in e.history] == ["untested", "needs_evidence", "confirmed"]
    states = [r.data["state"] for r in audit.read_all() if r.event == "research_hypothesis_state"
              and r.data["hypothesis_id"] == e.hypothesis.id]
    assert states == ["needs_evidence", "confirmed"]


def test_priority_orders_work_not_exploitability(lab):
    board, loop, _a = _board(lab, http=False, nmap=True)
    low = _propose(board, vuln_class="missing_security_header", statement="headers",
                   confidence="high")
    high = _propose(board, vuln_class="cors_misconfiguration", statement="cors",
                    confidence="high", supporting_evidence=[_rid(loop)])
    assert high.entry.priority["score"] > low.entry.priority["score"] > 0
    assert board.ranked()[0] is high.entry
    assert all(e.priority["note"] == PRIORITY_NOTE for e in board.entries.values())


def test_sync_mirrors_engine_decisions(lab):
    board, _loop, _a = _board(lab)
    rules = {e.hypothesis.verification_rule for e in board.entries.values()
             if e.hypothesis.origin == "rules"}
    assert {"http.service_observed", "http.cors_wildcard_origin",
            "http.missing_content_security_policy"} <= rules
    assert all(e.state in (State.CONFIRMED, State.REJECTED)
               for e in board.entries.values() if e.hypothesis.origin == "rules")


def test_ledger_on_synthetic_juice_shop_evidence(tmp_path):
    real = REPO / "tests" / "fixtures" / "synthetic-sessions"
    import shutil

    shutil.copytree(real, tmp_path / "d")
    sid = "7e868faf-768d-49af-aea6-81dc9d435e20"
    audit = AuditLog(tmp_path / "d" / "sessions" / f"{sid}.jsonl")
    from datetime import UTC, datetime, timedelta

    from avra.schemas.scope import ActionTier, Scope, Target

    checker = ScopeChecker(Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(1),
                                 targets=[Target(host="10.66.7.103", ports=[3000],
                                                 allowed_tiers=[ActionTier.PASSIVE],
                                                 allowed_tools=["http_probe"])]))
    loop = VerificationLoop(LoopConfig(evidence_root=tmp_path / "d" / "evidence"),
                            registry=web_registry())
    loop.bind(audit=audit, session_id=uuid.UUID(sid), checker=checker, tool_runs_left=0)
    loop.start()
    surfaces, _ = surfaces_from_evidence(loop.evidence, tmp_path / "d" / "evidence")
    board = HypothesisBoard(loop=loop, audit=audit, surfaces=surfaces)
    board.sync(0)
    led = board.ledger()
    weak = {w["rule"] for w in led["potential_weaknesses"]}
    assert weak == {"http.cors_wildcard_origin", "http.missing_content_security_policy"}
    assert led["verified_findings"] == []
    assert {"rule": "http.service_observed", "target": "10.66.7.103:3000",
            "proof": ["5c746502-d2e2-44a8-9180-c24cfa7c859c"]} in led["observed_facts"]
    assert any(f.get("endpoint_references") == 6 for f in led["observed_facts"])
    assert {r["rule"] for r in led["rejected_hypotheses"]} == {
        "http.missing_clickjacking_protection", "http.missing_x_content_type_options",
        "http.version_disclosure"}
    assert audit.verify()


def test_default_registry_without_web_rules(lab):
    board, _l, _a = _board(lab, registry=default_registry())
    p = _propose(board, vuln_class="cors_misconfiguration", statement="cors")
    # no CORS rule in the M8.4 catalogue: no check exists in this session
    assert p.entry.state is State.NEEDS_CAPABILITY
