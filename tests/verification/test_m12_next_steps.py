"""M12.1 (ADR 0020): evidence-driven next-step planning.

Real recorded Juice Shop session + SIMULATED-FIXTURE sessions (192.168.56.250)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from conftest import HOST, PORT, REPO, _client, _Sock, _Tunnel, http_response

from avra.chat import knowledge as kb
from avra.policy.scope import ScopeChecker
from avra.recon.web_surface import surfaces_from_evidence
from avra.research import next_steps
from avra.runner.tools import http_probe as child
from avra.runner_client.client import RunnerToken
from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
from avra.runner_client.tunnel import TunnelConfig
from avra.schemas.scope import ActionTier, Scope, Target
from avra.verification.cycle import Budget, ResearchCycle, RuleBasedProposer
from avra.verification.engine import VerificationEngine
from avra.verification.rules import validation_registry

ROOT = http_response(headers=(("Content-Type", "text/html"),),
                     body=(b'<script src="/main.js"></script><link rel="stylesheet" '
                           b'href="/styles.css"><img src="/logo.png">'))
MAIN = http_response(headers=(("Content-Type", "application/javascript"),),
                     body=b'a("/rest/user/whoami");b("/api/Products");c("/rest/admin/config")')


def _checker(paths=("/main.js",), host=HOST):
    return ScopeChecker(Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(1),
                              targets=[Target(host=host, ports=[PORT if host == HOST else 3000],
                                              allowed_tiers=[ActionTier.PASSIVE],
                                              allowed_tools=["http_get_path", "http_probe"],
                                              http_paths=list(paths))]))


def _plan(lab, sid, checker=None):
    ev = lab.evidence(sid)
    state = ResearchCycle(VerificationEngine(validation_registry()), [RuleBasedProposer()],
                          Budget()).run(ev)
    surfaces, _ = surfaces_from_evidence(ev, lab.evidence_root)
    from avra.storage.audit import AuditLog

    recs = AuditLog(lab.sessions / f"{sid}.jsonl").read_all()
    return next_steps.plan(evidence=ev, state=state, surfaces=surfaces, records=recs,
                           checker=checker, scope_allows=kb.scope_allows)


def _fetch(lab, sid, audit, path, resp, *, approval=APPROVAL_INTERACTIVE_TTY, raw=None):
    env = child.probe(HOST, PORT, 5, socket_factory=lambda: _Sock([resp]), path=path)
    return run_http_probe(checker=_checker(paths=("/",)), audit=audit,
                          session_id=uuid.UUID(sid), host=HOST, port=PORT, timeout_seconds=5,
                          token=RunnerToken("t" * 43), evidence_root=lab.evidence_root,
                          tunnel_cfg=TunnelConfig(), approval=approval,
                          tunnel_factory=_Tunnel,
                          client_factory=_client(raw or child.encode_envelope(env),
                                                 "http_get_path"), path=path)


def _by(plan):
    return {(s["kind"], s.get("path", "")): s for s in plan["steps"]}


def test_bundle_first_when_no_api_known(lab):
    sid = lab.http_session(ROOT)
    p = _plan(lab, sid, _checker())
    first = p["steps"][0]
    assert (first["kind"], first["path"], first["readiness"], first["value"]) == \
        ("http_get_path", "/main.js", "ready_to_propose", "high")
    assert "Best next step: http_get_path /main.js" in p["conclusion"]
    assert ("http_get_path", "/styles.css") not in _by(p)  # low-value assets skipped
    inv = p["inventory"][0]
    assert inv["skipped_low_value_assets"] == 2 and inv["http_root"]["status"] == 200


def test_after_fetch_api_paths_rank_and_fetched_is_not_repeated(lab):
    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    _fetch(lab, sid, audit, "/main.js", MAIN)
    p = _plan(lab, sid, _checker(paths=("/main.js", "/rest/")))
    by = _by(p)
    assert ("http_get_path", "/main.js") not in by
    assert by[("http_get_path", "/rest/user/whoami")]["value"] == "high"
    assert by[("http_get_path", "/rest/user/whoami")]["readiness"] == "ready_to_propose"
    assert by[("http_get_path", "/api/Products")]["readiness"] == "needs_scope_change"
    assert by[("http_get_path", "/api/Products")]["value"] == "medium"
    assert p["inventory"][0]["fetched"][0]["path"] == "/main.js"


def test_previous_failure_is_not_suggested_blindly(lab):
    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    _fetch(lab, sid, audit, "/main.js", MAIN, raw="not an envelope\n")  # broken evidence
    p = _plan(lab, sid, _checker())
    s = _by(p)[("http_get_path", "/main.js")]
    assert s["readiness"] == "previously_failed" and "previous_attempt" in s
    assert "Best next step: http_get_path /main.js" not in p["conclusion"]


def test_truncated_fetch_is_reported_as_a_limitation(lab):
    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    big = http_response(headers=(("Content-Type", "application/javascript"),),
                        body=b'x("/api/Late");' + b"a" * 300_000, content_length=False)
    out = _fetch(lab, sid, audit, "/main.js", big)
    assert out.ok and out.envelope.truncated
    p = _plan(lab, sid, _checker())
    lim = _by(p)[("analysis", "/main.js")]
    assert "truncated" in lim["why"] and lim["readiness"] == "offline_now"


def test_stop_when_nothing_in_scope_adds_evidence(lab):
    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    _fetch(lab, sid, audit, "/main.js", http_response(
        headers=(("Content-Type", "application/javascript"),), body=b"var x=1;"))
    p = _plan(lab, sid, _checker())
    assert all(s["readiness"] not in ("ready_to_propose",) for s in p["steps"])
    assert "no further action would add evidence" in p["conclusion"] \
        or "inside the current scope" in p["conclusion"]


def test_scope_change_conclusion(lab):
    sid = lab.http_session(ROOT)
    p = _plan(lab, sid, _checker(paths=("/other",)))
    assert _by(p)[("http_get_path", "/main.js")]["readiness"] == "needs_scope_change"
    assert "scope change" in p["conclusion"]


def test_synthetic_session_and_knowledge_wrapper(monkeypatch):
    monkeypatch.setenv("AVRA_DATA_DIR", str(REPO / "tests" / "fixtures" / "synthetic-sessions"))
    c = ScopeChecker(Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(1),
                           targets=[Target(host="10.66.7.103", ports=[3000],
                                           allowed_tiers=[ActionTier.PASSIVE],
                                           allowed_tools=["http_get_path"],
                                           http_paths=["/main.js"])]))
    p = kb.plan("7e868faf-768d-49af-aea6-81dc9d435e20", c)
    assert p["steps"][0]["path"] == "/main.js" and p["steps"][0]["readiness"] == \
        "ready_to_propose"
    assert kb.plan("4460bea8-d974-406c-bb65-75c3be0a899f")["conclusion"].startswith(
        "No scope is bound")


def test_board_links_fetched_endpoints_as_facts_not_verdicts(lab):
    from avra.research.hypotheses import HypothesisBoard, State
    from avra.verification.loop import LoopConfig, VerificationLoop

    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[ROOT])
    _fetch(lab, sid, audit, "/main.js", MAIN)
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root),
                            registry=validation_registry())
    loop.bind(audit=audit, session_id=uuid.UUID(sid), checker=_checker(paths=("/",)),
              tool_runs_left=0)
    loop.start()
    surfaces, _ = surfaces_from_evidence(loop.evidence, lab.evidence_root)
    board = HypothesisBoard(loop=loop, audit=audit, surfaces=surfaces)
    args = {"host": HOST, "port": PORT, "statement": "s", "supporting_evidence": [],
            "confidence": "medium", "uncertainty": "", "required_evidence": [],
            "verification_rule": ""}
    fetched = board.propose(step=1, vuln_class="sensitive_endpoint_exposure",
                            endpoint="/main.js", **args)
    only_ref = board.propose(step=1, vuln_class="sensitive_endpoint_exposure",
                             endpoint="/rest/user/whoami", **args)
    assert fetched.entry.state is State.NEEDS_CAPABILITY  # a 200 decides no weakness
    assert fetched.entry.priority["evidence_quality"] > only_ref.entry.priority[
        "evidence_quality"]
    led = board.ledger()
    rows = {r["endpoint"]: r for r in led["untested_hypotheses"]}
    assert rows["/main.js"]["endpoint_fetched"]["http_status"] == [200]
    assert rows["/rest/user/whoami"]["endpoint_fetched"] is False
    fact = next(f for f in led["observed_facts"] if "fetched_endpoint" in f)
    assert fact["fetched_endpoint"].endswith("/main.js") and "nothing about" in fact["status"]
