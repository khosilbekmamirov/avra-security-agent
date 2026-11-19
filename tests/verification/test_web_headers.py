"""ADR 0015 sprint: the opt-in passive web-header rule pack.

Real lab evidence (the M8.3 Juice Shop response) plus SIMULATED-FIXTURE responses
recorded through the real http_probe pipeline (conftest.Lab). The default
registry is unchanged; only ``web_registry()`` carries these rules."""

from __future__ import annotations

import pytest
from conftest import http_response

from avra.verification import Verdict, VerificationEngine
from avra.verification.cycle import ResearchCycle, RuleBasedProposer, Status
from avra.verification.evidence import load_session_evidence
from avra.verification.rules import default_registry, web_registry
from avra.verification.rules.web_headers import WEB_HEADER_RULES
from tests.verification.test_cycle import M83, REAL

CSP, FRAME = "http.missing_content_security_policy", "http.missing_clickjacking_protection"
CORS, VERSION = "http.cors_wildcard_origin", "http.version_disclosure"
NEW = {CSP, FRAME, CORS, VERSION}


def _run(evidence, registry):
    state = ResearchCycle(VerificationEngine(registry), [RuleBasedProposer()]).run(evidence)
    return {e.hypothesis.rule_id: e for e in state.entries.values()}, state


def test_default_registry_is_unchanged():
    assert set(default_registry().ids()) == {"net.tcp_port_open", "http.service_observed",
                                             "http.missing_x_content_type_options"}
    assert NEW <= set(web_registry().ids())


def test_synthetic_juice_shop_response_with_the_web_pack():
    ev = load_session_evidence(REAL / "sessions", REAL / "evidence", M83)
    by, state = _run(ev, web_registry())
    assert by[CSP].result.verdict is Verdict.CONFIRMED and by[CSP].result.reason_code == "csp_missing"
    assert by[CORS].result.verdict is Verdict.CONFIRMED
    assert by[FRAME].result.verdict is Verdict.REJECTED  # X-Frame-Options: SAMEORIGIN
    assert "SAMEORIGIN" in by[FRAME].result.reason
    assert by[VERSION].result.verdict is Verdict.REJECTED  # no Server / X-Powered-By
    assert {e.hypothesis.rule_id for e in state.findings()} == {CSP, CORS}
    for e in state.findings():  # proof is the hash-checked evidence, never model text
        assert e.result.evidence_used and e.result.evidence_used[0].kind.value == "http_envelope"
    # ...while the default rules alone still report no finding for the same evidence
    assert _run(ev, default_registry())[1].findings() == []


@pytest.mark.parametrize("headers,expect", [
    ((("Content-Type", "text/html"), ("Server", "nginx/1.18.0")),
     {CSP: Verdict.CONFIRMED, FRAME: Verdict.CONFIRMED, CORS: Verdict.REJECTED,
      VERSION: Verdict.CONFIRMED}),
    ((("Content-Type", "text/html"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
      ("X-Powered-By", "Express"), ("Access-Control-Allow-Origin", "https://lab.example")),
     {CSP: Verdict.REJECTED, FRAME: Verdict.REJECTED, CORS: Verdict.REJECTED,
      VERSION: Verdict.REJECTED}),
    ((("Content-Type", "text/html"), ("X-Frame-Options", "ALLOW-FROM https://x"),
      ("Content-Security-Policy-Report-Only", "default-src 'self'")),
     {CSP: Verdict.CONFIRMED, FRAME: Verdict.CONFIRMED}),
])
def test_synthetic_responses(lab, headers, expect):
    sid = lab.http_session(http_response(headers=headers))
    by, _ = _run(lab.evidence(sid), web_registry())
    for rule, verdict in expect.items():
        assert by[rule].result.verdict is verdict, (rule, by[rule].result.reason)


@pytest.mark.parametrize("response,code", [
    (http_response(status="404 Not Found"), "insufficient_evidence"),
    (http_response(body=b""), "insufficient_evidence"),
    (http_response(headers=(("Content-Security-Policy", "a"), ("Content-Security-Policy", "b"),
                            ("X-Frame-Options", "DENY"))), None),
])
def test_ineligible_or_ambiguous_responses_never_confirm(lab, response, code):
    sid = lab.http_session(response)
    by, state = _run(lab.evidence(sid), web_registry())
    if code:  # 404 / empty body: nothing is decided, a probe is proposed instead
        assert all(by[r].result.verdict is Verdict.INCONCLUSIVE for r in NEW if r in by)
    else:  # duplicate CSP headers: CSP-dependent rules cannot decide
        assert by[CSP].result.verdict is Verdict.INCONCLUSIVE
        assert by[FRAME].result.verdict is Verdict.INCONCLUSIVE
    assert not any(e.hypothesis.rule_id in NEW and e.status is Status.CONFIRMED
                   for e in state.entries.values() if by[e.hypothesis.rule_id].result.verdict
                   is not Verdict.CONFIRMED)


def test_contradictory_responses_are_inconclusive(lab):
    sid = lab.http_session(http_response(headers=(("Content-Type", "text/html"),)),
                           http_response(headers=(("Content-Security-Policy", "default-src 'self'"),)))
    by, _ = _run(lab.evidence(sid), web_registry())
    assert by[CSP].result.verdict is Verdict.INCONCLUSIVE
    assert by[CSP].result.reason_code == "contradictory_evidence"


def test_every_rule_describes_its_confirmation_requirements():
    for cls in WEB_HEADER_RULES:
        d = cls().describe()
        assert d["kind"] == "vulnerability" and d["confirmed_requires"] and cls.references
        assert d["severity"] in ("informational", "low")


def test_research_verification_loop_can_carry_the_web_pack(tmp_path, monkeypatch):
    from avra.cli import main as cli

    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path))
    default_ids = {r["rule_id"] if "rule_id" in r else r["id"] for r in cli._verification_loop().catalogue()}
    web_ids = {r["rule_id"] if "rule_id" in r else r["id"] for r in cli._verification_loop(True).catalogue()}
    assert NEW.isdisjoint(default_ids) and NEW <= web_ids
