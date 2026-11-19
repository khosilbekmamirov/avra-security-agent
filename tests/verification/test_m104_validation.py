"""M10.4 (ADR 0017): controlled validation - passive rules + fixture-only checks.

Fixtures are SIMULATED-FIXTURE (192.168.56.250, never a lab VM). Nothing here sends a
request; live validation must always be refused."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from conftest import HOST, PORT, REPO, http_response

from avra.verification.engine import VerificationEngine
from avra.verification.models import Hypothesis, Origin, Verdict
from avra.verification.rules import validation_registry, web_registry
from avra.verification.validation import (
    CHECKS,
    LIVE_REFUSAL,
    ValidationFixtureError,
    live_authorization,
    load_fixture,
    make_exchange,
    validate,
)

FIX = REPO / "tests" / "fixtures" / "validation"
CRED = "http.cors_wildcard_with_credentials"
COOKIE = "http.cookie_missing_httponly"


def _verdict(lab, rule, *headers):
    sid = lab.http_session(http_response(headers=(("Content-Type", "text/html"), *headers),
                                         body=b"<p>x</p>"))
    h = Hypothesis.create(rule_id=rule, host=HOST, port=PORT, origin=Origin.OWNER)
    return VerificationEngine(validation_registry()).verify(h, lab.evidence(sid))


# --- passive rules ---------------------------------------------------------------------------

def test_cors_wildcard_with_credentials(lab):
    r = _verdict(lab, CRED, ("Access-Control-Allow-Origin", "*"),
                 ("Access-Control-Allow-Credentials", "true"))
    assert r.verdict is Verdict.CONFIRMED and r.is_finding
    assert _verdict(lab, CRED, ("Access-Control-Allow-Origin", "*")).verdict is Verdict.REJECTED
    assert _verdict(lab, CRED, ("Access-Control-Allow-Origin", "http://a.example"),
                    ("Access-Control-Allow-Credentials", "true")).verdict is Verdict.REJECTED


def test_duplicate_cors_headers_are_ambiguous(lab):
    r = _verdict(lab, CRED, ("Access-Control-Allow-Origin", "*"),
                 ("Access-Control-Allow-Credentials", "true"),
                 ("Access-Control-Allow-Credentials", "false"))
    assert r.verdict is Verdict.INCONCLUSIVE


def test_cookie_without_httponly_names_only(lab):
    r = _verdict(lab, COOKIE, ("Set-Cookie", "token=s3cr3tvalue; Path=/"),
                 ("Set-Cookie", "lang=en; HttpOnly"))
    assert r.verdict is Verdict.CONFIRMED and "token" in r.reason
    assert "s3cr3tvalue" not in r.canonical()
    assert _verdict(lab, COOKIE, ("Set-Cookie", "a=1; HttpOnly; Secure")).verdict \
        is Verdict.REJECTED
    no_cookie = _verdict(lab, COOKIE)
    assert no_cookie.verdict is Verdict.REJECTED and "no Set-Cookie" in no_cookie.reason


def test_synthetic_juice_shop_response_passes_both_checks():
    from avra.verification.evidence import load_session_evidence

    real = REPO / "tests" / "fixtures" / "synthetic-sessions"
    ev = load_session_evidence(real / "sessions", real / "evidence",
                               "7e868faf-768d-49af-aea6-81dc9d435e20")
    eng = VerificationEngine(validation_registry())
    for rule in (CRED, COOKIE):
        h = Hypothesis.create(rule_id=rule, host="10.66.7.103", port=3000, origin=Origin.OWNER)
        assert eng.verify(h, ev).verdict is Verdict.REJECTED


def test_registries():
    assert {CRED, COOKIE} <= set(validation_registry().ids())
    assert not {CRED, COOKIE} & set(web_registry().ids())  # --web-rules unchanged
    assert set(web_registry().ids()) < set(validation_registry().ids())


def test_new_rules_are_configuration_weaknesses_with_fixes():
    from avra.assessment import CONFIG_WEAKNESS_RULES, RULE_REMEDIATION

    assert {CRED, COOKIE} <= CONFIG_WEAKNESS_RULES and RULE_REMEDIATION[COOKIE]


# --- fixture checks --------------------------------------------------------------------------

@pytest.mark.parametrize("name,verdict,code", [
    ("idor-cross-account-read", "CONFIRMED", "cross_account_read"),
    ("idor-access-denied", "REJECTED", "access_denied"),
    ("marker-reflected-unencoded", "CONFIRMED", "reflected_unencoded"),
    ("marker-reflected-encoded", "REJECTED", "reflected_encoded"),
])
def test_sample_fixtures(name, verdict, code):
    r = validate(load_fixture((FIX / f"{name}.json").read_text(encoding="utf-8")))
    assert (r.verdict.value, r.reason_code) == (verdict, code)
    assert r.simulated and not r.lab_finding and r.live_execution == "disabled"
    assert r.sha256() == r.sha256()


def _fx(check="idor.cross_account_object_access", exchanges=None, label="SIMULATED-FIXTURE",
        **kw):
    body = b'{"marker":"SYNTH-A"}'
    ex = exchanges or [
        make_exchange(role="owner", account="synthetic-user-a", path="/o/1", status=200,
                      body=body),
        make_exchange(role="other_account", account="synthetic-user-b", path="/o/1",
                      status=200, body=body)]
    return {"format": "avra-validation-fixture/1", "label": label, "check": check,
            "target": {"host": HOST, "port": PORT}, "owner_marker": "SYNTH-A",
            "exchanges": ex, **kw}


def _run(doc):
    return validate(load_fixture(json.dumps(doc)))


def test_recorded_lab_label_is_the_only_way_to_a_lab_finding():
    assert _run(_fx(label="RECORDED-LAB")).lab_finding is True
    assert _run(_fx()).lab_finding is False


def test_owner_baseline_must_hold():
    doc = _fx()
    doc["exchanges"][0] = make_exchange(role="owner", account="synthetic-user-a", path="/o/1",
                                        status=200, body=b'{"other":"data"}')
    r = _run(doc)
    assert r.verdict is Verdict.INCONCLUSIVE and r.reason_code == "owner_baseline_invalid"


def test_ambiguous_second_response():
    doc = _fx()
    doc["exchanges"][1] = make_exchange(role="other_account", account="synthetic-user-b",
                                        path="/o/1", status=200, body=b'{"id":2}')
    assert _run(doc).reason_code == "ambiguous_response"


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d["exchanges"][0].update(method="POST"), "valid"),
    (lambda d: d["exchanges"][1].update(account="admin@juice-sh.op"), "synthetic"),
    (lambda d: d["exchanges"][1].update(account="synthetic-user-a"), "different"),
    (lambda d: d["exchanges"][1].update(path="/o/2"), "same object path"),
    (lambda d: d["exchanges"][1].update(path="http://evil.example/o/1"), "valid"),
    (lambda d: d["exchanges"][0].update(body_sha256="0" * 64), "SHA-256"),
    (lambda d: d.update(check="rce.reverse_shell"), "unknown check"),
    (lambda d: d.update(owner_marker=None), "owner_marker"),
    (lambda d: d.update(label="LIVE"), "valid"),
    (lambda d: d.update(target={"host": "example.com", "port": 80}), "valid"),
    (lambda d: d.update(extra_field=1), "valid"),
])
def test_fixture_safety_refusals(mutate, needle):
    doc = _fx()
    mutate(doc)
    with pytest.raises(ValidationFixtureError, match=needle):
        _run(doc)


def _marker_fx(marker, path, body=b"<p>x</p>", ctype="text/html"):
    return _fx(check="input.marker_reflection", exchanges=[
        make_exchange(role="marker", path=path, marker=marker, status=200, body=body,
                      content_type=ctype)])


@pytest.mark.parametrize("marker,path", [
    ("<script>alert(1)</script>", "/s?q=x"),                    # free-form payload
    ("AVRA0123456789ABCDEF", "/s?q=AVRA0123456789ABCDEF"),       # no probe characters
    ("AVRA0123456789ABCDEF\"'<>", "/s?q=other"),                 # marker not sent
])
def test_marker_grammar_is_enforced(marker, path):
    with pytest.raises(ValidationFixtureError, match="marker"):
        _run(_marker_fx(marker, path))


def test_marker_not_reflected_and_not_html():
    m, q = "AVRA0123456789ABCDEF\"'<>", "/s?q=AVRA0123456789ABCDEF%22%27%3C%3E"
    assert _run(_marker_fx(m, q)).reason_code == "not_reflected"
    assert _run(_marker_fx(m, q, body=m.encode(), ctype="application/json")).reason_code \
        == "not_html"


def test_live_validation_is_always_refused():
    for cid in [*CHECKS, "anything"]:
        assert live_authorization(cid) == (False, LIVE_REFUSAL)
    assert all(not c.state_changing for c in CHECKS.values())


# --- board + CLI -----------------------------------------------------------------------------

def test_board_points_to_fixture_check_but_not_available(lab):
    from avra.research.hypotheses import HypothesisBoard, State
    from avra.verification.loop import LoopConfig, VerificationLoop

    sid, audit = lab.new_session()
    lab.http(sid, audit, chunks=[http_response(body=b'<a href="/rest/basket/1">b</a>')])
    loop = VerificationLoop(LoopConfig(evidence_root=lab.evidence_root),
                            registry=validation_registry())
    loop.bind(audit=audit, session_id=uuid.UUID(sid), checker=lab.checker, tool_runs_left=0)
    loop.start()
    board = HypothesisBoard(loop=loop, audit=audit)
    p = board.propose(step=1, vuln_class="broken_access_control", host=HOST, port=PORT,
                      endpoint="/rest/basket/1", statement="IDOR", supporting_evidence=[],
                      confidence="medium", uncertainty="", required_evidence=[],
                      verification_rule="")
    assert p.entry.state is State.NEEDS_CAPABILITY
    a = p.entry.next_action
    assert (a.kind, a.available, a.rule_id) == ("validation_check", False,
                                                "idor.cross_account_object_access")
    assert "disabled" in a.reason and p.entry.priority["score"] == 0.0
    # the passive validation rules were examined by the rule chain itself
    assert {CRED, COOKIE} <= {e.hypothesis.rule_id for e in loop.entries.values()}


def _cli(monkeypatch, tmp_path, *args):
    from typer.testing import CliRunner

    from avra.cli.main import app

    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path))
    return CliRunner().invoke(app, ["validate", *args])


def test_cli_fixture_is_audited(monkeypatch, tmp_path):
    r = _cli(monkeypatch, tmp_path, "fixture", "--file",
             str(FIX / "idor-cross-account-read.json"))
    assert r.exit_code == 0 and "CONFIRMED (cross_account_read) [SIMULATED - not a lab finding]" \
        in r.output
    from avra.storage.audit import AuditLog

    log = AuditLog(tmp_path / "validation" / "validation-audit.jsonl")
    rec = log.read_all()[-1]
    assert rec.event == "validation_run" and rec.data["lab_finding"] is False
    assert rec.data["live_execution"] == "disabled" and log.verify()


def test_cli_refuses_bad_fixture(monkeypatch, tmp_path):
    bad = tmp_path / "bad.json"
    doc = _fx()
    doc["exchanges"][0]["method"] = "DELETE"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    r = _cli(monkeypatch, tmp_path, "fixture", "--file", str(bad))
    assert r.exit_code == 1 and "Refused" in r.output
    assert not (tmp_path / "validation" / "validation-audit.jsonl").exists()


def test_cli_list(monkeypatch, tmp_path):
    r = _cli(monkeypatch, tmp_path, "list")
    assert r.exit_code == 0 and "live execution: DISABLED" in r.output
    assert "idor.cross_account_object_access" in r.output


def test_web_research_cli_uses_validation_registry(monkeypatch, tmp_path):
    from avra.cli import main as cli

    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path))
    assert CRED in cli._verification_loop(True, validation=True).registry.ids()
    assert CRED not in cli._verification_loop(True).registry.ids()
    assert cli._rule_registry(False) is None
    assert Path(cli._evidence_dir()).parent == tmp_path
