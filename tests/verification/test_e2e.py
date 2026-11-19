"""M8.4 Stage 3: end-to-end offline demonstration through the real CLI.

    recorded evidence -> AI-style hypothesis (supplied / mocked model)
    -> rule selection -> engine verdict -> research state -> report
    -> independent re-check

Separate fixture sessions show CONFIRMED, REJECTED and INCONCLUSIVE; the
synthetic M8.3-style evidence shows that its HTTP 200 is NOT a vulnerability.
No Kali, tunnel, target, network or API.
"""

from __future__ import annotations

import json
import shutil

import pytest
from conftest import FIXTURE_LABEL, HOST, PORT, REPO, http_response
from test_cycle import DONE, PROPOSE, FakeProvider, _resp
from typer.testing import CliRunner

import avra.cli.main as cli
from avra.storage.audit import AuditLog
from avra.verification.cycle import RuleBasedProposer
from avra.verification.model_proposer import ModelProposer
from avra.verification.report import check_verification, run_verification

NOSNIFF = "http.missing_x_content_type_options"
REAL = REPO / "tests" / "fixtures" / "synthetic-sessions"
M83 = "7e868faf-768d-49af-aea6-81dc9d435e20"


@pytest.fixture
def data(lab, monkeypatch):
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    return lab


def _hyp_file(tmp_path, origin="model"):
    """What a research model might propose, recorded as structured data."""
    path = tmp_path / "hyps.json"
    path.write_text(json.dumps({"hypotheses": [{
        "rule_id": NOSNIFF, "host": HOST, "port": PORT, "origin": origin,
        "rationale": "The page may be missing hardening headers. (model claims: CONFIRMED)"}]}),
        encoding="utf-8")
    return path


def _cli(*args):
    return CliRunner().invoke(cli.app, list(args))


def _report(lab, sid):
    out = check_verification(sessions_dir=lab.sessions, evidence_root=lab.evidence_root,
                             verification_root=lab.root / "data" / "verification", session_id=sid)
    return out, json.loads(out.report_path.read_bytes())


@pytest.mark.parametrize("response,verdict,section", [
    (http_response(), "CONFIRMED", "confirmed_findings"),
    (http_response(headers=(("X-Content-Type-Options", "nosniff"),)), "REJECTED", "rejected"),
    (http_response(status="503 Service Unavailable"), "INCONCLUSIVE", "inconclusive"),
])
def test_cli_end_to_end_supplied_ai_hypothesis(data, tmp_path, response, verdict, section):
    sid = data.http_session(response)
    r = _cli("verify", "session", "--session", sid, "--no-rules",
             "--hypotheses", str(_hyp_file(tmp_path)))
    assert r.exit_code == 0, r.output
    assert f"[{verdict}] {NOSNIFF}" in r.output and "Report sha256:" in r.output
    check, report = _report(data, sid)
    assert check.status == "VERIFIED" and check.reproduced == 1
    (entry,) = report[section]
    assert entry["rule_id"] == NOSNIFF and entry["verdict"] == verdict
    (hyp,) = report["hypotheses"]
    assert hyp["origin"] == "model" and "CONFIRMED" in hyp["rationale"]  # kept, never trusted
    assert report["session"]["scope_session_name"] == FIXTURE_LABEL
    if verdict == "CONFIRMED":
        (finding,) = report["confirmed_findings"]
        assert finding["severity"] == "low" and finding["proof"][0]["kind"] == "http_envelope"
        assert {c["outcome"] for c in finding["criteria"]} == {"met", "not_met"}
    if verdict == "INCONCLUSIVE":
        assert report["inconclusive"][0]["missing_evidence"]
        assert report["proposed_next_actions"][0]["executed"] is False
    assert _cli("verify", "check", sid).exit_code == 0


def test_cli_rule_driven_cycle_and_synthetic_m83_evidence_is_not_a_vulnerability(lab, monkeypatch):
    root = lab.root / "data"
    shutil.copytree(REAL / "sessions", root / "sessions")
    shutil.copytree(REAL / "evidence", root / "evidence")
    monkeypatch.setenv("AVRA_DATA_DIR", str(root))
    r = _cli("verify", "session", "--session", M83)
    assert r.exit_code == 0, r.output
    assert "CONFIRMED FINDINGS (vulnerability rules): 0" in r.output
    assert "[CONFIRMED] http.service_observed" in r.output
    assert f"[REJECTED] {NOSNIFF}" in r.output
    report = json.loads(next((root / "verification" / M83).glob("report-*.json")).read_bytes())
    assert report["confirmed_findings"] == []
    assert [o["rule_id"] for o in report["verified_observations"]] == ["http.service_observed"]
    assert report["run"]["stop_reason"] == "evidence_exhausted"
    assert any("scope snapshot" in lim for lim in report["limitations"])
    c = _cli("verify", "check", M83)
    assert c.exit_code == 0 and "VERIFIED (2 result(s) reproduced)" in c.output
    assert _cli("verify", "show", M83).exit_code == 0


def test_mocked_model_drives_the_cycle_and_every_call_is_audited(data):
    sid, audit = data.new_session()
    data.http(sid, audit, chunks=[http_response()])
    provider = FakeProvider([
        _resp([(PROPOSE, {"hypotheses": [
            {"rule_id": "http.service_observed", "host": HOST, "port": PORT, "rationale": "a"}]})]),
        _resp([(PROPOSE, {"hypotheses": [
            {"rule_id": NOSNIFF, "host": HOST, "port": PORT, "rationale": "HTTP seen; headers?"}
        ]})]),
        _resp([(DONE, {"summary": "Evidence exhausted."})]),
    ])
    run = run_verification(sessions_dir=data.sessions, evidence_root=data.evidence_root,
                           verification_root=data.root / "data" / "verification",
                           session_id=sid, proposers=[ModelProposer(provider)])
    rep = run.report
    assert [h["rule_id"] for h in rep["hypotheses"]] == ["http.service_observed", NOSNIFF]
    assert [h["iteration"] for h in rep["hypotheses"]] == [1, 2]  # feedback-driven 2nd round
    assert [f["rule_id"] for f in rep["confirmed_findings"]] == [NOSNIFF]
    assert rep["run"]["model_usage"]["calls"] == 3
    events = [r.event for r in AuditLog(run.audit_path).read_all()]
    assert events.count("verification_llm_call") == 3 and events.count("verification_result") == 2
    assert events[0] == "verification_started" and events[-1] == "verification_report_written"


def test_same_evidence_same_report_bytes_and_tamper_is_detected(data):
    sid, audit = data.new_session()
    rid = data.http(sid, audit, chunks=[http_response()])
    kw = {"sessions_dir": data.sessions, "evidence_root": data.evidence_root,
          "verification_root": data.root / "data" / "verification", "session_id": sid}
    a = run_verification(**kw, proposers=[RuleBasedProposer()])
    b = run_verification(**kw, proposers=[RuleBasedProposer()])
    assert a.report_sha256 == b.report_sha256 and a.report_path == b.report_path
    assert check_verification(**kw).status == "VERIFIED"
    ev = data.evidence_file(sid, rid, ".json")
    ev.write_bytes(ev.read_bytes()[:-2] + b" \n")
    bad = check_verification(**kw)
    assert bad.status == "FAILED" and any("result differs" in p for p in bad.problems)
    rep_path = a.report_path
    rep_path.write_bytes(rep_path.read_bytes().replace(b"CONFIRMED", b"REJECTED", 1))
    assert "does not match its audit hash" in check_verification(**kw).problems[0]


def test_report_keeps_hypotheses_observations_and_findings_apart(data):
    sid, audit = data.new_session()
    data.http(sid, audit, chunks=[http_response()])
    audit.record("llm_hypothesis", {"statement": "This is definitely vulnerable.",
                                    "basis": "gut feeling", "status": "unverified"})
    rep = run_verification(sessions_dir=data.sessions, evidence_root=data.evidence_root,
                           verification_root=data.root / "data" / "verification",
                           session_id=sid, proposers=[RuleBasedProposer()]).report
    assert rep["model_notes"][0]["status"].startswith("unverified")
    assert {f["rule_id"] for f in rep["confirmed_findings"]} == {NOSNIFF}
    assert {o["rule_id"] for o in rep["verified_observations"]} == {"http.service_observed"}
    assert not ({f["hypothesis_id"] for f in rep["confirmed_findings"]}
                & {o["hypothesis_id"] for o in rep["verified_observations"]})
    assert set(rep["verdict_meaning"]) == {"CONFIRMED", "REJECTED", "INCONCLUSIVE"}


def test_untrusted_session_and_bad_inputs(data, tmp_path):
    sid = data.http_session(http_response())
    log = data.sessions / f"{sid}.jsonl"
    log.write_text(log.read_text(encoding="utf-8").replace('"port": 8080', '"port": 9', 1),
                   encoding="utf-8")
    r = _cli("verify", "session", "--session", sid)
    assert r.exit_code == 2 and "NOT trusted" in r.output
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hypotheses": [{"rule_id": NOSNIFF, "host": HOST, "port": PORT,
                                               "verdict": "CONFIRMED"}]}), encoding="utf-8")
    assert _cli("verify", "session", "--session", sid, "--hypotheses", str(bad)).exit_code == 1
    assert _cli("verify", "session", "--session", "nope").exit_code == 1
    c = _cli("verify", "check", sid)  # the untrusted run's report reproduces, with a warning
    assert c.exit_code == 0 and "was NOT trusted" in c.output


def test_model_flag_refuses_without_a_terminal(data):
    sid = data.http_session(http_response())
    r = _cli("verify", "session", "--session", sid, "--model")
    assert r.exit_code == 1 and "interactive terminal" in r.output


def test_research_hook_runs_offline_verification(data, capsys):
    sid = data.http_session(http_response())
    import uuid
    cli._auto_verify(uuid.UUID(sid))
    out = capsys.readouterr().out
    assert "Offline verification: 0 confirmed vulnerability(ies), 1 configuration weakness(es)" in out
    assert (data.root / "data" / "verification" / sid).is_dir()


def test_rules_listing_states_confirmation_requirements():
    r = _cli("verify", "rules")
    assert r.exit_code == 0 and r.output.count("CONFIRMED requires:") == 3
    assert "severity low" in r.output
