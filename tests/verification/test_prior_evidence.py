"""Report schema 5: model text may cite VERIFIED evidence recorded earlier in
the SAME session (e.g. an owner's `avra probe http` before `avra research`).

Regression for the M8.5 real-model evaluation (data/eval/m85-real-02): the
model cited the session's M8.3 probe request id and the M7.9 claim check
(this run only) marked it unresolved -> INCOMPLETE. Everything else must
still fail closed: invented ids, other sessions' ids, tampered or
out-of-scope evidence. Real ResearchSession, real CLI report step, real
`verify_session` replay. Offline, fake model.
"""

from __future__ import annotations

import hashlib
import json
import uuid

import pytest
from conftest import HOST, PORT, http_response
from test_research_loop import Session, _resp

import avra.cli.main as cli
from avra.llm.tools import FINISH
from avra.reporting import PriorEvidence, validate_report
from avra.reporting.replay import find_runs, rebuild_report, verify_session
from avra.reporting.store import report_filename


def _run_and_publish(lab, s: Session, summary: str, monkeypatch):
    result, _, _ = s.run(lambda st, n: _resp((FINISH, {"summary": summary})))
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    try:
        cli._finish_report(result, session_id=uuid.UUID(s.sid), audit=s.audit)
    except SystemExit:
        pass
    run = find_runs(s.audit.read_all())[-1]
    path = lab.sessions / report_filename(uuid.UUID(s.sid), run.started.seq)
    return json.loads(path.read_bytes()), run


def _verified(lab, s):
    return verify_session(lab.sessions, lab.evidence_root, uuid.UUID(s.sid))


def test_citing_the_sessions_earlier_probe_resolves_and_verifies(lab, monkeypatch):
    s = Session(lab)
    probe = s.probe(http_response(headers=(("X-Content-Type-Options", "nosniff"),)))
    digest = hashlib.sha256(lab.evidence_file(s.sid, probe, ".json").read_bytes()).hexdigest()
    report, run = _run_and_publish(
        lab, s, f"HTTP 200 seen in request {probe} (evidence {digest}).", monkeypatch)
    assert report["schema_version"] == 5
    assert report["claim_checks"]["reference_mismatches"] == []
    assert report["claim_checks"]["references_checked"] == 2
    (prior,) = report["prior_session_evidence"]
    assert (prior["request_id"], prior["tool"], prior["target"], prior["sha256"]) == (
        probe, "http_probe", f"{HOST}:{PORT}", digest)
    assert prior["audit_seq"] < run.started.seq
    check = _verified(lab, s)
    assert check.verified, check.problems  # rebuilt byte-for-byte by replay


@pytest.mark.parametrize("token", ["00000000-0000-4000-8000-000000000000",  # invented
                                   "a" * 64])                               # invented hash
def test_invented_references_still_do_not_resolve(lab, monkeypatch, token):
    s = Session(lab)
    s.probe(http_response())
    report, _ = _run_and_publish(lab, s, f"See {token}.", monkeypatch)
    (m,) = report["claim_checks"]["reference_mismatches"]
    assert m["token"] == token and "verified earlier evidence of this session" in m["reason"]


def test_evidence_from_another_session_does_not_resolve(lab, monkeypatch):
    other = Session(lab)
    foreign = other.probe(http_response())
    s = Session(lab)
    s.probe(http_response())
    report, _ = _run_and_publish(lab, s, f"Request {foreign} shows HTTP.", monkeypatch)
    assert [m["token"] for m in report["claim_checks"]["reference_mismatches"]] == [foreign]
    assert foreign not in {p["request_id"] for p in report["prior_session_evidence"]}


def test_tampered_earlier_evidence_is_not_prior_evidence(lab, monkeypatch):
    s = Session(lab)
    probe = s.probe(http_response())
    f = lab.evidence_file(s.sid, probe, ".json")
    f.write_bytes(f.read_bytes()[:-2] + b" \n")
    report, _ = _run_and_publish(lab, s, f"See {probe}.", monkeypatch)
    assert report["prior_session_evidence"] == []
    assert [m["token"] for m in report["claim_checks"]["reference_mismatches"]] == [probe]


def test_earlier_evidence_outside_this_runs_scope_is_excluded(lab, monkeypatch):
    from datetime import UTC, datetime, timedelta

    from avra.policy.scope import ScopeChecker
    from avra.schemas.scope import ActionTier, Scope, Target

    s = Session(lab)
    probe = s.lab.http(s.sid, s.audit, chunks=[http_response()], port=8443)
    # the research run's scope covers only 8080: the 8443 probe is outside it
    lab.checker = ScopeChecker(Scope(
        session_name="SIMULATED-FIXTURE", expires_at=datetime.now(UTC) + timedelta(days=1),
        targets=[Target(host=HOST, ports=[PORT], allowed_tiers=[ActionTier.ACTIVE_SAFE],
                        allowed_tools=["nmap_connect_scan"])]))
    report, _ = _run_and_publish(lab, s, f"See {probe}.", monkeypatch)
    assert report["prior_session_evidence"] == []
    assert [m["token"] for m in report["claim_checks"]["reference_mismatches"]] == [probe]


def test_tampering_after_publication_breaks_verification(lab, monkeypatch):
    s = Session(lab)
    probe = s.probe(http_response())
    _run_and_publish(lab, s, f"See {probe}.", monkeypatch)
    assert _verified(lab, s).verified
    f = lab.evidence_file(s.sid, probe, ".json")
    f.write_bytes(f.read_bytes()[:-2] + b" \n")
    check = _verified(lab, s)
    assert not check.verified  # prior list no longer reproduces -> fail closed


def test_a_forged_prior_list_is_invalid(lab, monkeypatch):
    s = Session(lab)
    probe = s.probe(http_response())
    _run_and_publish(lab, s, f"See {probe}.", monkeypatch)
    run = find_runs(s.audit.read_all())[-1]
    report, result = rebuild_report(run, uuid.UUID(s.sid), lab.evidence_root, lab.sessions)
    fake = PriorEvidence(request_id=str(uuid.uuid4()), tool="http_probe",
                         target=f"{HOST}:{PORT}", sha256="b" * 64, audit_seq=1)
    forged = report.model_copy(update={"prior_session_evidence": (
        *report.prior_session_evidence, fake)})
    v = validate_report(forged, result)
    assert v.verdict.value == "INVALID"
    assert any("prior_session_evidence does not match" in r for r in v.reasons)
    older = report.model_copy(update={"schema_version": 4})
    assert any("older than schema 5" in r for r in validate_report(older, result).reasons)


def test_session_without_earlier_evidence_has_an_empty_prior_list(lab, monkeypatch):
    s = Session(lab)
    report, _ = _run_and_publish(lab, s, "Nothing was recorded yet.", monkeypatch)
    assert report["prior_session_evidence"] == []
    assert _verified(lab, s).verified


def test_evidence_lookup_is_tool_aware_and_fails_closed(tmp_path):
    from avra.reporting.replay import check_evidence, evidence_path

    sid, rid = uuid.uuid4(), uuid.uuid4()
    assert evidence_path(tmp_path, sid, rid).suffix == ".xml"                # legacy records
    assert evidence_path(tmp_path, sid, rid, "http_probe").suffix == ".json"
    check, raw = check_evidence({"request_id": str(rid), "evidence_sha256": "c" * 64,
                                 "tool": "sqlmap"}, sid, tmp_path)
    assert (check.state, raw) == ("invalid_reference", None)
