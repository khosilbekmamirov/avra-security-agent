"""Regression tests for the 2026-11-10 repository audit fixes (offline).

F-02  schema 5: a structured observation reference (evidence_request_id) to
      verified earlier evidence of the same session is valid, an invented one
      is still INVALID.
F-03  `avra verify show` never displays a report whose integrity fails.
F-04  the audit chain must be numbered 1..n (seq is used for ordering).
F-05  the evidence loader excludes a result that precedes its request.
F-07  out-of-range nmap values raise NmapXmlError, not a bare ValidationError.
F-08  (Runner) a Content-Length with thousands of digits is 413, not 500
      (test in tests/security/test_runner_http_security.py).
"""

from __future__ import annotations

import dataclasses
import json
import uuid

from conftest import http_response
from test_prior_evidence import _verified
from test_research_loop import Session, _resp
from typer.testing import CliRunner

import avra.cli.main as cli
from avra.llm.tools import FINISH, RECORD_OBSERVATION
from avra.storage.audit import AuditLog, _record_hash
from avra.verification.cycle import RuleBasedProposer
from avra.verification.report import check_verification, run_verification


def _observe_then_finish(evidence_id):
    seq = iter([_resp((RECORD_OBSERVATION, {"summary": "HTTP 200 was recorded.",
                                            "evidence_request_id": evidence_id})),
                _resp((FINISH, {"summary": "done"}))])
    return lambda st, n: next(seq)


def _publish(lab, s, policy, monkeypatch):
    result, _, _ = s.run(policy)
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    try:
        cli._finish_report(result, session_id=uuid.UUID(s.sid), audit=s.audit)
    except SystemExit:
        pass
    return next(r for r in reversed(s.audit.read_all()) if r.event == "report_generated").data


def test_f02_observation_may_reference_verified_earlier_evidence(lab, monkeypatch):
    s = Session(lab)
    probe = s.probe(http_response())
    attested = _publish(lab, s, _observe_then_finish(probe), monkeypatch)
    assert attested["verdict"] == "PASS", attested["reasons"]
    assert _verified(lab, s).verified


def test_f02_invented_observation_reference_is_still_invalid(lab, monkeypatch):
    s = Session(lab)
    s.probe(http_response())
    attested = _publish(lab, s, _observe_then_finish(str(uuid.uuid4())), monkeypatch)
    assert attested["verdict"] == "INVALID"
    assert "nor verified earlier evidence" in attested["reasons"][0]


def _verification(lab, s):
    kw = {"sessions_dir": lab.sessions, "evidence_root": lab.evidence_root,
          "verification_root": lab.root / "data" / "verification", "session_id": s.sid}
    return kw, run_verification(**kw, proposers=[RuleBasedProposer()])


def test_f03_show_refuses_a_report_that_fails_integrity(lab, monkeypatch):
    s = Session(lab)
    s.probe(http_response())
    kw, run = _verification(lab, s)
    monkeypatch.setenv("AVRA_DATA_DIR", str(lab.root / "data"))
    ok = CliRunner().invoke(cli.app, ["verify", "show", s.sid])
    assert ok.exit_code == 0 and "CONFIRMED FINDINGS" in ok.output
    run.report_path.write_bytes(run.report_path.read_bytes().replace(b"REJECTED", b"CONFIRMED"))
    bad = CliRunner().invoke(cli.app, ["verify", "show", s.sid])
    assert bad.exit_code == 1 and "Report NOT shown" in bad.output
    assert "CONFIRMED FINDINGS" not in bad.output
    assert check_verification(**kw).integrity_ok is False


def test_f03_audit_cannot_name_a_report_outside_its_folder(lab):
    s = Session(lab)
    s.probe(http_response())
    kw, run = _verification(lab, s)
    AuditLog(run.audit_path).record("verification_report_written", {
        "report_file": "..\\..\\sessions\\x.json", "report_sha256": run.report_sha256})
    out = check_verification(**kw)
    assert out.status == "FAILED" and not out.integrity_ok
    assert "invalid report file" in out.problems[0]


def test_f04_audit_chain_requires_contiguous_sequence_numbers(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    first = log.record("one", {})
    assert log.verify()
    # a second record numbered 3, with a correctly computed hash and link
    ts = "2026-11-10T00:00:00+00:00"
    forged = {"seq": 3, "ts": ts, "event": "two", "data": {}, "prev_hash": first.hash,
              "hash": _record_hash(3, ts, "two", {}, first.hash)}
    with log.path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(forged, sort_keys=True) + "\n")
    assert not log.verify()


def test_f05_result_recorded_before_its_request_is_excluded(lab):
    s = Session(lab)
    rid = s.probe(http_response())
    recs = s.audit.read_all()
    sent = next(r for r in recs if r.event == "tool_request_sent")
    res = next(r for r in recs if r.event == "tool_result_received")
    rebuilt = AuditLog(lab.sessions / f"{uuid.uuid4()}.jsonl")
    sid2 = rebuilt.path.stem
    (lab.evidence_root / sid2).mkdir(parents=True)
    (lab.evidence_root / sid2 / f"{rid}.json").write_bytes(
        lab.evidence_file(s.sid, rid, ".json").read_bytes())
    rebuilt.record(res.event, dataclasses.replace(res).data)   # result first
    rebuilt.record(sent.event, sent.data)
    ev = lab.evidence(sid2)
    assert ev.trusted and ev.observations == []
    assert (rid, "result_before_request") in {(i.label, i.code) for i in ev.issues}


# --- F-07: nmap parser never leaks a ValidationError -------------------------------------------

def _xml(portid: str) -> str:
    return ("<nmaprun><host><status state='up'/><address addr='192.168.56.250' "
            "addrtype='ipv4'/><ports><port protocol='tcp' portid='" + portid + "'>"
            "<state state='open'/></port></ports></host><runstats><finished "
            "exit='success'/></runstats></nmaprun>")


def test_out_of_range_nmap_port_is_a_parse_error():
    import pytest

    from avra.recon.nmap_xml import NmapXmlError, parse_nmap_xml

    for bad in ("0", "70000", "9" * 5000):
        with pytest.raises(NmapXmlError):
            parse_nmap_xml(_xml(bad))
    assert parse_nmap_xml(_xml("8080")).hosts[0].ports[0].port == 8080
