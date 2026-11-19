"""M7.8 Stage 3: evidence-grounded report builder + passive validator.

Pure offline tests — no network, no API, no scans. They prove the report is
built from recorded evidence (not model prose) and that the validator catches
fabrication, contradiction, failure-as-success, and unlabeled claims."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from avra.core.research import ResearchResult, StopReason
from avra.llm.config import Spend
from avra.recon.nmap_xml import parse_nmap_xml
from avra.reporting import (
    EvidenceConfidence,
    ExecutionStatus,
    PortFact,
    ResearchCoverage,
    Verdict,
    build_report,
    validate_report,
)
from avra.runner.schemas import NmapConnectScanRequest, ToolRunResult, ToolRunStatus
from avra.runner_client.scan import ScanOutcome
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.evidence import EvidenceRef

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "nmap"
OPEN_XML = (FIX / "m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")
CLOSED_XML = (FIX / "m5-juice-shop-3000-closed.xml").read_text(encoding="utf-8")
FILTERED_XML = (FIX / "m7-3000-filtered.xml").read_text(encoding="utf-8")
MIXED_XML = (FIX / "m7-mixed-states.xml").read_text(encoding="utf-8")
DOWN_XML = (FIX / "m7-host-down.xml").read_text(encoding="utf-8")
PROBED_XML = (FIX / "m7-3000-probed.xml").read_text(encoding="utf-8")

SID = uuid.UUID("f2ebab88-5e0c-4f17-8825-7b83dc4067ba")
OBJECTIVE = "Find out which services the host exposes on its allowed ports."


def _scope(host="10.66.7.103", ports=(3000,)):
    return Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                 description="Owner VirtualBox lab; training targets only.",
                 targets=[Target(host=host, description="OWASP Juice Shop training app",
                                 ports=list(ports), allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                 allowed_tools=["nmap_connect_scan"])])


def _ok_outcome(xml, host="10.66.7.103", ports=(3000,)):
    req = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=SID, host=host,
                                 ports=list(ports), timeout_seconds=60)
    sha = hashlib.sha256(xml.encode()).hexdigest()
    res = ToolRunResult(request_id=req.request_id, tool="nmap_connect_scan",
                        status=ToolRunStatus.COMPLETED, started_at=datetime.now(UTC),
                        finished_at=datetime.now(UTC), exit_code=0, raw_output=xml,
                        output_sha256=sha)
    ev = EvidenceRef(path=Path("x.xml"), sha256=sha, size=len(xml))
    return ScanOutcome(req, True, "in scope", result=res, hash_verified=True, evidence=ev,
                       report=parse_nmap_xml(xml))


def _timed_out_outcome(host="10.66.7.103", ports=(3000,)):
    req = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=SID, host=host,
                                 ports=list(ports), timeout_seconds=60)
    res = ToolRunResult(request_id=req.request_id, tool="nmap_connect_scan",
                        status=ToolRunStatus.TIMED_OUT, reason="killed after timeout")
    return ScanOutcome(req, True, "in scope", result=res, hash_verified=None)


def _failed_exit_outcome(xml=OPEN_XML):
    o = _ok_outcome(xml)
    o.errors.append("nmap exited with code 1")
    return o


def _result(outcomes=(), observations=(), hypotheses=(), stop=StopReason.FINISHED,
            summary="done"):
    return ResearchResult(stop_reason=stop, detail="", steps=1, tool_runs=len(outcomes),
                          spend=Spend(), final_summary=summary, proposals=len(outcomes),
                          outcomes=list(outcomes), observations=list(observations),
                          hypotheses=list(hypotheses))


def _report(outcomes=(), scope=None, objective=OBJECTIVE, **kw):
    res = _result(outcomes, **kw)
    return build_report(res, session_id=SID, scope=scope or _scope(), objective=objective), res


# --- happy paths ---------------------------------------------------------------------


def test_open_port_report_is_supported_and_valid():
    rep, res = _report([_ok_outcome(OPEN_XML)],
                       summary="Likely Juice Shop, but unverified — do not trust this prose.")
    assert rep.execution_status is ExecutionStatus.COMPLETED
    assert rep.coverage is ResearchCoverage.FULLY_EVALUATED
    assert rep.evidence_confidence is EvidenceConfidence.SUPPORTED
    assert len(rep.verified_facts) == 1 and rep.verified_facts[0].state == "open"
    assert rep.verified_facts[0].service_identified is False  # table guess, never "verified"
    assert rep.model_summary_is_authoritative is False
    assert validate_report(rep, res).verdict is Verdict.PASS  # prose is ignored by the validator


def test_no_open_ports_still_completes_and_is_inconclusive():
    rep, res = _report([_ok_outcome(CLOSED_XML)])
    assert rep.execution_status is ExecutionStatus.COMPLETED
    assert rep.coverage is ResearchCoverage.FULLY_EVALUATED  # the port WAS evaluated
    assert rep.evidence_confidence is EvidenceConfidence.INCONCLUSIVE
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_all_filtered_is_inconclusive_not_a_failure():
    rep, res = _report([_ok_outcome(FILTERED_XML)])
    assert rep.evidence_confidence is EvidenceConfidence.INCONCLUSIVE
    assert rep.tool_runs[0].result_state == "no_open_ports"
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_mixed_states_with_open_port_is_supported():
    scope = _scope(ports=(80, 3000, 9000))
    rep, res = _report([_ok_outcome(MIXED_XML, ports=(80, 3000, 9000))], scope=scope)
    assert rep.evidence_confidence is EvidenceConfidence.SUPPORTED
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_host_down_report():
    scope = _scope(host="10.66.7.199")
    rep, res = _report([_ok_outcome(DOWN_XML, host="10.66.7.199")], scope=scope)
    assert rep.tool_runs[0].result_state == "host_down"
    assert rep.evidence_confidence is EvidenceConfidence.INCONCLUSIVE
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_timed_out_scan():
    rep, res = _report([_timed_out_outcome()], stop=StopReason.DURATION)
    assert rep.execution_status is ExecutionStatus.TIMED_OUT
    assert rep.tool_runs[0].execution_ok is False and rep.tool_runs[0].result_state == "timed_out"
    assert rep.coverage is ResearchCoverage.NOT_EVALUATED
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_nonzero_exit_not_reported_as_success():
    rep, res = _report([_failed_exit_outcome()])
    assert rep.tool_runs[0].execution_ok is False
    assert "nmap exited with code 1" in rep.errors_and_limitations
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_interrupted_session():
    rep, _ = _report([], stop=StopReason.ABORTED)
    assert rep.execution_status is ExecutionStatus.INTERRUPTED
    assert rep.coverage is ResearchCoverage.NOT_EVALUATED


def test_inconclusive_with_only_hypotheses_is_inferred():
    rep, res = _report([], hypotheses=[{"step": 2, "statement": "it is Juice Shop",
                                        "basis": "default port", "status": "unverified"}])
    assert rep.evidence_confidence is EvidenceConfidence.INFERRED
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_observation_with_real_reference_is_valid():
    out = _ok_outcome(OPEN_XML)
    rid = str(out.request.request_id)
    rep, res = _report([out], observations=[{"step": 2, "summary": "port 3000 open",
                                             "evidence_request_id": rid, "status": "unverified"}])
    assert rep.model_observations[0].evidence_request_id == rid
    assert validate_report(rep, res).verdict is Verdict.PASS


# --- validator catches fabrication / contradiction -----------------------------------


def test_missing_objective_is_incomplete():
    rep, res = _report([_ok_outcome(OPEN_XML)], objective="")
    assert validate_report(rep, res).verdict is Verdict.INCOMPLETE


def test_bogus_evidence_reference_is_invalid():
    rep, res = _report([_ok_outcome(OPEN_XML)],
                       observations=[{"step": 2, "summary": "x",
                                      "evidence_request_id": str(uuid.uuid4()),  # never ran
                                      "status": "unverified"}])
    v = validate_report(rep, res)
    assert v.verdict is Verdict.INVALID and any("not a tool run" in r for r in v.reasons)


def test_service_marked_identified_without_probe_is_invalid():
    rep, res = _report([_ok_outcome(OPEN_XML)])
    bad = PortFact(host="10.66.7.103", port=3000, protocol="tcp", state="open",
                   reason="syn-ack", service_guess="http", service_method="table",
                   service_confidence=3, service_identified=True)  # table but claims identified
    tampered = rep.model_copy(update={"verified_facts": (bad,)})
    v = validate_report(tampered, res)
    assert v.verdict is Verdict.INVALID and any("without a probe" in r for r in v.reasons)


def test_contradicting_parsed_state_is_invalid():
    rep, res = _report([_ok_outcome(OPEN_XML)])
    tr = rep.tool_runs[0]
    liar = tr.port_facts[0].model_copy(update={"state": "closed"})  # evidence says open
    tampered = rep.model_copy(update={"tool_runs": (tr.model_copy(update={"port_facts": (liar,)}),)})
    v = validate_report(tampered, res)
    assert v.verdict is Verdict.INVALID and any("disagrees with parsed evidence" in r
                                                for r in v.reasons)


def test_failure_reported_as_success_is_invalid():
    rep, res = _report([_failed_exit_outcome()])
    tr = rep.tool_runs[0].model_copy(update={"execution_ok": True})  # lie: the run failed
    tampered = rep.model_copy(update={"tool_runs": (tr,)})
    v = validate_report(tampered, res)
    assert v.verdict is Verdict.INVALID and any("marked ok but the outcome failed" in r
                                                for r in v.reasons)


def test_verified_hypothesis_is_invalid():
    # An unsupported claim promoted to "verified" must be rejected.
    rep, res = _report([_ok_outcome(OPEN_XML)],
                       hypotheses=[{"step": 3, "statement": "RCE present", "basis": "guess",
                                    "status": "verified"}])
    v = validate_report(rep, res)
    assert v.verdict is Verdict.INVALID and any("not labelled unverified" in r for r in v.reasons)


def test_supported_without_open_port_is_invalid():
    rep, res = _report([_ok_outcome(CLOSED_XML)])
    tampered = rep.model_copy(update={"evidence_confidence": EvidenceConfidence.SUPPORTED})
    v = validate_report(tampered, res)
    assert v.verdict is Verdict.INVALID and any("no verified open port" in r for r in v.reasons)
