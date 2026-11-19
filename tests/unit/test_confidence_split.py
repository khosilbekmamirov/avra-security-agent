"""M7.9.3a (D1): port exposure and service identity are separate, and the
headline is never stronger than the weaker of the two.

Pure offline tests on recorded nmap fixtures (tests/fixtures/nmap). A
port-number table label (method="table") is never an identification; under
AVRA's fixed connect-scan flags nothing is ever probed, so live reports can
at most be ``partially_supported``.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avra.core.research import REPORT_SCHEMA_VERSION, ResearchResult, StopReason
from avra.llm.config import Spend
from avra.recon.nmap_xml import parse_nmap_xml
from avra.reporting import (
    CURRENT_SCHEMA,
    SCHEMA3_FIELDS,
    EvidenceConfidence,
    PortExposure,
    ReportLimits,
    ReportMetadata,
    ReportTokens,
    ServiceIdentity,
    Verdict,
    build_report,
    validate_report,
)
from avra.reporting.store import serialize_report
from avra.runner.schemas import NmapConnectScanRequest, ToolRunResult, ToolRunStatus
from avra.runner_client.scan import ScanOutcome
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.evidence import EvidenceRef

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "nmap"
OPEN = (FIX / "m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")       # ppp, table
PROBED = (FIX / "m7-3000-probed.xml").read_text(encoding="utf-8")              # http, probed
CLOSED = (FIX / "m5-juice-shop-3000-closed.xml").read_text(encoding="utf-8")
FILTERED = (FIX / "m7-3000-filtered.xml").read_text(encoding="utf-8")
MIXED = (FIX / "m7-mixed-states.xml").read_text(encoding="utf-8")              # 3000 open, table
DOWN = (FIX / "m7-host-down.xml").read_text(encoding="utf-8")
SID = uuid.uuid4()


def _scope():
    return Scope(session_name="t", expires_at=datetime.now(UTC) + timedelta(days=1),
                 targets=[Target(host="10.66.7.103", ports=[3000, 80, 9000],
                                 allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                 allowed_tools=["nmap_connect_scan"])])


def _ok(xml, ports=(3000,)):
    req = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=SID,
                                 host="10.66.7.103", ports=list(ports), timeout_seconds=60)
    sha = hashlib.sha256(xml.encode()).hexdigest()
    res = ToolRunResult(request_id=req.request_id, tool="nmap_connect_scan",
                        status=ToolRunStatus.COMPLETED, started_at=datetime.now(UTC),
                        finished_at=datetime.now(UTC), exit_code=0, raw_output=xml,
                        output_sha256=sha)
    return ScanOutcome(req, True, "in scope", result=res, hash_verified=True,
                       evidence=EvidenceRef(path=Path("x.xml"), sha256=sha, size=len(xml)),
                       report=parse_nmap_xml(xml))


def _unverified(xml):
    o = _ok(xml)
    o.hash_verified = False  # evidence not trustworthy -> not a verified fact
    return o


def _result(outcomes=(), hypotheses=()):
    return ResearchResult(stop_reason=StopReason.FINISHED, detail="", steps=1,
                          tool_runs=len(outcomes), spend=Spend(), final_summary="done",
                          proposals=len(outcomes), outcomes=list(outcomes),
                          hypotheses=list(hypotheses))


def _metadata():
    """Consistent schema-2/3 metadata (as replay.run_metadata would build it)."""
    tokens = {"input_tokens": 10, "output_tokens": 100, "cache_creation_input_tokens": 0,
              "cache_read_input_tokens": 0}
    return ReportMetadata(
        session_id=str(SID), run_started_seq=2, run_stopped_seq=4, run_stopped_hash="a" * 64,
        started_at="2026-11-08T00:00:00+00:00", finished_at="2026-11-08T00:01:00+00:00",
        avra_version="0.0.0", model="claude-opus-5-5", models_reported=("claude-opus-5-5",),
        model_consistent=True, prompt_version="m7-v2", effort="medium", max_tokens=4096,
        limits=ReportLimits(budget_usd=0.5, max_steps=5, max_tool_runs=5,
                            max_duration_seconds=1800),
        stop_reason="finished", steps=1, llm_calls=1, tool_runs=0, proposals=0,
        tokens=ReportTokens(**tokens), tokens_consistent=True, cost_usd=0.00204,
        cost_sum_of_calls_usd=0.00204, cost_from_tokens_usd=0.00204, cost_consistent=True,
        scope_file_sha256=None, scope_snapshot_sha256="b" * 64)


def _v3(outcomes=(), hypotheses=()):
    res = _result(outcomes, hypotheses)
    return build_report(res, session_id=SID, scope=_scope(), objective="o",
                        metadata=_metadata(), schema_version=3), res


HYP = [{"step": 1, "status": "unverified", "statement": "It is Juice Shop",
        "basis": "scope description"}]


# --- derivation ------------------------------------------------------------------------

@pytest.mark.parametrize("outcomes,hyp,exposure,identity,headline", [
    # the live M7.8 case: open port, nmap's port-table label only
    ([OPEN], (), "confirmed", "unidentified", "partially_supported"),
    ([MIXED], (), "confirmed", "unidentified", "partially_supported"),
    # a real probe identified the service -> the only "supported" case
    ([PROBED], (), "confirmed", "identified", "supported"),
    # some open ports probed, some only table-labelled
    ([PROBED, OPEN], (), "confirmed", "partially_identified", "partially_supported"),
    ([CLOSED], (), "none_open", "not_applicable", "inconclusive"),
    ([FILTERED], (), "none_open", "not_applicable", "inconclusive"),
    ([DOWN], (), "host_down", "not_applicable", "inconclusive"),
    ([], HYP, "not_evaluated", "not_applicable", "inferred"),
    ([], (), "not_evaluated", "not_applicable", "inconclusive"),
])
def test_exposure_identity_and_headline(outcomes, hyp, exposure, identity, headline):
    rep, res = _v3([_ok(x) for x in outcomes], hyp)
    assert (rep.port_exposure.value, rep.service_identity.value,
            rep.evidence_confidence.value) == (exposure, identity, headline)
    assert rep.schema_version == 3
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_unverified_evidence_never_confirms_exposure():
    rep, res = _v3([_unverified(PROBED)])
    assert rep.port_exposure is PortExposure.NOT_EVALUATED
    assert rep.service_identity is ServiceIdentity.NOT_APPLICABLE
    assert rep.evidence_confidence is not EvidenceConfidence.SUPPORTED
    assert validate_report(rep, res).verdict is not Verdict.INVALID


def test_model_claimed_identity_never_changes_the_headline():
    hyp = [{"step": 2, "status": "unverified", "statement": "Service is Node.js Express",
            "basis": "I am confident"}]
    rep, res = _v3([_ok(OPEN)], hyp)
    assert rep.service_identity is ServiceIdentity.UNIDENTIFIED
    assert rep.evidence_confidence is EvidenceConfidence.PARTIALLY_SUPPORTED
    assert validate_report(rep, res).verdict is Verdict.PASS


# --- validator rule 10: forged or inflated claims ----------------------------------------

@pytest.mark.parametrize("xml,update,why", [
    (OPEN, {"service_identity": ServiceIdentity.IDENTIFIED}, "service_identity"),
    (OPEN, {"evidence_confidence": EvidenceConfidence.SUPPORTED}, "supported"),
    (CLOSED, {"port_exposure": PortExposure.CONFIRMED}, "port_exposure"),
    (CLOSED, {"evidence_confidence": EvidenceConfidence.PARTIALLY_SUPPORTED},
     "does not follow"),
    (OPEN, {"evidence_confidence": EvidenceConfidence.INCONCLUSIVE}, "does not follow"),
    (PROBED, {"service_identity": ServiceIdentity.PARTIALLY_IDENTIFIED}, "service_identity"),
    (OPEN, {"port_exposure": None}, "without port_exposure"),
])
def test_forged_or_inconsistent_v3_fields_are_invalid(xml, update, why):
    rep, res = _v3([_ok(xml)])
    forged = rep.model_copy(update=update)
    v = validate_report(forged, res)
    assert v.verdict is Verdict.INVALID and any(why in r for r in v.reasons), v.reasons


def test_table_label_marked_identified_in_facts_cannot_support_identified():
    rep, res = _v3([_ok(OPEN)])
    fact = rep.verified_facts[0].model_copy(update={"service_identified": True})
    forged = rep.model_copy(update={"verified_facts": (fact,),
                                    "service_identity": ServiceIdentity.IDENTIFIED,
                                    "evidence_confidence": EvidenceConfidence.SUPPORTED})
    assert validate_report(forged, res).verdict is Verdict.INVALID


def test_schema3_fields_on_an_older_schema_are_invalid():
    res = _result([_ok(OPEN)])
    v1 = build_report(res, session_id=SID, scope=_scope(), objective="o")
    assert v1.schema_version == 1 and v1.port_exposure is None
    forged = v1.model_copy(update={"port_exposure": PortExposure.CONFIRMED})
    assert validate_report(forged, res).verdict is Verdict.INVALID


# --- older schemas keep their exact bytes and rules ---------------------------------------

# The exact top-level keys a schema-2 report had when M7.9.2 was committed (d96b811).
SCHEMA2_KEYS = {"session_id", "objective", "scope", "tool_runs", "verified_facts",
                "model_observations", "hypotheses", "errors_and_limitations",
                "execution_status", "coverage", "evidence_confidence", "model_summary",
                "model_summary_is_authoritative", "schema_version", "metadata"}


@pytest.mark.parametrize("version", [1, 2])
def test_older_schema_reports_keep_keys_and_old_headline(version):
    res = _result([_ok(OPEN)])
    rep = build_report(res, session_id=SID, scope=_scope(), objective="o",
                       schema_version=version)
    data = json.loads(serialize_report(rep))
    assert set(data) == SCHEMA2_KEYS and not set(SCHEMA3_FIELDS) & set(data)
    assert data["evidence_confidence"] == "supported"  # the old rule, frozen for replay


def test_versions_and_defaults():
    assert CURRENT_SCHEMA == REPORT_SCHEMA_VERSION == 5  # M8.5: + prior_session_evidence
    res = _result([_ok(OPEN)])
    with pytest.raises(ValueError):
        build_report(res, session_id=SID, scope=_scope(), objective="o", schema_version=6)
    rep3 = build_report(res, session_id=SID, scope=_scope(), objective="o", schema_version=3)
    assert set(json.loads(serialize_report(rep3))) == SCHEMA2_KEYS | set(SCHEMA3_FIELDS)
