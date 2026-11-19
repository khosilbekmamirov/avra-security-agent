"""M7.9.4a (D3): deterministic checks on the model's free text (schema 4).

Synthetic inputs only (plus verbatim copies of the M7.8 live report's model
text as a false-positive corpus). No network, no API, no scans, no LLM.
References that do not resolve lower the verdict to INCOMPLETE; suspicious
assertions are informational; prose never raises confidence.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from avra.core.research import ResearchResult, StopReason
from avra.llm.config import Spend
from avra.recon.nmap_xml import parse_nmap_xml
from avra.reporting import (
    EvidenceConfidence,
    ReportLimits,
    ReportMetadata,
    ReportTokens,
    ServiceIdentity,
    Verdict,
    build_report,
    validate_report,
)
from avra.reporting.claims import CLAIM_CHECK_NOTE, check_claims
from avra.reporting.store import serialize_report
from avra.runner.schemas import NmapConnectScanRequest, ToolRunResult, ToolRunStatus
from avra.runner_client.scan import ScanOutcome
from avra.schemas.scope import ActionTier, Scope, Target
from avra.storage.evidence import EvidenceRef

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "nmap"
OPEN = (FIX / "m5-juice-shop-3000-open.xml").read_text(encoding="utf-8")    # ppp, table
PROBED = (FIX / "m7-3000-probed.xml").read_text(encoding="utf-8")           # http, probed

# The synthetic M7.8-style session's identifiers (values only; nothing is read from data/).
SID = uuid.UUID("4460bea8-d974-406c-bb65-75c3be0a899f")
RID = uuid.UUID("19f10bf3-3a55-42f0-b7ac-3cb9b4fcccdb")
SHA = "fed58fd9a4fa3b48242b06c86de9dc17565e76f29af30ddd1e1b23c89643fb17"
LIVE_SUMMARY = (
    "Scan: TCP connect scan of 10.66.7.103, port 3000 only (the one allowed port). "
    "Approved and completed (request 19f10bf3-3a55-42f0-b7ac-3cb9b4fcccdb, output hash "
    "verified).\n\nResult: The host is up and TCP 3000 is open (syn-ack). Nmap called it "
    "\"ppp\", but that's just its port-number table (confidence 3, not identified). Treat it "
    "as a placeholder, not a real identification.\n\nHypothesis (not confirmed): Based on "
    "your scope description, this is most likely the OWASP Juice Shop web app "
    "(Node.js/HTTP), which uses port 3000 by default. A connect scan can't confirm what "
    "service is running. If you want confirmation, you could check it yourself by opening "
    "http://10.66.7.103:3000 in a browser, or allow a service/version probe (nmap -sV) "
    "in a future scope.\n\nNo other ports were checked because they're out of scope. No "
    "vulnerabilities were tested.")
LIVE_OBSERVATION = (
    "Host 10.66.7.103 is up. TCP 3000 is open (syn-ack). Nmap's \"ppp\" label comes only "
    "from its port-number table (confidence 3, service_identified=false), so the service "
    "was not actually fingerprinted. Output sha256 fed58fd9...b17, hash verified.")
LIVE_HYPOTHESIS = {"step": 3, "status": "unverified",
                   "statement": "The service on 10.66.7.103:3000 is the OWASP Juice Shop "
                                "web app (Node.js HTTP), not PPP.",
                   "basis": "The owner's scope says Juice Shop runs in Docker on this port."}


def _scope(ports=(3000,)):
    # A FIXED expiry: the report shows it, so a now()-based value would make two
    # otherwise identical builds differ (found by the determinism test).
    return Scope(session_name="lab", expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                 targets=[Target(host="10.66.7.103", ports=list(ports),
                                 allowed_tiers=[ActionTier.ACTIVE_SAFE],
                                 allowed_tools=["nmap_connect_scan"])])


def _outcome(xml=OPEN, rid=RID, sha=None):
    req = NmapConnectScanRequest(request_id=rid, session_id=SID, host="10.66.7.103",
                                 ports=[3000], timeout_seconds=60)
    sha = sha or hashlib.sha256(xml.encode()).hexdigest()
    res = ToolRunResult(request_id=rid, tool="nmap_connect_scan", status=ToolRunStatus.COMPLETED,
                        started_at=datetime.now(UTC), finished_at=datetime.now(UTC), exit_code=0,
                        raw_output=xml, output_sha256=sha)
    return ScanOutcome(req, True, "in scope", result=res, hash_verified=True,
                       evidence=EvidenceRef(path=Path("x.xml"), sha256=sha, size=len(xml)),
                       report=parse_nmap_xml(xml))


def _result(summary="", observations=(), hypotheses=(), outcomes=None):
    outcomes = [_outcome(sha=SHA)] if outcomes is None else outcomes
    obs = [{"step": i + 1, "status": "unverified", "summary": t} for i, t in
           enumerate(observations)]
    return ResearchResult(stop_reason=StopReason.FINISHED, detail="", steps=1,
                          tool_runs=len(outcomes), spend=Spend(), final_summary=summary,
                          proposals=len(outcomes), outcomes=list(outcomes), observations=obs,
                          hypotheses=list(hypotheses))


def _checks(summary="", observations=(), hypotheses=(), outcomes=None, ports=(3000,)):
    res = _result(summary, observations, hypotheses, outcomes)
    return check_claims(res, session_id=str(SID), targets=_scope(ports).targets)


def _metadata():
    tokens = {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 0,
              "cache_read_input_tokens": 0}
    return ReportMetadata(
        session_id=str(SID), run_started_seq=2, run_stopped_seq=4, run_stopped_hash="a" * 64,
        started_at="t0", finished_at="t1", avra_version="0.0.0", model="claude-opus-5-5",
        models_reported=("claude-opus-5-5",), model_consistent=True, prompt_version="m7-v2",
        effort="medium", max_tokens=4096,
        limits=ReportLimits(budget_usd=0.5, max_steps=5, max_tool_runs=5,
                            max_duration_seconds=1800),
        stop_reason="finished", steps=1, llm_calls=1, tool_runs=1, proposals=1,
        tokens=ReportTokens(**tokens), tokens_consistent=True, cost_usd=0.000024,
        cost_sum_of_calls_usd=0.000024, cost_from_tokens_usd=0.000024, cost_consistent=True,
        scope_file_sha256=None, scope_snapshot_sha256="b" * 64)


def _v4(summary="", observations=(), hypotheses=(), outcomes=None):
    res = _result(summary, observations, hypotheses, outcomes)
    rep = build_report(res, session_id=SID, scope=_scope(), objective="o",
                       metadata=_metadata(), schema_version=4)
    return rep, res


def _kinds(cc):
    return [(i.kind, i.token) for i in cc.reference_mismatches]


# --- the live M7.8 text is the false-positive corpus -----------------------------------

def test_live_m78_text_has_no_mismatches_and_no_flags():
    cc = _checks(LIVE_SUMMARY, [LIVE_OBSERVATION], [LIVE_HYPOTHESIS])
    assert cc.reference_mismatches == () and cc.ambiguous_references == ()
    assert cc.suspicious_assertions == ()
    # summary: request id, 10.66.7.103, the URL's 10.66.7.103:3000;
    # observation: 10.66.7.103, sha fed58fd9...b17; hypothesis: 10.66.7.103:3000
    assert cc.references_checked == 6
    rep, res = _v4(LIVE_SUMMARY, [LIVE_OBSERVATION], [LIVE_HYPOTHESIS])
    assert validate_report(rep, res).verdict is Verdict.PASS
    assert rep.claim_checks.note == CLAIM_CHECK_NOTE


# --- request IDs and hashes --------------------------------------------------------------

def test_fabricated_request_id_is_a_mismatch_but_session_id_resolves():
    fake = "00000000-0000-4000-8000-000000000000"
    cc = _checks(f"Request {fake} and session {SID} were reviewed.")
    assert _kinds(cc) == [("request_id", fake)]
    assert cc.references_checked == 2


@pytest.mark.parametrize("text,expected", [
    (f"Evidence hash {SHA}.", []),
    (f"Evidence hash {'0' * 64}.", [("sha256", "0" * 64)]),
    ("Output sha256 fed58fd9...b17.", []),
    ("Output sha256 fed58fd9…b17.", []),                    # unicode ellipsis
    ("Output sha256 fed58fd9...b18.", [("sha256_abbrev", "fed58fd9...b18")]),
    ("Output sha256 deadbe...ef.", [("sha256_abbrev", "deadbe...ef")]),
    ("sha256 FED58FD9A4FA.", []),                                # case-insensitive prefix
    ("request 19f10bf3 ran.", []),                               # UUID prefix after "request"
    ("hash deadbeef00 recorded.", [("hex_prefix", "deadbeef00")]),
])
def test_hash_and_prefix_references(text, expected):
    assert _kinds(_checks(text)) == expected


@pytest.mark.parametrize("text", [
    "Build 0123abcd4567 of the tool.",            # hex without a reference word: ignored
    "Commit cafebabe1234 changed nothing.",
    "The colour was #deadbeef in the UI.",
])
def test_arbitrary_hex_is_not_treated_as_a_reference(text):
    cc = _checks(text)
    assert cc.references_checked == 0 and cc.reference_mismatches == ()


def test_ambiguous_prefixes_are_never_resolved_or_mismatched():
    a = "abcdef" + "1" * 56 + "99"
    b = "abcdef" + "2" * 56 + "99"
    outs = [_outcome(sha=a, rid=uuid.uuid4()), _outcome(sha=b, rid=uuid.uuid4())]
    cc = _checks("Evidence sha256 abcdef...99 and hash abcdef12.", outcomes=outs)
    assert cc.reference_mismatches[0].token == "abcdef12"           # matches nothing
    assert [(i.kind, i.token) for i in cc.ambiguous_references] == [
        ("sha256_abbrev", "abcdef...99")]


# --- IPv4 and IP:port --------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("The target 10.66.7.103 answered.", []),
    ("I also saw 10.0.0.5 respond.", [("ipv4", "10.0.0.5")]),
    ("Open http://10.66.7.103:3000/ in a browser.", []),
    ("Then check 10.66.7.103:22 for SSH.", [("ipv4_port", "10.66.7.103:22")]),
    ("Port 10.66.7.103:99999 looked odd.", [("ipv4_port", "10.66.7.103:99999")]),
    ("The lab is on 192.168.56.0/24 only.", []),                  # CIDR: not a host
    ("Nmap 7.94 and version 1.2.3.4.5 ran.", []),                 # not an IPv4
    ("Value 256.1.1.1 is not an address.", []),
    ("Ends with 10.66.7.103.", []),                            # sentence period
])
def test_ip_and_ip_port_references(text, expected):
    assert _kinds(_checks(text)) == expected


@pytest.mark.parametrize("text", [
    "Something else, e.g. 10.0.0.5, would differ.",
    "For example 10.0.0.5 is a private address.",
    "A typical lab uses addresses such as 10.0.0.5.",
    "The doc writes \"10.0.0.5\" as a placeholder.",
    "Use `curl http://10.0.0.5:8080` only in your own lab.",
])
def test_example_quoted_and_code_ips_are_not_claims(text):
    cc = _checks(text)
    assert cc.reference_mismatches == () and cc.references_checked == 0


def test_duplicates_count_once_per_field():
    text = f"Request {RID} done. Again: request {RID}."
    assert _checks(text).references_checked == 1
    assert _checks(text, [text]).references_checked == 2  # summary + observation


@pytest.mark.parametrize("text", [
    "Address x10.66.7.103 is glued to a letter.",
    "Token ü19f10bf3-3a55-42f0-b7ac-3cb9b4fcccdb is glued to a letter.",
    "Fullwidth １９２.１６８.５６.１０３ digits.",
])
def test_unicode_boundaries_do_not_create_references(text):
    assert _checks(text).references_checked == 0


# --- informational assertions (observations + summary only) -------------------------------

def _cats(cc):
    return [a.category for a in cc.suspicious_assertions]


@pytest.mark.parametrize("text,cats", [
    ("Result: 3000/tcp open.", []),                               # matches the evidence
    ("Port 3000 is closed.", ["port_state"]),                     # contradicts it
    ("Port 8080 is open.", ["port_state"]),                       # no verified scan
    ("Port 3000 is not closed.", []),                             # negation
    ("Port 3000 may be closed.", []),                             # hedging
    ("If port 3000 were closed, nothing would load.", []),        # conditional
    ("The log says \"3000/tcp closed\" earlier.", []),            # quotation
    ("Run `nmap` and expect 3000/tcp closed in `out`.", ["port_state"]),
    ("The service is definitely Express.", ["service_identity"]),
    ("The service was not identified.", []),
    ("It is probably an Express server.", []),
    ("The app was exploited successfully.", ["vulnerability"]),
    ("No vulnerabilities were tested.", []),
    ("Juice Shop is an intentionally vulnerable training app.", []),
])
def test_assertion_flags(text, cats):
    assert _cats(_checks(text)) == cats


def test_identity_claim_not_flagged_when_a_probe_identified_it():
    cc = _checks("The service is definitely Express.",
                 outcomes=[_outcome(xml=PROBED, sha=SHA)])
    assert cc.suspicious_assertions == ()


def test_hypotheses_are_never_assertion_checked():
    hyp = {"statement": "The service is definitely Express and was exploited.",
           "basis": "Port 3000 is closed."}
    cc = _checks(hypotheses=[hyp])
    assert cc.suspicious_assertions == ()


# --- verdict effects and forgery ----------------------------------------------------------

def test_reference_mismatch_lowers_verdict_to_incomplete_only():
    rep, res = _v4("Request 00000000-0000-4000-8000-000000000000 completed.")
    v = validate_report(rep, res)
    assert v.verdict is Verdict.INCOMPLETE
    assert any("request_id" in r and "not a request" in r for r in v.reasons)


def test_suspicious_assertions_never_change_the_verdict():
    rep, res = _v4("The service is definitely Express. The app was exploited. Port 3000 is "
                   "closed.")
    assert len(rep.claim_checks.suspicious_assertions) == 3
    assert validate_report(rep, res).verdict is Verdict.PASS


def test_prose_never_strengthens_confidence():
    loud = ("The service is definitely identified as Express. Vulnerability confirmed and "
            "exploited. 3000/tcp open.")
    rep_loud, _ = _v4(loud, [loud])
    rep_quiet, _ = _v4("")
    for field in ("port_exposure", "service_identity", "evidence_confidence"):
        assert getattr(rep_loud, field) == getattr(rep_quiet, field)
    assert rep_loud.service_identity is ServiceIdentity.UNIDENTIFIED
    assert rep_loud.evidence_confidence is EvidenceConfidence.PARTIALLY_SUPPORTED


@pytest.mark.parametrize("forge", ["drop_mismatch", "count", "note", "add_flag", "remove"])
def test_forged_claim_checks_are_invalid(forge):
    rep, res = _v4("Request 00000000-0000-4000-8000-000000000000 done. Service definitely "
                   "Express.")
    cc = rep.claim_checks
    update = {
        "drop_mismatch": {"claim_checks": cc.model_copy(update={"reference_mismatches": ()})},
        "count": {"claim_checks": cc.model_copy(update={"references_checked": 0})},
        "note": {"claim_checks": cc.model_copy(update={"note": "All claims verified."})},
        "add_flag": {"claim_checks": cc.model_copy(update={
            "suspicious_assertions": cc.suspicious_assertions * 2})},
        "remove": {"claim_checks": None},
    }[forge]
    v = validate_report(rep.model_copy(update=update), res)
    assert v.verdict is Verdict.INVALID


def test_claim_checks_on_older_schema_are_invalid():
    res = _result("x")
    rep3 = build_report(res, session_id=SID, scope=_scope(), objective="o",
                        metadata=_metadata(), schema_version=3)
    assert rep3.claim_checks is None
    forged = rep3.model_copy(update={"claim_checks": check_claims(
        res, session_id=str(SID), targets=_scope().targets)})
    assert validate_report(forged, res).verdict is Verdict.INVALID


# --- determinism and serialization --------------------------------------------------------

def test_checks_and_bytes_are_deterministic():
    args = (LIVE_SUMMARY + " Request 00000000-0000-4000-8000-000000000000.",
            [LIVE_OBSERVATION], [LIVE_HYPOTHESIS])
    assert _checks(*args) == _checks(*args)
    assert serialize_report(_v4(*args)[0]) == serialize_report(_v4(*args)[0])


@pytest.mark.parametrize("version,has_claims", [(2, False), (3, False), (4, True)])
def test_claim_checks_key_only_from_schema_4(version, has_claims):
    res = _result("x")
    rep = build_report(res, session_id=SID, scope=_scope(), objective="o",
                       metadata=_metadata(), schema_version=version)
    assert ("claim_checks" in json.loads(serialize_report(rep))) is has_claims


# --- M7.9.4b adversarial boundaries ---------------------------------------------------
# These pin CURRENT behaviour, including known false positives (FP) and false
# negatives (FN). A test marked FP/FN documents a limitation; changing it means
# changing a detection rule, which needs a reviewed decision.

def _summary(text, **kw):
    cc = _checks(text, **kw)
    return ([(i.kind, i.token) for i in cc.reference_mismatches],
            [(i.kind, i.token) for i in cc.ambiguous_references],
            [a.category for a in cc.suspicious_assertions], cc.references_checked)


def test_fp_conversational_unrelated_ip_is_a_mismatch():
    # FP (strict by design): any explicit IP outside scope/evidence counts.
    assert _summary("By the way, my router is 192.168.1.1 at home.")[0] == [
        ("ipv4", "192.168.1.1")]


def test_illustrative_ip_is_not_a_claim():
    assert _summary("Private ranges such as 10.0.0.5 are not routable.") == ([], [], [], 0)


def test_url_with_in_scope_ip_port_resolves():
    assert _summary("Browse to https://10.66.7.103:3000/#/login to check.") == (
        [], [], [], 1)


def test_out_of_scope_host_with_an_allowed_port_is_a_mismatch():
    assert _summary("Then 192.168.56.104:3000 was reachable.")[0] == [
        ("ipv4_port", "192.168.56.104:3000")]


def test_valid_hash_in_several_fields_resolves_in_each():
    m, a, s, n = _summary(f"Hash {SHA}.", observations=[f"sha256 {SHA}"],
                          hypotheses=[{"statement": f"evidence {SHA}", "basis": "b"}])
    assert (m, a, s, n) == ([], [], [], 3)


def test_invalid_hash_prefixes_are_mismatches():
    assert _summary("sha256 94f5813b; evidence 0000aaaa1111.")[0] == [
        ("hex_prefix", "94f5813b"), ("hex_prefix", "0000aaaa1111")]


def test_ambiguous_request_id_prefix_is_ambiguous_not_a_mismatch():
    r1 = uuid.UUID("abcdef12-0000-4000-8000-000000000001")
    r2 = uuid.UUID("abcdef12-0000-4000-8000-000000000002")
    outs = [_outcome(rid=r1, sha="1" * 64), _outcome(rid=r2, sha="2" * 64)]
    assert _summary("See request abcdef12 for details.", outcomes=outs)[:2] == (
        [], [("hex_prefix", "abcdef12")])


def test_fp_ordinary_hex_after_generic_id_word_is_a_mismatch():
    # FP: "id" is one of the reference words, so an unrelated hex id is checked.
    assert _summary("The user id 1a2b3c4d logged in.")[0] == [("hex_prefix", "1a2b3c4d")]
    assert _summary("Ticket 1a2b3c4d was closed.") == ([], [], [], 0)  # no reference word


@pytest.mark.parametrize("text", [
    'The banner said "service confirmed as Express".',
    "The banner said “service confirmed as Express”.",
])
def test_quoted_service_confirmation_is_not_flagged(text):
    assert _summary(text)[2] == []


def test_negated_vulnerability_claim_is_not_flagged():
    assert _summary("No vulnerability was exploited or tested.")[2] == []


def test_hypothesis_with_unverified_identity_is_not_flagged():
    hyp = {"statement": "The service is definitely Express", "basis": "It was exploited."}
    assert _summary("", hypotheses=[hyp])[2] == []


@pytest.mark.parametrize("text,flags", [
    ("Port 3000 is closed。It is fine.", ["port_state"]),      # ideographic stop
    ("Port 3000 is closed… really.", ["port_state"]),         # ellipsis
    ("Port 3000 is closed.", ["port_state"]),            # no-break spaces
    # FN: U+3002 is not a sentence boundary, so the next sentence's "not" hides it.
    ("Port 3000 is closed。It is not open.", []),
    # FN: one negated clause makes the whole sentence non-assertive.
    ("The service isn’t identified — it is definitely Express.", []),
])
def test_unicode_punctuation_and_sentence_boundaries(text, flags):
    assert _summary(text)[2] == flags
