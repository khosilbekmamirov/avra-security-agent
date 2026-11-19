"""Evidence-grounded final report + passive validator (M7.8 Stage 3).

The report is built **by code** from what AVRA already recorded — the scan
outcomes (`ScanOutcome`) and the model's own notes — not authored by the
model. This is a deliberate design choice: the model can *explain* evidence
in its free-text summary, but it can never manufacture an evidence
reference or mark an unsupported claim as verified, because it does not
write the structured report.

Three independent dimensions describe the outcome (never conflated):

* execution status — how the session ended;
* research coverage — how much of the authorized scope was evaluated;
* evidence confidence — how well the evidence answers the objective.

The passive ``validate_report`` re-checks the built report against the
ground-truth outcomes and returns PASS / INCOMPLETE / INVALID with reasons.
It inspects structured fields only — never natural-language keywords — so a
model's prose can never satisfy or defeat a validation guarantee.
"""

from __future__ import annotations

import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict

from avra.core.research import ResearchResult, StopReason, classify_result
from avra.reporting.claims import CLAIM_CHECK_NOTE, ClaimChecks, check_claims
from avra.runner_client.scan import ScanOutcome
from avra.schemas.scope import Scope


class ExecutionStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DENIED = "denied"
    INTERRUPTED = "interrupted"


class ResearchCoverage(str, Enum):
    FULLY_EVALUATED = "fully_evaluated"
    PARTIALLY_EVALUATED = "partially_evaluated"
    NOT_EVALUATED = "not_evaluated"


class EvidenceConfidence(str, Enum):
    # Schema 3 (M7.9.3, D1): SUPPORTED only when exposure is confirmed AND every
    # open port's service was identified by a probe. Schemas 1-2 used the older
    # rule (any verified open port), kept only to rebuild those reports exactly.
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"  # exposure confirmed, identity not fully
    INFERRED = "inferred"         # only hypotheses, no direct verified evidence
    CONTRADICTED = "contradicted"  # a claim conflicts with the evidence (validator only)
    INCONCLUSIVE = "inconclusive"  # evidence is insufficient to conclude


class PortExposure(str, Enum):
    """Schema 3: is anything reachable? (machine-verified scans only)"""
    CONFIRMED = "confirmed"          # at least one verified open port
    NONE_OPEN = "none_open"          # verified scans, a host up, nothing open
    HOST_DOWN = "host_down"          # verified scans, no host reported up
    NOT_EVALUATED = "not_evaluated"  # no verified scan at all


class ServiceIdentity(str, Enum):
    """Schema 3: what answers on the open ports? A port-number table label
    (nmap method="table") is never an identification."""
    IDENTIFIED = "identified"                      # every verified open port probed
    PARTIALLY_IDENTIFIED = "partially_identified"  # some, not all
    UNIDENTIFIED = "unidentified"                  # open ports, none probed
    NOT_APPLICABLE = "not_applicable"              # no verified open port


class Verdict(str, Enum):
    PASS = "PASS"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"


_STOP_TO_EXECUTION = {
    StopReason.FINISHED: ExecutionStatus.COMPLETED,
    StopReason.END_TURN: ExecutionStatus.COMPLETED,
    StopReason.BUDGET: ExecutionStatus.COMPLETED,
    StopReason.MAX_STEPS: ExecutionStatus.COMPLETED,
    StopReason.DURATION: ExecutionStatus.TIMED_OUT,
    StopReason.REFUSAL: ExecutionStatus.DENIED,
    StopReason.MAX_TOKENS: ExecutionStatus.FAILED,
    StopReason.PROVIDER_ERROR: ExecutionStatus.FAILED,
    StopReason.UNEXPECTED: ExecutionStatus.FAILED,
    StopReason.ABORTED: ExecutionStatus.INTERRUPTED,
    StopReason.NO_PROGRESS: ExecutionStatus.COMPLETED,  # M8.5: nothing left to do
    StopReason.KILL_SWITCH: ExecutionStatus.INTERRUPTED,  # M8.7: local emergency stop
}


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PortFact(_Model):
    host: str
    port: int
    protocol: str
    state: str
    reason: str
    service_guess: str
    service_method: str
    service_confidence: int | None
    service_identified: bool


class ToolRunReport(_Model):
    request_id: str
    host: str
    ports: tuple[int, ...]
    timeout_seconds: int
    owner_approved: bool
    result_state: str
    execution_ok: bool
    status: str | None
    exit_code: int | None
    evidence_sha256: str | None
    hash_verified: bool | None
    nmap_exit_status: str | None
    hosts: tuple[dict, ...]
    port_facts: tuple[PortFact, ...]
    errors: tuple[str, ...]


class Note(_Model):
    step: int
    text: str
    evidence_request_id: str | None = None
    status: str = "unverified"


class ReportTarget(_Model):
    host: str
    ports: tuple[int, ...]
    tiers: tuple[str, ...]
    tools: tuple[str, ...]
    description: str = ""


class ReportScope(_Model):
    session_name: str
    expires_at: str
    environment_description: str = ""
    targets: tuple[ReportTarget, ...]


class ReportLimits(_Model):
    budget_usd: float
    max_steps: int
    max_tool_runs: int
    max_duration_seconds: int


class ReportTokens(_Model):
    input_tokens: int
    output_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int


class ReportMetadata(_Model):
    """Schema-2 metadata (M7.9.2). Every field comes from verified audit
    records (avra.reporting.replay.run_metadata) — never from model prose."""

    session_id: str
    run_started_seq: int
    run_stopped_seq: int
    run_stopped_hash: str          # audit anchor: hash of the research_stopped record
    started_at: str                # audit timestamps of research_started / _stopped
    finished_at: str
    avra_version: str
    model: str                     # configured model (research_started)
    models_reported: tuple[str, ...]  # what the API reported per call
    model_consistent: bool
    prompt_version: str
    effort: str
    max_tokens: int
    limits: ReportLimits
    stop_reason: str
    steps: int
    llm_calls: int
    tool_runs: int
    proposals: int
    tokens: ReportTokens
    tokens_consistent: bool        # research_stopped totals == sum of llm_call usage
    cost_usd: float                # research_stopped.total_cost_usd
    cost_sum_of_calls_usd: float
    cost_from_tokens_usd: float    # tokens x the price table recorded at start
    cost_consistent: bool
    scope_file_sha256: str | None
    scope_snapshot_sha256: str


class PriorEvidence(_Model):
    """Schema 5: one piece of verified evidence recorded earlier in the same
    session (e.g. an owner's ``avra probe http`` before the research run)."""

    request_id: str
    tool: str
    target: str          # host:port, inside this run's scope
    sha256: str          # evidence file SHA-256 (= the Runner's output hash)
    audit_seq: int       # seq of its tool_result_received record


class ResearchReport(_Model):
    session_id: str
    objective: str
    scope: ReportScope
    tool_runs: tuple[ToolRunReport, ...]
    verified_facts: tuple[PortFact, ...]       # machine-confirmed, hash-verified
    model_observations: tuple[Note, ...]       # model's record_observation (unverified)
    hypotheses: tuple[Note, ...]               # model's record_hypothesis (unverified)
    errors_and_limitations: tuple[str, ...]
    execution_status: ExecutionStatus
    coverage: ResearchCoverage
    evidence_confidence: EvidenceConfidence
    model_summary: str = ""                    # free text from finish_session
    model_summary_is_authoritative: bool = False  # always False: prose is never evidence
    # 1: pre-M7.9.2 (no metadata; also every legacy file). 2: metadata from audit.
    # 3: + port_exposure / service_identity and the stricter headline (M7.9.3).
    schema_version: int = 1
    metadata: ReportMetadata | None = None
    port_exposure: PortExposure | None = None        # schema 3+
    service_identity: ServiceIdentity | None = None  # schema 3+
    # Schema 4 (M7.9.4, D3): deterministic checks on the model's free text.
    # Informational about the prose; never evidence and never an upgrade.
    claim_checks: ClaimChecks | None = None          # schema 4+
    # Schema 5 (M8.5): evidence recorded EARLIER in this same session (before
    # this run) that AVRA verified (audit chain, request/result pairing, file
    # hash, parse, target in this run's scope). Model text may cite it.
    prior_session_evidence: tuple[PriorEvidence, ...] = ()  # schema 5+

    def canonical_dict(self) -> dict:
        """What gets serialized. Keys introduced by a later schema are left out,
        so reports attested by older code rebuild to the exact same bytes."""
        data = self.model_dump(mode="json")
        for version, keys in SCHEMA_FIELDS.items():
            if self.schema_version < version:
                for key in keys:
                    data.pop(key, None)
        return data


CURRENT_SCHEMA = 5
SCHEMA3_FIELDS = ("port_exposure", "service_identity")
SCHEMA4_FIELDS = ("claim_checks",)
SCHEMA5_FIELDS = ("prior_session_evidence",)
SCHEMA_FIELDS = {3: SCHEMA3_FIELDS, 4: SCHEMA4_FIELDS,
                 5: SCHEMA5_FIELDS}  # first schema that has each key


class ValidationResult(_Model):
    verdict: Verdict
    reasons: tuple[str, ...] = ()


def _port_facts(outcome: ScanOutcome) -> list[PortFact]:
    if outcome.report is None:
        return []
    return [PortFact(host=h.address, port=p.port, protocol=p.protocol, state=p.state,
                     reason=p.reason, service_guess=p.service, service_method=p.service_method,
                     service_confidence=p.service_confidence,
                     service_identified=p.service_identified)
            for h in outcome.report.hosts for p in h.ports]


def _tool_run_report(outcome: ScanOutcome) -> ToolRunReport:
    state, _ = classify_result(outcome)
    r = outcome.result
    return ToolRunReport(
        request_id=str(outcome.request.request_id),
        host=outcome.request.host,
        ports=tuple(outcome.request.ports),
        timeout_seconds=outcome.request.timeout_seconds,
        owner_approved=True,  # an outcome only exists after owner approval + execute()
        result_state=state,
        execution_ok=outcome.ok,
        status=r.status.value if r is not None else None,
        exit_code=r.exit_code if r is not None else None,
        evidence_sha256=outcome.evidence.sha256 if outcome.evidence is not None else None,
        hash_verified=outcome.hash_verified,
        nmap_exit_status=outcome.report.exit_status if outcome.report is not None else None,
        hosts=tuple({"host": h.address, "status": h.status} for h in outcome.report.hosts)
        if outcome.report is not None else (),
        port_facts=tuple(_port_facts(outcome)),
        errors=tuple(outcome.errors),
    )


def _coverage(scope: Scope, outcomes: list[ScanOutcome]) -> ResearchCoverage:
    in_scope = {(t.host, port) for t in scope.targets for port in t.ports}
    covered = {(o.request.host, port) for o in outcomes if o.ok for port in o.request.ports}
    if not covered:
        return ResearchCoverage.NOT_EVALUATED
    return (ResearchCoverage.FULLY_EVALUATED if in_scope <= covered
            else ResearchCoverage.PARTIALLY_EVALUATED)


def _evidence_confidence(outcomes: list[ScanOutcome], hypotheses: list) -> EvidenceConfidence:
    """Schemas 1-2 headline (kept only to rebuild those reports byte-for-byte):
    any verified open port counted as SUPPORTED — the D1 overstatement."""
    ok = [o for o in outcomes if o.ok and o.report is not None]
    if any(p.state == "open" for o in ok for h in o.report.hosts for p in h.ports):
        return EvidenceConfidence.SUPPORTED
    if ok:
        return EvidenceConfidence.INCONCLUSIVE  # scans ran but nothing resolving
    return EvidenceConfidence.INFERRED if hypotheses else EvidenceConfidence.INCONCLUSIVE


# --- schema 3 (M7.9.3, D1): exposure and identity, never conflated -------------------

def _verified_reports(outcomes: list[ScanOutcome]) -> list:
    return [o.report for o in outcomes if o.ok and o.report is not None]


def _open_ports(outcomes: list[ScanOutcome]) -> list:
    return [p for r in _verified_reports(outcomes) for h in r.hosts for p in h.ports
            if p.state == "open"]


def port_exposure(outcomes: list[ScanOutcome]) -> PortExposure:
    reports = _verified_reports(outcomes)
    if not reports:
        return PortExposure.NOT_EVALUATED
    if _open_ports(outcomes):
        return PortExposure.CONFIRMED
    if any(h.status == "up" for r in reports for h in r.hosts):
        return PortExposure.NONE_OPEN
    return PortExposure.HOST_DOWN


def service_identity(outcomes: list[ScanOutcome]) -> ServiceIdentity:
    open_ports = _open_ports(outcomes)
    if not open_ports:
        return ServiceIdentity.NOT_APPLICABLE
    identified = sum(1 for p in open_ports if p.service_identified)
    if identified == len(open_ports):
        return ServiceIdentity.IDENTIFIED
    return (ServiceIdentity.PARTIALLY_IDENTIFIED if identified
            else ServiceIdentity.UNIDENTIFIED)


def evidence_confidence_v3(outcomes: list[ScanOutcome], hypotheses: list) -> EvidenceConfidence:
    """Never stronger than the weaker of exposure and identity."""
    exposure = port_exposure(outcomes)
    if exposure is PortExposure.CONFIRMED:
        return (EvidenceConfidence.SUPPORTED
                if service_identity(outcomes) is ServiceIdentity.IDENTIFIED
                else EvidenceConfidence.PARTIALLY_SUPPORTED)
    if exposure is not PortExposure.NOT_EVALUATED:
        return EvidenceConfidence.INCONCLUSIVE  # scans ran, nothing open to describe
    return EvidenceConfidence.INFERRED if hypotheses else EvidenceConfidence.INCONCLUSIVE


def build_report(result: ResearchResult, *, session_id: uuid.UUID, scope: Scope,
                 objective: str, metadata: ReportMetadata | None = None,
                 schema_version: int | None = None) -> ResearchReport:
    """Assemble the structured report deterministically from recorded data.

    ``schema_version`` defaults to ``CURRENT_SCHEMA`` with metadata (built from
    the audit) and to 1 without. Replay passes the version the run's audit
    recorded, so a report always rebuilds with the rules it was made with."""
    if schema_version is None:
        schema_version = CURRENT_SCHEMA if metadata is not None else 1
    if schema_version not in (1, 2, 3, 4, 5):
        raise ValueError(f"unknown report schema version {schema_version!r}")
    verified = [f for o in result.outcomes if o.ok for f in _port_facts(o)]
    if schema_version >= 3:
        headline = evidence_confidence_v3(result.outcomes, result.hypotheses)
        exposure, identity = port_exposure(result.outcomes), service_identity(result.outcomes)
    else:
        headline = _evidence_confidence(result.outcomes, result.hypotheses)
        exposure = identity = None
    prior = tuple(result.prior_evidence) if schema_version >= 5 else None
    claims = (check_claims(result, session_id=str(session_id), targets=scope.targets,
                           prior=prior)
              if schema_version >= 4 else None)
    return ResearchReport(
        session_id=str(session_id),
        objective=objective,
        scope=ReportScope(
            session_name=scope.session_name,
            expires_at=scope.expires_at.isoformat(),
            environment_description=scope.description,
            targets=tuple(ReportTarget(host=t.host, ports=tuple(t.ports),
                                       tiers=tuple(x.value for x in t.allowed_tiers),
                                       tools=tuple(t.allowed_tools), description=t.description)
                          for t in scope.targets),
        ),
        tool_runs=tuple(_tool_run_report(o) for o in result.outcomes),
        verified_facts=tuple(verified),
        model_observations=tuple(Note(step=o.get("step", 0), text=o.get("summary", ""),
                                      evidence_request_id=o.get("evidence_request_id"),
                                      status=o.get("status", "unverified"))
                                 for o in result.observations),
        hypotheses=tuple(Note(step=h.get("step", 0),
                              text=f"{h.get('statement', '')} | basis: {h.get('basis', '')}",
                              status=h.get("status", "unverified"))
                         for h in result.hypotheses),
        errors_and_limitations=tuple(e for o in result.outcomes for e in o.errors),
        execution_status=_STOP_TO_EXECUTION.get(result.stop_reason, ExecutionStatus.FAILED),
        coverage=_coverage(scope, result.outcomes),
        evidence_confidence=headline,
        model_summary=result.final_summary,
        schema_version=schema_version,
        metadata=metadata,
        port_exposure=exposure,
        service_identity=identity,
        claim_checks=claims,
        prior_session_evidence=prior or (),
    )


def validate_report(report: ResearchReport, result: ResearchResult) -> ValidationResult:
    """Passive, structural cross-check of a report against ground-truth
    outcomes. Returns INVALID for a contradiction/fabrication, INCOMPLETE for
    a missing-but-not-contradictory gap, PASS otherwise."""
    invalid: list[str] = []
    incomplete: list[str] = []

    # Ground truth, keyed by request_id.
    truth = {str(o.request.request_id): o for o in result.outcomes}
    truth_facts = {rid: {(f.host, f.port): f for f in _port_facts(o)} for rid, o in truth.items()}

    # 1. required fields present.
    if not report.session_id or not report.objective or not report.scope.targets:
        incomplete.append("missing required field (session_id, objective, or scope targets)")

    # 3. every reported tool run actually occurred.
    for tr in report.tool_runs:
        if tr.request_id not in truth:
            invalid.append(f"tool_run {tr.request_id} has no matching session outcome")
            continue
        o = truth[tr.request_id]
        # 4. reported states agree with parsed evidence.
        for pf in tr.port_facts:
            real = truth_facts[tr.request_id].get((pf.host, pf.port))
            if real is None or real.state != pf.state or real.service_guess != pf.service_guess:
                invalid.append(f"tool_run {tr.request_id}: port {pf.host}:{pf.port} "
                               "disagrees with parsed evidence")
        # 5. an execution failure must not be reported as a clean/ok run.
        if tr.execution_ok and not o.ok:
            invalid.append(f"tool_run {tr.request_id} marked ok but the outcome failed")

    # 2. model observation evidence references must exist in this session.
    # Schema 5: a reference may also point at earlier evidence of this session
    # that AVRA verified itself (result.prior_evidence - never the report's own
    # list). Schemas 1-4 keep "this run only" and their original wording.
    schema5 = report.schema_version >= 5
    prior_ids = {p.request_id for p in result.prior_evidence} if schema5 else set()
    for obs in report.model_observations:
        rid = obs.evidence_request_id
        if rid and rid not in truth and rid not in prior_ids:
            invalid.append(f"observation cites evidence {rid}, " + (
                "which is neither a tool run of this run nor verified earlier "
                "evidence of this session" if schema5 else
                "which is not a tool run in this session"))

    # 6. port-table guesses must not be presented as verified identities.
    for pf in (*report.verified_facts, *(p for tr in report.tool_runs for p in tr.port_facts)):
        if pf.service_identified and pf.service_method != "probed":
            invalid.append(f"service on {pf.host}:{pf.port} marked identified without a probe")

    # 7. hypotheses must stay explicitly unverified.
    for hyp in report.hypotheses:
        if hyp.status != "unverified":
            invalid.append(f"hypothesis at step {hyp.step} is not labelled unverified")

    # 8. partial / inconclusive outcomes must not be inflated.
    if report.evidence_confidence is EvidenceConfidence.SUPPORTED and not any(
        pf.state == "open" for pf in report.verified_facts
    ):
        invalid.append("evidence_confidence=supported but no verified open port exists")
    if (report.coverage is ResearchCoverage.FULLY_EVALUATED
            and _coverage_scope_unmet(report)):
        incomplete.append("coverage=fully_evaluated but not every in-scope port was verified")

    # 10. schema 3 (M7.9.3, D1): exposure / identity / headline follow from the
    # verified evidence, and a port-table label can never count as identified.
    if report.schema_version >= 3:
        open_facts = [pf for pf in report.verified_facts if pf.state == "open"]
        if report.port_exposure is None or report.service_identity is None:
            invalid.append("schema 3 report without port_exposure/service_identity")
        else:
            if report.port_exposure is not port_exposure(result.outcomes):
                invalid.append(f"port_exposure={report.port_exposure.value} does not follow "
                               "from the verified evidence")
            if report.service_identity is not service_identity(result.outcomes):
                invalid.append(f"service_identity={report.service_identity.value} does not "
                               "follow from the verified evidence")
            if report.service_identity is ServiceIdentity.IDENTIFIED and not (
                    open_facts and all(pf.service_identified and pf.service_method == "probed"
                                       for pf in open_facts)):
                invalid.append("service_identity=identified without every open port probed")
            if report.port_exposure is PortExposure.CONFIRMED and not open_facts:
                invalid.append("port_exposure=confirmed without a verified open port")
        expected = evidence_confidence_v3(result.outcomes, result.hypotheses)
        if report.evidence_confidence is not expected:
            invalid.append(f"evidence_confidence={report.evidence_confidence.value} does not "
                           f"follow from exposure/identity (expected {expected.value})")
        if (report.evidence_confidence is EvidenceConfidence.SUPPORTED
                and report.service_identity is not ServiceIdentity.IDENTIFIED):
            invalid.append("evidence_confidence=supported without an identified service")
    elif report.port_exposure is not None or report.service_identity is not None:
        invalid.append("schema-3 fields on a report of an older schema")

    # 11. schema 4 (M7.9.4, D3): claim checks on the model's free text. The
    # block must equal an independent recomputation (forged/edited -> INVALID);
    # an explicit reference that does not resolve -> INCOMPLETE; suspicious
    # assertions are informational and never change the verdict. Prose is
    # never INVALID on its own and never raises confidence.
    # 12. schema 5: prior same-session evidence must equal what AVRA itself
    # derived from the audit + evidence (result.prior_evidence), never the
    # report's own claim; older schemas must not carry it.
    expected_prior = tuple(result.prior_evidence) if report.schema_version >= 5 else None
    if report.schema_version >= 5:
        if tuple(report.prior_session_evidence) != expected_prior:
            invalid.append("prior_session_evidence does not match the verified session "
                           "evidence recomputed by AVRA")
    elif report.prior_session_evidence:
        invalid.append("prior_session_evidence on a report older than schema 5")

    if report.schema_version >= 4:
        expected_claims = check_claims(result, session_id=report.session_id,
                                       targets=report.scope.targets, prior=expected_prior)
        if report.claim_checks is None:
            invalid.append("schema 4 report without claim_checks")
        elif report.claim_checks != expected_claims:
            invalid.append("claim_checks do not match an independent recomputation")
        elif report.claim_checks.note != CLAIM_CHECK_NOTE:
            invalid.append("claim_checks limitation note was altered")
        for issue in expected_claims.reference_mismatches[:10]:
            incomplete.append(f"{issue.field} cites {issue.kind} {issue.token!r}: "
                              f"{issue.reason}")
        extra = len(expected_claims.reference_mismatches) - 10
        if extra > 0:
            incomplete.append(f"... and {extra} more unresolved references in model text")
    elif report.claim_checks is not None:
        invalid.append("schema-4 claim_checks on a report of an older schema")

    # 9. schema-2 metadata (M7.9.2): present, about this session, consistent.
    if report.schema_version >= 2:
        md = report.metadata
        if md is None:
            invalid.append(f"schema_version {report.schema_version} report without metadata")
        else:
            if md.session_id != report.session_id:
                invalid.append("metadata.session_id does not match the report")
            if not md.model_consistent:
                incomplete.append("API-reported model differs from the configured model")
            if not md.tokens_consistent:
                incomplete.append("token totals do not match the per-call usage")
            if not md.cost_consistent:
                incomplete.append("recorded cost does not reconcile with calls/tokens")

    if invalid:
        return ValidationResult(verdict=Verdict.INVALID, reasons=tuple(invalid + incomplete))
    if incomplete:
        return ValidationResult(verdict=Verdict.INCOMPLETE, reasons=tuple(incomplete))
    return ValidationResult(verdict=Verdict.PASS)


def _coverage_scope_unmet(report: ResearchReport) -> bool:
    in_scope = {(t.host, port) for t in report.scope.targets for port in t.ports}
    verified = {(tr.host, port) for tr in report.tool_runs if tr.execution_ok for port in tr.ports}
    return not in_scope <= verified
