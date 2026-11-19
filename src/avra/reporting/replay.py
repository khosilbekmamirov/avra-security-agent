"""Deterministic offline replay and read-only verification (M7.9.2).

A schema-2 report is a pure function of the session audit log and the
evidence files: the scope comes from the snapshot recorded in
``research_started`` (never from the current scope file), the outcomes are
rebuilt from the tool events plus the stored nmap XML, and the metadata
comes from audit records only. ``verify_session`` rebuilds every research
run that way and compares the canonical bytes with the attested report.

Nothing here writes a file, calls a network service, runs a tool or talks
to a model. Every audit field is treated as untrusted input: types are
checked, evidence paths are built only from validated UUIDs, and files are
inspected without following links.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from avra.core.research import ResearchResult, StopReason
from avra.core.snapshot import SnapshotError, scope_from_snapshot
from avra.llm.config import Spend
from avra.recon.nmap_xml import NmapXmlError, parse_nmap_xml
from avra.reporting import (
    PriorEvidence,
    ReportLimits,
    ReportMetadata,
    ReportTokens,
    ResearchReport,
    build_report,
    validate_report,
)
from avra.reporting.store import (
    PublicationState,
    ReportStoreError,
    _chain_ok,
    _inspect,
    report_filename,
    report_states,
    serialize_report,
)
from avra.runner.schemas import (
    NmapConnectScanRequest,
    RejectionStage,
    RunnerRejection,
    ToolRunResult,
    ToolRunStatus,
)
from avra.runner_client.scan import ScanOutcome
from avra.schemas.scope import Scope
from avra.storage.audit import AuditLog, AuditRecord
from avra.storage.evidence import EvidenceRef

TOKEN_KEYS = ("input_tokens", "output_tokens", "cache_creation_input_tokens",
              "cache_read_input_tokens")
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_DATA_ERRORS = (KeyError, TypeError, ValueError, ValidationError)


class ReplayError(Exception):
    """The run cannot be rebuilt from the audit log and evidence."""


class LegacyRunError(ReplayError):
    """The run predates M7.9.2: no scope snapshot / metadata was recorded."""


@dataclass(frozen=True)
class Run:
    started: AuditRecord
    stopped: AuditRecord
    body: tuple[AuditRecord, ...]  # records strictly between started and stopped


@dataclass(frozen=True)
class EvidenceCheck:
    request_id: str
    state: str  # ok | missing | mismatch | unsafe | invalid_reference
    detail: str = ""


def find_runs(records: list[AuditRecord]) -> list[Run]:
    """research_started ... research_stopped pairs, in order."""
    runs, start, body = [], None, []
    for rec in records:
        if rec.event == "research_started":
            start, body = rec, []
        elif rec.event == "research_stopped" and start is not None:
            runs.append(Run(start, rec, tuple(body)))
            start, body = None, []
        elif start is not None:
            body.append(rec)
    return runs


def _data(rec: AuditRecord) -> dict:
    if not isinstance(rec.data, dict):
        raise ReplayError(f"audit record {rec.seq}: data is not an object")
    return rec.data


def _is_v2(run: Run) -> bool:
    return isinstance(run.started.data, dict) and run.started.data.get("record_format") == 2


# --- trusted inputs ---------------------------------------------------------------

def trusted_scope(run: Run) -> Scope:
    if not _is_v2(run):
        raise LegacyRunError("legacy run: no scope snapshot recorded "
                             "(the current scope file is never substituted)")
    d = _data(run.started)
    try:
        return scope_from_snapshot(d.get("scope_snapshot"), d.get("scope_snapshot_sha256"))
    except SnapshotError as exc:
        raise ReplayError(f"scope snapshot: {exc}") from None


def run_metadata(run: Run, session_id: uuid.UUID) -> ReportMetadata:
    """Schema-2 metadata, from audit records only, with cross-checks."""
    if not _is_v2(run):
        raise LegacyRunError("legacy run: no metadata recorded")
    s, t = _data(run.started), _data(run.stopped)
    calls = [_data(r) for r in run.body if r.event == "llm_call"]
    try:
        model = s["model"]
        reported = tuple(sorted({c["model"] for c in calls}))
        tokens = {k: t["tokens"][k] for k in TOKEN_KEYS}
        per_call = {k: sum(c["usage"][k] for c in calls) for k in TOKEN_KEYS}
        price = s["prices_usd_per_mtok"]
        cost = float(t["total_cost_usd"])
        sum_calls = round(sum(float(c["cost_usd"]) for c in calls), 6)
        from_tokens = round((tokens["input_tokens"] * price["input"]
                             + tokens["output_tokens"] * price["output"]
                             + tokens["cache_creation_input_tokens"] * price["cache_write"]
                             + tokens["cache_read_input_tokens"] * price["cache_read"])
                            / 1_000_000, 6)
        tolerance = 1e-6 * (len(calls) + 1)  # per-call costs are audited rounded to 6 dp
        return ReportMetadata(
            session_id=str(session_id), run_started_seq=run.started.seq,
            run_stopped_seq=run.stopped.seq, run_stopped_hash=run.stopped.hash,
            started_at=run.started.ts, finished_at=run.stopped.ts,
            avra_version=s["avra_version"], model=model, models_reported=reported,
            model_consistent=all(m == model for m in reported),
            prompt_version=s["prompt_version"], effort=s["effort"], max_tokens=s["max_tokens"],
            limits=ReportLimits(**s["limits"]), stop_reason=t["stop_reason"], steps=t["steps"],
            llm_calls=len(calls), tool_runs=t["tool_runs"], proposals=t["proposals"],
            tokens=ReportTokens(**tokens), tokens_consistent=tokens == per_call,
            cost_usd=cost, cost_sum_of_calls_usd=sum_calls, cost_from_tokens_usd=from_tokens,
            cost_consistent=abs(cost - sum_calls) <= tolerance
            and abs(cost - from_tokens) <= tolerance,
            scope_file_sha256=s.get("scope_file_sha256"),
            scope_snapshot_sha256=s["scope_snapshot_sha256"],
        )
    except _DATA_ERRORS as exc:
        raise ReplayError(f"run metadata is malformed ({type(exc).__name__})") from None


def report_schema_version(run: Run) -> int:
    """The report schema this run's AVRA build produced, from the audit.
    record_format-2 runs that predate M7.9.3 do not record it: they are 2."""
    if not _is_v2(run):
        raise LegacyRunError("legacy run: no report schema recorded")
    version = _data(run.started).get("report_schema_version", 2)
    if type(version) is not int or version not in (2, 3, 4, 5):
        raise ReplayError("research_started.report_schema_version is not 2, 3, 4 or 5")
    return version


def trusted_report_inputs(audit: AuditLog, session_id: uuid.UUID
                          ) -> tuple[Scope, str, ReportMetadata, int]:
    """For the run that just finished (the CLI): scope, objective, metadata and
    report schema version — all from the audit log, exactly as ``verify`` will
    later read them."""
    records = audit.read_all()
    runs = find_runs(records)
    if not runs or runs[-1].stopped.seq != records[-1].seq:
        raise ReplayError("the last audit record does not close a research run")
    run = runs[-1]
    objective = _data(run.started).get("objective")
    if not isinstance(objective, str):
        raise ReplayError("research_started has no objective")
    return (trusted_scope(run), objective, run_metadata(run, session_id),
            report_schema_version(run))


# --- evidence ----------------------------------------------------------------------

def _uuid(value: object) -> uuid.UUID | None:
    if not isinstance(value, str):
        return None
    try:
        u = uuid.UUID(value)
    except ValueError:
        return None
    return u if str(u) == value else None


# Evidence file extension per tool (M8.5: http_probe evidence is a JSON
# envelope). Records without a tool field are legacy nmap results.
_EVIDENCE_SUFFIX = {None: ".xml", "nmap_connect_scan": ".xml", "http_probe": ".json"}


def evidence_path(evidence_root: Path, session_id: uuid.UUID, request_id: uuid.UUID,
                  tool: str | None = None) -> Path:
    """Built only from validated UUIDs (and a known tool) — the recorded
    evidence_path is ignored."""
    return Path(evidence_root) / str(session_id) / f"{request_id}{_EVIDENCE_SUFFIX[tool]}"


def check_evidence(data: dict, session_id: uuid.UUID, evidence_root: Path
                   ) -> tuple[EvidenceCheck, bytes | None]:
    rid = _uuid(data.get("request_id"))
    recorded = data.get("evidence_sha256")
    label = str(data.get("request_id"))[:64]
    if rid is None:
        return EvidenceCheck(label, "invalid_reference", "request_id is not a UUID"), None
    if not isinstance(recorded, str) or not _HEX64.fullmatch(recorded):
        return EvidenceCheck(label, "invalid_reference", "recorded hash is malformed"), None
    tool = data.get("tool")
    if tool not in _EVIDENCE_SUFFIX:  # fail closed on anything unknown
        return EvidenceCheck(label, "invalid_reference", "unknown tool for evidence"), None
    path = evidence_path(evidence_root, session_id, rid, tool)
    entry = _inspect(path)
    if entry.kind == "absent":
        return EvidenceCheck(label, "missing", "evidence file not found"), None
    if entry.kind == "unsafe":
        return EvidenceCheck(label, "unsafe", entry.why), None
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != recorded or entry.sha256 != recorded:
        return EvidenceCheck(label, "mismatch", "SHA-256 differs from the audit record"), None
    return EvidenceCheck(label, "ok"), raw


# --- outcomes ---------------------------------------------------------------------

_TOOL_EVENTS = ("tool_request_denied_locally", "tool_request_sent", "tool_request_failed",
                "tool_request_rejected", "tool_result_received")


def _request(d: dict, session_id: uuid.UUID) -> NmapConnectScanRequest:
    rid = _uuid(d.get("request_id"))
    if rid is None:
        raise ReplayError("tool event request_id is not a UUID")
    return NmapConnectScanRequest(request_id=rid, session_id=session_id, host=d["host"],
                                  ports=d["ports"], timeout_seconds=d["timeout_seconds"])


def _ts(value: object) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _expected_errors(result: ToolRunResult, hash_verified: object,
                     outcome: ScanOutcome, raw: bytes | None) -> list[str]:
    """The deterministic part of the pipeline's error list (runner_client.scan)."""
    errors = []
    if hash_verified is not True:
        errors.append("output hash could not be verified")
    if result.status is ToolRunStatus.COMPLETED:
        if result.exit_code not in (0, None):
            errors.append(f"nmap exited with code {result.exit_code}")
        if raw is not None:
            try:
                outcome.report = parse_nmap_xml(raw.decode("utf-8"))
                if outcome.report.exit_status == "error":
                    errors.append("nmap runstats reported exit=error (incomplete scan)")
            except NmapXmlError as exc:
                errors.append(f"parse: {exc}")
    return errors


def _apply_result(o: ScanOutcome, d: dict, session_id: uuid.UUID, evidence_root: Path,
                  checks: list[EvidenceCheck]) -> None:
    raw = None
    if d.get("evidence_sha256") is not None:
        check, raw = check_evidence(d, session_id, evidence_root)
        checks.append(check)
        if check.state != "ok":
            raise ReplayError(f"evidence {check.request_id}: {check.state} ({check.detail})")
    recorded = d["errors"]
    if not isinstance(recorded, list) or not all(isinstance(e, str) for e in recorded):
        raise ReplayError("tool_result_received.errors is malformed")
    if any(e.startswith("evidence:") for e in recorded):
        raise ReplayError("evidence was not stored for this run; it cannot be rebuilt")
    status = ToolRunStatus(d["status"])
    reason = d.get("reason") or ("(reason not recorded)" if status is ToolRunStatus.DENIED
                                 else "")
    result = ToolRunResult(
        request_id=o.request.request_id, tool="nmap_connect_scan", status=status,
        reason=reason, started_at=_ts(d["started_at"]), finished_at=_ts(d["finished_at"]),
        exit_code=d["exit_code"], raw_output=raw.decode("utf-8") if raw is not None else None,
        output_truncated=d["output_truncated"], output_sha256=d["output_sha256"])
    o.result, o.hash_verified = result, d["hash_verified"]
    if raw is not None:
        o.evidence = EvidenceRef(path=evidence_path(evidence_root, session_id,
                                                    o.request.request_id),
                                 sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
    if _expected_errors(result, d["hash_verified"], o, raw) != recorded:
        raise ReplayError(f"recorded errors for {o.request.request_id} do not match the evidence")
    o.errors = list(recorded)


def replay_result(run: Run, session_id: uuid.UUID, evidence_root: Path
                  ) -> tuple[ResearchResult, list[EvidenceCheck]]:
    """Rebuild the ResearchResult of one run from audit + evidence."""
    outcomes: dict[str, ScanOutcome] = {}
    checks: list[EvidenceCheck] = []
    try:
        for rec in run.body:
            if rec.event not in _TOOL_EVENTS:
                continue
            d = _data(rec)
            rid = d.get("request_id")
            if rec.event in ("tool_request_denied_locally", "tool_request_sent"):
                if rid in outcomes:
                    raise ReplayError(f"request {rid} appears twice")
                sent = rec.event == "tool_request_sent"
                reason = d["local_policy"] if sent else d["reason"]
                outcomes[rid] = ScanOutcome(_request(d, session_id), sent, reason)
                continue
            o = outcomes.get(rid)
            if o is None:
                raise ReplayError(f"{rec.event} for unknown request {str(rid)[:64]}")
            if rec.event == "tool_request_failed":
                errors = d.get("errors")
                if errors is None:  # legacy record: best-effort text
                    errors = [f"{d['error']}: {d['detail']}"]
                if not isinstance(errors, list) or not all(isinstance(e, str) for e in errors):
                    raise ReplayError("tool_request_failed.errors is malformed")
                o.errors = list(errors)
            elif rec.event == "tool_request_rejected":
                o.rejection = RunnerRejection(stage=RejectionStage(d["stage"]),
                                              reason=d["reason"],
                                              request_id=o.request.request_id)
            else:
                _apply_result(o, d, session_id, evidence_root, checks)

        t = _data(run.stopped)
        calls = [r for r in run.body if r.event == "llm_call"]
        summary = t.get("final_summary")
        if summary is None:  # legacy: only finish_session text was audited
            finish = [r for r in run.body if r.event == "llm_finish"]
            summary = _data(finish[-1]).get("summary", "") if finish else ""
        if not isinstance(summary, str):
            raise ReplayError("final summary is not text")
        notes = {kind: [dict(_data(r)) for r in run.body if r.event == kind]
                 for kind in ("llm_observation", "llm_hypothesis")}
        result = ResearchResult(
            stop_reason=StopReason(t["stop_reason"]), detail=t["detail"], steps=t["steps"],
            tool_runs=t["tool_runs"],
            spend=Spend(usd=float(t["total_cost_usd"]), calls=len(calls),
                        tokens={k: t["tokens"][k] for k in TOKEN_KEYS}),
            final_summary=summary, proposals=t["proposals"],
            outcomes=list(outcomes.values()), observations=notes["llm_observation"],
            hypotheses=notes["llm_hypothesis"])
    except _DATA_ERRORS as exc:
        raise ReplayError(f"audit data is malformed ({type(exc).__name__})") from None
    return result, checks


def prior_session_evidence(sessions_dir: Path, evidence_root: Path, session_id: uuid.UUID,
                           run: Run, scope: Scope) -> tuple[PriorEvidence, ...]:
    """Schema 5: evidence recorded in THIS session before ``run`` started that
    AVRA verifies independently of the model: the session audit chain
    verifies, the result pairs with exactly one request (tool/host/port), the
    run completed with a verified output hash equal to the evidence hash, the
    file (found from UUIDs only, no symlink) has that hash, its content parses
    and matches the request, and its host:port is in this run's scope.
    Anything else is simply absent (fail closed). Never cross-session."""
    from avra.verification.evidence import load_session_evidence  # lazy: import cycle

    ev = load_session_evidence(Path(sessions_dir), Path(evidence_root), str(session_id))
    if not ev.trusted:
        return ()
    allowed = {(t.host, int(p)) for t in scope.targets for p in t.ports}
    out = {}
    for o in ev.observations:
        if o.ref.audit_seq < run.started.seq and (o.target.host, o.target.port) in allowed:
            item = PriorEvidence(request_id=o.ref.request_id, tool=o.ref.tool,
                                 target=o.target.label(), sha256=o.ref.sha256,
                                 audit_seq=o.ref.audit_seq)
            out[(item.audit_seq, item.request_id, item.target)] = item
    return tuple(out[k] for k in sorted(out))


def trusted_prior_evidence(audit: AuditLog, session_id: uuid.UUID, evidence_root: Path
                           ) -> tuple[PriorEvidence, ...]:
    """For the run that just finished (the CLI), exactly as replay computes it."""
    run = find_runs(audit.read_all())[-1]
    return prior_session_evidence(audit.path.parent, evidence_root, session_id, run,
                                  trusted_scope(run))


def rebuild_report(run: Run, session_id: uuid.UUID, evidence_root: Path,
                   sessions_dir: Path | None = None
                   ) -> tuple[ResearchReport, ResearchResult]:
    scope = trusted_scope(run)
    objective = _data(run.started).get("objective")
    if not isinstance(objective, str):
        raise ReplayError("research_started has no objective")
    metadata = run_metadata(run, session_id)
    version = report_schema_version(run)
    result, _ = replay_result(run, session_id, evidence_root)
    if version >= 5:
        if sessions_dir is None:
            raise ReplayError("schema 5 needs the session directory to verify prior evidence")
        result = dataclasses.replace(result, prior_evidence=prior_session_evidence(
            sessions_dir, evidence_root, session_id, run, scope))
    return (build_report(result, session_id=session_id, scope=scope, objective=objective,
                         metadata=metadata, schema_version=version), result)


# --- read-only verification ---------------------------------------------------------

@dataclass
class RunCheck:
    """One research run. ``ok`` (counts toward VERIFIED) needs ALL of:
    integrity PASS, metadata consistency PASS and a rerun verdict of PASS.
    A faithfully reproduced INCOMPLETE/INVALID report is never ``ok``."""

    started_seq: int
    attestation: str = "NONE"
    publication: str = "N/A"
    reproduction: str = "NOT CHECKED"
    integrity: str = "NOT CHECKED"   # attested + published + identical + verdict as attested
    metadata: str = "NOT CHECKED"    # model / tokens / cost consistency
    validator: str = "NOT CHECKED"   # rerun verdict of the report itself
    ok: bool = False
    integrity_ok: bool = False


def _metadata_consistency(md: ReportMetadata | None) -> tuple[bool, str]:
    if md is None:
        return False, "FAIL: no metadata"
    reasons = []
    if not md.model_consistent:
        reasons.append(f"API-reported model(s) {list(md.models_reported)} differ from the "
                       f"configured {md.model!r}")
    if not md.tokens_consistent:
        reasons.append("token totals do not equal the sum of per-call usage")
    if not md.cost_consistent:
        reasons.append(f"cost does not reconcile (total {md.cost_usd}, sum of calls "
                       f"{md.cost_sum_of_calls_usd}, from tokens {md.cost_from_tokens_usd})")
    return (not reasons), ("PASS" if not reasons else "FAIL: " + "; ".join(reasons))


@dataclass
class SessionCheck:
    session_id: str
    audit: str = "NOT CHECKED"
    evidence: str = "NOT CHECKED"
    runs: list[RunCheck] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # each one prevents VERIFIED
    notes: list[str] = field(default_factory=list)     # informational
    verified: bool = False            # the ONLY "clean" result
    integrity_verified: bool = False  # descriptive: chain/evidence/reproduction all hold


def _legacy_validator(sessions_dir: Path, session_id: uuid.UUID, run: Run,
                      evidence_root: Path) -> str:
    path = Path(sessions_dir) / f"{session_id}.report.json"
    entry = _inspect(path)
    if entry.kind != "regular":
        return "NOT CHECKED: no legacy report file"
    try:
        legacy = ResearchReport.model_validate(json.loads(path.read_bytes()))
        result, _ = replay_result(run, session_id, evidence_root)
    except ReplayError as exc:
        return f"NOT CHECKED: {exc}"
    except (ValueError, ValidationError):
        return "NOT CHECKED: legacy report file is not a valid report"
    verdict = validate_report(legacy, result).verdict.value
    return f"{verdict} (rerun on the legacy file; unattested, not reproducible)"


def verify_session(sessions_dir: Path, evidence_root: Path,
                   session_id: uuid.UUID) -> SessionCheck:
    """Read-only. VERIFIED only if every dimension of every run passes."""
    sc = SessionCheck(session_id=str(session_id))
    log = Path(sessions_dir) / f"{session_id}.jsonl"
    entry = _inspect(log)
    if entry.kind != "regular":
        sc.audit = ("FAIL: audit log not found" if entry.kind == "absent"
                    else f"FAIL: audit log is not a plain file ({entry.why})")
        sc.problems.append("audit log unavailable")
        return sc
    audit = AuditLog(log)  # directory exists, so this creates nothing
    try:
        records = audit.read_all()
    except (OSError, ValueError, TypeError, KeyError):
        sc.audit = "FAIL: audit log is unreadable"
        sc.problems.append("audit log unreadable")
        return sc
    if not _chain_ok(audit):
        sc.audit = "FAIL: hash chain does not verify"
        sc.problems.append("audit chain broken; nothing else can be trusted")
        return sc
    sc.audit = f"PASS ({len(records)} records, hash chain intact)"

    checks = [check_evidence(r.data, session_id, evidence_root)[0] for r in records
              if r.event == "tool_result_received" and isinstance(r.data, dict)
              and r.data.get("evidence_sha256") is not None]
    bad = [c for c in checks if c.state != "ok"]
    if not checks:
        sc.evidence = "NONE (no evidence recorded)"
    elif bad:
        sc.evidence = f"FAIL ({len(bad)} of {len(checks)} files)"
        sc.problems += [f"evidence {c.request_id}: {c.state} ({c.detail})" for c in bad]
    else:
        sc.evidence = f"PASS ({len(checks)} file(s), SHA-256 match the audit)"

    try:
        states = report_states(audit, Path(sessions_dir))
    except ReportStoreError as exc:
        sc.problems.append(f"report events: {exc}")
        states = []
    for st in states:
        if st.state is PublicationState.INVALID_EVENT:
            sc.problems.append(f"invalid report_generated at seq {st.event_seq}: {st.detail}")
    by_name = {st.report_file: st for st in states if st.report_file}
    by_seq = {r.seq: r for r in records}

    runs = find_runs(records)
    started = [r for r in records if r.event == "research_started"]
    if len(started) != len(runs):
        sc.problems.append("a research run has no research_stopped record")
    if (Path(sessions_dir) / f"{session_id}.report.json").exists():
        sc.notes.append(f"legacy report {session_id}.report.json present "
                        "(pre-M7.9.1, unattested; never modified)")

    for i, run in enumerate(runs):
        rc = RunCheck(started_seq=run.started.seq)
        st = by_name.get(report_filename(session_id, run.started.seq))
        if st is not None:
            rc.attestation = f"ATTESTED (audit seq {st.event_seq})"
            rc.publication = st.state.value.upper() + (f" ({st.detail})" if st.detail else "")
        attested_verdict = (by_seq[st.event_seq].data.get("verdict")
                            if st is not None else None)
        try:
            report, result = rebuild_report(run, session_id, evidence_root, sessions_dir)
        except LegacyRunError:
            rc.reproduction = ("NOT POSSIBLE: legacy run (no scope snapshot; "
                               "the current scope file is never substituted)")
            rc.integrity = "NOT POSSIBLE: legacy run"
            rc.metadata = "NOT POSSIBLE: legacy run (no metadata recorded)"
            rc.validator = (_legacy_validator(sessions_dir, session_id, run, evidence_root)
                            if i == len(runs) - 1 else "NOT CHECKED: legacy run")
            sc.runs.append(rc)
            continue
        except ReplayError as exc:
            rc.reproduction = f"FAIL: {exc}"
            rc.integrity = "FAIL: the run cannot be rebuilt from audit + evidence"
            sc.runs.append(rc)
            continue
        sha = hashlib.sha256(serialize_report(report)).hexdigest()
        identical = st is not None and sha == st.sha256
        if st is None:
            rc.reproduction = f"REBUILT, nothing attested to compare (sha256 {sha[:16]}...)"
        elif identical:
            rc.reproduction = f"IDENTICAL (sha256 {sha[:16]}...)"
        else:
            rc.reproduction = "FAIL: rebuilt report differs from the attested bytes"
        validation = validate_report(report, result)
        verdict = validation.verdict.value
        verdict_as_attested = st is not None and verdict == attested_verdict
        if st is None:
            rc.validator = f"{verdict} (nothing attested)"
        elif verdict_as_attested:
            rc.validator = f"{verdict} (matches attested)"
        else:
            rc.validator = f"{verdict} (attested {attested_verdict!r}: MISMATCH)"
        if verdict != "PASS" and validation.reasons:
            rc.validator += " - " + "; ".join(validation.reasons)

        published = st is not None and st.state is PublicationState.PUBLISHED
        rc.integrity_ok = published and identical and verdict_as_attested
        if rc.integrity_ok:
            rc.integrity = "PASS (attested, published, reproduced byte-for-byte)"
        else:
            missing = [label for label, good in (("attested", st is not None),
                                                 ("published", published),
                                                 ("reproduced", identical),
                                                 ("verdict as attested", verdict_as_attested))
                       if not good]
            rc.integrity = "FAIL: not " + ", not ".join(missing)
        metadata_ok, rc.metadata = _metadata_consistency(report.metadata)
        rc.ok = rc.integrity_ok and metadata_ok and verdict == "PASS"
        sc.runs.append(rc)

    if not runs:
        sc.notes.append("no research runs in this session (audit and evidence only)")
    for rc in sc.runs:
        if not rc.integrity_ok:
            sc.problems.append(f"run {rc.started_seq}: integrity not verified")
        if not rc.metadata.startswith("PASS"):
            sc.problems.append(f"run {rc.started_seq}: metadata consistency not PASS")
        if not rc.validator.startswith("PASS"):
            sc.problems.append(f"run {rc.started_seq}: report validation is not PASS")
    sc.verified = bool(runs) and not sc.problems and all(rc.ok for rc in sc.runs)
    sc.integrity_verified = (bool(runs) and sc.audit.startswith("PASS")
                             and not sc.evidence.startswith("FAIL")
                             and all(rc.integrity_ok for rc in sc.runs))
    return sc
