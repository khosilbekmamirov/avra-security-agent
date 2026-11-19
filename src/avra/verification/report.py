"""Verification report: build, store, audit and re-check (M8.4 Stage 3).

A verification run reads a session's evidence, runs the bounded cycle and
writes ONE write-once report ``data/verification/<session>/report-<sha16>.json``
plus its own hash-chained audit log ``verification-audit.jsonl`` in the same
directory. The session's own audit log, evidence and M7.9 research report
are never modified (compatibility: research reports stay schema 1-4).

The report keeps five things apart, by section:

* ``observations``           facts from hash-checked evidence;
* ``model_notes``            the model's free-text hypotheses — unverified;
* ``hypotheses``/``results`` structured proposals and the engine's verdicts;
* ``confirmed_findings``     CONFIRMED vulnerability rules only, with proof;
* ``verified_observations``  CONFIRMED observation rules (facts, not findings);
* plus ``rejected``, ``inconclusive`` (with missing evidence) and
  ``proposed_next_actions`` (never executed; owner approval required).

``check_verification`` re-derives every result from the stored hypotheses
and the current evidence and compares SHA-256s: same evidence -> same bytes.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from avra.reporting.store import _inspect
from avra.storage.audit import AuditLog
from avra.verification.cycle import (
    Budget,
    CycleState,
    HypothesisProposer,
    ResearchCycle,
    Status,
    observation_summary,
)
from avra.verification.engine import VerificationEngine
from avra.verification.evidence import SessionEvidence, _uuid, load_session_evidence
from avra.verification.models import (
    ENGINE_VERSION,
    Hypothesis,
    VerificationResult,
    canonical_json,
    sha256_hex,
)
from avra.verification.rules import RuleRegistry

REPORT_FORMAT = "avra-verification-report/2"  # /2 (M8.5): + research_loop; /1 still checkable
AUDIT_NAME = "verification-audit.jsonl"
_REPORT_NAME = re.compile(r"report-[0-9a-f]{16}\.json")
_HEX64 = re.compile(r"[0-9a-f]{64}")
MEANING = {
    "CONFIRMED": ("The recorded, hash-checked evidence satisfies every condition of the "
                  "rule. For a vulnerability rule this is a confirmed finding about the "
                  "examined response only; for an observation rule it is a verified fact, "
                  "not a vulnerability."),
    "REJECTED": "Trusted evidence shows the rule's condition is false for the examined data.",
    "INCONCLUSIVE": ("The evidence cannot decide (missing, insufficient, contradictory, "
                     "untrusted, or no rule). Never read as 'safe'."),
}
GENERAL_LIMITS = (
    ("Verdicts cover only the recorded evidence at its collection time; this is not a "
     "complete security assessment."),
    "No proposed next action was executed; each needs scope and owner approval.",
    "Model text (rationales, notes) is shown as unverified and never affects a verdict.",
)


class VerificationRunError(Exception):
    pass


def build_report(evidence: SessionEvidence, state: CycleState, registry: RuleRegistry, *,
                 budget: Budget, proposers: list[str],
                 model_usage: dict[str, Any] | None = None) -> dict[str, Any]:
    entries = sorted(state.entries.values(), key=lambda e: (e.iteration, e.hypothesis.id))

    def summary(e) -> dict[str, Any]:
        rule = registry.get(e.hypothesis.rule_id)
        return {"hypothesis_id": e.hypothesis.id, "rule_id": e.hypothesis.rule_id,
                "title": rule.title if rule else "(unsupported rule)",
                "target": e.hypothesis.target.label(), "verdict": e.result.verdict.value,
                "reason": e.result.reason}

    limitations = set(GENERAL_LIMITS) | set(evidence.provenance_limitations())
    for e in entries:
        limitations |= set(e.result.limitations)
    return {
        "format": REPORT_FORMAT,
        "engine_version": ENGINE_VERSION,
        "verdict_meaning": MEANING,
        "session": {"session_id": evidence.session_id,
                    # M8.6 (G4): the label recorded when the SESSION was created;
                    # each research run's own scope is in research_run_scopes.
                    "scope_session_name": evidence.scope_session_name,
                    "scope_label_source": "session_created",
                    "research_run_scopes": list(evidence.run_scopes),
                    "audit_sha256": evidence.audit_sha256,
                    "audit_records": evidence.audit_records,
                    "audit_chain_valid": evidence.audit_valid,
                    "scope_snapshot_recorded": evidence.scope_snapshot_recorded},
        "rules": [r.describe() for r in registry.rules()],
        "run": {"budget": {"max_iterations": budget.max_iterations,
                           "max_hypotheses": budget.max_hypotheses},
                "proposers": proposers,
                "stop_reason": state.stop_reason.value if state.stop_reason else None,
                "iterations": [vars(i) for i in state.iterations],
                "proposer_notes": list(state.proposer_notes),
                "model_usage": model_usage},
        "observations": observation_summary(evidence),
        "excluded_evidence": [i.model_dump() for i in evidence.issues],
        "model_notes": [{"audit_seq": n.audit_seq, "statement": n.statement, "basis": n.basis,
                         "status": "unverified free text; no rule evaluates it"}
                        for n in evidence.model_notes],
        "hypotheses": [{**json.loads(e.hypothesis.canonical()), "proposed_by": e.proposed_by,
                        "iteration": e.iteration} for e in entries],
        "results": [{"result": json.loads(e.result.canonical()),
                     "result_sha256": e.result.sha256()} for e in entries],
        "confirmed_findings": [
            {**summary(e), "severity": registry.get(e.hypothesis.rule_id).severity,
             "references": list(registry.get(e.hypothesis.rule_id).references),
             "confirmed_requires": registry.get(e.hypothesis.rule_id).confirmed_requires,
             "proof": [r.model_dump(mode="json") for r in e.result.evidence_used],
             "criteria": [c.model_dump() for c in e.result.checks],
             "limitations": list(e.result.limitations)} for e in state.findings()],
        "verified_observations": [
            {**summary(e), "proof": [r.request_id for r in e.result.evidence_used]}
            for e in state.verified_observations()],
        "rejected": [{**summary(e), "explanation": e.explanation}
                     for e in state.by_status(Status.REJECTED)],
        "inconclusive": [{**summary(e), "reason_code": e.result.reason_code,
                          "missing_evidence": list(e.result.missing_evidence)}
                         for e in state.by_status(Status.INCONCLUSIVE)],
        "proposed_next_actions": [{**a.model_dump(mode="json"), "executed": False}
                                  for _, a in sorted(state.next_actions.items())],
        "dropped_proposals": [vars(d) for d in state.dropped],
        "research_loop": research_loop_trace(evidence),
        "limitations": sorted(limitations),
    }


def research_loop_trace(evidence: SessionEvidence) -> dict[str, Any] | None:
    """The live research loop's own record for this session (M8.5), rebuilt
    from the session audit: which hypotheses the model / rules raised at
    which step, every verdict and revision, repeats, the no-progress stop.
    None for sessions that never ran in verification mode."""
    ev = evidence.loop_events
    if not ev:
        return None
    hyps = [e for e in ev if e["event"] == "verification_hypothesis"]
    return {
        "runs": [{"seq": e["seq"], "prompt_version": e.get("prompt_version"),
                  "config": e.get("verification_loop"), "scope": e.get("run_scope")}
                 for e in ev if e["event"] == "research_started"],
        "refused_requests": [{k: e.get(k) for k in ("seq", "step", "status", "rule_id",
                                                    "host", "port", "reason")}
                             for e in ev if e["event"] == "verification_request_refused"],
        "hypotheses": [{k: e.get(k) for k in ("seq", "step", "hypothesis_id", "rule_id",
                                              "target", "origin", "proposed_by", "rationale")}
                       for e in hyps],
        "verdict_history": [{k: e.get(k) for k in ("seq", "step", "trigger", "hypothesis_id",
                                                   "rule_id", "rule_version", "verdict",
                                                   "reason_code", "revised_from", "evidence",
                                                   "result_sha256")}
                            for e in ev if e["event"] == "verification_verdict"],
        "repeats": [{"seq": e["seq"], "step": e.get("step"),
                     "hypothesis_id": e.get("hypothesis_id"), "verdict": e.get("verdict")}
                    for e in ev if e["event"] == "verification_repeat"],
        "stops": [{"seq": e["seq"], "stop_reason": e.get("stop_reason"),
                   "detail": e.get("detail"), "summary": e.get("verification")}
                  for e in ev if e["event"] == "research_stopped"],
        "no_progress_stops": [{"seq": e["seq"], "step": e.get("step"),
                               "idle_steps": e.get("idle_steps")}
                              for e in ev if e["event"] == "verification_no_progress"],
    }


def loop_hypotheses(evidence: SessionEvidence) -> list[Hypothesis]:
    """Model-proposed hypotheses from the research loop, re-created exactly
    (same rule/target -> same id) so the report re-verifies them."""
    from avra.verification.models import Origin

    out = []
    for e in evidence.loop_events:
        if e["event"] != "verification_hypothesis" or e.get("origin") != "model":
            continue
        host, _, port = str(e.get("target", "")).rpartition(":")
        try:
            out.append(Hypothesis.create(rule_id=str(e.get("rule_id")), host=host,
                                         port=int(port), origin=Origin.MODEL,
                                         rationale=str(e.get("rationale", ""))))
        except (ValueError, TypeError):
            continue  # the loop only records validated hypotheses; skip anything else
    return out


@dataclass
class VerificationRun:
    report: dict[str, Any]
    report_path: Path
    report_sha256: str
    audit_path: Path
    state: CycleState
    evidence: SessionEvidence


def _write_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                     0o644)
    except FileExistsError:
        entry = _inspect(path)
        if entry.kind != "regular" or path.read_bytes() != data:
            raise VerificationRunError(f"{path.name} exists with different content") from None
        return  # identical report already stored (same evidence, same run)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def run_verification(*, sessions_dir: Path, evidence_root: Path, verification_root: Path,
                     session_id: str, proposers: list[HypothesisProposer],
                     budget: Budget | None = None, registry: RuleRegistry | None = None,
                     model_usage: Any = None) -> VerificationRun:
    """Offline: reads the session, writes only under verification_root/<session>."""
    sid = _uuid(session_id)
    if sid is None:
        raise VerificationRunError("session id must be a UUID")
    budget = budget or Budget()
    engine = VerificationEngine(registry)
    evidence = load_session_evidence(sessions_dir, evidence_root, str(sid))
    if not evidence.audit_present:
        raise VerificationRunError(f"no audit log for session {sid}")
    out_dir = Path(verification_root) / str(sid)
    audit = AuditLog(out_dir / AUDIT_NAME)
    check = audit.verify_detailed()
    if not check.ok:
        raise VerificationRunError("verification audit chain is broken - refusing to append "
                                   f"({check.describe()})")
    audit.record("verification_started", {
        "session_id": str(sid), "engine_version": ENGINE_VERSION,
        "session_audit_sha256": evidence.audit_sha256, "session_audit_records":
            evidence.audit_records, "session_trusted": evidence.trusted,
        "rules": [f"{r.id}@{r.version}" for r in engine.registry.rules()],
        "budget": {"max_iterations": budget.max_iterations,
                   "max_hypotheses": budget.max_hypotheses},
        "proposers": [p.name for p in proposers]})
    for p in proposers:  # audit every model call made by an LLM proposer
        if hasattr(p, "on_call"):
            p.on_call = lambda rec, _a=audit: _a.record("verification_llm_call", rec)

    def on_result(entry) -> None:
        audit.record("verification_result", {
            "hypothesis_id": entry.hypothesis.id, "rule_id": entry.hypothesis.rule_id,
            "target": entry.hypothesis.target.label(), "origin": entry.hypothesis.origin.value,
            "proposed_by": entry.proposed_by, "iteration": entry.iteration,
            "verdict": entry.result.verdict.value, "reason_code": entry.result.reason_code,
            "result_sha256": entry.result.sha256()})

    seeds = loop_hypotheses(evidence)
    if seeds:  # the live loop's model hypotheses are re-verified first (M8.5)
        from avra.verification.cycle import StaticProposer

        proposers = [StaticProposer(seeds, name="research-loop"), *proposers]
    state = ResearchCycle(engine, proposers, budget, on_result=on_result).run(evidence)
    for p in proposers:
        detail = getattr(p, "stop_detail", "")
        if detail:
            state.proposer_notes.append(f"{p.name}: {detail}"[:500])
        for bad in getattr(p, "rejected_proposals", []):
            state.proposer_notes.append(
                f"{p.name} proposal rejected by AVRA validation (not a provider "
                f"refusal): {bad}"[:500])
    usage = model_usage
    for p in proposers:
        spend = getattr(p, "spend", None)
        if spend is not None and spend.calls:
            usage = {"calls": spend.calls, "tokens": dict(spend.tokens),
                     "cost_usd": round(spend.usd, 6)}
    report = build_report(evidence, state, engine.registry, budget=budget,
                          proposers=[p.name for p in proposers], model_usage=usage)
    data = (canonical_json(report) + "\n").encode("ascii")
    digest = sha256_hex(data.decode("ascii"))
    path = out_dir / f"report-{digest[:16]}.json"
    _write_once(path, data)
    audit.record("verification_report_written", {
        "report_file": path.name, "report_sha256": digest,
        "stop_reason": report["run"]["stop_reason"],
        "counts": {"hypotheses": len(report["hypotheses"]),
                   "confirmed_findings": len(report["confirmed_findings"]),
                   "verified_observations": len(report["verified_observations"]),
                   "rejected": len(report["rejected"]),
                   "inconclusive": len(report["inconclusive"]),
                   "proposed_next_actions": len(report["proposed_next_actions"])},
        "model_usage": usage})
    return VerificationRun(report, path, digest, audit.path, state, evidence)


@dataclass
class CheckOutcome:
    status: str  # VERIFIED | FAILED
    # True only when the verification audit chain verifies AND the report
    # file is the exact bytes that chain attests. A report whose integrity
    # is not established must never be displayed as if it were a result.
    integrity_ok: bool = False
    report_path: Path | None = None
    report_sha256: str = ""
    reproduced: int = 0
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def check_verification(*, sessions_dir: Path, evidence_root: Path, verification_root: Path,
                       session_id: str, registry: RuleRegistry | None = None) -> CheckOutcome:
    """Read-only: verification audit chain + report hash + byte-for-byte
    re-derivation of every recorded result from the current evidence."""
    out = CheckOutcome(status="FAILED")
    sid = _uuid(session_id)
    if sid is None:
        out.problems.append("session id must be a UUID")
        return out
    audit = AuditLog(Path(verification_root) / str(sid) / AUDIT_NAME)
    check = audit.verify_detailed()
    if check.ok and check.record_count == 0:
        out.problems.append("no verification has been recorded for this session")
        return out
    if not check.ok:
        out.problems.append(f"verification audit chain does not verify ({check.describe()})")
        return out
    records = audit.read_all()
    written = [r for r in records if r.event == "verification_report_written"]
    if not written:
        out.problems.append("no verification report was written")
        return out
    last = written[-1].data
    name, digest = str(last.get("report_file", "")), str(last.get("report_sha256", ""))
    # The file name comes from the audit record: accept only the exact shape
    # run_verification writes (no directories, no traversal), bound to its hash.
    if not _REPORT_NAME.fullmatch(name) or not _HEX64.fullmatch(digest) \
            or name != f"report-{digest[:16]}.json":
        out.problems.append("verification audit names an invalid report file")
        return out
    path = audit.path.parent / name
    out.report_path, out.report_sha256 = path, digest
    entry = _inspect(path)
    if entry.kind != "regular" or entry.sha256 != out.report_sha256:
        out.problems.append("report file is missing, unsafe or does not match its audit hash")
        return out
    raw = path.read_bytes()
    if sha256_hex(raw.decode("ascii", errors="replace")) != digest:
        out.problems.append("report file changed while it was being read")
        return out
    out.integrity_ok = True
    try:
        return _recheck(out, json.loads(raw), sessions_dir, evidence_root, str(sid), registry)
    except (KeyError, TypeError, ValueError) as exc:  # attested but not a valid report
        out.status = "FAILED"
        out.problems.append(f"report is not a well-formed verification report "
                            f"({type(exc).__name__})")
        return out


def _recheck(out: CheckOutcome, report: dict, sessions_dir: Path, evidence_root: Path,
             sid: str, registry: RuleRegistry | None) -> CheckOutcome:
    evidence = load_session_evidence(sessions_dir, evidence_root, sid)
    if not report["session"]["audit_chain_valid"]:
        out.notes.append("the session's evidence was NOT trusted when this report was made: "
                         "it reproduces, but no verdict in it rests on evidence")
    if evidence.audit_sha256 != report["session"]["audit_sha256"]:
        out.notes.append("the session audit log changed after this verification; results "
                         "are re-derived from the current evidence")
    engine = VerificationEngine(registry)
    for hyp_data, res in zip(report["hypotheses"], report["results"], strict=True):
        h = Hypothesis.model_validate({k: v for k, v in hyp_data.items()
                                       if k not in ("proposed_by", "iteration")})
        again = engine.verify(h, evidence)
        if again.sha256() != res["result_sha256"] or VerificationResult.model_validate(
                res["result"]).sha256() != res["result_sha256"]:
            out.problems.append(f"{h.id} ({h.rule_id}): result differs "
                                f"(now {again.verdict.value})")
        else:
            out.reproduced += 1
    if not out.problems:
        out.status = "VERIFIED"
    return out


def render_text(report: dict[str, Any]) -> list[str]:
    s = report["session"]
    lines = [f"Verification report ({report['format']}, engine {report['engine_version']})",
             (f"Session {s['session_id']}  created under scope '{s['scope_session_name']}'  audit "
              f"{'valid' if s['audit_chain_valid'] else 'NOT VALID'} ({s['audit_records']} "
              f"records){'' if s['scope_snapshot_recorded'] else ', no scope snapshot'}"),
             (f"Run: {len(report['run']['iterations'])} round(s), stop: "
              f"{report['run']['stop_reason']}, proposers: "
              f"{', '.join(report['run']['proposers'])}")]
    if report["run"]["model_usage"]:
        u = report["run"]["model_usage"]
        lines.append(f"Model usage: {u['calls']} call(s), ${u['cost_usd']:.4f}")
    for note in report["run"].get("proposer_notes", []):
        lines.append(f"Proposer note: {note}")
    lines.append(f"Observations from verified evidence: {len(report['observations'])}; "
                 f"excluded evidence: {len(report['excluded_evidence'])}")
    for x in report["excluded_evidence"]:
        lines.append(f"  excluded {x['label']}: {x['code']} {x['detail']}".rstrip())

    def block(title, items, extra=None):
        lines.append(f"{title}: {len(items)}")
        for it in items:
            lines.append(f"  [{it['verdict']}] {it['rule_id']} @ {it['target']} - {it['reason']}")
            if extra:
                lines.extend(f"      {x}" for x in extra(it))

    block("CONFIRMED FINDINGS (vulnerability rules)", report["confirmed_findings"],
          lambda f: [f"severity {f['severity']}; proof: "
                     + ", ".join(p["request_id"] for p in f["proof"])])
    block("Verified observations (facts, not vulnerabilities)", report["verified_observations"])
    block("Rejected hypotheses", report["rejected"])
    block("Inconclusive (open questions)", report["inconclusive"],
          lambda i: [f"needs: {m}" for m in i["missing_evidence"]])
    loop = report.get("research_loop")
    if loop:
        lines.append(f"Research loop: {len(loop['hypotheses'])} hypothesis(es) raised during "
                     f"the session, {len(loop['verdict_history'])} verdict record(s) "
                     f"({sum(1 for v in loop['verdict_history'] if v['revised_from'])} "
                     f"revision(s)), {len(loop['repeats'])} repeat(s) answered from state")
        for run in loop["runs"]:
            sc = run.get("scope") or {}
            lines.append(f"  research run (seq {run['seq']}, {run['prompt_version']}) used scope "
                         f"'{sc.get('scope_session_name') or 'not verifiable'}'"
                         + (f" (snapshot {sc['scope_snapshot_sha256'][:16]})"
                            if sc.get("scope_snapshot_sha256") else ""))
        for r_ in loop.get("refused_requests", []):
            lines.append(f"  refused model request (step {r_['step']}): {r_['status']} - "
                         f"{r_['rule_id']} @ {r_['host']}:{r_['port']}")
        for s_ in loop["stops"]:
            summ = s_.get("summary") or {}
            extra = ""
            if "proposed_next_actions" in summ:
                extra = (f"; next actions proposed {summ['proposed_next_actions']}, "
                         f"executable by the agent with the remaining budget "
                         f"{summ['agent_actionable_next_actions']}")
            lines.append(f"  research run stopped: {s_['stop_reason']}{extra}")
    lines.append(f"Proposed next actions (all candidates, regardless of budget; NOT executed; "
                 f"owner approval needed): "
                 f"{len(report['proposed_next_actions'])}")
    for a in report["proposed_next_actions"]:
        lines.append(f"  {a['tool']} {a['target']['host']}:{a['target']['port']} - {a['reason']}")
    if report["model_notes"]:
        lines.append(f"Model notes (unverified free text): {len(report['model_notes'])}")
    return lines
