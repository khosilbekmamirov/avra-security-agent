"""M14.3 (ADR 0022): evidence-driven investigation report.

Built only from records AVRA holds: the investigation's own hash-chained log (phases,
actions, approvals, notes) and a fresh, read-only engine pass over the session's
hash-checked evidence. Every statement is one of:

* VERIFIED      - the Verification Engine CONFIRMED it from evidence (with request ids and
                  SHA-256 hashes). An *observation* is a fact, not a vulnerability;
* REJECTED      - the engine ruled the hypothesis out from evidence;
* INCONCLUSIVE  - the engine could not decide; the missing evidence is named;
* NOT TESTED    - a live step that was never sent (out of scope, denied, expired, not
                  reached). No request was made, so nothing is claimed about it;
* FAILED        - an action that was sent but produced no trustworthy evidence, or was
                  interrupted (never re-run).

No severity or CVSS is assigned. Model text appears only under "UNVERIFIED model notes".
Building a report writes nothing to the investigation log.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from avra.research.controller import LIVE_TOOLS, Analysis
from avra.research.investigation import ActionStatus, Investigation

REPORT_SCHEMA = "avra-investigation-report/1"
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
_EXECUTED = {ActionStatus.SUCCEEDED, ActionStatus.FAILED, ActionStatus.INTERRUPTED}


def _cell(text: Any, limit: int = 160) -> str:
    """Safe inside a Markdown table cell: no control/bidi chars, pipes or backticks."""
    s = _CTRL.sub(" ", str(text if text is not None else ""))
    return s.replace("|", "\\|").replace("`", "'")[:limit]


def build_report(inv: Investigation, analysis: Analysis | None, *,
                 session_audit_valid: bool | None,
                 now: datetime | None = None) -> dict[str, Any]:
    snap = inv.snapshot()
    verified_by_action = {n["data"].get("action_id"): bool(n["data"].get("evidence_verified"))
                          for n in inv.notes if n["kind"] == "verification"}
    actions = []
    for a in inv.actions.values():
        actions.append({"action_id": a.action_id, "tool": a.tool,
                        "target": f"{a.host}:{a.port}", "path": a.path, "tier": a.tier,
                        "risk": a.risk, "status": a.status.value, "fingerprint": a.fingerprint,
                        "request_id": a.request_id, "evidence_sha256": a.evidence_sha256,
                        "evidence_verified": verified_by_action.get(a.action_id),
                        "scope_allowed": a.scope_allowed, "reason": a.reason,
                        "errors": list(a.errors)})

    results = analysis.results if analysis is not None else []
    verified = [r for r in results if r["verdict"] == "CONFIRMED"]
    rejected = [r for r in results if r["verdict"] == "REJECTED"]
    inconclusive = [r for r in results if r["verdict"] == "INCONCLUSIVE"]

    failed = [x for x in actions if x["status"] in (ActionStatus.FAILED.value,
                                                     ActionStatus.INTERRUPTED.value)]
    executed_keys = {(a.tool, f"{a.host}:{a.port}", a.path) for a in inv.actions.values()
                     if a.status in _EXECUTED}
    not_tested: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for x in actions:
        if x["status"] in (ActionStatus.DENIED.value, ActionStatus.EXPIRED.value,
                           ActionStatus.REFUSED.value, ActionStatus.PROPOSED.value,
                           ActionStatus.APPROVED.value):
            key = (x["tool"], x["target"], x["path"])
            if key in executed_keys or key in seen:
                continue
            seen.add(key)
            not_tested.append({"tool": x["tool"], "target": x["target"], "path": x["path"],
                               "why": f"action {x['status'].lower()}"})
    if analysis is not None:
        for s in analysis.plan.get("steps", []):
            if s.get("kind") not in LIVE_TOOLS:
                continue
            key = (s["kind"], str(s.get("target")), str(s.get("path") or ""))
            if key in executed_keys or key in seen:
                continue
            seen.add(key)
            not_tested.append({"tool": key[0], "target": key[1], "path": key[2],
                               "why": f"planner readiness: {s.get('readiness')}",
                               "value": s.get("value")})

    explanations = [n["data"] for n in inv.notes if n["kind"] == "explanation"]
    cost = sum(float(e.get("cost_usd") or 0) for e in explanations)
    report = {
        "schema": REPORT_SCHEMA,
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "investigation": {k: snap[k] for k in ("investigation_id", "objective", "session_id",
                                               "scope_name", "state")},
        "integrity": {"investigation_log": inv.log_summary(),
                      "session_audit_valid": session_audit_valid,
                      "analysis_source": "fresh engine pass over hash-checked session evidence"
                      if analysis is not None else "unavailable"},
        "history": snap["history"],
        "stop_reason": next((n["data"].get("reason") for n in reversed(inv.notes)
                             if n["kind"] == "stop"), None),
        "verified": verified, "rejected": rejected, "inconclusive": inconclusive,
        "not_tested": not_tested, "failed": failed, "actions": actions,
        "unverified_model_notes": explanations,
        "model_usage": {"calls": len(explanations),
                        "tokens_in": sum(int(e.get("tokens_in") or 0) for e in explanations),
                        "tokens_out": sum(int(e.get("tokens_out") or 0) for e in explanations),
                        "estimated_cost_usd": round(cost, 6)},
        "limitations": [
            ("No severity or CVSS is assigned; VERIFIED means the engine confirmed it from "
             "evidence, and an observation is a fact, not a vulnerability."),
            "NOT TESTED means no request was sent; nothing is claimed about it.",
            ("The audit chains are unkeyed hash chains: they prove internal consistency, not "
             "authorship (ADR 0006/0012)."),
            "Model notes are explanations only; they never set a verdict or an action.",
        ],
    }
    return report


def canonical_sha256(report: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":"),
                                     default=str).encode()).hexdigest()


def render_markdown(report: dict[str, Any]) -> str:
    inv = report["investigation"]
    integ = report["integrity"]
    log = integ["investigation_log"]
    out = [f"# AVRA investigation report - {inv['investigation_id']}", "",
           f"- Objective: {_cell(inv['objective'], 300)}",
           f"- Session: `{inv['session_id']}`  Scope: {_cell(inv['scope_name'])}",
           f"- Final state: **{inv['state']}** ({_cell(report.get('stop_reason') or '-', 200)})",
           f"- Generated: {report['generated_at']}", "",
           "## Integrity", "",
           (f"- Investigation log: {log['records']} records, chain "
            f"{'VALID' if log['chain_valid'] else 'BROKEN'}, head `{log['head_hash']}`"),
           f"- Session audit chain: {_fmt_bool(integ['session_audit_valid'])}",
           f"- Analysis: {integ['analysis_source']}", ""]

    def section(title: str, rows: list[dict], cols: list[tuple[str, str]], empty: str) -> None:
        out.extend([f"## {title}", ""])
        if not rows:
            out.extend([empty, ""])
            return
        out.append("| " + " | ".join(h for h, _ in cols) + " |")
        out.append("|" + "---|" * len(cols))
        for r in rows:
            out.append("| " + " | ".join(_cell(_get(r, k)) for _, k in cols) + " |")
        out.append("")

    ev_cols = [("Rule", "rule_id"), ("Target", "target"), ("Kind", "kind"),
               ("Evidence (request id : sha256)", "evidence"), ("Reason", "reason")]
    section("VERIFIED (engine-confirmed)", report["verified"], ev_cols, "None.")
    section("REJECTED", report["rejected"], ev_cols, "None.")
    section("INCONCLUSIVE", report["inconclusive"],
            [("Rule", "rule_id"), ("Target", "target"), ("Missing evidence", "missing_evidence")],
            "None.")
    section("NOT TESTED (no request sent)", report["not_tested"],
            [("Tool", "tool"), ("Target", "target"), ("Path", "path"), ("Why", "why")], "None.")
    section("FAILED", report["failed"],
            [("Action", "action_id"), ("Tool", "tool"), ("Target", "target"), ("Path", "path"),
             ("Status", "status"), ("Errors", "errors")], "None.")
    section("Actions (audit references)", report["actions"],
            [("Action", "action_id"), ("Tool", "tool"), ("Target", "target"), ("Path", "path"),
             ("Tier/risk", "tier_risk"), ("Status", "status"), ("Fingerprint", "fingerprint"),
             ("Request id", "request_id"), ("Evidence sha256", "evidence_sha256"),
             ("Verified", "evidence_verified")], "No action was proposed.")
    out.extend(["## UNVERIFIED model notes", ""])
    if not report["unverified_model_notes"]:
        out.extend(["None.", ""])
    for n in report["unverified_model_notes"]:
        out.append(f"- ({_cell(n.get('model'))}, action {_cell(n.get('action_id'), 8)}, "
                   f"response sha256 `{n.get('response_sha256')}`) "
                   f"{_cell(n.get('text'), 1500)}")
    u = report["model_usage"]
    usage = (f"Model usage: {u['calls']} call(s), {u['tokens_in']} in / "
             f"{u['tokens_out']} out tokens, estimated ${u['estimated_cost_usd']:.4f}.")
    out.extend(["", usage, "", "## Limitations", ""])
    out.extend(f"- {x}" for x in report["limitations"])
    out.extend(["", f"Report JSON sha256: `{canonical_sha256(report)}`", ""])
    return "\n".join(out)


def _fmt_bool(v: bool | None) -> str:
    return "unknown" if v is None else ("VALID" if v else "BROKEN")


def _get(row: dict, key: str) -> Any:
    if key == "evidence":
        return ", ".join(f"{e['request_id'][:8]}:{e['sha256'][:16]}" for e in row.get(key, []))
    if key == "tier_risk":
        return f"{row.get('tier')}/{row.get('risk')}"
    if key == "action_id":
        return str(row.get(key, ""))[:8]
    if key == "fingerprint":
        return str(row.get(key, ""))[:16]
    v = row.get(key)
    if isinstance(v, list):
        return "; ".join(str(x) for x in v)
    return "-" if v is None or v == "" else v


def write_report(root: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    """``<root>/reports/<investigation_id>/report-<UTC>.{json,md}`` - never overwrites."""
    inv_id = report["investigation"]["investigation_id"]
    d = Path(root) / "reports" / inv_id
    d.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    for n in range(100):  # exclusive create: a same-instant second report gets a suffix
        name = f"report-{stamp}" + (f"-{n}" if n else "")
        jp, mp = d / f"{name}.json", d / f"{name}.md"
        try:
            f = jp.open("x", encoding="utf-8")
            break
        except FileExistsError:
            continue
    else:  # pragma: no cover
        raise FileExistsError("could not choose a new report file name")
    with f:
        json.dump(report, f, indent=2, sort_keys=True, default=str)
    with mp.open("x", encoding="utf-8") as f:
        f.write(render_markdown(report))
    return jp, mp
