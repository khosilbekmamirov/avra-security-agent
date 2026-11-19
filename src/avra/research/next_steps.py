"""Evidence-driven next-step planning (M12.1, ADR 0020).

A pure, deterministic planner over what AVRA already holds for one session:

* an INVENTORY per target - TCP state, the GET / response, every fetched path (status,
  size, truncation) and what recorded responses still only reference;
* candidate STEPS with an explained value (high/medium/low) and a READINESS:
    - ``offline_now``          an offline check that can run immediately;
    - ``ready_to_propose``     a live, read-only action the bound scope allows (it still
                               needs the owner's /approve and a running Runner);
    - ``needs_scope_change``   useful, but the bound scope does not allow it (owner decision);
    - ``needs_scope``          no scope is bound, so nothing live can be proposed;
    - ``needs_capability``     AVRA has no permitted tool for it yet (e.g. live validation);
    - ``previously_failed``    tried before without new evidence - retry only after the cause
                               changed;
* a CONCLUSION: the single best next step, or an explicit statement that nothing within the
  current scope and capabilities would add evidence (so research should stop there).

Nothing here executes anything, sends a request or calls a model. Values describe research
usefulness, never exploitability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

READINESS_ORDER = {"offline_now": 0, "ready_to_propose": 1, "needs_scope_change": 2,
                   "needs_scope": 3, "previously_failed": 4, "needs_capability": 5}
VALUE_ORDER = {"high": 0, "medium": 1, "low": 2}
_SENSITIVE = re.compile(r"(user|admin|basket|order|card|address|login|auth|account|"
                        r"wallet|payment|secur|password|token|config|upload|file)", re.IGNORECASE)
_BUNDLE = re.compile(r"^/(main|app|runtime|scripts|bundle|vendor|index)[\w.-]*\.js$", re.IGNORECASE)
LOW_VALUE_KINDS = frozenset({"stylesheet", "resource"})
MAX_STEPS = 10


@dataclass
class Step:
    kind: str                 # http_get_path | http_probe | nmap_connect_scan | analysis | ...
    target: str
    value: str                # high | medium | low
    value_reason: str
    readiness: str
    why: str
    path: str = ""
    detail: dict = field(default_factory=dict)

    def as_dict(self, sid: str) -> dict:
        d = {"step": sid, "kind": self.kind, "target": self.target, "value": self.value,
             "value_reason": self.value_reason, "readiness": self.readiness, "why": self.why}
        if self.path:
            d["path"] = self.path
        if self.detail:
            d.update(self.detail)
        return d


def _attempts(records: list) -> dict[tuple[str, int, str], dict]:
    """Earlier live attempts per (host, port, path): last outcome from the audit log."""
    out: dict[tuple[str, int, str], dict] = {}
    for r in records:
        d = r.data if isinstance(r.data, dict) else {}
        if d.get("tool") not in ("http_get_path", "http_probe"):
            continue
        key = (str(d.get("host")), d.get("port"), d.get("path") or "/")
        if r.event == "tool_result_received":
            ok = d.get("status") == "completed" and not d.get("errors")
            out[key] = {"ok": ok, "status": d.get("http_status_code"),
                        "reason": "" if ok else str(d.get("errors") or d.get("status"))[:160]}
        elif r.event in ("tool_request_failed", "tool_request_rejected",
                         "tool_request_denied_locally"):
            out[key] = {"ok": False, "status": None,
                        "reason": f"{r.event}: {str(d.get('reason') or d.get('error') or '')[:120]}"}
    return out


def _path_value(path: str, kinds: tuple[str, ...], api_known: int) -> tuple[str, str]:
    if "api_candidate" in kinds:
        if _SENSITIVE.search(path):
            return "high", ("API candidate whose name suggests user data or an access decision;"
                            " fetching it shows whether it answers without credentials")
        return "medium", "API candidate referenced by the application's own code"
    if "form_action" in kinds:
        return "medium", "server-side handler of a form (a GET only; the form is never submitted)"
    if "script" in kinds and _BUNDLE.match(path):
        if api_known == 0:
            return "high", ("first-party application bundle: client-side apps usually reference "
                            "their API routes here, and none are known yet")
        return "low", "application bundle; API routes are already known from other evidence"
    if "script" in kinds:
        return "low", "third-party or helper script"
    if "link" in kinds or "redirect" in kinds or "header_hint" in kinds:
        return ("medium" if _SENSITIVE.search(path) else "low"), "linked page"
    return "low", "static asset"


def plan(*, evidence: Any, state: Any, surfaces: list, records: list,
         checker: Any = None, scope_allows=None) -> dict:
    """``scope_allows(checker, tool, host, port, path) -> bool`` is injected (the same
    deterministic policy function the pipelines use)."""
    from avra.verification.evidence import HttpObservation, TcpPortObservation
    from avra.verification.models import Verdict

    attempts = _attempts(records)
    inventory: dict[str, dict] = {}

    def inv(label: str) -> dict:
        return inventory.setdefault(label, {"target": label, "tcp": None, "http_root": None,
                                            "fetched": [], "referenced_not_fetched": {},
                                            "open_engine_questions": 0})

    for o in evidence.observations:
        row = inv(o.target.label())
        if isinstance(o, TcpPortObservation):
            row["tcp"] = o.state
        elif isinstance(o, HttpObservation):
            f = o.facts
            entry = {"path": getattr(o, "path", "/"), "status": f.status_code if f else None,
                     "outcome": o.outcome, "body_bytes": f.body_bytes if f else 0,
                     "truncated": o.truncated, "content_type": (f.content_type if f else "")[:60],
                     "evidence": o.ref.request_id}
            if entry["path"] == "/":
                row["http_root"] = entry
            else:
                row["fetched"].append(entry)

    steps: list[Step] = []

    def readiness(tool: str, host: str, port: int, path: str | None) -> str:
        prev = attempts.get((host, port, path or "/"))
        if prev is not None and not prev["ok"]:
            return "previously_failed"
        if checker is None or scope_allows is None:
            return "needs_scope"
        return "ready_to_propose" if scope_allows(checker, tool, host, port, path) \
            else "needs_scope_change"

    for e in sorted(state.entries.values(), key=lambda e: e.hypothesis.rule_id):
        if e.result.verdict is not Verdict.INCONCLUSIVE:
            continue
        t = e.result.target
        inv(t.label())["open_engine_questions"] += 1
        miss = " ".join(e.result.missing_evidence)
        tool = "http_probe" if "http_probe" in miss else "nmap_connect_scan" if "nmap" in miss \
            else ""
        if not tool or any(s.kind == tool and s.target == t.label() for s in steps):
            continue
        steps.append(Step(tool, t.label(), "high", "the engine cannot decide "
                          f"{e.hypothesis.rule_id} without it", readiness(tool, t.host, t.port,
                                                                          None),
                          f"missing evidence: {miss[:160]}"))

    for s in surfaces:
        label = f"{s.host}:{s.port}"
        row = inv(label)
        api_known = sum(1 for x in s.endpoints if "api_candidate" in x.kinds)
        skipped = 0
        for x in s.endpoints:
            if x.status == "fetched" or x.path.startswith("/#"):
                continue
            for k in x.kinds:
                row["referenced_not_fetched"][k] = row["referenced_not_fetched"].get(k, 0) + 1
            if set(x.kinds) <= LOW_VALUE_KINDS:
                skipped += 1
                continue
            value, why_value = _path_value(x.path, x.kinds, api_known)
            src = x.provenance[0] if x.provenance else None
            steps.append(Step(
                "http_get_path", label, value, why_value,
                readiness("http_get_path", s.host, s.port, x.path),
                f"referenced via {src.source if src else 'a fetch'} in evidence "
                f"{src.request_id[:8] if src else '?'}; it has never been fetched",
                path=x.path,
                detail=({"previous_attempt": attempts[(s.host, s.port, x.path)]["reason"]}
                        if (s.host, s.port, x.path) in attempts else {})))
        if skipped:
            row["skipped_low_value_assets"] = skipped
        for m in s.responses:
            if m.path != "/" and getattr(m, "truncated", False):
                steps.append(Step("analysis", label, "medium", "known limitation of evidence",
                                  "offline_now",
                                  f"the response for {m.path} was truncated at the 256 KiB "
                                  "fetch limit: references after that point are unknown, and "
                                  "no tool can fetch the rest", path=m.path))

    if any(e.result.verdict is Verdict.CONFIRMED for e in state.entries.values()):
        steps.append(Step("explain_verdict", "-", "low", "already decided", "offline_now",
                          "review why the engine confirmed its findings (explain_verdict)"))
    steps.append(Step("validation_check", "-", "low", "would decide access-control or "
                      "input-handling hypotheses", "needs_capability",
                      "IDOR / marker-reflection checks run on fixtures only; live validation "
                      "is disabled until separately authorized"))

    # actionable steps first (ordered by value), then the blocked ones by how close they are
    actionable_now = ("offline_now", "ready_to_propose")
    steps.sort(key=lambda s: (s.readiness not in actionable_now, VALUE_ORDER[s.value],
                              READINESS_ORDER[s.readiness], s.kind, s.path))
    shown = steps[:MAX_STEPS]
    actionable = [s for s in shown if s.readiness == "ready_to_propose"
                  or (s.readiness == "offline_now" and s.kind != "explain_verdict")]
    blocked = [s for s in shown if s.readiness == "needs_scope_change" and s.value != "low"]
    if actionable:
        best = actionable[0]
        conclusion = (f"Best next step: {best.kind}"
                      f"{' ' + best.path if best.path else ''} on {best.target} "
                      f"({best.value} value: {best.value_reason}).")
        if best.readiness == "ready_to_propose":
            conclusion += " It is read-only and in scope; it still needs your /approve."
    elif blocked:
        conclusion = ("Nothing further can be done inside the current scope. The most useful "
                      f"scope change (owner decision) would allow {blocked[0].kind} "
                      f"{blocked[0].path} on {blocked[0].target}.")
    elif any(s.readiness == "needs_scope" for s in shown):
        conclusion = "No scope is bound: bind one (avra chat --scope) before live steps."
    else:
        conclusion = ("Within the current scope and capabilities no further action would add "
                      "evidence. Stop here, or extend capabilities/scope deliberately.")
    return {"inventory": list(inventory.values()),
            "steps": [s.as_dict(f"S{i}") for i, s in enumerate(shown, 1)],
            "conclusion": conclusion,
            "note": ("A plan only - nothing has been run. 'value' is research usefulness, not "
                     "exploitability. Live steps need the owner's /approve for each action.")}
