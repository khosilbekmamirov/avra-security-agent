"""Grounded capability status for ``avra chat`` (M14.5).

The model used to describe AVRA's abilities from the prompt and its own guesses, mixing up
"exists in the code", "offered in this chat", "passed automated tests", "ran in this session"
and "validated against the live lab". These are separate facts here:

* the STATIC part (:data:`REGISTRY`) is a curated, dated record. Each entry cites where the
  status is documented (ADR / NEXT_SESSION). It is updated by hand when a milestone changes a
  status - never by the model. ``LIVE_VALIDATED`` is only set when a recorded, owner-approved
  live run exists; existence in source code is never enough;
* the RUNTIME part is computed from this chat's actual objects (scope bound? executor wired?
  scope permits the tool?) and from what happened in THIS run (actions executed, /runner
  check). Nothing claims a service is running unless it was checked in this run.

No credentials, tokens, hosts' secrets or file contents are included.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

AS_OF = "2026-11-19"


class Status(StrEnum):
    IMPLEMENTED = "IMPLEMENTED"            # code exists; nothing more is claimed
    OFFLINE_TESTED = "OFFLINE_TESTED"      # automated offline tests pass (fakes/fixtures)
    LIVE_VALIDATED = "LIVE_VALIDATED"      # a recorded, owner-approved run against the lab
    NOT_TESTED = "NOT_TESTED"              # never run live (may be offline-tested)
    DISABLED = "DISABLED"                  # deliberately unavailable by design
    UNDER_DEVELOPMENT = "UNDER_DEVELOPMENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Capability:
    id: str
    what: str
    statuses: tuple[Status, ...]
    source: str
    note: str = ""


REGISTRY: tuple[Capability, ...] = (
    Capability("evidence_tools", "read recorded investigations: list, summarize, explain "
               "verdicts, web surface, research history, plan next steps",
               (Status.IMPLEMENTED, Status.OFFLINE_TESTED), "ADR 0019, M13",
               "local files only; used with the local Bonsai model in chat"),
    Capability("offline_verification", "re-run the deterministic Verification Engine on "
               "recorded evidence", (Status.IMPLEMENTED, Status.OFFLINE_TESTED),
               "ADR 0009/0010", "touches no target"),
    Capability("nmap_connect_scan", "nmap TCP connect scan of one in-scope host/port, via the "
               "Kali Runner, after /approve", (Status.IMPLEMENTED, Status.OFFLINE_TESTED,
                                                Status.LIVE_VALIDATED),
               "ADR 0019; chat action A3 executed 2026-11-14",
               "later attempts also failed when the Runner was unreachable"),
    Capability("http_probe", "one fixed 'GET /' to an in-scope web service, after /approve",
               (Status.IMPLEMENTED, Status.OFFLINE_TESTED, Status.LIVE_VALIDATED),
               "ADR 0007, M8.3", "live-validated through 'avra probe'; not yet run from chat"),
    Capability("http_get_path", "one fixed read-only GET of a path already seen in recorded "
               "responses, after /approve", (Status.IMPLEMENTED, Status.OFFLINE_TESTED,
                                              Status.NOT_TESTED),
               "ADR 0018, M13.3 Stage 3", "deployed on Kali; the first live GET /main.js has "
               "not been run"),
    Capability("avra_investigate", "multi-step investigation: planner chooses, owner "
               "approves, engine decides (CLI 'avra investigate')",
               (Status.IMPLEMENTED, Status.OFFLINE_TESTED, Status.NOT_TESTED),
               "ADR 0022, M14.2-M14.4", "not available inside chat"),
    Capability("kill_switch", "local fail-closed kill switch ('avra kill')",
               (Status.IMPLEMENTED, Status.OFFLINE_TESTED), "ADR 0012",
               "the Runner emergency stop is NOT verified operationally"),
    Capability("live_validation", "authenticated / exploit-style validation checks",
               (Status.DISABLED,), "ADR 0017/0021", "only simulated fixtures, never the lab"),
    Capability("shell_and_payloads", "shell commands, arbitrary requests, payloads, form "
               "submission, logging in", (Status.DISABLED,), "CLAUDE.md safety rules",
               "never available to the model"),
)


def runtime(*, checker: Any, executor_wired: bool, executed_actions: int,
            runner_check: str | None) -> dict:
    """What THIS chat can do right now - computed, not claimed."""
    if checker is None:
        tools: list[str] = []
        proposals = "unavailable: no scope file is bound (chat is read-only)"
    else:
        tools = sorted({t for tgt in checker.scope.targets for t in tgt.allowed_tools})
        proposals = ("available for the scope's tools; each needs the owner's /approve and a "
                     "terminal [y/N] confirmation")
    return {
        "read_only_evidence_tools": "available",
        "live_action_proposals": proposals,
        "scope_permitted_tools": tools,
        "execution_path": "wired (audited pipeline -> SSH tunnel -> Kali Runner)"
        if executor_wired else "not wired in this chat",
        "runner_reachable": runner_check or "NOT CHECKED in this run (owner can type /runner)",
        "live_actions_executed_this_run": executed_actions,
    }


def report(**runtime_kw: Any) -> dict:
    """The full, structured answer for the ``get_capabilities`` tool."""
    return {
        "as_of": AS_OF,
        "legend": {
            "IMPLEMENTED": "code exists (nothing more)",
            "OFFLINE_TESTED": "automated offline tests pass",
            "LIVE_VALIDATED": "a recorded, owner-approved run against the lab exists",
            "NOT_TESTED": "never run live",
            "DISABLED": "unavailable by design",
        },
        "capabilities": [{"id": c.id, "what": c.what,
                          "status": [s.value for s in c.statuses],
                          "source": c.source, **({"note": c.note} if c.note else {})}
                         for c in REGISTRY],
        "this_chat_now": runtime(**runtime_kw),
        "rule": "Existing in code is not 'tested'; offline-tested is not 'live-validated'; "
                "nothing here says a service is running unless this_chat_now says it was "
                "checked.",
    }


def prompt_digest() -> str:
    """One compact line per capability for the system prompt (~120 tokens)."""
    return "; ".join(f"{c.id}={'/'.join(s.value for s in c.statuses)}" for c in REGISTRY)
