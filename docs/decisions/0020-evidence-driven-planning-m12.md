# ADR 0020 — M12 Evidence-driven planning and live-integration hardening

_Status: Accepted (2026-11-13, owner's "M10.5 deployment → M11 live integration" sprint).
M12.1 implemented and tested offline._

## M12.1 — Next-step planner (`avra.research.next_steps`)

**Problem.** The M11 chat's `plan_next_steps` listed candidates but did not know:
- what had already been tried or had failed;
- which steps the bound scope actually allows;
- when to stop.

So a real model could keep proposing low-value or impossible actions.

**Decision.** A pure, deterministic planner over a session's trusted evidence, the engine's
in-memory verdicts, the web surface and the session audit log. It returns three things.

1. **Inventory per target:** TCP state, the `GET /` response, every fetched path (status,
   size, content type, truncation), counts of still-unfetched references by kind, and open
   engine questions.
2. **Steps** with an explained **value** (high/medium/low = research usefulness, never
   exploitability) and a **readiness**:

   | Readiness | Meaning |
   |---|---|
   | `offline_now` | an offline check that can run immediately |
   | `ready_to_propose` | in the bound scope; still needs `/approve` and a running Runner |
   | `needs_scope_change` | useful, but the scope does not allow it (owner decision) |
   | `needs_scope` | no scope bound |
   | `needs_capability` | e.g. live validation (disabled) |
   | `previously_failed` | an earlier attempt failed or produced no evidence (from the audit log); not suggested blindly again |

3. **Conclusion:**
   - the best actionable step; or
   - "nothing further inside the current scope; the most useful scope change would be …";
     or
   - "no further action would add evidence — stop here".

**Value heuristics (deterministic, explained in each step).**

| Referenced item | Value |
|---|---|
| API candidate with a sensitive name (user, admin, basket, login, …) | high |
| other API candidate | medium |
| form action | medium (GET only, never submitted) |
| first-party bundle (`main*.js`, …) while no API route is known yet | high |
| bundle once API routes are known | low |
| static assets (CSS, images) | skipped and counted |

Fetched paths are never suggested again. A response truncated at the 256 KiB fetch limit
becomes an explicit limitation step.

**Chat (`chat-v2` prompt).**
- Only `ready_to_propose` steps may be proposed with `request_action`.
- `needs_scope_change` and `needs_capability` are explained, not attempted.
- A failed approved action is explained with its recorded reason and the checks the owner
  can make (Runner, tunnel, both scopes, target, kill switch); it is not re-proposed until
  something has changed.

**Web surface.** `ResponseMeta` now records `truncated` and `body_bytes`. The digest flags
`truncated_at_limit`, and `get_investigation` reports the content type, size and
truncation of every HTTP response.

**Unchanged.** No permission was added. Readiness is computed with the same
`authorize_tool_request` the pipelines use; the plan executes nothing.
