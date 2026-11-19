# ADR 0001 — Initial architecture decisions

- **Date:** 2026-11-04
- **Status:** Approved
- **Context:** `docs/architecture.md` (full architecture proposal, v0.1)

These are the 12 decisions the architecture proposal asked the project
owner to approve, plus the refinements agreed on afterward in discussion,
plus decisions 13 and 14, each added later as a standalone strategic
directive. All 14 are now approved. This file is the canonical record —
if chat history and this file ever disagree, this file wins; update it
when a decision changes.

| # | Decision | Approved choice | Notes |
|---|---|---|---|
| 1 | Deployment layout | Hybrid: AVRA core on Windows 11 Pro host, Tool Runner on a Kali Linux VM, target on an Ubuntu VM. | Owner confirmed despite the added complexity, because Windows 11 Pro is the fixed host OS. See "Autonomy" below for a related, explicitly deferred ambition. |
| 2 | Runner transport | Typed HTTP service (FastAPI) between host and Runner. | Rejected plain SSH to keep requests typed and validated. |
| 3 | Language & interface | Python 3.12, Pydantic, Typer; CLI only for MVP. | Web dashboard explicitly deferred. |
| 4 | Storage | SQLite + evidence files on disk. | PostgreSQL deferred to a multi-user phase. |
| 5 | Agent control | Orchestrator-driven state machine; the model decides only within a phase, never the overall loop. | Rejected giving the model a fully free-running loop. |
| 6 | Model policy | Everything runs on Claude Opus 5.5. Model tiering (cheaper models for simple sub-tasks) is deferred and requires the owner's explicit approval before it's introduced. | Owner confirmed: no tiering by default. |
| 7 | Action tiers | Four tiers (passive / active-safe / intrusive / destructive); intrusive actions require approval every time. | Rejected auto-approving all active actions. |
| 8 | First vulnerability classes | Open directory listing (misconfiguration) + login SQL injection. | XSS and others deferred to later phases. |
| 9 | Lab layout | Juice Shop runs in Docker inside the Ubuntu VM; Kali is the attack/runner machine. | Confirmed via the owner's description of the intended workflow (recon/attack practice on Kali against the Ubuntu-hosted target). |
| 10 | Cost policy | Per-session budget, a dedicated Anthropic API key with a monthly cap; the owner sets the cap. | Unlimited spend explicitly rejected. |
| 11 | Host memory | Plan for a RAM upgrade (to 32 GB) rather than running one VM at a time on 16 GB. | — |
| 12 | Next step | Phase 0 = lab confirmation + Git repo skeleton (this commit). VMs were already built by the owner before Phase 0 started, so Phase 0 is scoped down to repo/doc scaffolding plus a lab network/version check (see `docs/lab-setup.md`). | GitHub (private repo, `khosilbekmamirov/avra`) added as a requirement during this step, for versioning and so the owner can resume work from another machine later. |
| 13 | Progressive Autonomy (home-lab scope) | Approved, binary model: inside a scope file explicitly designated as the home-lab scope, AVRA runs passive/active-safe/intrusive actions without a live per-step approval prompt (the scope file is the capability grant — "Capability-First", `docs/architecture.md` §8a). Outside that scope, decision 7's rule stands: intrusive actions require approval every time. Destructive stays blocked everywhere. | Policy-layer enforcement (the actual scope schema flag and the check itself) isn't built yet — that's a security/policy-layer change needing its own sign-off under CLAUDE.md's Working protocol, likely alongside Phase 2. Distinct from the graduated/track-record trust idea below, which remains undesigned. |
| 14 | Development Policy vs Runtime Policy split | Approved: Claude Code's own hands-on lab work (SSH into the two declared VMs, `docs/lab-setup.md`) is governed by a separate **Development Policy** (`docs/dev-environment.md`), independent of AVRA's Runtime Policy. Destructive/irreversible dev actions still need the owner's approval every time; Runtime Policy code (`src/avra/policy/`, `schemas/scope.py`, `storage/audit.py`) is untouched. Dev-session record in `docs/dev-log.md`, separate from AVRA's runtime audit log. | Closes a gap, not a conflict: CLAUDE.md's Safety rules were always about AVRA/Opus 5.5 and simply never addressed Claude Code's own dev-time authority, which had led to an ad hoc, overly strict rule being improvised in chat before this decision formalized it properly. |

## Autonomy inside the lab network

**Amendment (2026-11-04 — Development Autonomy & Agent Capability Policy
directive):** decision 13 above approves the binary form of this. Inside a
scope file explicitly designated as the home-lab scope, AVRA runs
passive/active-safe/intrusive actions without a live per-step approval
prompt — see `docs/architecture.md` §8a ("Progressive Autonomy" /
"Capability-First"). This relaxes the per-action approval requirement
*only* inside that designated scope. Everywhere else — any other target,
including any future real-network target — decision 7's rule is
unchanged: intrusive actions require approval every time, and this is
never remembered as blanket consent for the next one. The destructive
tier stays blocked everywhere, lab or not.

**Still not designed, and not approved by decision 13:** a graduated or
scored trust model — AVRA earning progressively fewer approvals over time
based on its own track record of safe behavior. That's a different idea
from the binary home-lab/non-home-lab switch above, and remains exactly as
originally flagged: do not build "auto-approve after N successful runs"
(or any other trust-score) logic without its own design pass and the
owner's explicit sign-off. Real-network use of any kind still additionally
requires the owner's explicit authorization and is out of scope for now.

## Development Policy vs Runtime Policy

Decision 14 above formalizes this. Claude Code's own hands-on work in
the lab (SSH into the two declared VMs — `docs/lab-setup.md` — to run
tools directly, deploy and debug Runner code, read logs) is governed by
a separate, now-explicit **Development Policy** (`docs/dev-environment.md`),
not by AVRA's Runtime Policy. Before this decision, CLAUDE.md was silent
on Claude Code's own authority in the lab — a gap, not a contradiction —
and leaving it unaddressed had already led to an overly strict, ad hoc
rule being improvised mid-conversation; this closes that gap properly
instead of leaving it to be re-improvised turn by turn.

The two policies are independent: loosening Development Policy never
loosens Runtime Policy, and Claude Code's SSH-based dev actions never
call into, bypass, or substitute for AVRA's own Policy/Runner/audit code
(`src/avra/policy/`, `src/avra/schemas/scope.py`,
`src/avra/storage/audit.py`), which is unchanged by this decision.
Destructive or irreversible dev actions (VM snapshot revert, forced
power-off, deleting data, network/firewall changes, SSH key/user
changes) still need the owner's explicit approval every time — this is
CLAUDE.md's general hard-to-reverse-change rule, not a new mechanism.

Dev-session record: `docs/dev-log.md` — a line per notable session, kept
separate from AVRA's own hash-chained runtime audit log. A vulnerability
found by hand during dev work is a dev note, not an AVRA finding, until
it becomes an actual Verification Engine test case.

## Remote / multi-device access (noted, not yet designed)

The owner also wants to be able to reach AVRA from other machines (e.g. a
laptop at university), not just the Windows 11 Pro host. Technically
feasible (hosted service + thin client), but it's a platform-phase item
(`docs/architecture.md` roadmap phase 6), not MVP. The MVP CLI runs
locally on the host only.
