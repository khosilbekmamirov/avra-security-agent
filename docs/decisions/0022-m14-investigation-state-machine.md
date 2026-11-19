# ADR 0022 — M14 Intelligent Research Loop: investigation state machine (M14.1)

_Status: **Accepted.** M14.1 (2026-11-17). M14.2-M14.4 with **Option A** approved by the
owner on 2026-11-18 and implemented OFFLINE the same day (see "M14.2-M14.4 (implemented)"
below). No live run, no deployment._

## Context

M13.3 established the baseline (2008 offline tests pass; Bonsai, tunnel, Runner and both
scopes verified, live `/main.js` GET not yet run). The M14 brief asks for
Observe → Analyze → Plan → Propose → Approve → Execute → Verify → Report.

A gap analysis showed most parts **already exist** and must be reused, not duplicated:

| M14 stage | Existing component |
|---|---|
| Planner (Stage 5) | `avra.research.next_steps` (ADR 0020): deterministic, scope-aware, prefers existing evidence, never repeats fetched paths, explicit stop conclusion |
| Analysis (Stage 7) | Verification Engine (ADR 0009) + hypothesis board (ADR 0017): deterministic verdicts, contradictions → INCONCLUSIVE, model never sets CONFIRMED |
| Proposal/approval (Stage 6) | chat `request_action` + `/approve` + second terminal confirmation (ADR 0019, M13) |
| Execution | audited pipelines `run_http_probe` / `run_nmap_connect_scan` (Windows scope → tunnel → Runner re-check, kill switch) |
| Report (Stage 10) | verification reports (ADR 0009/0010), `/summary`, `/details` |

What is **missing**: a durable *investigation* object. Today an objective lives only in
chat history; pending actions are in memory and expire when the process ends; nothing ties
objective, proposals, approvals, executions and the final verdict together, and there is no
explicit, validated phase.

## Decision (M14.1, implemented)

`src/avra/research/investigation.py` — a persistent, event-sourced state machine.

- **Storage:** one hash-chained `AuditLog` per investigation
  (`data/investigations/<uuid>.jsonl`). State is never stored; it is rebuilt by replay and
  every replayed transition is validated again. Broken chain or illegal history → refuse
  to load.
- **States:** CREATED, OBSERVING, ANALYZING, PLANNING, WAITING_APPROVAL, EXECUTING,
  VERIFYING; terminal COMPLETED, INCONCLUSIVE, FAILED, CANCELLED. `TRANSITIONS` is the
  whole graph; EXECUTING is reachable only through `begin_execution`.
- **Actions:** PROPOSED → APPROVED → EXECUTING → SUCCEEDED/FAILED, or DENIED, EXPIRED,
  INTERRUPTED, REFUSED. Each records investigation id, tool, host, port, path, the
  registry-fixed tier, risk (derived from tier, never chosen by the model), reason,
  expected evidence, scope result and a **fingerprint** (SHA-256 of what would run).
- **Invariants:**
  1. default deny: no scope check, or a raising one, means REFUSED;
  2. approval quotes the fingerprint, is single-use, expires (15 min default) and
     re-checks scope; the second terminal confirmation stays in the caller, before
     `approve`;
  3. at most once: `action_started` is written before anything is sent; on reload an
     unfinished action becomes INTERRUPTED and the investigation FAILED — never re-run;
  4. no duplicate target actions: a (tool, host, port, path) that is pending, approved,
     running or succeeded cannot be proposed again;
  5. a "success" without an evidence hash is recorded as FAILED; result must carry the
     started request id; error text is redacted.

It plans nothing, calls no model and contacts no host.

### Alternatives considered

| Option | Why not (for now) |
|---|---|
| Keep state in the chat conversation file | not hash-chained, no transition validation, mixes owner text with control state |
| A SQLite table | mutable rows, a second integrity mechanism beside the audit chain |
| Model-reported state ("I am now verifying") | violates "the model proposes, it never decides" |

## Proposed next increments (need the owner's choice)

**M14.2 — controller + CLI (`avra investigate`).** Drives the machine with existing parts:
observe = load session evidence; analyze = engine + hypotheses; plan = `next_steps.plan`;
propose = its best `ready_to_propose` step; approve = the same terminal two-step gate;
execute = existing pipeline with the recorded request id; verify = evidence hash + engine
re-run; report = Markdown/JSON from the snapshot + engine report.

Key decision — **who chooses the next action**:

| | A. Deterministic planner chooses, model explains (recommended) | B. Model chooses among `ready_to_propose` steps |
|---|---|---|
| Reliability with Bonsai 27B / 4096 ctx | high; works with the model off | lower; long contexts, malformed calls |
| Cost/latency | ~1 short model call per iteration (optional) | several calls per iteration |
| Safety | same gates either way | same gates; more refusals to handle |
| "Intelligence" | heuristics in ADR 0020 | model judgement within the same bounded set |

**M14.3 — report generator** (VERIFIED / INCONCLUSIVE / NOT TESTED / FAILED, audit refs,
evidence hashes; no severity/CVSS). **M14.4 — adversarial regression set** (prompt
injection in bodies, loop limits, kill switch mid-loop, LLM timeout).

## Consequences

- New data directory `data/investigations/` (gitignored with `data/`).
- No change to policy, scope schema, audit storage, Runner or approval semantics.
- Chat is untouched in M14.1; wiring it to investigations is a later decision.

## M14.2-M14.4 (implemented 2026-11-18, offline) - Option A

**Owner decision:** Option A. The deterministic planner selects the next candidate action;
the model (Bonsai or any provider) only explains it and may suggest hypotheses as text; it
never authorises or executes. The seam for a future model-assisted planner is
`select_candidate` / `Ports` in the controller - replacing it would not touch any gate.

**M14.2 - controller + CLI.** `src/avra/research/controller.py`:
Observe (session evidence) -> Analyze (engine, recomputed in memory) -> Plan
(`next_steps.plan`, first `ready_to_propose` live step not yet tried here) -> Propose (scope
check, fingerprint) -> Approve (owner) -> Execute (existing audited pipeline) -> Verify
(evidence SHA-256 must match a hash-checked observation of the SAME request id in the session
audit) -> Analyze again ... -> COMPLETED / INCONCLUSIVE / FAILED / CANCELLED.
All collaborators are injected (`Ports`), so the controller has no network/model/terminal
access of its own. Reused, not duplicated: `chat.knowledge.analysis()` (shared with chat's
`plan`), `kb.scope_allows` -> `authorize_tool_request`, `_chat_execute` -> `run_http_probe` /
`run_nmap_connect_scan`, the kill switch, `AuditLog`, `wrap_data`, `redact`, `Styler.sanitize`.

Small additive changes to existing code (no behaviour change for existing callers):
- `run_http_probe` / `run_nmap_connect_scan` / `_chat_execute`: optional `request_id`, so the
  id written by `begin_execution` BEFORE sending is the one the Runner sees and the session
  audit records (correlation; it passes no gate).
- `Investigation`: state-neutral `note_recorded` events (closed set of kinds, bounded size);
  `load(reconcile=False)` read-only view; `run_lock()` (cross-process, reuses the audit
  file-lock) so only the process driving an investigation can reconcile/advance it;
  `withdraw_approval()` - an APPROVED action whose process stopped lapses to EXPIRED (never
  reused; a retry needs a fresh proposal + approval); `deny` also from APPROVED (kill switch
  at the last gate).

Guards: max actions per investigation (default 3, CLI `--max-actions` 1-10), 10 proposals,
60 phase steps per run; kill switch checked before every phase AND between approval and
`begin_execution` (the pipeline checks it again); KeyboardInterrupt leaves the action
EXECUTING in the log and the CLI reconciles it at once to INTERRUPTED (investigation FAILED,
never re-run); explainer failures/timeouts are recorded (`explanation_failed`) and never block
the owner gate.

CLI `avra investigate start|resume|cancel|list|show|report`. `start` binds the scope file by
SHA-256; `resume` refuses a different file. Approval in a real terminal only: type the first
12 characters of the fingerprint, then confirm "Send this ONE ... request"; non-interactive ->
the proposal stays pending (exit 2). Model explanation is optional (`--explain`), paid
providers need an explicit confirmation, text is redacted, labelled UNVERIFIED, hashed and
token/cost-logged in the investigation log.

**M14.3 - report.** `src/avra/research/investigation_report.py`, `avra investigate report`:
JSON + Markdown under `data/investigations/reports/<id>/` (exclusive create, never
overwrites). Sections VERIFIED (engine CONFIRMED, with request ids + SHA-256), REJECTED,
INCONCLUSIVE (missing evidence), NOT TESTED (no request sent: denied/expired/refused/out of
scope/not reached), FAILED (failed or interrupted); actions with fingerprint, request id,
evidence hash and verification; investigation-log head hash; model usage. No severity/CVSS.
Building a report writes nothing to the investigation log. Markdown cells are sanitised.

**M14.4 - adversarial offline regression set** (`tests/verification/test_m14_*.py`,
`tests/unit/test_m14_investigate_cli.py`): prompt injection in a response body and in model
output; model never offered tools; timeouts; endless planner / everything-refused loops;
raising scope check; kill switch before start, mid-loop, between approval and start, and
inside the pipeline; interrupted execution + recovery; approved-but-unstarted on resume;
wrong fingerprint; TTL expiry; scope narrowed before approval; foreign request id; success
without evidence; unverifiable evidence; tampered and forged (validly hashed, illegal)
logs; unknown note kinds; oversized notes; run-lock exclusivity; approval-screen spoofing.

**Not done / still open:** no live run of `avra investigate` (needs the owner's approval
and the lab); M13.3 Stage 3 live `GET /main.js` remains **NOT TESTED**; chat is not yet wired
to investigations.

