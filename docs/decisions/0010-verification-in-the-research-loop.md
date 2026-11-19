# ADR 0010 — Verification feedback inside the research loop (M8.5)

_Status: **Accepted** (2026-11-09). Implemented and tested offline with a
fake model (commit `969c404`). Not yet run with the real model or against
the lab; the default research mode is unchanged (m7-v2)._

## Context

M8.4 (ADR 0009) built a deterministic Verification Engine and an *offline*
cycle, but the live M7 research loop (`core/research.py`) still only
recorded free-text hypotheses. The model never learned what the evidence
proved, so it could not adapt, and nothing stopped it from re-asking
decided questions.

Constraints found in Stage 0:

- The M7 eval harness pins the production prompt to `m7-v2` and compares
  28 scenarios to a committed baseline; its registry says activating a
  new production prompt needs the owner's approval after evaluation.
- Report replay segments runs by `research_started`/`research_stopped`,
  ignores unknown events, and requires `research_stopped` to be the last
  record of a run.
- `core.research` ← `reporting` ← `verification` would be circular at
  import time.

## Decision

1. **Opt-in verification mode.** `ResearchSession(verification=VerificationLoop(...))`,
   CLI `avra research --verification`. Without it the session is
   byte-for-byte the M7 loop (prompt, tools, results, events). With it:
   prompt **`m8.5-v1`** (= `m7-v2` + one appended section, so the cached
   prefix is shared) and tool list `TOOL_DEFINITIONS_VERIFY` (= M7 tools +
   `verify_hypothesis`). The production default stays `m7-v2` until a live
   evaluation with the real model (cost and behaviour are unmeasured).

2. **Hypotheses → typed requests.** `verify_hypothesis{rule_id, host, port,
   rationale}` — strict schema, no verdict/status field. The loop checks
   the target is in the session scope, builds `Hypothesis.create(origin=model)`
   (rule id format, IPv4, port), and the engine verifies it. A missing rule
   or no evidence gives INCONCLUSIVE; free-text `record_hypothesis` notes
   stay unverified as in M7.

3. **When verification happens.** At session start (existing evidence,
   e.g. an owner's `avra probe http` in the same session), on every
   `verify_hypothesis` call, and after every executed tool run — then
   EVERY known hypothesis is re-verified (verdicts can be revised;
   `revised_from` is audited) and the rules propose follow-ups (bounded
   rounds). Verification is offline and needs no confirmation.

4. **Feedback to the model.** A bounded structured digest
   (`VerificationLoop.feedback`): verified observations, confirmed findings
   (engine only, with proof request ids), rejected (with the rule's
   reason), inconclusive (with missing evidence), ranked next actions,
   remaining verification budget, and for a submitted hypothesis its
   criteria and verdict history. It is placed in the first message (with
   the rule catalogue) and in tool results, inside the existing
   `<untrusted_tool_output>` wrapper. It contains no server-controlled
   text (rules' own reasons, ids, verdicts, request ids only).

5. **State, dedup, contradictions.** Hypothesis ids derive from
   (rule, target, params): a repeated submission is answered from state
   (`repeat` / `rejected_repeat` — "Already REJECTED … do not propose it
   again") and audited as `verification_repeat`, never re-verified. The
   model cannot overrule a verdict; only new evidence can change it.

6. **Planning (Stage 2).** `verification/planner.py`: candidate actions
   come only from rules' `next_actions` for INCONCLUSIVE results (no
   scripted sequences). Score = expected information gain (open hypotheses
   the evidence would decide, weighted by rule kind/severity, + follow-up
   rules it enables) ÷ tier cost (probe 1, scan 2), gated by the scope
   (same policy function as the pipelines), by who may run it (`agent`:
   `nmap_connect_scan`; `owner_only`: `http_probe`, ADR 0008 D1) and by the
   tool-run budget. Blocked actions stay listed with the reason. Nothing is
   executed by the planner; agent actions still go through
   propose → scope → owner approval.

7. **Progress detection.** A marker (evidence set, verdict map, tool runs,
   proposals, notes) is compared after each model step; `no_progress_steps`
   (default 3) unchanged steps stop the session with the new stop reason
   `no_progress` (report execution status COMPLETED; CLI exit 0).

8. **Audit and reports.** `verification_hypothesis`, `verification_verdict`
   (rule version, result SHA-256, trigger, revision), `verification_repeat`
   and `verification_no_progress` are recorded inside the run;
   `research_started` carries `prompt_version` and a `verification_loop`
   block; `research_stopped` carries the loop summary. Research reports
   (schema 4), replay and `avra report verify` are unchanged. The
   verification report becomes **`avra-verification-report/2`**: a
   `research_loop` section rebuilt from those audit events (hypotheses with
   step/origin, verdict history incl. revisions, repeats, stops), and the
   loop's model hypotheses are re-verified as seeds, so provenance and
   reproducibility come from the audit, not from memory. `/1` reports
   still re-check; historical sessions get `research_loop: null`.

## Compatibility evidence

- The 28 M7 eval scenarios pass against the unchanged m7-v2 baseline
  (default mode) **and** produce identical outcomes and metrics in
  verification mode (`tests/eval/test_eval_m85_compat.py`): where no
  evidence or rule applies, the mode changes nothing.
- Real M8.3 evidence: still 0 findings (header hypothesis REJECTED); the
  previously stored `/1` verification reports still `verify check`
  VERIFIED.

## Alternatives considered

- Making `m8.5-v1` the production default now — rejected: never evaluated
  with the real model; the harness rule requires an owner decision after a
  live evaluation.
- Letting the model call http_probe — rejected (ADR 0008 D1); it is an
  `owner_only` planned action.
- Embedding verification results in the attested research report
  (schema 5) — still deferred to ADR 0008 §3.

## Amendment 2026-11-09 — prompt `m8.5-v2`, refusal observability

**What happened.** The first real-model evaluation (`m8.5-v1`, copy
`data/eval/m85-real-01`, objective framed around security hypotheses,
`--max-tool-runs 0`) was refused at step 1: `stop_reason=refusal`, category
`cyber`, 0 output tokens, $0.0186 (3,716 cache-write tokens). The provider
explanation is generic ("Cyber safeguards flagged this message"). **The exact
cause is not known** and cannot be derived from the category. Compared with
the last accepted run (M7.8, `m7-v2`), five things changed at once:
prompt, tool list, objective framing (service inventory → security
hypotheses), +2.1 k characters of vulnerability-rule catalogue and verdicts,
and that block's label (`<untrusted_tool_output>` before any tool ran).

**Changes (accuracy, no new permissions):**
- Prompt `m8.5-v2`. The first message adds **"Session facts enforced by
  AVRA"**, derived only from the validated scope and the runtime config:
  authorized targets/tools/tiers, scope expiry, the network-tool budget
  (0 → stated as offline analysis of already-collected evidence, not active
  testing), and counts of hash-checked evidence. It states that the owner's
  environment note (isolation, VMs, authorization) is **not verified by
  AVRA**; with no note, it says nothing about the environment. The engine's
  state is labelled `<avra_verification_state>` (AVRA-computed data) instead
  of `<untrusted_tool_output>`; tool results keep the untrusted wrapper.
- `llm_refusal` now records `refused_by: provider`, category, explanation,
  model, request id, prompt version, stop reason, usage, cost, tool runs so
  far / `tool_executed`, verification mode and block types; the CLI says the
  provider refused (not AVRA's policy) and that nothing ran. The `verify
  --model` proposer records the same fields (ADR 0009 amendment, prompt
  `m8.4-proposer-v2`), and AVRA's own proposal rejections are labelled
  "rejected by AVRA validation (not a provider refusal)".
- Unchanged: `m7-v2` (byte-identical M7 first message, prompt and tools),
  scope checks, approvals, tool-run limits, verdicts. No retries, no
  fallback model.

**Separate design option, not implemented (owner review needed):** the
Claude API's documented refusal fallback (configuring another model to
answer when one refuses) conflicts with ADR 0005 decision 5 / CLAUDE.md
("never bypass refusals"). The provider's own suggestion for legitimate
security work is the Cyber Verification Program, an owner decision.

## Amendment 2026-11-10 — report schema 5: earlier same-session evidence

**Root cause (confirmed).** The second real-model evaluation
(`data/eval/m85-real-02`) ran, and the model correctly cited the session's
M8.3 probe `5c746502-…`. The M7.9.4 claim check resolves request ids and
hashes **only from the current research run's own tool runs**; that probe
was recorded before the run started (audit seq 2–3 vs run start seq 4), so
the reference was "not a request or session ID of this run" → INCOMPLETE.
The verification engine, which reads the whole session, had VERIFIED it.
Fixing it surfaced a second, older defect: `verify_session` looked for
**every** evidence file as nmap `<id>.xml`, so a session containing an
`http_probe` result (`<id>.json`) could never pass `avra report verify`
(ADR 0008 §2's replay gap, evidence-lookup part).

**Changes.**
- Report **schema 5** (new runs; `research_started.report_schema_version`
  = 5): field `prior_session_evidence` = evidence recorded in the SAME
  session before the run started that AVRA verifies with the M8.4 evidence
  loader (audit chain, request/result pairing, completed + output hash ==
  evidence hash, symlink-safe file whose SHA-256 matches, strict parse and
  request match) and whose host:port is in the run's scope snapshot. Claim
  checks also resolve those request ids and evidence hashes. The list is
  computed by AVRA (CLI at report time, replay at verify time), never taken
  from the model or the report; the validator marks a report INVALID if its
  list differs from the recomputation, or if an older schema carries one.
- `evidence_path`/`check_evidence` choose the file by the recorded tool
  (`http_probe` → `.json`, `nmap_connect_scan`/legacy → `.xml`); unknown
  tools are `invalid_reference` (fail closed).
- Unchanged: schema 1–4 runs keep their exact rules and rebuild
  byte-for-byte (the eval copy's schema-4 report still reproduces and stays
  INCOMPLETE as attested); cross-session, invented, tampered and
  out-of-scope references still fail; scope, approvals and verdicts.

ADR 0008's planned "schema 5" (HTTP observations in the research report)
becomes schema 6 when implemented.

## Limits

- Autonomy is demonstrated with scripted / feedback-reading fake models
  only; real-model behaviour, prompt adherence and token cost are unknown.
- The loop can only gather new evidence with `nmap_connect_scan` (owner
  approval each time); HTTP evidence requires the owner's `avra probe http`.
- Information gain is a transparent heuristic, not a probabilistic model.
- Re-verifying all hypotheses on new evidence is O(hypotheses) per tool
  run (bounded by `max_verifications`, default 40).
