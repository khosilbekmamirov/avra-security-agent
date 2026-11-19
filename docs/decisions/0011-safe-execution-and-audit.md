# ADR 0011 — Safe tool execution & audit completion (M8.6)

_Status: **Accepted** (2026-11-10). Implemented and verified offline
(commit `29267a1`). Windows-side only: no Runner code changed, nothing
deployed._

## Context

The post-M8.5 review (findings G1–G4, G3b) showed audit and reporting gaps
around the research loop: refused `verify_hypothesis` requests left no
record (G3b), the exact feedback the model received could not be proven
afterwards (G3), and the verification report blurred session vs run scope
(G4), proposed vs executable next actions (G2) and earlier evidence vs this
run's coverage (G1).

## Decisions

1. **Refused model requests are audited (G3b).** `VerificationLoop.submit`
   writes `verification_request_refused` for `out_of_scope`, `invalid` and
   `budget`, with step, status, rule id (≤ 80 chars), host, port, a fixed
   reason and the verification budget — no rationale or other free text.
2. **Model-facing payloads are hashed when sent (G3).** Immediately before
   each provider call, `ResearchSession` writes one `model_feedback` record
   per payload in that request that was not recorded before: `kind`
   (`first_message` / `tool_result`), `step` (the call that sends it),
   `tool_use_id`, `tool`, `is_error`, `sha256` and `bytes` of the exact UTF-8
   bytes of the payload text, `prompt_version`; the first-message record
   also carries `system_sha256` and `tools_sha256` (canonical JSON of the
   tool list). Payloads are **not stored**: tool results can contain
   target-derived data; the hash lets anyone holding a candidate payload
   prove whether it is what was sent. If the record cannot be written, the
   exception propagates and **no API call is made**. Applies in M7 and
   verification mode; a payload built but never sent (e.g. the result of
   `finish_session`) gets no record. Token-counting requests (before the
   budget gate) are not counted as delivery.
3. **Run scope vs session scope (G4).** The verification report keeps
   `session.scope_session_name` (now labelled `scope_label_source:
   session_created`) and adds `research_run_scopes` and
   `research_loop.runs[].scope`: each run's scope label and snapshot hash
   from its own `research_started`, trusted only if the snapshot verifies.
4. **Next actions (G2).** The loop summary adds `proposed_next_actions`
   (all candidates, as in the verification report) and
   `agent_actionable_next_actions` (agent-executable with the remaining
   tool budget); `open_next_actions` keeps its old meaning for old records.
5. **Earlier evidence (G1).** Display only: after a schema-5 report the CLI
   states that N earlier same-session items are citable but not counted in
   this run's coverage/exposure. Report schema unchanged (schema 6 remains
   ADR 0008 §3).

## Verified properties (tests in `tests/verification/test_m86_execution_audit.py` unless noted)

| Property | Evidence |
|---|---|
| Out-of-scope / malformed requests rejected before execution | Runner: `tests/security/test_runner_core_security.py` (rejections never execute, injection strings, unknown fields); Windows: `tests/security/test_scope_default_deny.py`; research: `test_lab_context.py` |
| Approval enforced; zero tool budget never reaches approval | `tests/unit/test_llm_research.py` (decline), `test_zero_tool_budget_never_reaches_approval_or_execution` |
| Audit-write failure blocks execution | Runner: `test_pre_execution_audit_failure_blocks_execution`; Windows: scan + HTTP-probe pipelines open no tunnel; research runs nothing when `llm_proposal`/`owner_decision` cannot be written; no API call when `model_feedback` cannot be written |
| Replays are re-checked and re-audited, never silent | `test_replayed_runner_request_is_authorized_and_audited_again` |
| Refused verify requests audited (G3b) | 4 tests (out of scope ×2, invalid, budget) + report listing |
| Feedback hashes equal the delivered bytes (G3) | `test_every_sent_payload_has_a_matching_hash_record` (both modes) |
| Chain detects edit, reorder, gap, insertion | `test_chain_detects_edit_reorder_gap_and_insertion` |

## Trust limits (unchanged, stated plainly)

- The audit chain is an **unsigned** SHA-256 hash chain: it detects changes
  to, removal of, or insertion among existing records, but **not removal of
  the last records** (`test_tail_truncation_is_not_detected_by_the_chain_alone`)
  and not a full rewrite by someone who can write the file. Attested reports
  act as an external anchor for their run (truncating an attested session
  makes `avra report verify` fail). It is not cryptographic authentication.
- Ctrl+C on Windows stops AVRA's side; a scan already running on Kali ends
  at the Runner's own timeout (process-group kill), not immediately.
- `avra kill` is still a placeholder.
