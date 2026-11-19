# ADR 0009 — Verification Engine and offline research cycle (M8.4)

_Status: **Accepted** (2026-11-09). Implemented and tested offline
(commits `207d8c7`, `53b2b76`, `06a8772`). No live validation yet (Stage 4,
separate owner approval)._

## Context

AVRA's model can propose scans and write free-text hypotheses
(`record_hypothesis`), and reports (ADR 0006) check that model text does
not contradict evidence. Nothing could independently establish whether a
security condition is *true*. ADR 0001 decision 6 and `architecture.md`
reserve that for a deterministic Verification Engine.

The owner's M8.4 mandate (2026-11-09) re-scoped M8.4 to the Verification
Engine and an offline hypothesis → verification → feedback cycle, ahead of
exposing `http_probe` to the model. ADR 0008 (HTTP evidence → report
schema 5) remains accepted but is now the following milestone; this ADR
delivers its typed, hash-bound HTTP observation (ADR 0008 §1) inside the
engine's evidence layer, without touching `replay.py` or the research
report schema.

## Decision

### 1. Separation of roles

| Thing | Produced by | Can set a verdict? |
|---|---|---|
| Observation | `verification/evidence.py`, from hash-checked evidence | — (a fact) |
| Hypothesis | a proposer: rule generator, owner file, or the LLM | **no** |
| Verification result | `VerificationEngine.verify` only | **yes** (only here) |
| Finding | a CONFIRMED result of a `vulnerability` rule | — |
| Verified observation | a CONFIRMED result of an `observation` rule | — (never a finding) |

AI reasoning drives *which* hypotheses are checked; deterministic rules
decide *whether* they hold. A hypothesis' id is derived from (rule, target,
params) only, so rationale text can neither change identity nor verdict.

### 2. Evidence trust (fail closed)

Evidence is trusted only if the session audit chain verifies, the result
pairs with exactly one request (same tool/host/port(s)), the run completed
with a verified output hash equal to the recorded evidence hash, the file
(located from validated UUIDs only; no symlink/junction) has that SHA-256,
and the content parses with the tool's strict parser and matches the
request (nmap host/ports; HTTP fixed request bytes). Anything else becomes
an `EvidenceIssue` and supports nothing. The audit chain is unsigned: it
shows consistency, not authorship (limitation stated in every result).
Sessions without a scope snapshot are usable, with that limitation stated.

### 3. Verdicts

- **CONFIRMED** — trusted evidence satisfies every condition of the rule.
- **REJECTED** — trusted evidence shows the rule's condition is false for
  the examined data (e.g. the header is present). Absence of evidence is
  never a rejection.
- **INCONCLUSIVE** — missing, insufficient, contradictory or untrusted
  evidence, unsupported rule or invalid hypothesis.

Engine invariants: unknown rule / invalid params / untrusted session →
INCONCLUSIVE before the rule runs; a CONFIRMED/REJECTED that does not cite
trusted evidence for the exact target is downgraded
(`rule_invariant_violation`). Results serialize canonically; same evidence
→ same bytes → same SHA-256.

### 4. Rules (plugin registry)

`VerificationRule` declares id, version, kind, evidence kinds, positive and
negative criteria and `confirmed_requires`; `evaluate` is pure; `suggest`
proposes follow-ups from verdicts so far; `next_actions` names the new
evidence that would resolve an INCONCLUSIVE result. Built-in:

| Rule | Kind | CONFIRMED requires |
|---|---|---|
| `net.tcp_port_open` | observation | a trusted nmap result `open` for host:port, none `closed` |
| `http.service_observed` | observation | a trusted probe with a valid HTTP status line, none refused/non-HTTP |
| `http.missing_x_content_type_options` | vulnerability, low, CWE-693 | a trusted, complete, untruncated 2xx response with body, fully parsed headers (none dropped/malformed, ≤ 1 XCTO header) and no effective `nosniff`; and no eligible response with it |

A generic HTTP 200, open port, banner or title satisfies no vulnerability
criterion. A CONFIRMED header finding is about the examined `GET /`
response only.

### 5. Offline research cycle

`ResearchCycle` runs proposals → admission (host must appear in the
evidence; dedup by id) → engine → feedback, within `Budget`
(iterations ≤ 50, hypotheses ≤ 500). CONFIRMED is kept with its proof,
REJECTED is discarded with the reason (never re-verified), INCONCLUSIVE
yields `ProposedAction`s (never executed: a live request still needs scope
and owner approval, M8.3). A round with nothing new ends the cycle
(`evidence_exhausted`). No human confirmation is needed for this offline
analysis.

Proposers: `RuleBasedProposer` (deterministic chaining TCP open → HTTP →
headers), `StaticProposer` (owner/AI-supplied file), `ModelProposer` (the
existing LLM provider; sees structured facts and prior verdicts only —
header names, no header values, body, banner or title; no verdict field
in its tool schema; token count + worst-case cost check before each call;
every call audited; prompt `m8.4-proposer-v1`, separate from the research
prompt `m7-v2`, whose eval baseline is unchanged).

**Amendment (2026-11-09, owner-approved): prompt `m8.4-proposer-v2`.** The
owner reported `cyber`-category refusals. The proposer lacked the
environment context that the research loop already sends, and it did not
record why a refusal happened. Two changes:
- `ModelProposer` now receives the owner's environment description
  (`Scope.description`) with the same label the research loop uses, placed
  before and outside the untrusted wrapper. It is taken only from the
  latest research run's scope snapshot, and only if that snapshot verifies
  against its recorded hash; otherwise the model gets none (fail closed).
  The engine and the rules never read it.
- A refusal records `stop_details` category and explanation as a
  `verification_llm_call` record with phase `refusal`, and the stop detail
  names the category. It is still never retried or rerouted (no fallbacks).

Tested with a fake provider only. Whether the added context reduces
real-model refusals has not been measured.

### 6. Reports and integration

A separate, versioned **verification report** (`avra-verification-report/1`)
is written once to `data/verification/<session>/report-<sha16>.json` with
its own audit chain (`verification_started`, `verification_llm_call`,
`verification_result`, `verification_report_written`). It separates
observations, unverified model notes, hypotheses, results, confirmed
findings (with proof, criteria, severity, limitations), verified
observations, rejected and inconclusive items and proposed next actions.
`check_verification` re-derives every result and compares hashes.
Research reports (schemas 1–4), `replay.py` and `avra report verify` are
unchanged; `avra research` additionally runs the rule-only offline cycle
after publishing its report (no API, exit code unchanged).

CLI: `avra verify session|show|check|rules` (see
`docs/operator-guide-verification.md`).

## Alternatives considered

- **Schema-5 research report with a verification block** — rejected for
  now: published M7.9 reports are attested and immutable; a separate
  linked artifact keeps every old report and `avra report verify` intact.
  Merging is ADR 0008's milestone.
- **Rules operating on banners/titles** — rejected: server-controlled.
- **Letting the model's free-text hypotheses become structured
  automatically** — rejected: they stay unverified notes; only structured
  proposals naming a registered rule are verified.
- **Treating an observation as a finding** — rejected by construction
  (`RuleKind`).

## Consequences and limits

- With today's tools only exposure/protocol facts and one header weakness
  can be confirmed; no injection or access-control class can be verified
  yet (no tool collects that evidence).
- The real M8.3 Juice Shop response sends `nosniff`: the header finding is
  REJECTED; HTTP is a verified observation; zero findings.
- Contradictions across time (open then closed) are INCONCLUSIVE; there is
  no freshness model yet.
- `ModelProposer` was tested only with a scripted fake provider; no live
  API call has been made (cost unmeasured).
- Kali (Python 3.14) is unaffected: nothing in the Runner changed.

## Acceptance

- [x] Engine, models, registry, three rules; 43 Stage-1 tests (positive,
      negative, insufficient, corrupted, contradictory, unsupported,
      wrong target/ids, determinism, serialization).
- [x] Cycle + proposers on fixture sessions built by the real pipelines
      and on byte-exact copies of real lab evidence (M7.8 `4460bea8`,
      M8.3 `7e868faf`; in this public repository: synthetic equivalents in
      `tests/fixtures/synthetic-sessions/`).
- [x] End-to-end CLI tests: CONFIRMED, REJECTED, INCONCLUSIVE; real M8.3
      evidence produces no finding; tamper detection; audited model calls.
- [x] Full offline regression and lint (see `docs/dev-log.md`).
- [ ] Live validation (Stage 4) — not started; needs owner approval.
