# ADR 0006 — Report integrity, trusted metadata and offline verification (M7.9.1–M7.9.4)

_Status: accepted and implemented 2026-11-08 (owner approved each stage).
M7.9.1 committed in `09d042e`, M7.9.2 in `d96b811`, M7.9.2R (controlled
recovery, decision 7) in `9c6d6a4`, M7.9.3 (confidence split, decision 8)
in `a0793c1`, M7.9.4 (model claim checks, decision 9) in `5dde874`. M7.9
closed (documentation only) in M7.9.5. Operator guide:
`docs/operator-guide-reports.md`._

## Summary (M7.9 complete)

| Milestone | Commit | What it delivers | Fixes |
|---|---|---|---|
| M7.9.1 | `09d042e` | attested, immutable report files (exact LF bytes, audited hash, no overwrite) | D2, D6 |
| M7.9.2 | `d96b811` | scope snapshot + schema-2 metadata from the audit; deterministic replay; read-only `avra report verify` | D4, D5 |
| M7.9.2R | `9c6d6a4` | interactive, per-report owner-approved `avra report recover` | — |
| M7.9.3 | `a0793c1` | `port_exposure` / `service_identity`; `partially_supported` headline (schema 3) | D1 |
| M7.9.4 | `5dde874` | deterministic `claim_checks` on model text, validator rule 11 (schema 4) | D3 (partly) |

| Report schema | Introduced | Adds | Rebuilt with |
|---|---|---|---|
| 1 | M7.8 | evidence-grounded report, passive validator | legacy only (no snapshot: never reproducible) |
| 2 | M7.9.2 | audit-derived `metadata` | its own rules (old headline) |
| 3 | M7.9.3 | `port_exposure`, `service_identity`, stricter headline | its own rules |
| 4 | M7.9.4 | `claim_checks` | its own rules (current) |

Each run records `report_schema_version` in `research_started`; replay uses
it (record_format-2 runs without it are schema 2; other values fail
closed). Each older schema serializes without later keys, so it rebuilds
byte-for-byte — checked against the committed previous build at every step.

**Implemented and tested (offline, Windows host):** decisions 1–9; 950
tests passed, 26 skipped; eval 28 scenarios × 13 metrics all passing.
**Untested, platform-specific:** recovery's Linux handle-based link
(`/proc/self/fd`) — never run on Linux, designed to fail safely; symlink
cases on Windows (need a privilege; junctions and hard links are tested).
**Accepted limitations:** audit chain not keyed or signed (consistency, not
authorship); small filesystem check-then-act windows (detected, fail
closed); claim-check false positives (conversational out-of-scope IP;
generic "id" + hex) and false negatives (ideographic punctuation;
sentence-wide negation; paraphrase); historical sessions stay legacy; the
fixed `-sT` scan never establishes service identity. Not semantic
verification of model prose; not cryptographic provenance.
**Deferred:** see "Deferred" below.

## Context

The M7.8 live audit (ADR 0005, "Live results") found that research reports
were written with a plain overwrite, were not bound to the audit chain (D2),
were hashed differently from their on-disk bytes on Windows (D6), lacked
metadata (D4) and depended on the *current* scope file (D5), so a report
could not be independently re-checked later.

## Decisions (implemented)

### 1. Attested, immutable report files (M7.9.1, `avra.reporting.store`)

- Deterministic bytes: JSON, sorted keys, UTF-8, LF only, written in binary
  mode; SHA-256 over exactly those bytes.
- Order: exclusive private temp file → fsync → read-back check → audit
  `report_generated` (sha256, size, verdict, reasons, anchor to
  `research_stopped`) → publish with `os.link`, which never replaces an
  existing name → verify published bytes → drop the temp name.
- Run-scoped names `<session>.run<research_started seq>.report.json`; a
  resumed session gets one report per run. Legacy `<session>.report.json`
  files are never touched.
- Failure before the audit event: not attested, nothing published, temp
  kept (never deleted silently). Failure after it: attested, recoverable from
  the fsynced temp file. The CLI shows a verdict as a result only for a
  published report; otherwise "in-memory only", exit 3.
- Every `report_generated` field is untrusted (the chain is not keyed):
  names are rebuilt from the session UUID and a validated run seq, types,
  hashes and sequence references are validated, files are inspected with
  `lstat` (no symlinks, junctions/reparse points or extra hard links).
  States: PUBLISHED, RECOVERABLE, CONFLICT, MISSING, INVALID_EVENT,
  UNSAFE_PATH. This closed a path traversal found in review.

### 2. Trusted scope snapshot (M7.9.2, `avra.core.snapshot`)

`research_started` (`record_format: 2`) records the enforced scope as a
canonical snapshot (`Scope.model_dump(mode="json")`, sorted-key compact
UTF-8), its SHA-256, the scope file's SHA-256, the AVRA version and the price
table. Rebuilding requires hash match, schema validity and canonical form.
`research_stopped` records `final_summary`; the scan pipeline records the
exact `errors` of a failed request and the Runner's `reason`.

### 3. Schema-2 report metadata (`avra.reporting.ReportMetadata`)

Taken only from audit records: run anchor (seqs + `research_stopped` hash),
timestamps, configured vs API-reported models, prompt version, effort,
limits, stop data, tokens, and cost three ways (logged total, sum of
per-call costs, tokens × recorded prices) with `model_consistent`,
`tokens_consistent`, `cost_consistent`. Validator rule 9: schema 2 without
metadata or for another session → INVALID; an inconsistency → INCOMPLETE.
Model prose is never used for metadata.

### 4. Deterministic replay (`avra.reporting.replay`)

The CLI builds the report from the **live** result; replay rebuilds it from
the audit + evidence only (scope from the snapshot, outcomes from tool events
and the stored nmap XML, recorded errors cross-checked against the evidence).
Identical bytes therefore prove the audit fully captures the report. Evidence
paths come only from validated UUIDs; the recorded `evidence_path` is ignored.

### 5. Strict verification semantics (`avra report verify <session>`)

Read-only (writes, deletes and creates nothing; no network, API or tools).
Dimensions shown separately: audit integrity, evidence integrity, and per run
attestation, publication, reproduction, **integrity**, **metadata
consistency**, **report validation**.

**VERIFIED** (exit 0) only if: audit chain valid; all evidence hashes valid;
every run attested, published with matching bytes and reproduced
byte-for-byte; metadata consistency PASS; rerun validator verdict **PASS**
and equal to the attested verdict; no other problem. A faithfully reproduced
INCOMPLETE or INVALID report is **never** VERIFIED (a review finding fixed
before commit); it is shown as "NOT VERIFIED - integrity holds, but ...".
Anything else exits 1; a malformed session id exits 2.

### 6. Legacy sessions

Runs without a snapshot are "NOT POSSIBLE: legacy run"; the current scope
file is never substituted, and such sessions are never VERIFIED. For the
last legacy run the validator is re-run on the legacy report file and shown
as "unattested, not reproducible". All four sessions in `data/` (M6.6,
M7.6, M7.7, M7.8) are legacy.

### 7. Controlled recovery (M7.9.2R, `avra report recover <session>`)

- `complete_publication(audit, dir, authorized=frozenset({(event_seq,
  sha256), ...}), confirmation=...)`: authorization is mandatory and exact.
  Malformed, conflicting, unknown or mismatched pairs abort before anything
  happens; only the authorized entries are processed; reports that become
  recoverable later are ignored. Only entries RECOVERABLE at the moment of
  acting are published (INVALID_EVENT, UNSAFE_PATH, CONFLICT, MISSING and
  PUBLISHED_RECOVERY_UNAUDITED are refused).
- CLI: interactive terminal required, no `--yes`; shows seq, file name and
  full SHA-256 per report; y/N per report, default No; never retries;
  exit 0 all published and audited, 1 partial/failed, 2 refused/nothing.
- Per report, immediately before acting: re-verify the chain and the event;
  open the temp file and prove through the handle that it is the same plain,
  single-link file with exactly the attested bytes; final name absent; audit
  `report_recovery_authorized` (owner_confirmed) BEFORE acting; link without
  overwrite; prove the published name is the same file with the attested
  bytes; audit `report_publication_completed`. Failures are audited as
  `report_recovery_failed`; nothing is ever deleted except the temp name of
  a verified, audited publication. The first refusal/failure stops the run.
- Publication vs audit: an authorization is closed only by a LATER record
  naming that authorization seq, the same report and (completion) the same
  SHA-256. A published file with an open authorization is
  `PUBLISHED_RECOVERY_UNAUDITED` — never "published", so `verify` reports
  NOT VERIFIED (a review finding fixed before commit).
- Remaining threat model: Linux links from the open handle
  (`/proc/self/fd/N`, AT_SYMLINK_FOLLOW) — **UNVERIFIED by execution** (no
  Linux run yet; a Linux-only integration test exists). Windows links by
  path, but the held handle blocks renaming/deleting the source (tested). On
  every platform an in-place rewrite between hashing and linking is detected
  afterwards and fails closed (may leave a CONFLICT name; nothing deleted).
  Any platform where the handle link fails can only FAIL, never mis-publish.

### 8. Port exposure separated from service identity (M7.9.3, D1) — report schema 3

Before: the headline `evidence_confidence` was `supported` whenever any
verified scan showed an open port, so a "which services?" report looked
answered although nmap's service name was only a port-number guess.

- Two dimensions, derived only from verified scans (machine evidence):
  - `port_exposure`: `confirmed` (≥1 verified open port) | `none_open`
    (verified scans, a host up, nothing open) | `host_down` |
    `not_evaluated` (no verified scan).
  - `service_identity`: `identified` (every verified open port's service was
    probed) | `partially_identified` | `unidentified` (only nmap
    port-number table labels) | `not_applicable` (no verified open port).
    A table label (`method="table"`) is never an identification.
- Headline, never stronger than the weaker dimension: `supported` only for
  confirmed + identified; new value `partially_supported` for confirmed but
  not fully identified; `inconclusive` / `inferred` as before. Under AVRA's
  fixed `-sT` flags nothing is probed, so live reports are at most
  `partially_supported` (the M7.8 Juice Shop case: confirmed, unidentified).
- Validator rule 10 (schema 3): each dimension and the headline must equal
  what the verified evidence gives; `identified` needs every open fact
  probed; `confirmed` needs a verified open fact; `supported` needs
  `identified`; schema-3 fields on an older schema → INVALID. Model prose
  (notes, hypotheses, summary) is never an input.
- Versioning: `research_started.report_schema_version` (3) records what the
  run's build produces; record_format-2 runs without it are schema 2; any
  other value fails closed. Replay builds each run with its recorded
  version. Schemas 1–2 keep the old headline rule and serialize without the
  schema-3 keys (`ResearchReport.canonical_dict`), so older attested reports
  rebuild byte-for-byte — verified against the committed M7.9.2R build
  (identical 4817-byte schema-2 report, SHA-256 `9918a34a…`).
- Evaluation: the harness now builds reports exactly like the CLI (scope,
  objective, metadata, schema from the run's audit). 24 scenarios (22 + 2
  new: `probed_and_table_partially_identified` on a clearly labelled
  synthetic fixture, `model_claimed_identity_stays_hypothesis`), 11 metrics
  (+ `headline_not_overstated`, `confidence_correct`). Approved baseline
  change (reviewed leaf by leaf: 134 added, 0 removed, 17 changed): exactly
  six scenarios `supported` → `partially_supported` (`normal_tool_use_open`,
  `service_table_guess_not_identified`, `mixed_port_states`,
  `duplicate_proposal`, `unsupported_vuln_claim_stays_hypothesis`,
  `invalid_evidence_reference`); `probed_service_identified` stays
  `supported`; no stop reason, execution, verdict, diagnostic, result state
  or cost changed. Baseline SHA-256 `e0b92b0e…26da` (working-tree bytes).

### 9. Deterministic checks on the model's free text (M7.9.4, D3) — report schema 4

Before: the model's summary, observations and hypotheses were stored as
non-authoritative prose and never examined, so a summary citing a request
that never ran, a wrong hash or an unauthorized IP:port passed validation.

- `ClaimChecks` block (`avra.reporting.claims`, pure functions, no network,
  no model, no LLM judge), derived only from the run's verified outcomes,
  the session ID and the scope targets:
  - **References** (all model text, hypotheses included): canonical request
    UUIDs (must be a request of this run or the session ID); full SHA-256
    (a recorded evidence/output hash); abbreviated `prefix...suffix` (also
    `…`; must match one recorded hash at both ends); bare hex 8–63 chars only
    right after a reference word (sha256, hash, digest, request, request ID,
    evidence, id); IPv4 (octets ≤255, not CIDR, not part of a longer dotted
    number; must be a scope or verified-evidence host); IP:port incl. URLs
    (pair must be in scope). IPs in quotes, inline code or example sentences
    are not counted. Overlaps count once; the same reference twice in one
    field counts once. A prefix that fits several known values is recorded
    as ambiguous — never resolved, never a mismatch.
  - **Assertions** (observations and summary only; hypotheses never):
    explicit port-state claims compared with the verified facts, "service
    confirmed/identified" claims while no probe identified it, and
    vulnerability/exploitation claims (AVRA runs no vulnerability tests).
    Sentences with negation, hedging, conditionals or example markers are
    skipped; quotes and inline code are masked. **Informational only.**
  - Fixed note: passing the checks does NOT mean the model's text is true.
- **Rule 11** (schema ≥4): the block must equal an independent
  recomputation (forged/edited/missing block or altered note → INVALID;
  the block on an older schema → INVALID); each unresolved reference →
  INCOMPLETE; ambiguous references and suspicious assertions never change
  the verdict. Prose alone is never INVALID and never changes exposure,
  identity or the headline (eval metric `prose_cannot_strengthen`: the same
  run with every model text blanked gives identical results in all 28
  scenarios). This is not semantic verification.
- Versioning: `report_schema_version` 4 for new runs; replay accepts 2–4
  from the audit; older schemas serialize without `claim_checks` and keep
  their rules. Verified against the committed M7.9.3 build `a0793c1` with
  model text that schema 4 would flag: schema 2 (`8f79ffed…`, 5147 bytes)
  and schema 3 (`24fdce89…`, 5235 bytes) identical in bytes and validation.
- Evaluation: 28 scenarios (+4: `fabricated_request_id_in_summary` and
  `out_of_scope_ip_port_in_observation` → INCOMPLETE;
  `negated_and_hedged_claims_no_flags` → PASS, no flags;
  `asserted_exploitation_flagged` → PASS with an informational flag),
  13 metrics (+ `claims_correct`, `prose_cannot_strengthen`). Approved
  baseline change (reviewed leaf by leaf: 230 added, 0 removed, 13
  changed — summary counts only): no existing verdict, confidence,
  execution, diagnostic, result state or cost changed; all existing
  scenarios have 0 mismatches; `model_claimed_identity_stays_hypothesis`
  gains one informational `service_identity` flag (verdict still PASS).
  Baseline SHA-256 `2c5cc90c…abba` (working-tree bytes).
- **Known limitations** (pinned as tests, not hidden):
  1. A conversational out-of-scope IP (e.g. "my router is 192.168.1.1")
     is a mismatch → INCOMPLETE (strict by design).
  2. The generic word "id" followed by hex ("user id 1a2b3c4d") is checked
     as a reference → INCOMPLETE.
  3. Ideographic punctuation (U+3002) is not a sentence boundary, so a
     negation in the next sentence can hide an assertion.
  4. Sentence-wide negation: one negated clause hides a later affirmative
     assertion in the same sentence.
  Also not detected: paraphrases, numbers in words, Unicode lookalike
  digits, hostnames, claims split across sentences, single-quoted text.

## Deferred (not implemented, needs its own approval)

- Keyed/signed audit chain (authorship, not just consistency).
- Running the Linux recovery integration test on a Linux host.
- Any change to the claim-check rules (e.g. the generic "id" false
  positive, U+3002 sentence boundaries) — needs a reviewed rule change and
  baseline diff.
- Service identification (a probing tool), the Verification Engine and
  vulnerability validation — future tracks, each with its own ADR.

## Consequences and limitations

- Verification proves internal consistency of audit + evidence + report, not
  who wrote them: whoever can rewrite all three consistently can forge a
  session.
- Small check-then-act windows: scope file hashed right after loading;
  evidence `lstat` before read (the bytes must still match the recorded
  hash). Windows has no directory fsync.
- Metadata parsing is lenient (Pydantic non-strict); live and replay read the
  same audit values, so reproduction cannot diverge.
- A dated API model id would be flagged as a model mismatch (not yet seen).
- D1 fixed in M7.9.3 (decision 8). D3 addressed in M7.9.4 (decision 9) by
  deterministic reference checks and informational assertion flags — not
  semantic verification of the model's prose; the four known limitations
  of decision 9 apply.
