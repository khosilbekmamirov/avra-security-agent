# Operator guide — checking and recovering research reports

For the owner. Plain steps for the two report commands added in M7.9
(design: `docs/decisions/0006-report-integrity-and-verification.md`).
Neither command talks to the model, the Runner, the lab or the network.

Run them from the project folder, `E:\Projects\avra`. They read
`data\sessions\` and `data\evidence\` (or the folder named by the
`AVRA_DATA_DIR` environment variable).

---

## 1. `avra report verify` — is this session's report trustworthy?

```
.venv\Scripts\avra.exe report verify <session-uuid>
```

**Read-only.** It never writes, deletes, creates, recovers or "fixes"
anything. Safe to run as often as you like.

It re-checks everything from the recorded facts and prints one line per
check:

| Line | What it checks |
|---|---|
| Audit integrity | the session's hash chain is unbroken |
| Evidence integrity | every stored nmap output still has its recorded SHA-256 |
| Attestation | a valid `report_generated` record exists for the run |
| Publication | the report file is there, is a plain file, and has exactly the attested bytes |
| Reproduction | the report rebuilt from audit + evidence alone is byte-for-byte the attested one |
| Integrity | attestation + publication + reproduction + verdict-as-attested all hold |
| Metadata consistency | configured vs API-reported model, token totals and cost all agree |
| Report validation | the validator's verdict on the report itself (PASS / INCOMPLETE / INVALID) |

### Reading the result

| Result line | Meaning | Exit code |
|---|---|---|
| `Result: VERIFIED (integrity, metadata and report validation all PASS)` | Every check passed for every run. The only "clean" result. | 0 |
| `Result: NOT VERIFIED - integrity holds, but metadata consistency and/or report validation is not PASS` | The report is faithfully recorded and reproducible, **but it is not clean**: read the Metadata consistency and Report validation lines and the `Problem:` lines. | 1 |
| `Result: NOT VERIFIED` | Something structural failed (chain, evidence, publication, reproduction), or the session is legacy, or it has no research runs. | 1 |
| `session must be a session UUID` | You mistyped the ID. | 2 |

### "Integrity PASS" but report validation INCOMPLETE or INVALID

This means: *AVRA recorded exactly what happened, and the report honestly
says the result is incomplete or wrong.* It is **not** a clean result.

- **INCOMPLETE** — something is missing or unresolved, for example the
  model's text cites a request ID, hash, IP or IP:port that does not exist
  in this run or scope, or the metadata does not reconcile.
  Since report **schema 5** (M8.5), a reference also resolves if it points
  at evidence recorded **earlier in the same session** that AVRA verifies
  (audit chain, request/result pairing, file hash, parse, target inside this
  run's scope) — e.g. your `avra probe http` before `avra research`. Such
  evidence is listed in the report's `prior_session_evidence`. IDs from
  other sessions, invented IDs and tampered or out-of-scope evidence still
  make the report INCOMPLETE. Runs recorded with schema 4 or older keep
  their original rules: their attested verdict never changes.
- **INVALID** — a structured claim contradicts the evidence (for example a
  model observation pointing at evidence that was never collected).

A VERIFIED result is never possible while the report's own verdict is not
PASS.

### What VERIFIED does *not* mean

- It does **not** mean a vulnerability exists or was proven. AVRA only runs
  a TCP connect scan; it tests no vulnerabilities.
- It does **not** mean the model's free text is true. The `claim_checks`
  block only checks explicit references (IDs, hashes, IPs) and flags a few
  explicit assertions; see its limitation note.
- It does **not** prove who wrote the files. The audit chain is not keyed
  or signed: someone who can rewrite the audit, evidence and report
  consistently could forge a session.

### Legacy sessions

All four sessions recorded before M7.9.2 (`af1cbe72`, `5ca44629`,
`f2ebab88`, `4460bea8`) show `Reproduction: NOT POSSIBLE: legacy run`.
They were recorded without a scope snapshot, so their report cannot be
rebuilt from the audit alone, and AVRA will never substitute today's scope
file. They will always be NOT VERIFIED. Their audit chains and evidence
are still checked. Never edit them.

---

## 2. `avra report recover` — publishing a stuck report

When a research run finishes but its report could not be published (the
research command ends with `Report NOT published: ... attested ... but NOT
published ...` and exit code 3), the report's exact bytes are kept in a
private temp file and recorded in the audit. `recover` finishes the job —
only with your explicit approval.

```
.venv\Scripts\avra.exe report recover <session-uuid>
```

- **Interactive only.** It needs a real terminal; there is no `--yes`
  option. Without a terminal it refuses: `Refused: recovery needs an
  interactive terminal; nothing done.`
- It first lists anything it will **not** touch:
  `Not recoverable (left untouched): seq N <file>: <state> - <reason>`.
- For each recoverable report it shows the audit `seq`, the file name and
  the **full SHA-256**, then asks `Publish this exact report? [y/N]`.
  Enter (or `n`) means **No**.
- It never retries, never overwrites an existing file and never deletes
  anything except the temporary name of a report it has just published and
  verified.

### Why exact per-report approval?

Your "yes" is bound to that exact `(audit seq, SHA-256)` pair. If anything
about that report changes between your answer and the publication — its
bytes, the temp file, the final name, the audit — the entry is **REFUSED**
and nothing is published. Reports you were not asked about are never
published, even if they become recoverable meanwhile.

### Outcomes and exit codes

| Line | Meaning |
|---|---|
| `PUBLISHED` | Published, re-verified, and the completion is in the audit. |
| `PUBLISHED_UNAUDITED` | The file is correct, but the completion record could not be written. |
| `REFUSED - ...` | It changed since you approved (or is no longer recoverable). Nothing done. |
| `FAILED - ...` | Publication was attempted and did not complete; nothing overwritten, nothing deleted. |
| `NOT_ATTEMPTED` | An earlier report in this run stopped the run; this one was left alone. |

| Exit | Meaning |
|---|---|
| 0 | Every report you approved was published and audited. |
| 1 | Partial: something was refused or failed (read each line). |
| 2 | Refused before starting, nothing to recover, or nothing approved. |

`Nothing to recover.` and `Nothing approved; nothing done.` both exit 2 and
change nothing.

### `PUBLISHED_RECOVERY_UNAUDITED`

`verify` shows this publication state when a recovery you approved put the
correct bytes in place but **no matching completion (or failure) record**
exists — for example the process was interrupted, or writing the audit
record failed. The report itself is correct, but its publication is not
fully audited, so the session is **NOT VERIFIED**. `recover` lists it as
not recoverable and shows: `Note: recovery authorized at audit seq N has
no completion or failure record`. Do not try to "fix" it by hand; note the
seq and keep the files as they are.

### Handling failures and conflicts safely

- **CONFLICT** (a different file already has the report's name) and
  **UNSAFE_PATH** (a link, junction or special file where the report or
  temp file should be): nothing is touched. Inspect the folder; do not
  delete or rename files without deciding what happened first.
- **MISSING** (neither the published file nor the temp file has the
  attested bytes): the report cannot be recovered. The audit still records
  what was attested.
- **INVALID_EVENT**: an audit record is malformed or does not fit this
  session (for example a forged file name). It is never acted on.
- **FAILED during publication** (for example "published name does not hold
  the attested file … left in place, not deleted"): the folder was changed
  while recovery ran. Treat it as a CONFLICT and inspect before anything
  else.
- After any problem, run `avra report verify <session-uuid>` again — it is
  read-only and shows the current state of every report.

---

## 3. Other exit codes you may see

| Command | Exit | Meaning |
|---|---|---|
| `avra research ...` | 0 | Session finished normally (`finished` / `end_turn`) and the report was published. |
| | 1 | Session stopped for another reason (budget, steps, refusal, error, Ctrl+C). |
| | 3 | Session ended but the report was **not built or not published** (`Report NOT built` / `Report NOT published`). The verdict is then shown as "in-memory only, NOT a verified result". |

## 4. Known limitations (do not rely on these)

- The audit chain proves consistency, not authorship (not keyed/signed).
- The Linux recovery path (link from an open file handle) has not been run
  on Linux; it is built to fail safely if it does not work.
- On Windows, symlink-related tests need a privilege and are skipped.
- Tiny check-then-act windows remain between checking a file and using it;
  changes there are detected and fail closed.
- `claim_checks` false positives: a conversational out-of-scope IP, or the
  word "id" followed by hex, can make a report INCOMPLETE. False negatives:
  ideographic punctuation (`。`) and a negation elsewhere in the same
  sentence can hide an assertion. Paraphrases are not detected.
- AVRA's fixed `-sT` scan never identifies a service; reports say
  `service_identity: unidentified` and at most `partially_supported`.
