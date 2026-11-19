# ADR 0012 — Audit integrity, remote cancellation and emergency stop (M8.7)

_Status (current, 2026-11-12): **Stages 1–8 Accepted.**
- Stages 1–6 and 8 are done.
- Stage 7 is **COMPLETE WITH LIMITATIONS** after the owner-gated recovery
  ("Stage 7 recovery" section). The Stage 4–7 Runner (wheel `e5b39513…`) is
  deployed and active on Kali, and the cancel API is live-verified.
- **NOT OBSERVED** on the operational Runner: cancelling an actually running
  job.
- **NOT VERIFIED:** the operational emergency stop (latch READY, never
  engaged), and live enforcement of the restored Kali scope.
- **Open:** S7-2 (Low). No operational HMAC key has been created, and the
  local kill switch was never engaged.

Earlier status (2026-11-11/12, superseded): Stages 1–5 implemented OFFLINE,
nothing deployed, Stages 6–8 proposed only._

## Context

The M8.7 read-only preflight (2026-11-11) found:

- **K1 (High)** `avra kill` is a placeholder; nothing blocks new executions.
- **C1 (High)** an in-flight Runner job cannot be cancelled; Ctrl+C on
  Windows only closes the tunnel and the Kali job runs to its timeout.
- **A1 (High, known)** Windows audit logs have no external anchor: tail
  truncation and full rewrites are undetectable without an attested report.
- **A2 (Medium)** `AuditLog.record()` did not fsync; a torn last line made
  every later write fail with a raw `JSONDecodeError`, and readers crashed
  with tracebacks (`session show`, `--session`).
- **A3 (Medium)** no cross-process writer lock on Windows: two `avra`
  processes on one session could fork the chain.
- **A4 (Low)** appends did not re-check the chain.

Proposed stages: 1 AuditLog reliability; 2 anchors + HMAC key; 3 Windows
kill switch; 4 Runner cancellation + emergency latch; 5 Windows client
integration; 6 Kali offline tests; 7 deploy + live check; 8 docs.

## Stage 1 decisions (implemented — `src/avra/storage/audit.py`)

1. **Durable appends.** Each record is written, flushed and `fsync`-ed
   before `record()` returns; a new log's directory entry is fsynced on
   POSIX (best effort, as `reporting.store`). Failure raises
   `AuditWriteError` (subclass of `OSError`, so existing fail-closed
   `except OSError` / `except Exception` paths are unchanged). If the bytes
   reached the file before the failure, the log may show a record the
   caller treated as failed: it can over-report, never under-report.
2. **Cross-process writer lock, no new files.** `record()` takes the
   in-process thread lock and an OS lock on the audit file itself, each
   with a bounded wait (`lock_timeout`, default 10 s, max 300 s) →
   `AuditLockTimeout`, nothing written. Windows: a one-byte
   `msvcrt.locking` range lock at offset `0x7FFFFFF0` (beyond any real log;
   reads and appends unaffected — verified, including from a second
   process). POSIX: `flock` on a read-only descriptor (works with Kali's
   `chattr +a`; distinct from the Runner's `<audit>.lock` owner lock, so no
   self-deadlock). A sidecar lock file was rejected: it would appear in
   `data/sessions/` next to every log.
3. **Never extend a damaged log.** Under the lock, the whole file is
   checked (format + chain) before appending; any problem raises
   `AuditCorruptError` and nothing is written. Nothing ever truncates,
   repairs, rewrites or normalizes a log.
4. **Structured diagnostics.** `verify_detailed() -> AuditVerification`
   (status, exists, record_count, 1-based line, detail, valid-prefix
   last_seq/head_hash), deterministic, never raises. Statuses: `valid`,
   `torn_tail` (last line unterminated or unparseable), `malformed_record`
   (an earlier line: invalid UTF-8/JSON, duplicate keys, missing/extra
   fields, non-int `seq`, non-string `ts/event/prev_hash/hash`), `seq_gap`
   (seq not exactly 1..n: gap, repeat, reorder), `hash_mismatch` (broken
   `prev_hash` link or content ≠ hash), `unreadable` (I/O). The first
   problem in file order is reported. `verify() -> bool` keeps its meaning
   and now never raises. `data` may still be any JSON value (unchanged;
   event-level validators judge it).
5. **Controlled errors.** `read_all()` raises `AuditCorruptError`
   (`ValueError`) for unparseable lines and `AuditUnreadableError`
   (`OSError`) for I/O errors — never raw `JSONDecodeError`/`TypeError`;
   records with a broken chain are still returned for inspection. Messages
   never contain record content. `avra session show` and `--session`
   print the diagnosis and exit 1 instead of a traceback; the verification
   report and `verify check` include it; report store / replay also catch
   `OSError`.
6. **Compatibility.** Record bytes and hash semantics unchanged (text-mode
   append, CRLF on Windows, `sort_keys`). Blank lines still tolerated.

### Stage 1 evidence

- `tests/unit/test_audit_reliability.py` (43 tests): independent-process
  concurrent writers (4 × 25, contiguous, none lost), torn tails (partial
  line, missing newline, garbage last line), 8 malformed-record shapes,
  invalid UTF-8, edited record, wrong hash field, broken link, missing seq,
  reorder, first-problem ordering, determinism, no content in messages,
  unreadable path, fsync and write failures, in-process / other-handle /
  other-process lock timeouts, Runner returns `AUDIT_UNAVAILABLE` and never
  executes on a damaged or locked log, CLI exits 1 without a traceback,
  historical fixtures verify read-only, append to a copy keeps old bytes.
- Mutation check (scratch, not committed): with the file lock disabled the
  same 4-process workload forked the chain after 3 records (`seq_gap`) and
  every writer then refused to append; with the lock, 100 valid records.
- Full suite 1269 passed / 26 skipped (was 1226 / 26); Ruff 27 (unchanged).
- All 15 historical logs (13 in `data/`, 2 fixtures): bytes identical
  before/after, all `valid`; `report verify`, `verify check` and
  `session show` output identical to the pre-change code on all 5 sessions.

### Limits after Stage 1 (unchanged trust model)

- Still an unkeyed chain: tail truncation and a consistent full rewrite are
  not detected (Stage 2). A damaged log stays unwritable until the owner
  decides what to do; there is deliberately no repair command.
- Locks are advisory against non-AVRA programs (POSIX) / only cover AVRA
  writers; file permissions and `chattr +a` remain the defence there.
- Each append re-reads the whole log (O(n)); fine at current sizes.
- Runner-side code shares this module but is **not deployed**; Kali keeps
  the M8.2/F-08 build until an approved redeploy. *(Superseded: deployed on
  Kali 2026-11-12 in the Stage 7 recovery, wheel `e5b39513…`.)*

## Stage 2 decisions (implemented — `src/avra/storage/keys.py`, `anchors.py`, `avra audit`)

Owner-approved architecture: HMAC-SHA256 (stdlib), Windows DPAPI for the
key at rest, anchors under `%LOCALAPPDATA%\AVRA\anchors`, explicit keygen,
backward compatible, no new dependency, no Kali cross-anchor.

1. **State location.** `<state>` = `AVRA_STATE_DIR` if set, else
   `%LOCALAPPDATA%\AVRA` (non-Windows: `~/.local/state/avra`); never inside
   `data/`. `<state>\anchors\anchors.jsonl` holds anchors;
   `<state>\keys\` holds the key ring `keyring.json` and the head witness
   `anchor-head.json` — separate directories on purpose (decision 6).
2. **Keys.** 256-bit `secrets.token_bytes`, created ONLY by
   `avra audit keygen` (interactive terminal, explicit "y", default No;
   refused if a key exists without `--rotate`). Protected with DPAPI
   CurrentUser scope + app entropy (`ctypes`, no UI); the blob header is
   checked (version, DPAPI provider) and **machine-scoped blobs are
   rejected** (`KEY_INVALID`); round-trip checked before anything is
   committed. `key_id` = first 128 bits of HMAC-SHA256(key, label): stable,
   one-way, not secret. Raw keys never appear in output, audit, files or
   messages (reprs redacted; tested). Before any key material is written,
   keygen restricts `<state>\keys` to the current user's SID and SYSTEM
   (`icacls /inheritance:r`, fixed argv); failure → nothing written.
3. **Rotation.** `keygen --rotate` adds a new active key and keeps every
   older key as `retired`, so older anchors keep verifying. Refused unless
   the store verifies first.
4. **Anchors (v1).** One canonical JSON line each (sorted keys, no
   whitespace, ASCII; a stored line must equal its canonical form): `v`,
   `anchor_seq` (1..n, contiguous), `prev_anchor_hash` (SHA-256 of the
   previous line), `log_id`, `log_genesis_hash`, `audit_seq`,
   `audit_head_hash`, `sealed_at`, `key_id`, `mac`. `mac` =
   HMAC-SHA256(key, `"AVRA-audit-anchor-v1\0"` || canonical(fields without
   mac)). `log_id` = `normcase(realpath(path))` with `/` (resolves case,
   relative paths, links); `log_genesis_hash` (record 1) means a different
   log at the same path never matches. Per log, `audit_seq` must increase
   and the genesis must not change. Appends are fsynced under the Stage 1
   file lock; sealing takes the audit log's lock, then the store's (fixed
   order).
5. **Outcomes and severity.** VERIFIED (ok, exit 0); LEGACY_UNANCHORED
   and UNANCHORED_TAIL (warning, exit 2 — never presented as protected);
   TRUNCATED, HASH_MISMATCH, ANCHOR_CORRUPT, KEY_UNAVAILABLE, KEY_INVALID,
   UNREADABLE (failure, exit 1). Every anchor of a log is checked, not just
   the last, so truncation between two anchors is caught. A damaged
   unkeyed chain is never only a warning. A store problem fails closed for
   every log.
6. **Deletion / rollback — trust boundary.** The keyed head witness (in
   `keys\`, not `anchors\`) records the latest anchor. Detected: deleting
   or rolling back `anchors\` (witness ahead of the store); deleting the
   witness while a key exists; deleting both while the key survives; a
   forged witness. Tolerated: store AHEAD of the witness (crash between the
   anchor append and the witness update) — only because those anchors'
   MACs verify; the next seal updates the witness. **Not detectable
   locally:** a consistent rollback of BOTH `anchors\` and `keys\`, or
   deleting the whole state directory. Logs then show LEGACY_UNANCHORED —
   never VERIFIED. Any code running as this Windows user can do that and
   can also use DPAPI to read the key; Stage 2 does not claim protection
   against a compromised Windows account. Detecting it needs a copy of the
   head outside the account (the deferred Kali cross-anchor, or the owner
   recording `avra audit status` output elsewhere).
7. **Crash ordering.** First keygen writes the witness BEFORE the key ring
   ("ring exists ⇒ witness was written"); a crash in between leaves no
   ring and no anchors, so keygen can simply run again. Rotation commits
   the ring first, then re-signs the witness (the old key stays in the
   ring). A torn anchor line is ANCHOR_CORRUPT and blocks sealing (fail
   closed; no repair command).
8. **CLI.** `avra audit keygen [--rotate]`; `avra audit status`;
   `avra audit seal <session-uuid> | --log PATH` (explicit; anchors the
   current valid head; refuses damaged, truncated or tampered logs; no-op
   at the same head); `avra audit verify <session-uuid> | --log PATH |
   --all` (read-only; the unkeyed hash chain and the HMAC anchor result on
   separate lines; `--all` covers every session log plus every anchored
   log, so a deleted anchored log shows TRUNCATED).
9. **Not automatic (deliberate).** Nothing seals on its own; historical
   logs are never sealed implicitly. Automatic sealing after terminal
   events (`research_stopped`, `tool_result_received`, ...) needs the key
   during runs and a rule for what a key failure does then (it must neither
   block auditing nor be skipped silently) — left as an explicit later
   integration step.

### Operator procedures

- **First use:** `avra audit keygen`; after a run you want protected,
  `avra audit seal <session>`; any time, `avra audit verify <session>` or
  `avra audit verify --all`. Sealing a historical log anchors its state
  *as of the seal*; it proves nothing about earlier changes.
- **Backup:** copy the whole `%LOCALAPPDATA%\AVRA` folder (keys and anchors
  together). The DPAPI blob is decryptable only by the same Windows user
  profile (or after a DPAPI-aware profile migration).
- **Key loss** (profile reset, new machine, deleted `keys\`): existing
  anchors can no longer be verified (KEY_UNAVAILABLE) and cannot be
  re-keyed. AVRA refuses to create a new key over existing anchors; the
  owner must deliberately move the old `anchors\` folder aside (keeping it
  as a record), then run keygen. Logs are LEGACY_UNANCHORED until sealed
  again. Audit logs themselves are unaffected.
- **ANCHOR_CORRUPT:** stop and investigate; do not edit the files.
  `avra audit status` shows the reason.

### Stage 2 evidence

- `tests/unit/test_audit_anchors.py` (69 tests): HMAC value recomputed
  independently; edited record; self-consistent rewrites (new genesis, and
  same genesis with a recomputed chain); truncation below and between
  anchors; deleted log; unanchored tail; torn tail after an anchor; anchor
  field edit, foreign-key forgery, non-canonical line, broken link, gap,
  duplicate, inconsistent history; forged anchor appended past the
  witness; anchor-dir deletion, store rollback, witness deletion, both,
  old-witness replay, full-state deletion (documented limit, never
  VERIFIED); wrong / missing / undecryptable / id-mismatched / malformed /
  short keys; no silent regeneration; rotation with old-anchor
  verification; ACL-first keygen and crash ordering; real DPAPI round trip,
  corrupted payload and header, machine-scoped blob, other-context
  refusal and real `icacls` ACL (Windows); DPAPI-unavailable behaviour;
  interrupted anchor write; crash before the witness update
  (authenticated, then repaired); anchor fsync failure; 6 concurrent
  sealing processes; legacy, empty, missing, unreadable logs; historical
  fixtures untouched; `report verify` output identical before and after
  sealing; no key material in files, reprs or errors; CLI exit codes,
  read-only verify (byte snapshot), nothing created without a key,
  non-TTY keygen refused.
- Mutation checks (scratch copies, not committed): removing the witness
  rollback check, the per-anchor MAC check, or the anchored head-hash
  comparison each makes tests fail. The last two initially survived; the
  two attack tests above were added to close those gaps.
- Full suite 1338 passed / 26 skipped; Ruff 27 (unchanged); all 15
  historical logs byte-identical. No operational key was created
  (`%LOCALAPPDATA%\AVRA` does not exist).

### Limits after Stage 2

- Same-user compromise and a consistent rollback of the whole state
  (decision 6).
- Cross-user protection relies on DPAPI CurrentUser scope; no second
  Windows account was available offline (simulated with a different DPAPI
  entropy plus the blob-scope check).
- Python cannot reliably wipe key bytes from memory.
- Only logs the owner seals are anchored; no automatic sealing yet.
- The anchors directory keeps default per-user permissions: anchors are not
  secret and are integrity-protected by the MAC and the witness.

## Stage 3 decisions (implemented — `src/avra/control/killswitch.py`, `avra kill`)

**LOCAL ONLY.** Engaging the latch stops this Windows machine from starting
new work. It does **not** reach the Kali Runner: a job already running there
continues until the Runner's own timeout (nmap timeout + 10 s) or manual
intervention. Every engaged display says: *LOCAL STOP ENGAGED - REMOTE
CANCELLATION NOT YET VERIFIED*. Remote cancel and a Runner-side latch are
Stages 4–5.

1. **Files** (`<state>` as in Stage 2): `control\killswitch.json` (the
   latch, v1 schema, ≤ 4 KiB, never deleted), `control\control-audit.jsonl`
   (hash-chained Stage 1 `AuditLog`: `kill_switch_engaged`,
   `kill_switch_reset`, `kill_switch_execution_denied`,
   `kill_switch_transition_failed`), `control\killswitch.lock`
   (cross-process transition/gate lock), `control\active\*.active` (locked
   markers of running work). The latch is the state; the control audit is
   the history; both are read on every check.
2. **Semantics (fail closed).** DISENGAGED only for a fresh machine (no
   control folder / no transitions) or a "disengaged" latch backed by the
   matching `kill_switch_reset` record (same transition id). ENGAGED for a
   valid engaged latch. CORRUPT (blocks) for: malformed, oversized,
   duplicate-key or wrong-schema latch; a latch that is not a regular file;
   a symlink/junction/reparse point on the control path (or a foreign owner
   on POSIX); a damaged control audit; a missing latch while the audit says
   engaged; a disengaged latch without its reset record. UNREADABLE
   (blocks) for I/O errors (one 50 ms retry for transient sharing
   violations). A corrupt latch file is never overwritten, repaired or
   deleted — it stays as evidence.
3. **Transitions** (under the control lock, bounded wait). *Engage*: write
   the ENGAGED latch atomically (own temp file, fsync, `os.replace`, POSIX
   directory fsync) FIRST, read it back, THEN record `kill_switch_engaged`.
   Idempotent (already engaged → recorded as `already`, no rewrite). Write
   failure → `kill_switch_transition_failed` (best effort) and exit 1 "NOT
   engaged". Audit failure → still ENGAGED, exit 1. Best-effort owner-only
   ACL on `control\` (never blocks engaging). *Reset*: refused unless
   ENGAGED and valid, the control audit intact and no live active-work
   marker; record `kill_switch_reset` FIRST (failure → nothing changes),
   THEN write the disengaged latch (failure → still ENGAGED). Crash
   analysis: a crash during engage leaves ENGAGED without its record
   (reported as a note); a crash during reset leaves the engaged latch →
   still ENGAGED. No crash can make an engaged latch read as disengaged.
4. **Gate.** `KillSwitch.active(op)` checks the latch under the control lock
   and registers a locked active-work marker (fail closed if the gate itself
   fails: lock timeout, unsafe path, I/O). The ticket re-checks the latch
   AND its epoch (transition id at entry) at every later checkpoint, so an
   engage-then-reset during a run still stops it. A dead process's marker is
   unlocked and ignored (left on disk). Enforced in library code, not only
   in the CLI:
   - `run_nmap_connect_scan`, `run_http_probe`: gate before
     `tool_request_sent` (blocked → `tool_request_denied_locally`, reason
     "kill switch engaged", no tunnel); re-check right before the tunnel
     (engaged in between → `tool_request_failed` / `KillSwitchEngaged`).
   - `ResearchSession.run`: the whole run is registered (reset refused while
     it runs); refused before anything is recorded; checkpoints before every
     token count and model call, before an approval prompt, and again after
     approval before execution; stop reason `kill_switch` (report execution
     status INTERRUPTED); `llm_proposal_rejected` with `kill_switch` /
     `kill_switch_after_approval`. Nothing resumes after a reset.
   - `ModelProposer` (model-assisted verification): refused before building
     the request and before each call (`phase: kill_switch`).
   - `ClaudeProvider`: defence in depth — no `count_tokens` or `create`
     request while blocked, whoever the caller is.
   - CLI: `research`, `scan nmap-connect`, `probe http` and
     `verify session --model` refuse before any prompt (exit 3).
   Read-only commands (`session show`, `report verify`, `verify
   show/check/rules`, `audit verify/status`, `kill --status`) stay
   available.
5. **CLI.** `avra kill [--reason]` (engage; exit 0, or 1 if not durably
   engaged or not recorded); `avra kill --status` (read-only, creates
   nothing; exit 0 DISENGAGED, 3 ENGAGED, 1 CORRUPT/UNREADABLE; shows the
   control-audit chain and that it is anchored only if sealed with
   `avra audit seal --log <control-audit path>`); `avra kill --reset`
   (interactive terminal only, non-empty reason prompt, type `RESET`;
   refused for CORRUPT/UNREADABLE/DISENGAGED or while work is registered;
   says it cannot know whether a Kali job is still running; restarts
   nothing).
6. **Test isolation.** `tests/conftest.py` gives every test its own
   `AVRA_STATE_DIR`; no test touches `%LOCALAPPDATA%\AVRA`.

### Races and what Stage 3 cannot interrupt

- Work that passed its last checkpoint just before `avra kill` returned
  proceeds (the window between the pre-tunnel re-check and the tunnel
  opening). Closing it fully needs the Runner-side latch (Stage 4).
- A synchronous call already in flight — a model request, or the blocking
  HTTP request to the Runner while nmap runs — is not interrupted; the run
  stops at the next checkpoint after it returns. The remote job runs to its
  Runner timeout. No PID killing, process termination or Windows-wide
  action was added.
- Any code running as this Windows user can delete the `control` folder and
  thereby disengage (the same-user limit as in Stage 2).

### Stage 3 evidence

- `tests/unit/test_killswitch.py` (72 passed, 1 skipped — file-symlink
  creation needs a Windows privilege; the junction variant runs):
  fresh/engaged/persistent across a real process restart; 7 malformed
  latch variants, oversized, directory, unreadable; deleted latch; forged
  disengaged latch; damaged control audit (reset refused, evidence kept);
  corrupt latch never overwritten; stray temp file; replace/fsync failure
  not reported as engaged; crash after the engage write; crash after the
  reset record; reset audit failure; reason validation; junction control
  folder (nothing written through it); 5 concurrent engaging processes;
  concurrent engage/reset threads (no lost transition); gate denial
  recorded; reset refused while work runs; stale marker of a killed
  process; epoch change; gate lock timeout fails closed; scan and probe
  blocked with no tunnel and no request (default switch, no bypass);
  engage between gate and tunnel; research refused at start with session
  evidence untouched; a running loop stops at the next checkpoint with no
  approval prompt and no further paid call; engaged during approval never
  executes; reset refused mid-run and nothing resumes; `ClaudeProvider` and
  `ModelProposer` make no call; CLI engage/status/reset paths and exit
  codes, no remote-success claim, read-only status, refusal before prompts
  for research/scan/probe/`verify --model`; read-only commands still work
  with evidence unchanged.
- Mutation checks (scratch copies, with a passing unmutated control): a
  missing latch that ignores the audit, no checkpoint before approval, no
  re-check before the tunnel, and no provider gate are each caught by the
  intended test.
- Full suite 1410 passed / 27 skipped (was 1338 / 26); Ruff 27; all 15
  historical logs byte-identical; `%LOCALAPPDATA%\AVRA` still does not
  exist.

## Stage 4 decisions (implemented OFFLINE — Runner code; NOT deployed)

> Historical record as of Stage 4. **Superseded:** deployed to the
> operational Kali Runner on 2026-11-12 (see "Stage 7 recovery").

Code only: `src/avra/runner/{core,execution,emergency,http_app,schemas,server}.py`.
The Kali Runner still runs the earlier build; nothing was contacted or
deployed. Windows-side use of these endpoints is Stage 5.

1. **Endpoints** (same bearer auth, `application/json` only, 16 KiB body
   cap, 5 s body deadline, header cap; plus a stop-request rate limit of 30
   per 60 s → 429, recorded as `http_rejected stop_rate_limited`):
   - `POST /v1/tools/cancel` `{request_id, session_id, reason}` — both ids
     canonical lower-case UUID strings, `reason` ∈ {`operator_request`,
     `client_interrupt`, `local_kill_switch`}, no other field (no PID,
     process group, path, command, signal or tool argument). 200 with
     `{outcome, request_id, session_id, audit_recorded}`; 400 invalid
     (`cancel_rejected` audited); 503 if the state lock is unavailable.
   - `POST /v1/emergency-stop` `{reason}` (`operator_emergency_stop` |
     `local_kill_switch`). 200 only if the latch reads back STOPPED AND the
     audit records succeeded; otherwise 503 with the exact partial state
     `{outcome: engaged|already_engaged|not_durable, latch, durable,
     audit_recorded, active_job}`.
   - **No reset endpoint** (no route; tested for 404/405 on likely paths).
2. **Job ownership.** One job at a time (unchanged execution lock). A
   separate short state lock guards an `ActiveJob` record (request_id,
   session_id, state ACCEPTED → RUNNING → FINISHED, cancel event + reason,
   monotonic accept time, final outcome), a bounded table of the last 64
   finished jobs and the tombstones. Cancel/stop never wait for the
   execution lock.
3. **Cancel outcomes (deterministic).** Active job with both ids →
   `cancellation_applied` if it ends as cancelled within 6 s, else
   `cancellation_requested`, or `already_finished` if it ended on its own
   first (the real outcome — e.g. TIMED_OUT — is never relabelled);
   repeated → `already_cancelled`; request_id known but session differs →
   `identifier_mismatch` (job untouched); finished → `already_finished` /
   `already_cancelled`; unknown → `not_active` plus a **tombstone**. A
   cancel's audit-write failure does not stop the cancel (`audit_recorded:
   false`): stopping is the safe direction.
4. **Tombstones** (cancel arriving before its run): keyed by
   (request_id, session_id), TTL 15 min, at most 256 (oldest dropped),
   in memory only (lost on restart — documented). A run with a tombstoned
   pair, and every retried copy of it within the TTL, is refused with stage
   `cancelled` (409) and never executes; an unrelated job (different
   request_id) cannot be affected. This is cancellation idempotence, not
   run-replay protection: the Runner still re-authorizes and re-audits
   replayed run requests (ADR 0011).
5. **Subprocess.** `SubprocessRunner.run(..., cancel=event)`: set before
   start → never started; set while running → the existing termination
   path (SIGTERM to the job's own process group, SIGKILL after the grace
   period, reap, group sweep). Poll order per iteration: cancel, output
   limit, timeout. Outcome `CANCELLED` → `ToolRunStatus.CANCELLED`, reason
   stated, exit code kept, **no output returned** (hashes only, in
   `execution_finished`, which now also carries `cancel_requested` and
   `cancel_reason`). Only processes this call created are signalled.
   systemd `KillMode`, sandbox, `TasksMax`, `IPAddressAllow` unchanged.
6. **Disconnect → cancel.** While a run executes, its handler awaits the
   ASGI `receive()`; uvicorn 0.54 (h11) returns `http.disconnect` only on
   connection loss or after the response was sent. The watcher runs only
   while the job runs and is cancelled as soon as the result exists, so a
   completed response is never a disconnect. On disconnect the job named by
   that request's own ids is cancelled (`client_disconnected`, no
   tombstone). Limits: a half-open TCP connection (e.g. the VM network
   vanishes) is not seen until TCP gives up — the Runner timeout still
   bounds the job; detection depends on the server stack (re-verify if
   uvicorn/h11 changes). Tested with a fake ASGI transport and with real
   uvicorn on 127.0.0.1.
7. **Emergency latch** (`<audit dir>/emergency-stop.json`, i.e.
   `/var/lib/avra-runner/audit/` on Kali; no `runner.env` change needed).
   Same fail-closed design as the Windows switch, cross-checked against the
   Runner's append-only audit log: READY only for a fresh install (no file,
   no emergency transition in the audit) or a "ready" file backed by its
   `emergency_stop_reset` record; STOPPED for a valid stopped file; CORRUPT
   (malformed/oversized/wrong schema/link/foreign owner, damaged audit, a
   missing file while the audit says stopped or after a reset);
   UNREADABLE on I/O errors. Read on every run request and at start
   (`runner_started.emergency_latch`). Emergency stop: record
   `emergency_stop_requested`; set an in-memory stop under the state lock
   (refuses new registrations from that instant); write STOPPED atomically
   (fsync, replace, dir fsync) and read it back; record
   `emergency_stop_engaged`; THEN cancel the active job
   (`emergency_stop_cancelled_job`). A corrupt latch is kept as evidence
   (`emergency_stop_engage_failed`, `not_durable`). A Runner whose latch is
   not READY still starts but executes nothing; `/v1/health` returns 503
   with `emergency_stop_clear: false`. A restart never clears it.
8. **Local reset only.** `python -m avra.runner --reset-emergency-stop` on
   Kali: takes the audit owner lock (refused while a Runner runs — exit 3),
   verifies the chain, accepts only a valid STOPPED latch, needs a real
   terminal, a reason and the word `RESET`; records `emergency_stop_reset`
   FIRST, then writes READY (exit 0; refused → exit 5). Restarts nothing.
   `--check` now prints the latch state.
9. **Compatibility.** New enum values (`ToolRunStatus.CANCELLED`,
   `RejectionStage.EMERGENCY_STOP` / `CANCELLED`) are unknown to a
   pre-Stage-4 Windows client, whose strict models then reject the answer
   (`RunnerClientError`) — fail closed, never success (tested). Existing
   request schemas, scope checks, audit events and their meaning are
   unchanged; `execution_finished` gains two fields.

### Stage 5 integration requirements (not done at Stage 4; implemented in Stage 5 below)

Windows `RunnerClient.cancel()` / `emergency_stop()` with strict response
models; accept `CANCELLED` / `emergency_stop` / `cancelled` in the client
and the M6 pipelines (a cancelled run is never evidence); Ctrl+C →
best-effort cancel over a fresh tunnel and a terminal `tool_request_*`
record; `avra kill` → engage the local latch first, then call
`/v1/emergency-stop`, reporting an unreachable Runner precisely;
`avra kill --status` may show the Runner latch via `/v1/health`. Deploy
order: Runner first (old clients fail closed against it), then Windows.

### Stage 4 evidence

- `tests/security/test_runner_cancellation.py` (67 passed, 2 skipped on
  Windows — SIGTERM-ignoring child and grandchild cleanup need POSIX;
  **NOT VERIFIED on Linux** until an approved Kali offline test run):
  cancel active / wrong request_id / wrong session_id / same session other
  request / before registration incl. retried run / tombstone expiry and
  bound / after completion / duplicate / racing a timeout / 10 concurrent
  cancels (exactly one applies) / 8 invalid shapes incl. `pid` and `signal`
  fields / audit failure; emergency stop idle / during a job / latch
  written before the job is cancelled / repeated / survives restart / fresh
  install READY / 4 corrupt latches kept and blocking / deleted latch /
  unreadable / replace and fsync failure (not durable, still blocks in
  memory) / audit failure reported / run arriving during a slow engage
  refused / invalid requests; local reset flow, refused while a Runner owns
  the audit, refused for a corrupt latch, audit failure keeps STOPPED;
  HTTP: 5 bad auth variants × 2 endpoints, validation/415/413, no reset
  route, 503 partial stop, rate limit, no PID/path/token in responses,
  completed response is not a disconnect, disconnect via fake ASGI
  transport and via real uvicorn on loopback; real child processes: prompt
  cancel, never started if cancelled first, cancel wins a same-poll
  timeout, unrelated process survives, output cap still applies;
  old-client schema rejects `cancelled`; cancelled results carry no
  evidence.
- Mutation checks against a passing unmutated control: removing the
  session-id check, the persistent-latch read, the cancel check in the poll
  loop, the disconnect cancel, the tombstone check, the deleted-latch rule,
  or the in-memory stop before the disk write is each caught. (The first
  disconnect mutant run hung instead of failing — the test fake waited
  forever; it now gives up after 15 s, and leftover test processes from
  that run were stopped.)

## Stage 4 security review (2026-11-12, offline; findings R1–R7)

Independent review of commit `6ef9dd8` (implementation read, not only test
results). Each confirmed finding was first reproduced by a test that FAILED
on `6ef9dd8` (`tests/security/test_runner_stage4_review.py`), then fixed.

| # | Severity | Finding | Fix |
|---|---|---|---|
| R1 | Medium | Disconnect-cancel chose the job by the **payload ids** of the disconnecting request. A second connection re-sending the same ids (client retry, replay) was answered "busy" — but if it disconnected first, it cancelled the ORIGINAL job; the freed execution lock then let the duplicate request start a new job (reproduced: test hung on the duplicate's job). | Each run carries an opaque per-connection owner object; `Runner.cancel_owned(owner)` cancels only the job that connection registered. Payload ids are no longer used for disconnects. |
| R2 | Medium | One rate-limit bucket for cancel AND emergency stop: 30 cancels (any token holder, or a buggy client loop) made the next emergency stop answer 429. | Separate buckets; cancel traffic cannot consume the emergency stop's allowance. |
| R3 | Medium | Runner shutdown with a job in flight: `runner_stopped` was recorded while the job still ran; `execution_finished` never written (reproduced: audit `… execution_started, runner_stopped`); only systemd's later SIGKILL ended the process group. | `RunnerServer.stop()` (signal or programmatic) cancels the active job at once (helper thread, never blocking a signal handler); before `runner_stopped` the server cancels and waits (bounded) for `execution_finished` (reason `runner_shutdown`). |
| R4 | Medium | With a damaged Runner audit log (e.g. torn tail after a crash) an emergency stop did not write the STOPPED latch at all (`not_durable`) — it blocked only because the audit was damaged; after the owner repaired/archived the audit, a READY latch file would have re-enabled execution. | `engage` judges the latch FILE on its own: a parseable file (READY or none) is replaced by STOPPED and `durable` is true when the file reads back STOPPED; the audit problem is still reported (`audit_recorded: false`, latch CORRUPT, HTTP 503). Only a malformed/unsafe latch file is kept as evidence. |
| R5 | Low | `cancel()` / `emergency_stop()` lacked the last-resort guard that `handle()` has: an unexpected internal error escaped to the generic 500 handler without an `internal_error` audit record. | Contained: `internal_error {error_type, operation}` recorded, generic reason returned (no detail). The emergency stop's in-memory refusal is now set BEFORE anything that can fail, so runs stay refused even then. |
| R6 | Info | The "old client" compatibility test only simulated an old schema; the real Windows code shares `avra.runner.schemas` and therefore *parses* `CANCELLED`. | Verified on the real code (tests): the M6 scan pipeline treats a CANCELLED result as failed — no evidence stored, `classify_result` = `failed`, audit status `cancelled`; the real `RunnerClient` maps 503 `emergency_stop` to a rejection and 409 `cancelled` to `RunnerClientError` (fail closed). Handling 409 explicitly is Stage 5. |
| R7 | Low (docs) | The Kali reset instructions loaded `runner.env` with `env $(sudo cat … \| xargs)`: word splitting and glob expansion of values, configuration in process arguments and shell history; a secret placed in `runner.env` would leak. (Today the file holds only paths — the token stays in its own file.) | Replaced by `systemd-run --pty … -p EnvironmentFile=/etc/avra-runner/runner.env` (same mechanism as the unit); a rule never to expand `runner.env` in a shell. Not executed (Stage 6/7). |

Reviewed and found sound (no change): exact two-id matching; mismatch never
touches the active job; tombstones bounded (256), expire after 15 min, keyed
by both ids so an expired or foreign tombstone cannot affect a new job; a
cancelled run never returns output; CANCELLED and TIMED_OUT stay distinct
(fixed poll order; a timeout that wins is never relabelled); latch write →
read-back → audit order; READY only on a fresh install or a matching reset
record; no HTTP reset route; local reset needs the owner lock, an intact
chain, a valid STOPPED latch, a terminal, a reason and `RESET`; auth runs
before body reading and before the rate limiter (unauthenticated requests
cannot consume the stop allowance); no PID, path or token in responses.

Residual risks (documented, not fixed in Stage 4):

- **Disconnect detection.** False positive: a client that half-closes its
  sending side after the request (HTTP/1.1 allows it; AVRA's urllib client
  does not) is treated as gone and its job is cancelled — the safe
  direction. False negative: a half-open connection (VM network lost
  without FIN/RST) is not noticed until TCP gives up; the Runner timeout
  still bounds the job. Depends on uvicorn 0.54 / h11 semantics.
- **Process groups (POSIX, NOT VERIFIED here).** A descendant that calls
  `setsid()` leaves the job's process group and survives a cancel until the
  service stops (systemd `KillMode=control-group` then kills it; `TasksMax=64`
  bounds it). nmap and `avra-http-probe` do not daemonize. The final
  group sweep after reaping has the known tiny PGID-reuse window (only
  `avra-runner`-owned processes could be hit).
- **Same principal.** Anyone holding the Runner token can cancel any job and
  engage the stop (by design: stop-only). Code running as `avra-runner` can
  append a forged reset record and write READY; root can delete the latch
  and truncate the audit. Tombstones are lost on restart.

Review evidence: 17 regression tests (`test_runner_stage4_review.py`; R1–R5
failed on `6ef9dd8`, R6 documents existing fail-closed behaviour, plus
concurrent cancel/emergency stop, cancel racing completion, corrupt latch
after restart). Mutation checks against a passing control: reverting R1, R2,
R4 or R5 is caught; the first R3 test alone did NOT catch removal of the
pre-`runner_stopped` safety net (the early cancel in `stop()` masked it), so
`test_r3b` (uvicorn exits without `stop()`) was added — both R3 safeguards
are now caught, the `stop()` one by a timing assertion (shutdown waited
10.2 s). Full suite 1494 passed / 29 skipped; Ruff 27; `git diff --check`
clean; 15 historical logs byte-identical; no operational state touched.

## Stage 5 decisions (implemented OFFLINE — Windows side; NOT verified against Kali)

Windows code only: `src/avra/runner_client/{client,stop,scan,http_probe,tunnel}.py`,
`src/avra/control/killswitch.py`, `src/avra/core/research.py`, `src/avra/cli/main.py`.
The deployed Kali Runner is still the pre-Stage-4 build, so against it the
remote stop answers **404 → "UNSUPPORTED OR UNCONFIRMED"** until Stage 7.

> Historical record as of Stage 5. **Superseded 2026-11-12:** the operational
> Runner now has the Stage 4–7 code. Ctrl+C was checked live (C3 attempt 1:
> exact-id cancel, `already_finished`). `avra kill`'s remote emergency stop
> against the operational Runner is still **NOT VERIFIED** (never engaged).
> See "Stage 7 recovery".

1. **Client protocol.** `RunnerClient.cancel(request_id, session_id, reason)`
   and `.emergency_stop(reason)` POST only to `/v1/tools/cancel` and
   `/v1/emergency-stop` (an internal allowlist; any other path raises),
   with the existing bearer token, loopback-only base URL, no proxy, no
   redirects; timeouts 15 s / 20 s; responses capped at 16 KiB; **no
   retries**. They return a `StopCallResult` and never raise for Runner or
   transport problems. Only a schema-valid Runner answer counts
   (`category == "ok"`): 200/503 bodies are validated with the Stage 4
   models; the ids must equal the request's; the Runner's own status rules
   are enforced (cancel: 503 ⇔ `cancellation_unavailable`; emergency: 200 ⇔
   durable AND audited). Everything else is a non-confirming category:
   `unsupported` (404/405 — older Runner), `auth_failed` (401), `rejected`
   (400), `rate_limited` (429), `unavailable` (500/503 without a valid
   body), `invalid_response` (bad JSON/shape/size/schema/ids, 409),
   `transport` (unreachable, timeout, reset, tunnel), `config`,
   `interrupted`. `cancel_confirmed` is true only for
   `cancellation_applied`, `already_cancelled`, `already_finished`,
   `not_active` (the Runner states the job is not running);
   `cancellation_requested` is NOT confirmation. `emergency_confirmed`
   requires `durable` and latch `STOPPED`. `RunnerClient.run` now accepts
   409 (`cancelled`) as a rejection and refuses while the local kill switch
   blocks (defence in depth).
2. **Stop-only transport** (`runner_client/stop.py`). The only path to the
   Runner while the local latch blocks: a fresh restricted tunnel (same
   fixed argv; ready timeout capped at 15 s) and `StopOnlyClient`, whose
   only methods are `cancel` and `emergency_stop` (no `run`, `health`,
   generic call or reset). It does not consult the latch because it cannot
   start work; there is no `ignore_kill_switch` flag anywhere, and the latch
   is never disengaged to send a stop. Execution stays blocked: the
   pipelines' gate, `RunnerClient.run`, `ClaudeProvider` (tested).
3. **Ctrl+C** (`run_nmap_connect_scan`, `run_http_probe`; research and the
   CLI use these). The pipeline records `tool_request_interrupted`
   (`submitted` true once the run request may have been sent). If submitted:
   `remote_cancel_requested`, then ONE bounded cancel of exactly that
   request_id + session_id (`client_interrupt`) over a fresh stop-only
   tunnel, then `remote_cancel_confirmed` or `remote_cancel_unconfirmed`
   (category, HTTP status, outcome). The operator sees the Runner's answer
   or "REMOTE CANCELLATION UNCONFIRMED … may still be running". The
   interrupt is then re-raised (never swallowed): research stops as
   `aborted`. Closing the run tunnel may already have cancelled the job
   (Stage 4 disconnect-cancel) — the Runner then answers
   `already_cancelled`/`already_finished`/`not_active`, which confirm.
   A second Ctrl+C abandons the attempt (`interrupted`, unconfirmed). Audit
   write failures never skip the cancel. No result or evidence is invented;
   replay ignores the new events (reports rebuild unchanged).
4. **Cancelled results.** `ToolRunStatus.CANCELLED` adds an error
   ("cancelled by the Runner …; not evidence"), stores no evidence, and
   `classify_result` = `cancelled` (distinct from `timed_out`/`failed`);
   the verification evidence layer already requires `completed` + exit 0.
5. **`avra kill`** (new options `--local-only`, `--kali`, `--key`):
   (1) engage the local latch (durable, read back, recorded) FIRST;
   (2) record `remote_emergency_stop_requested` in the control audit;
   (3) stop-only remote emergency stop (`local_kill_switch`);
   (4) record and print the remote result separately:
   `remote_emergency_stop_confirmed` / `_not_durable` / `_unsupported` /
   `_unconfirmed`. Output: "LOCAL STOP ENGAGED" plus one of "REMOTE
   EMERGENCY STOP CONFIRMED", "REMOTE EMERGENCY STOP NOT DURABLY
   CONFIRMED", "REMOTE STOP UNSUPPORTED OR UNCONFIRMED", "REMOTE EMERGENCY
   STOP UNCONFIRMED … may still be running". **Exit codes: 0** = local
   engaged and recorded AND remote confirmed durable and audited; **4** =
   local engaged, remote not confirmed; **1** = local engagement or its
   record failed (the remote stop is still attempted — justified because it
   can only stop work — but the overall result is never success);
   `--local-only` exits 0/1 on the local result and says the remote was not
   attempted. A local control-audit failure never skips the remote stop.
   Ctrl+C during the remote attempt → unconfirmed (exit 4).
6. **Reset stays local.** `avra kill --reset` never contacts the Runner and
   says so: the Runner's latch stays STOPPED until the owner resets it on
   Kali. `kill --status` shows the last remote stop outcome from the control
   audit, so a reset never hides an unconfirmed remote stop. No remote reset
   exists anywhere.
7. **Test safety net.** `tests/conftest.py` sets a dummy `AVRA_RUNNER_TOKEN`
   (the real `.env` is never read by tests) and makes the tunnel's default
   process launcher refuse — no test can start a real ssh to Kali.

### Stage 5 evidence

- `tests/unit/test_stage5_remote_stop.py` (71 tests): client outcomes
  (6 cancel outcomes; unavailable), 18 failure answers incl. 401/404/405/
  400/429/503/500/409, bad JSON, wrong shape, extra field, wrong ids,
  oversize, timeout, reset, refused — all non-confirming and never retried;
  token never in results; emergency-stop strictness (7 cases); stop-path
  allowlist; StopOnlyClient surface; remote stop works while the latch
  blocks and never calls `run`; execution, `RunnerClient.run` and model
  calls stay blocked; tunnel failure; real ssh impossible in tests; Ctrl+C
  during execution (exact ids, records, two tunnels opened and closed, no
  evidence, gate released), before submission (no cancel), honest outcomes
  (race already_cancelled/finished confirm; requested/transport/404
  unconfirmed), second Ctrl+C, audit failure never skips the cancel, HTTP
  probe, research abort + replay; cancelled result never evidence; `avra
  kill` cases A–E, malformed/401/429/config, interrupted remote, local
  audit failure, `--local-only`, repeated and 4 concurrent invocations,
  reset local-only with remote history kept, `record_event` restricted;
  end-to-end against the real Stage 4 Runner app on loopback (cancel
  APPLIED, CANCELLED result parsed, repeat already_cancelled, emergency
  confirmed, next run refused `emergency_stop`, wrong token auth_failed).
- Updated: the Stage 3 CLI test now uses `--local-only` (the old local-only
  behaviour, explicitly); the review test R6 now expects `cancelled`
  instead of the less specific `failed`.
- Mutation checks (10, against a passing unmutated control): requested
  counted as confirmed; local latch not engaged; `run()` ignoring the
  latch; stop-path allowlist removed; cancel when never submitted; 404
  reported as confirmed; 200/503 consistency removed; KeyboardInterrupt
  swallowed; durability ignored; an answer for other ids accepted — all
  caught. "Durability ignored" first SURVIVED (every non-durable test
  answer also had a non-STOPPED latch); two cases with latch STOPPED but
  `durable: false` were added (71 tests) and now catch it.

## Stage 6 — Linux/POSIX validation (2026-11-12, Kali, isolated; operational Runner untouched)

Environment: Kali Rolling, kernel 7.1.5, Python 3.14.8, systemd 262, as
the unprivileged `kali` user (no sudo) in a fresh `/tmp` workspace (repo
exported with `git -c core.autocrlf=false archive`; a first export with
CRLF was detected by hash and discarded). Dependencies: the Runner venv's
pinned starlette/uvicorn/pydantic (read-only via PYTHONPATH) + Kali's
pytest/httpx/defusedxml; nothing downloaded. Afterwards the operational
unit (`11d4d77b…`), installed code (`server.py c6b9705c…`) and service state
were unchanged; the workspace was removed.

Results:

- Full suite on Linux: **1464 passed, 13 skipped** (DPAPI ×7, NTFS
  junctions ×3, Windows share modes, Windows-only limitation note, needs
  Git checkout), **3 failed + 2 collection errors, all environmental**: 4
  need the `anthropic` SDK (not installed on Kali, not used by the Runner;
  they pass on Windows) and 1 needs a Git checkout (known since M8.2).
  Linux-only tests now verified: SIGTERM → SIGKILL after the grace period
  (exit −9), graceful SIGTERM (exit −15), grandchild cleanup in the job's
  group, no zombies (waitpid), unrelated process untouched, job runs as
  its own session/group leader, cross-process audit flock, symlinked latch
  rejected, unreadable latch/audit fail closed, latch file 0600 and
  atomically replaced, real-signal Runner shutdown, real-uvicorn disconnect
  cancel.
- `tests/linux/systemd_stage6_harness.py` (disposable transient USER unit,
  KillMode=control-group, TimeoutStopSec=20, MemoryMax, TasksMax; harmless
  job; test-only token, scope, audit and latch; private loopback port):
  **31/31** — auth 200/401/401; `systemctl stop` with a running job: job
  and grandchild gone, `execution_finished` before `runner_stopped`, stop
  in 0.2 s; exact cancel → `cancellation_applied`, processes gone, CANCELLED
  without output; wrong session → `identifier_mismatch`, job untouched;
  client disconnect → cancelled (`client_disconnected`); emergency stop
  during a job → durable STOPPED, job cancelled, new runs 503, repeat
  idempotent, no reset route; `systemctl restart` keeps STOPPED (health
  503, runs refused, `runner_started.emergency_latch` STOPPED); reset
  refused while running (exit 3) and without a terminal (exit 5); `--check`
  shows STOPPED; test-only reset of the DISPOSABLE latch; SIGKILL to the
  cgroup leaves no processes and no torn audit line; restart works.

Findings:

| # | Severity | Finding | Resolution |
|---|---|---|---|
| S6-1 | **Medium** | A descendant that leaves the job's process group (`setsid`) while holding the job's stdout/stderr pipe kept `SubprocessRunner.run()` blocked until it exited: the reader never saw EOF and closing the stream waited on the reader's lock. Reproduced: a **1 s timeout took 120 s**; a cancel likewise. The Runner's single execution slot stayed occupied — the timeout and cancel bounds were violated (POSIX only; invisible on Windows). nmap and avra-http-probe do not do this. | POSIX readers now `poll()` with a stop event and raw `os.read`; after the group is killed and the grace period passes, a reader still waiting is stopped and the pipe closed, recorded in `cleanup_error` ("output pipe held open by a process outside the job's process group"). Regression tests failed on the old code (1 s timeout → 120 s; cancel likewise) and pass now (≈5 s). The escapee itself still survives (documented residual; systemd's control-group kill removes it at service stop). |
| S6-2 | Info | Under systemd, `systemctl stop` SIGTERMs every process of the unit's cgroup at once, so the job usually dies of systemd's signal (recorded `outcome exited`, exit −15, status `completed`) before the Runner's own `runner_shutdown` cancel labels it. Ordering and cleanup hold. | Documented. A non-zero exit is never evidence: the Windows pipelines flag it as an error and the verification layer requires `completed` AND exit 0. |
| S6-3 | Low (test) | `test_leaking_dropin_is_detected` built both labs in one folder → `FileExistsError` on Linux (it had only ever run skipped on Windows). | Fixed: separate folders; passes on Linux. |

Not verifiable in Stage 6 (no root, by design): `chattr +a` interaction
of the new code, the foreign-owner latch check, and the system unit's
sandbox (`ProtectSystem`, `IPAddressAllow`, `ReadWritePaths`) — these are
exercised only by a real deployment under `avra-runner.service`.
PGID reuse remains a theoretical window (not deterministically testable).

## Stage 7 — pre-deployment gate, disposable E2E (2026-11-12); deployment BLOCKED

> Historical record of the first Stage 7 attempt. **Superseded the same
> day:** all three blockers were resolved by the owner-gated "Stage 7
> recovery" below (isolation restored, owner-run sudo, operational audit
> verified), and the Runner was deployed. The disposable E2E and S7-1
> results below remain valid.

**Gate result: BLOCKED before snapshot and deployment** (nothing on the
operational Runner was changed; no snapshot was taken because a snapshot
taken now would be stale by the time the owner deploys):

1. **Lab network ≠ the authorized configuration** (found read-only via
   `VBoxManage showvminfo`): "Ubuntu desktop" (the Juice Shop target) has
   adapter 1 **Bridged to the host Wi-Fi with the cable connected**, and
   "Kali linux" has adapter 1 **NAT, connected** (default route via
   10.0.2.2). ADR 0002 / `docs/lab-setup.md` say the Bridged cables are
   disconnected and Kali is host-only. Changing VM networking needs the
   owner's explicit approval (dev policy), so it was not touched.
2. **Deployment needs root on Kali** (wheel into root-owned
   `/opt/avra-runner`, service restart, `chattr`); Claude Code has no sudo
   by design and must not escalate. The operational audit log is readable
   only by root / `avra-runner`, so its integrity before deployment could
   not be confirmed either.
3. Found, not a blocker: `avra-runner` was **active** (documented as
   stopped; started by the owner for the 2026-11-12 health check);
   listener `127.0.0.1:8765` only; unit `11d4d77b…` and sandbox unchanged;
   installed code is the pre-Stage-4 build (no `emergency` module).

**Pre-deployment E2E against a DISPOSABLE Runner** (the brief's first
verification step): new Runner code as a transient user unit on Kali
(private port, test token, own latch/audit, harmless job; no target
traffic), reached from Windows through a development SSH forward as
`kali` (the restricted `avra-tunnel` account can only forward to the
operational port 8765). Real Windows `RunnerClient`, stop-only module, scan
pipeline and kill switch (temporary state dir): health OK; exact remote
cancel `cancellation_applied` in 0.1 s, run answered CANCELLED without
output; `avra kill` sequence — local latch engaged first, remote emergency
stop CONFIRMED (durable STOPPED, running job cancelled), local latch blocks
`RunnerClient.run`, Runner refuses new runs (503 `emergency_stop`), local
latch never disengaged.

**Finding S7-1 (Medium, fixed):** on Windows, Ctrl+C during a blocking
Runner request was delivered only when the socket read returned — measured
**67.1 s**, i.e. at the job's own timeout — so the follow-up cancel was
truthfully `already_finished` and could not stop anything (the Stage 5
fakes raised KeyboardInterrupt in Python code and missed this; it was open
question C3 of the Stage 0 preflight). Fix: `call_interruptibly()` runs
`health()`/`run()` in a daemon worker and the main thread waits in 0.2 s
steps. Regression test (a real C-level `recv`) failed on the old pipeline
(held back 12.0 s) and passes now; re-run live against a fresh disposable
Runner: **Ctrl+C took effect after 0.1 s, the Runner answered
`cancellation_applied` (`client_interrupt`), and the job and its grandchild
were gone on Kali.**

Not done in Stage 7 (blocked): snapshot, deployment, live checks of the
deployed Runner (single-job cancel, disconnect, operational emergency
stop), live target traffic. Owner runbook: `docs/NEXT_SESSION.md`.

## Stage 7 recovery — deployment and live validation (2026-11-12)

**Verdict: COMPLETE WITH LIMITATIONS.** The Stage 4–7 Runner is deployed
and live-validated on the operational Kali Runner. Three things remain
unverified (listed below), and no stop is claimed beyond its evidence. Every
state change was approved by the owner at its own gate. Every `sudo` command
was run by the owner in their own terminal; Claude Code never saw or stored
a password. The operational emergency latch was never engaged or reset.

| Gate | Result | Evidence |
|---|---|---|
| A preflight | PASS | HEAD `74f89b2`, clean tree; deviation from the 2026-11-12 morning still present |
| B isolation | PASS | Owner-approved `VBoxManage controlvm "<VM>" setlinkstate1 off` on "Ubuntu desktop" (Bridged) and "Kali linux" (NAT). After the change: no default route in either guest, Ubuntu `enp0s3` has no IPv4 address, `eth0`/`enp0s3` NO-CARRIER, host-only SSH and the restricted tunnel work, no internet path from Kali. |
| C operational audit | PASS (owner-run, read-only) | 40 records, chain valid, contiguous, `chattr +a`, 0600 `avra-runner`, 0 unfinished executions, no latch file |
| D wheel | PASS | `dist/m8.7/avra-0.0.0-py3-none-any.whl`, sha256 `e5b39513f54f714569720f6c4259394ef166c63e91d50f865e0c083a651222aa`. Built from `74f89b2`, offline, from an LF `git archive`; two builds produced identical hashes. 68 modules byte-identical to `src/`, no CR bytes, console scripts `avra` and `avra-http-probe`. Runner tests against the extracted wheel: 318 passed, 3 skipped. `requirements-runner.txt` unchanged since M4.1, so the wheel-only upgrade applies. |
| E snapshot | PASS | Owner stopped `avra-runner` first (audit 41 = `runner_stopped`); live snapshot `AVRA-M8.7-S7-PreDeploy`, UUID `af19866e-b127-47be-8545-d2ac3b270b0c`, taken in 25 s. It includes RAM (`.sav` 1.9 GB). C: had 13.08 GB free before and 11.17 GB after; a 5 GB reserve was kept. `AVRA-M8.2-PreDeploy` is kept. VM running throughout, SSH OK, Runner inactive. |
| F1 install | PASS | Owner ran the documented wheel-only upgrade: backup `/root/avra-backup-m8.7-2026-11-12` (old `/opt/avra-runner`, `runner.env`), then `pip --no-deps --no-index --force-reinstall`. Read-only checks: 68/68 installed modules equal the wheel; nothing group/other-writable, no setuid, everything `root`-owned; unit `11d4d77b…` with no drop-ins; `runner.env` identical to its backup; token 0600; scope `ac4b8b18…`; audit unchanged (41); `--check` OK with `emergency latch READY`. |
| F2 start | PASS | Owner started the service (08:28:28 EST). Health OK through the restricted tunnel. Wrong token → 401, no token → 401, `POST /v1/emergency-stop/reset` → 404 (no HTTP reset). Tunnel: forward to 8765 allowed; forward to :22, shell and PTY refused. Sandbox unchanged (`ProtectSystem=strict`, empty capability set, `IPAddressAllow=192.168.56.103 127.0.0.1`, `MemoryMax=512M`, `TasksMax=64`, `KillMode=control-group`). Listener `127.0.0.1:8765` only. No default route, no external connections. Audit 43 (`runner_started`, then one throttled `http_rejected`). |
| G1 scope negatives | PASS | 6 synthetic requests (`.104:22`, `.1:445`, `.103:22`, `.103:[3000,22]`, probe `.103:8080`, probe `.103:3000` under the nmap-only Kali scope). The Runner refused all 6 with 403 at the `scope` stage; Windows refused the first 5. 0 tool processes afterwards. |
| G3a bounded scan | PASS | Owner-approved: `avra scan nmap-connect` on `192.168.56.103:3000` (session `432758f3…`, request `57f91060…`): open, completed, exit 0. Evidence sha256 `faea589a…` equals the Runner's `output_sha256`; Windows audit 3 records, chain valid. |
| G3b HTTP probe | PASS | Exactly one probe, run by the owner with `avra probe http` and an interactive "y" (session `0e1593e8-583c-4eff-81b4-a912921e9ebf`, request `5e376e79-29a7-4584-b4eb-8990d7a06a19`, 14:27:02 UTC): completed, exit 0. Evidence (13,691 bytes) sha256 `f4bae082645b1505065eca7a8bc1dab8489cbd09328a093e6810f60562f9cb00` = Runner `output_sha256` = Kali `stdout_sha256`. Kali audit 83 `request_received`, 84 `execution_started`, 85 `execution_finished`. Two `http_probe` executions in the whole Kali log (M8.3 and this one). |
| G4 cancel API (C1) | PASS | Live, no tool run: finished job → `already_finished`; wrong session id → `identifier_mismatch`; unknown ids → `not_active`. Ids echoed back, Runner audit recorded each call. |
| G4 active-job cancel (C2) | **NOT OBSERVED** | 3 bounded scans with a cancel 0.03, 0.10 and 0.25 s after submission. All completed first; the Runner answered `already_finished` with exact ids. A one-port scan takes under 1 s end to end, so a cancel cannot catch it; intensity and scope were deliberately not increased. `already_finished` is not counted as a stopped job. Applied cancellation is verified on the disposable Runner only (Stage 7 above). |
| G4 Ctrl+C (C3) | PARTIAL; S7-2 open | Attempt 1 (`96ce1812…`): the interrupt reached the pipeline, which recorded `tool_request_interrupted`, sent a cancel for that exact request id, got `already_finished`, and re-raised the interrupt. Attempt 2 (`99c00b80…`): see S7-2. |
| G6 operational emergency stop | **NOT VERIFIED** | Not engaged (owner decision). Latch READY, no latch file. Verified on the disposable Runner only. |
| H rollback | Not needed for the deployment | No full deployment rollback was performed; snapshot `AVRA-M8.7-S7-PreDeploy` and backup `/root/avra-backup-m8.7-2026-11-12` remain unused. The **temporary Kali scope was restored with S2** (owner-run, four idempotent runs 09:27:26–09:30:32 EST, final hash `ac4b8b18…`). |
| Kali audit after G | PASS (owner-run) | 93 records, chain valid, contiguous, last event `runner_started`, no latch file |
| Restored scope, live enforcement | **NOT VERIFIED** (owner decision C) | Restore is shown by the hash check in S2 and by the start order (below). The one approved synthetic check (`cee72a05…`, session `83098896…`) was refused on Windows before sending (`no interactive owner approval`), so the Runner never saw it. No further request was sent. |

**Temporary probe scope (owner-approved, reverted).** One entry was added
to Kali's `scope.yaml`: `http_probe`, tier `passive`, `192.168.56.103:3000`.
The nmap entry stayed byte-identical. Offline, 540 host/port/tool/tier
combinations were compared, and exactly one changed; the Runner's own
`RunnerPolicy` agreed. Hashes:
- original: `ac4b8b181829b6ee6c9eb84b0749710402ca7b7433b29ccdc6c59d0ee64b4602`
- temporary: **`ae45fcd8b722f8fea259932402b28bde659b2966d6e20a17c22702d943eeeaf2`**

A plan message first gave the temporary hash as `e45fcd8b…` (leading `a`
lost when reading Windows `sha256sum` output, which prefixes `\` for
backslash paths). It was corrected before S1 ran; S1's hash check would
have stopped on the wrong value.

Timeline from the Kali sudo journal (EST):
- 09:25:04: S1 (backup, stop, replace, `--check`, start at 09:25:05).
- 09:27:02: the probe.
- 09:27:26, 09:29:25, 09:30:12, 09:30:31: S2 four times (idempotent).

The current Runner (PID 171328) started at 09:30:32, after the last restore,
and the Runner reads its scope only at startup.

**S2 startup/audit race (Low, procedure).** S2 read the audit right after
`systemctl start`. That returns once systemd has launched the process
(`Type=simple`), about one second before the Runner writes
`runner_started`, so the check showed `runner_stopped` as the last event.
Journal: start 09:30:32, `Started server process` 09:30:33. The audit itself
is correct; the later read shows record 93 `runner_started`. Fix (runbook):
wait until `runner_started` follows the last `runner_stopped`, or the
loopback listener is up, before reading.

*(M8.8 update, ADR 0014: S7-2 was not reproduced as a lost interrupt in 173
offline trials. It is not definitively disproven, and genuine interactive
Ctrl+C is a Phase 1C test. The investigation found and fixed F-1, a missing
terminal record after the Runner answered, and F-4, an ssh child surviving
an interrupt.)*

**S7-2 (Low, unresolved).** In C3 attempt 2 the scan completed normally and
was recorded. The interrupt, injected by a timer 0.15 s after `run()`
started, never surfaced in the test process. The test process exited 0
with no "Exception ignored" message. What was checked offline:
- the real pipeline re-raised 3 of 3 mid-run injections in a row in one
  process (about 0.3 s each);
- when the injection fires after the job has finished, the pipeline does
  not see it, and Python on Windows delivers it to the caller only once a
  `time.sleep` returns (0.55 s instead of 0.17 s); `_thread.interrupt_main`
  does not wake a sleeping thread.

No code path that swallows `KeyboardInterrupt` was found. Every
`BaseException` handler re-raises. Most likely this is an artefact of
timer-based injection, not a lost real Ctrl+C. A real console Ctrl+C
during a live operational job has not been exercised.

**Final regression (Phase I, offline): 1577 passed, 42 skipped, 0 failed.**
That includes the 11 Stage 8 provider-factory tests. The first run had 1
failure, `test_real_state_dir_is_never_used_by_tests`. It asserted that the
real `%LOCALAPPDATA%\AVRA\control` does not exist, but the real Stage 7 CLI
scan had legitimately created it (gate/active markers and a lock file,
08:41:19 EST; no latch state file, since the local latch was never
engaged). The isolation guarantee itself held: `state_dir()` was the
per-test folder. Fixed in the tests only. `tests/conftest.py` snapshots the
real folder (path, size, mtime) when pytest starts and fails at session end
if anything in it changed; the test compares against that snapshot. Checked
in a throwaway `LOCALAPPDATA`: a clean run passes, and a run that writes
`control/state.json` fails.

**Other observations (no change made):**
- Runner auth failures are audited at most once per 10 s (the next record
  carries `suppressed_since_last`).
- Requests to unknown routes get 404 and are not audited.
- Kali listens on `127.0.0.1:9050` (probably Tor; not AVRA). It predates
  this work and has no egress now; owner to confirm.
- `juiceshop` was started (owner-approved) and is still running, bound to
  `192.168.56.103:3000` only. `juiceshop-old` (binds all interfaces) is
  exited.
- Operator scripts remain in Kali `/tmp`: `avra-audit-check.py`,
  `avra-f1-verify.sh`, `avra-s1-apply-scope.sh`, `avra-s2-restore-scope.sh`,
  `avra-scope-temp.yaml`, `avra-scope-orig-reference.yaml`, `avra-m8.7.whl`.
  Deleting them needs owner approval.

## Stage 8 — final review and readiness (2026-11-12)

> The review below was done before the Stage 7 recovery. The readiness
> table and the "Remaining" list were updated afterwards and are
> **current as of the Stage 7 recovery** (2026-11-12).

End-to-end chain reviewed (CLI → research loop → scope/approval/kill
switch → RunnerClient → restricted tunnel → Runner API → Runner policy →
subprocess → evidence/audit/reports), reading the implementation, not only
test results. Defects found and fixed during M8.7 (all with regression
tests that failed before the fix): R1–R5, R7 (Stage 4 review), S6-1
(escaped pipe holder), S7-1 (Ctrl+C held back on Windows). Provider
abstraction: ADR 0013 (explicit `LLMConfig.provider`, `avra.llm.factory`,
no fallback; 11 tests; mutation-checked in isolated temporary copies — a
real silent fallback is caught; one equivalent mutant behind the guard is
unreachable).

**Readiness (separate classifications — no blanket "secure" label):**

| Capability | CODE COMPLETE | OFFLINE TESTED | LINUX VERIFIED | DEPLOYED | LIVE LAB VERIFIED | OPERATIONALLY VERIFIED |
|---|---|---|---|---|---|---|
| Durable single-writer audit (S1) | yes | yes | yes | yes (Windows; Kali since Stage 7 recovery) | yes (Kali 93 records, chain valid) | Kali: yes · anchors: NOT VERIFIED |
| HMAC anchors (S2) | yes | yes | n/a (DPAPI) | yes (no key created) | n/a | NOT VERIFIED (no key) |
| Local kill switch (S3) | yes | yes | n/a | yes | n/a | NOT VERIFIED (never engaged) |
| Runner cancel API (S4) | yes | yes | yes (incl. systemd user unit) | **yes** (wheel `e5b39513…`) | cancel API yes (C1); applying a cancel to a running job: disposable only | active-job cancel **NOT OBSERVED** |
| Runner emergency latch (S4) | yes | yes | yes | **yes** (READY) | disposable instance only | **NOT VERIFIED** (never engaged) |
| Windows integration (S5, S7-1) | yes | yes | n/a | yes | Ctrl+C path yes (C3 attempt 1, `already_finished`); S7-2 open | partial |
| Provider seam (S8) | yes | yes | n/a | yes | n/a | n/a |

Table updated after the Stage 7 recovery (see that section).

**Remaining, by severity:**

- ~~High (operational): lab isolation broken~~: **restored 2026-11-12**
  (owner-approved NIC1 unplug on both VMs; Stage 7 recovery, Gate B).
- ~~High (gap): deployed Runner lacks Stages 4–7~~: **deployed
  2026-11-12**. Still unverified on the operational Runner: stopping an
  actually running job, and the emergency latch (see the Stage 7 recovery
  section).
- **Medium (open):** operational emergency stop NOT VERIFIED (never
  engaged); cancelling an actually running job on the operational Runner
  NOT OBSERVED (disposable Runner only); no operational HMAC key.
- **Medium:** a descendant that escapes the job's process group survives a
  cancel until the service stops (S6-1 keeps the Runner bounded);
  half-open connections are not detected until TCP gives up.
- **Medium (accepted):** same-user compromise on Windows can delete the
  local latch / anchors / keys; passphrase-free runtime SSH key; Runner
  audit unkeyed (relies on `chattr +a`).
- **Low:** PGID-reuse window in the final group sweep; tombstones lost on
  Runner restart; `.env` is a plain file.
- **Low (Stage 7 recovery):** S7-2 (injected Ctrl+C not surfaced once,
  unresolved); live enforcement of the restored Kali scope NOT VERIFIED
  (shown by the hash check and start order only); S2 audit read raced
  `runner_started` (procedure, fixed in the runbook); unknown-route requests
  not audited; unexplained Kali listener `127.0.0.1:9050`.

M8.7 completion does not make AVRA v1.0-ready (threat model §4).

Unverified on Linux/POSIX before Stage 6 (now verified unless listed in Stage 6): SIGTERM → SIGKILL escalation
on cancel, grandchild cleanup on cancel, flock-based locks under
`chattr +a`, `systemd-run --pty` procedures, shutdown under real systemd
signals. All belong to the approved-only Stage 6 Kali offline run.
