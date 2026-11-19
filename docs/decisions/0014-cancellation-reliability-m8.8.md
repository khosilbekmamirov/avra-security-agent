# ADR 0014 — Cancellation reliability and operational safety validation (M8.8)

_Status: **Phase 0, 1A and 1B done (2026-11-12, Windows only, offline).
Phase 1C COMPLETE (2026-11-13):** all automated trials against a disposable
Kali Runner passed; finding F-6 was found and fixed; the owner's physical
interactive Ctrl+C (T8) passed per request. Phase 2 (operational) needs the
owner's separate approval and has not started. Builds on ADR 0012._

## Context

M8.7 closed COMPLETE WITH LIMITATIONS (ADR 0012, "Stage 7 recovery"). Open
items were:
- S7-2: an injected Ctrl+C was not surfaced once in a live test;
- cancelling an actually running job on the operational Runner: NOT OBSERVED;
- the operational emergency stop: NOT VERIFIED.

M8.8 investigates these in phases. Phase 0 was a read-only analysis (plan
in the session record). It found that a Ctrl+C after the Runner had
answered was handled by no code path (F-1).

## Phase 1A — offline reproduction (evidence)

The harness was a scratch harness, kept outside the repo. It drove the
**real** scan and HTTP-probe pipelines and the real `RunnerClient`
(real HTTP on 127.0.0.1). It also used the real `SshTunnel`; only its child
was swapped for a loopback stand-in for `ssh.exe`. The fake Runner used
the real response schemas.

It instrumented six windows: before the request, while the job runs,
tunnel close, after the Runner answered, evidence write and audit write.
Interrupts were injected three separate ways: `_thread.interrupt_main`
from a timer, as S7-2 did; C-level `raise(SIGINT)`; and a **genuine
console `CTRL_C_EVENT`** sent to the trial's own console. The console
event also reaches the ssh stand-in, as it would reach `ssh.exe`.

The runs were a pilot of 43 trials and a full run of 130 trials. No
interrupt was lost, and every trial kept a valid chain and exact ids.

| ID | Result |
|---|---|
| **F-1** | **Confirmed defect, both pipelines.** An interrupt after the Runner answered (leaving the kill-switch context, storing evidence, parsing, writing `tool_result_received`) left the request with **no terminal audit record**: 54/54, all three methods incl. genuine console Ctrl+C. During the audit write, the stored evidence was not referenced by any record. One S7-2-timed replica hit the window naturally (inside `AuditLog.record`). |
| **F-4** | **Confirmed (Low).** A non-console interrupt as `SshTunnel.close()` was entered left the ssh child (and its local forward) running: 12/12. A genuine console Ctrl+C also ends `ssh.exe`, so it was 0/6 there. |
| F-2 | Confirmed: an interrupt during tunnel close records `tool_request_interrupted`, sends a cancel and gets `already_finished`, and discards a result the Runner had completed. |
| F-5 | Withdrawn: a `RuntimeError` came from the harness's own thread start inside the profiling hook. The real `call_interruptibly` gave 400/400 `KeyboardInterrupt` under randomly timed SIGINT. |
| S7-2 | **Not reproduced as a loss** (0/173). With S7-2's timing, the job finishes before the timer fires, and the interrupt arrives later in the caller after a correctly recorded result. `interrupt_main` on Windows does not wake a sleeping thread. **Not definitively disproven:** why the live script did not surface it is unknown. Genuine interactive Ctrl+C remains a Phase 1C test. |

## Phase 1B decisions (implemented)

1. **One terminal record per sent request (F-1).** In `scan.py` and
   `http_probe.py`, everything from `with stack:` to the end of the function
   is inside `try/except BaseException`. The handler calls
   `record_unfinished_request` (`runner_client/stop.py`) and re-raises.
   - **No duplicates:** if the session audit already holds a terminal record
     for the request_id, nothing is added. That covers the tunnel-phase
     handlers, and a `tool_result_received` written durably just before
     the interrupt.
   - **The Runner already answered** (`run` set): `phase: after_result`.
     **No cancel is ever sent.** The record carries the Runner's
     `result_status`, `exit_code`, `output_sha256`, `http_status`, any
     `runner_rejection_stage`, and, if stored, `evidence_sha256` and
     `evidence_path`. Evidence written before the interrupt therefore stays
     traceable (by `evidence_sha256`, or by `output_sha256`, which equals the
     evidence file's hash).
   - **No answer yet** (`run` is None): `phase: before_result`. A Ctrl+C
     there is still handled by `cancel_after_interrupt` as before, so this
     covers only unexpected errors.
   - **Event type:** `KeyboardInterrupt` gives `tool_request_interrupted`.
     Any other exception, e.g. an audit write failure, gives
     `tool_request_failed`, with `error`, `detail` and `errors` (the
     replay-compatible shape). **A failed write is never reported as a
     completed request**, and the exception still propagates.
   - **Exact ids:** request_id comes from the pipeline's own `base`; the
     session is the pipeline's session log.
2. **Ownership of the ssh child (F-4).** `SshTunnel` keeps `_child` until
   the process is confirmed exited, plus a module registry of children not
   yet confirmed stopped. The registry is keyed by object identity.
   - `__exit__`: if `close()` raises, including an interrupt at its entry,
     the owned child is terminated (then killed), and the exception
     continues.
   - An `atexit` safety net terminates registered children when the
     interpreter exits, including after an unhandled KeyboardInterrupt.
   - No new process. The ssh command line, the single `-L`, `BatchMode`,
     the pinned host key and the restricted account are unchanged (tested).
   - **Not covered:** a hard kill of AVRA itself (no atexit). A Windows Job
     Object would be the stronger option and remains a possible later
     decision.
3. **F-2 accepted (documented, no change).** Discarding a result after an
   interrupt during tunnel close is fail-safe and truthful: the audit says
   interrupted, plus `already_finished`. Nothing is claimed that was not
   observed. The job's evidence is simply not kept. The tests showed no
   security or correctness defect.

## Audit semantics (after 1B)

For every `tool_request_sent`, exactly one of `tool_result_received`,
`tool_request_rejected`, `tool_request_failed` or `tool_request_interrupted`
follows. The exception is a process that dies outright (power loss, hard
kill).

**Residual windows:**
- a **second** Ctrl+C while the terminal record itself is being written;
- an unreadable audit log, which makes the duplicate check fail open:
  the handler then attempts a record, and that write most likely fails too.

`tool_request_interrupted` and `tool_request_failed` are never evidence.
Replay ignores `tool_request_interrupted`, and the Verification Engine
trusts only a `tool_result_received` that pairs with its
`tool_request_sent`.

## Evidence (Phase 1B)

- **New tests:** `tests/unit/test_m88_post_result_interrupt.py` (20) and
  `tests/unit/test_m88_tunnel_cleanup.py` (4).
- **Before the fix:** **19 failed / 5 passed**. The 5 that passed are
  the intended guards: no duplicate after a written result (2), normal run
  (2), unchanged ssh command line (1). Every failure was the defect itself:
  16 missing terminal records, and 3 where the child survived or the
  safety net was missing. **After the fix: 24/24.**
- **Full offline suite:** 1601 passed, 42 skipped. **Ruff:** 27 findings,
  all pre-existing (unchanged); the changed files are clean.
- **Phase 1A harness re-run on the fixed code** (43 trials, all three
  methods):
  - requests without a terminal record: 0 (before: 18/43);
  - ssh children left running: 0 (before: 4);
  - evidence written during the audit-write window: 7/7 traceable through
    the new record;
  - lost interrupts: 0;
  - chains valid and ids exact: 43/43.

  The real `%LOCALAPPDATA%\AVRA` was unchanged before and after.

## Phase 1C — disposable Kali Runner (2026-11-13): COMPLETE

_Automated trials and F-6 below; the owner key-press test T8 is in the next
section. This section was first written while T8 was still pending._

Owner-approved. The operational `avra-runner` stayed inactive and untouched.
No target was contacted. No sudo, installs or API calls were used.

**Setup.**
- **Kali side:** HEAD `0ac8bb8` `src/` ran as a transient systemd USER unit
  (`systemd-run --user --collect`, KillMode=control-group, MemoryMax, TasksMax).
  It used a private `/tmp` workspace, a private loopback port, a test-only
  token, its own scope (`192.168.56.103:3000`, nmap only), and its own audit
  and latch. A harmless job was mapped as "nmap": either it printed a recorded
  nmap XML fixture, or it slept 60 s with one grandchild. This is the pattern
  of `tests/linux/systemd_stage6_harness.py`.
- **Windows side:** the real `run_nmap_connect_scan`, the real `SshTunnel`
  with a real `ssh.exe`, and the real `RunnerClient`, `AuditLog`, evidence
  store and `KillSwitch`, with a per-trial `AVRA_STATE_DIR`. The only seam is
  the existing `popen` hook. It sends the single forward to the disposable port
  as the dev account `kali`, because the restricted account can reach only
  8765.
- **Interrupts:** each trial ran in its own hidden console, with genuine
  console `CTRL_C_EVENT`s that reach both python and `ssh.exe`. T2n and T6
  used non-console interrupts on purpose.
- **Harness:** scratch only, outside the repo. Evidence is in
  `E:\Backups\avra\m88-1c-evidence-20261113\`.

**Results (final attempt, all PASS):**

| Trial | Result |
|---|---|
| T1 success (×3) | completed, exit 0, hash verified, evidence = `output_sha256`, 1 sent / 1 terminal |
| T9 scope/auth | local deny before any tunnel; Runner 403 `scope` for `.103:22` and `.1:3000`, nothing executed; wrong token 401 |
| T2 Ctrl+C during tunnel open (×3) | interrupt in 0.03 s; `submitted: false`; no cancel; the Runner never saw the request |
| T3 Ctrl+C while the job runs (×4) | interrupt in 0.20–0.22 s; the job stopped about 2.0 s after start by the Runner's disconnect-cancel (`client_disconnected`, exit −15); the explicit cancel was confirmed `already_cancelled`; job and grandchild gone; one `tool_request_interrupted` |
| T4a / T4b Ctrl+C after the Runner answered (evidence window / audit-write window) | one `tool_request_interrupted`, `phase: after_result`; **no cancel** in the session audit or the Runner audit; evidence traceable by hash (F-1 confirmed live) |
| T5 repeated Ctrl+C (×4) | always exactly one terminal record; T5c (second Ctrl+C while the cancel tunnel opened): `remote_cancel_unconfirmed` (`interrupted`), and the job was still stopped by disconnect-cancel |
| T6 non-console interrupt at `close()` (×2) | ssh child stopped before interpreter exit (F-4 confirmed live); cancel `already_finished` (F-2 as documented) |
| T10 recovery | unit stopped, no test processes, workspace removed; Kali and Windows match the pre-test fingerprint |

Every session audit chain is valid. Both disposable Runner audits are valid
(11 and 84 records), and every `execution_started` has an `execution_finished`.

**Three harness problems were found and fixed during the run.** None is a
product defect, and the evidence is kept:
- `pgrep` matched the Runner itself;
- Kali's user manager stops 10 s after the last session (no linger), so one
  test-owned ssh session kept it alive;
- the harness process tree had inherited "ignore Ctrl+C"
  (`CREATE_NEW_PROCESS_GROUP`), which a real terminal does not have. The
  trial calls `SetConsoleCtrlHandler(NULL, FALSE)`.

**Finding F-6 (Low), fixed offline.**
- **Problem:** an exception raised while `SshTunnel.open()` waited for the
  forward (KeyboardInterrupt or any error) left the ssh child running. `with`
  never calls `__exit__` when `__enter__` raises. The child, with its forward,
  lived until the atexit net ran at interpreter exit, or for good after a hard
  kill.
- **Seen in T2n:** the child was still alive when the pipeline returned. A
  console Ctrl+C hides the problem, because `ssh.exe` dies of the same event.
- **Fix** (`tunnel.py`): `open()` wraps the wait in `try/except BaseException`.
  It marks the tunnel closed, stops the child with the never-raising
  `_stop_child`, and re-raises.
- **Unchanged:** the argv, the readiness check, the success path, and the
  timeout path (`TunnelError`).
- **Tests:** `tests/unit/test_m88_tunnel_open_cleanup.py` (6 tests). On the
  unfixed code 4 fail and the 2 guards pass; after the fix 6/6 pass.
- **Full offline suite:** 1607 passed, 42 skipped. The skips are environmental:
  POSIX, Linux sshd, and symlinks in a non-elevated shell. Ruff is clean on
  the changed files.
- **Residual:** a second interrupt during `_stop_child` itself still falls back
  to the atexit net, the same as F-4.

**Not covered by Phase 1C:**
- **Explicit cancel ending a running job (`cancellation_applied`):** this was
  not the stop path here. The tunnel close always triggers the Runner's
  disconnect-cancel first. Applied cancel was shown on a disposable Runner in
  ADR 0012 Stage 7.

## Phase 1C T8 — physical interactive Ctrl+C (2026-11-13): PASS per request

**What was tested.** The owner pressed Ctrl+C on the keyboard in a normal
PowerShell window. The command was
`trial.py T8h run\cfg.json run\T8h`, run against a fresh disposable Runner
(same isolated setup as above: harmless 60 s job, no target traffic). The
Windows side was the working tree with the F-6 fix.

The harness copy differed from the preserved one in one place: the T8 stop
criterion was "the job ends CANCELLED before its natural 60 s end"
(< 55 s), instead of T3's < 15 s, because a person reacts more slowly than a
timer.

**The harness evaluator reported FAIL, kept as found.** Its checks
"exactly 1 sent, exactly 1 terminal" and "exactly one
`tool_request_interrupted`" failed.
- **Root cause:** the trial was run twice in the same output folder
  (11:17:18 and 11:17:51 local). The session audit file is appended to, so it
  holds two requests. `result.json` holds only the second run's timeline.
- **Why the check failed:** the evaluator counted terminal records per file
  instead of per request.
- **Status:** a harness limitation, not a product defect. The original
  `evaluated.json` is unchanged in the evidence folder.

**Verdict per request**, checked independently against the Windows session
audit and the disposable Runner audit, each with a valid chain (8 and 12
records):

| Request | Ctrl+C after send | Windows session audit | Cancel | Disposable Runner audit |
|---|---|---|---|---|
| `41d74bdc-f3a1-40d6-856c-376a183f121d` | 15.8 s | sent, `tool_request_interrupted` (submitted), cancel requested, confirmed: **1 terminal** | `already_cancelled`, 0.18 s | received, started, `cancel_handled` (client_disconnected), finished **cancelled** (exit −15), `cancel_handled` already_cancelled |
| `06ebc6e2-ed61-498f-b943-02e9a43139ad` | 3.5 s | same: **1 terminal** | `already_cancelled`, 0.18 s | same |

No record belongs to any other request id.

**Cleanup afterwards:** unit stopped, no test processes, workspace removed.
The operational `avra-runner` stayed inactive/disabled and unchanged.
`%LOCALAPPDATA%\AVRA` was unchanged, and no ssh.exe was left.

**Evidence:** `E:\Backups\avra\m88-1c-t8-20261113\` (read-only, `SHA256SUMS`;
`README.md` and `run/T8h/per-request-evaluation.txt`).

**F-6 fix status:** committed together with this record. Full offline suite
before the commit: 1607 passed / 42 skipped.

## Still open

- F-6 touches only the Windows wheel, so nothing on Kali needs redeploying.
- Cancelling an actually running job on the operational Runner: **NOT
  OBSERVED**.
- Operational emergency stop: **NOT VERIFIED**.
- Live enforcement of the restored Kali scope: **NOT VERIFIED** (ADR 0012).
- Phase 2 (O1–O3): not started; needs separate owner approval.
