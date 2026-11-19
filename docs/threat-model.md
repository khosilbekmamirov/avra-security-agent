# AVRA threat model and v1.0 readiness (2026-11-10)

Written at the end of the 2026-11-10 repository audit (F-02…F-08). It states
only what the code and tests show today; "residual" lists what is NOT
covered. Rationale lives in `docs/architecture.md` §8 and the ADRs.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The authorization boundary (scope) | AVRA must never touch anything outside the owner's lab allowlist. |
| The owner's host and networks | Windows host, Wi-Fi, VirtualBox host-only network. |
| Secrets | `ANTHROPIC_API_KEY`, Runner bearer token (`.env`), runtime SSH key. |
| Audit logs and evidence | The record of what was requested, approved, run and observed. |
| Report and verdict truthfulness | A finding must never be invented or overstated. |
| Budget | Paid API spend. |

## 2. Trust boundaries

```
Owner ──CLI──> Windows Orchestrator ──HTTPS──> Anthropic API (model: untrusted output)
                     │
                     └─SSH tunnel (host-only, fixed argv, pinned host key)──> Kali Runner
                                                                    │ argv, sandboxed
                                                                    └──> lab target (untrusted content)
```

Trusted: the owner, the Orchestrator's code, both policy layers.
Untrusted: model output, tool output, target content, evidence content
until verified, anything a file on disk claims about itself.

## 3. Threats, mitigations, residual risk

| # | Threat | Mitigation (implemented) | Evidence | Residual |
|---|---|---|---|---|
| T1 | Model proposes an out-of-scope target or action | Typed tool schemas (IPv4 literal, port ranges, no free-form args); Windows scope check; owner approval of every executed scan; Runner's independent scope check; kernel IP allowlist in the systemd unit | `tests/security/test_scope_default_deny.py`, `test_runner_scope_enforcement.py`, `test_runner_deploy.py` | Owner can approve a bad-but-in-scope scan. |
| T2 | Prompt injection from target content | Tool results wrapped as untrusted data; server-controlled strings bounded/escaped; HTTP banners/titles never reach the model; verdicts never depend on text | `tests/unit/test_http_probe.py`, `tests/verification/test_cycle.py` (server text not in model context) | The model may still be misled in its prose; claim checks flag some of it (informational). |
| T3 | Model fabricates findings or verdicts | Verdicts only from the deterministic engine; no verdict field in any model tool; report validator; claim checks on model text | `tests/verification/test_engine.py`, `test_research_loop.py`, `test_lab_context.py`, `test_m86_execution_audit.py` | Claim checks are pattern-based, not semantic (ADR 0006 decision 9). Since M8.6 every payload sent to the model is hashed in `model_feedback` (ADR 0011), so what the model was told can be proven afterwards. |
| T4 | Shell/command injection into the Runner | `shell=False`, argv built by the registry from typed fields, fixed absolute executables, minimal env, stdin closed | `tests/security/test_runner_execution_security.py`, `test_runner_input_validation.py` | — |
| T5 | Runner resource exhaustion / hostile output | Wall-clock timeout + process-group kill; stdout/stderr caps with concurrent draining; one execution at a time; HTTP body cap + read timeout; header cap; Content-Length digit check (F-08) | `test_runner_execution*.py`, `test_runner_http_security.py` | F-08 is defence in depth. In-process (Starlette TestClient, no HTTP parser) a 4300+-digit Content-Length made `int()` fail -> generic 500; F-08 returns 413, covered by offline regression tests. On the deployed stack uvicorn's h11 parser rejects any Content-Length over 20 digits first: the live 5,000-digit request (2026-11-10) got HTTP 400 `Invalid HTTP request received.` before reaching AVRA (no audit record), so the 500 was never reachable there; values of up to 20 digits reach AVRA, and old and new code answer them identically (413 when the value exceeds 16 KiB). F-08 matters only if the server/parser in front of AVRA changes. Deployed 2026-11-10 (wheel `f2f0b4e4`); still included in the M8.7 wheel `e5b39513…` deployed 2026-11-12. |
| T6 | Unauthorized access to the Runner | Loopback bind; reachable only through the restricted SSH tunnel (`from=`, `permitopen=`, `restrict`, `nologin`); bearer token, constant-time compare; strict header parsing | `test_runner_http_security.py`, `test_tunnel_*.py` | Passphrase-free runtime key (accepted, ADR 0003 M4.4). |
| T7 | Malicious/malformed tool output crashes or misleads parsers | defusedxml + size cap for nmap XML; nmap value errors always `NmapXmlError` (F-07); HTTP envelope strict, hashed, paired, "read never repair" | `tests/unit/test_m6_pipeline.py`, `test_http_probe.py`, `tests/verification/test_audit_fixes.py` | — |
| T8 | Tampering with audit logs, evidence or reports | Hash-chained audit with contiguous `seq` (F-04); evidence located from UUIDs only, symlink/junction-safe, SHA-256 checked; attested reports rebuilt byte-for-byte; verification reports hash-bound (F-03) | `tests/unit/test_replay.py`, `test_report_recovery.py`, `tests/verification/*` | The chain is **unsigned**: anyone who can rewrite a whole log can forge a consistent one (Track B, not started). It also cannot detect removal of the LAST records on its own (tested); attested reports anchor their run. Audit-write failures block execution on both sides (ADR 0011). Since M8.7 Stage 1 (ADR 0012): appends are fsynced, one writer at a time across processes (bounded lock), a damaged log is never extended, and damage is diagnosed by type and line without tracebacks (`tests/unit/test_audit_reliability.py`). Since Stage 2: owner-sealed logs carry HMAC anchors (DPAPI-protected key, `avra audit seal/verify`), which detect truncation below an anchor and full rewrites (`tests/unit/test_audit_anchors.py`); unsealed logs remain chain-only (LEGACY_UNANCHORED). Not covered: a compromised Windows account that rolls back both the key and anchor folders consistently. |
| T9 | Evidence from the wrong place supports a claim | Evidence trust requires same-session audit pairing, completed run, matching hashes, strict parse, target in scope; cross-session/invented ids rejected (schema 5) | `tests/verification/test_prior_evidence.py` | — |
| T10 | Secret leakage | Tokens/keys never in errors, logs or audit; child env empty | `tests/unit/test_llm_research.py`, `test_lab_context.py` (no secret in audit/CLI) | `.env` is a plain file on the Windows host. |
| T11 | Runaway spend | Worst-case cost check before every call; step/tool/duration limits; no retries; no fallback model; `no_progress` stop | `tests/unit/test_llm_research.py`, `test_research_loop.py` | — |
| T12 | Network exposure of the lab or host | Host-only lab network; Bridged/NAT adapter 1 disconnected on both lab VMs (ADR 0002); Kali `IPAddressAllow` | `docs/lab-setup.md`, live checks 2026-11-09 and 2026-11-12 | **Current (2026-11-12):** lab isolated again: NIC1 cable off on both lab VMs, no default route in either guest (verified). Isolation is the owner's VirtualBox configuration and is not verified by AVRA at runtime. "Ubuntu server" VM (not lab) has a connected Bridged cable. History: Windows OpenSSH Server was found on 0.0.0.0:22 on 2026-11-10 (not used by AVRA); it is now Stopped/Manual (resolved). On 2026-11-12 lab isolation was found broken ("Ubuntu desktop" Bridged cable and Kali NAT connected) and restored the same day (owner-approved NIC1 unplug; `docs/lab-setup.md`). |
| T14 | Unrecorded model actions | Refused `verify_hypothesis` requests (out of scope, invalid, budget) audited; proposals, rejections, decisions, verdicts and every sent payload's hash recorded (ADR 0011) | `tests/verification/test_m86_execution_audit.py` | **Current (M8.7, deployed 2026-11-12):** Ctrl+C during a Runner request cancels exactly that job and is delivered within about 0.2 s even during a blocking request (S7-1); `avra kill` engages the persistent local latch, then asks the Runner for its persistent emergency stop; the Runner has cancel, disconnect-cancel and an emergency latch (`tests/security/test_runner_cancellation.py`; review R1-R7 in ADR 0012, `test_runner_stage4_review.py`); the cancel API is live-verified on the operational Runner. **Residual:** stopping an actually running job on the operational Runner is **NOT OBSERVED** (one-port jobs end in under 1 s; disposable Runner only); operational emergency stop **NOT VERIFIED** (never engaged); S7-2 (Low): one injected Ctrl+C did not surface in a test process, not reproduced offline. History: before the deployment, Ctrl+C and `avra kill` could not stop a job already running on Kali; the Runner's timeout ended it. M8.8 Phase 1B (ADR 0014): a Ctrl+C or error after the Runner answered now always leaves exactly one terminal audit record (F-1), and the tunnel's ssh child cannot outlive an interrupt or the interpreter (F-4). |
| T13 | Bypassing the model provider's safety behaviour | Refusals recorded and stop the session; never retried or rerouted; accurate, labelled context only | `test_lab_context.py`, ADR 0005 decision 5 | — |

## 4. v1.0 readiness matrix

"v1.0" here = a trustworthy, owner-operated lab research assistant for the
current scope (one host, connect scans + one fixed HTTP probe), not a
general scanner.

| Area | Status | Gap to v1.0 |
|---|---|---|
| Scope / authorization (two independent checks) | Done | — |
| Runner isolation & execution safety | Done (offline-tested; deployed wheel since 2026-11-12: M8.7 `e5b39513…`, verified 68/68 modules, sandbox unchanged; earlier F-08 wheel `f2f0b4e4` deployed 2026-11-10, superseded) | — |
| Audit integrity | Done: durable, single-writer, diagnosed (Stage 1); HMAC anchors for sealed logs (Stage 2, no key created yet) | Owner keygen + sealing practice; automatic sealing; an anchor copy outside the Windows account (Kali cross-anchor). |
| Evidence handling & replay | Done | ADR 0008 §2: replay still treats an in-run `http_probe` as nmap (no run contains one today). |
| Reports (attested, schema 5) | Done | Live PASS with schema 5 not yet observed. |
| Verification Engine | Done offline (3 rules) | Rules for real weaknesses need tools that collect that evidence. |
| Verification in the research loop (`m8.5-v2`) | Done offline; one real-model run of v2 completed | More real-model runs; decide default prompt. |
| Model-facing context & refusal handling | Done | Effect on real refusals not measured systematically. |
| Evaluation harness | Done (28 scenarios, fake model) | No real-model benchmark; no metrics on research quality. |
| Operator documentation | Partial | `docs/security.md` still has aspirational lines (marked); README brief. |
| Dependency hygiene | Partial | Versions pinned; no automated vulnerability check (`pip-audit` not set up). |
| Kill switch | Partial: local latch (Stage 3); Runner cancel + persistent latch (Stage 4) and Windows integration (Stage 5), Linux-verified (Stage 6), **deployed 2026-11-12** with the cancel API live-verified (Stage 7) | Live evidence that a running operational job is stopped; an operational emergency-stop drill (owner decision; needs the local reset afterwards); S7-2. |
| Live validation | Partial | Live: nmap (M7.8), HTTP probe (M8.3), two real-model M8.5 runs on recorded evidence. No live end-to-end `--verification` run with new evidence. |

**Verdict:** not v1.0 yet. The safety boundary (T1–T11, T13) is in place
and tested; the open items are mostly validation depth (M8.7: operational
emergency stop NOT VERIFIED, active-job cancel NOT OBSERVED, S7-2) and one
owner decision (signed audit / HMAC key), not missing safety controls. The
host `sshd` decision is resolved (Stopped/Manual, 2026-11-12).
