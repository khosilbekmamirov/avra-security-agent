# Security model (working reference)

Full detail and rationale: `docs/architecture.md` §8. This is the quick
reference used day to day; keep it in sync with the architecture doc and
with ADRs in `docs/decisions/`. **What is actually implemented and tested,
threat by threat, with residual risks: `docs/threat-model.md`** (2026-11-10).
Lines below marked *(as built)* correct earlier design intent.

## Core rule

The model proposes. The policy layer authorizes. The Runner executes only
validated, typed requests. The model never gets raw shell access.

Trusted: the owner, the Orchestrator, the Policy layer.
Untrusted (never acted on as instructions): the model's own proposals
(validated before use), tool output, target content, anything in the
knowledge base.

## Action tiers

| Tier | Example | Approval |
|---|---|---|
| Passive | Plain GET requests, page metadata | Automatic, in scope |
| Active-safe | Limited Nmap profile, slow crawl | *(as built)* the owner approves **every** executed scan; one execution at a time; per-session tool-run limit |
| Intrusive | Payload-based checks (e.g. SQLi test) | Explicit approval every time |
| Destructive | Delete/modify data, stop a service, credential brute-forcing | Not permitted in MVP |

## Defenses (MVP)

- **Scope**: YAML allowlist (target, ports, allowed tools/tiers,
  expiry). Default-deny. Checked twice: Orchestrator and Runner both
  validate independently.
- **Network isolation**: Kali VM on a host-only lab network only, no
  internet egress. *(as built)* both lab VMs still have a Bridged/NAT
  adapter 1 configured, with its cable disconnected (ADR 0002; found
  connected and disconnected again on 2026-11-12). On
  2026-11-10 the Windows host was found running OpenSSH Server on all
  interfaces (not used by AVRA). Resolved: it is now Stopped/Manual
  (verified 2026-11-12; `docs/threat-model.md` T12).
- **Typed tools, least privilege**: Runner takes an argument list, not a
  shell string; allowlisted arguments; timeouts; output size caps;
  non-root; Nmap starts at connect-scan only.
- **Human approval**: every intrusive action shows what, where, and the
  risk, before it runs.
- **Audit log**: append-only, hash-chained JSONL — prompt, tool request,
  result hash, approval decision.
- **Kill switch**: Ctrl+C stops the Orchestrator; the Runner kills its
  child process group on timeout. *(as built, M8.7 Stage 3)* `avra kill`
  engages a persistent, fail-closed LOCAL latch (no new tool runs, tunnels,
  approvals or model calls on this machine until an interactive, audited
  `avra kill --reset`). *(M8.7 Stage 4, deployed 2026-11-12)* The Runner has authenticated `/v1/tools/cancel` (one job, by
  request_id + session_id) and `/v1/emergency-stop` (persistent latch, no
  HTTP reset, local reset command on Kali), and cancels a job whose client
  connection closes. *(Stage 5)* Windows uses them: Ctrl+C
  during a Runner request cancels exactly that job (or reports REMOTE
  CANCELLATION UNCONFIRMED); `avra kill` engages the local latch first and
  then the Runner's emergency stop through a stop-only tunnel, reporting
  both separately (exit 4 when the remote stop is not confirmed).
  *(Stage 7, live)* The cancel API is verified on the operational Runner.
  Not yet observed there: stopping an actually running job, and the
  emergency latch (never engaged). Both were verified on a disposable
  Runner.
- **Model provider** *(as built, ADR 0013)*: chosen explicitly by
  `LLMConfig.provider` (default `anthropic`, the only implemented one); no
  automatic fallback or mid-session switch; the provider is recorded in
  `research_started`. Scope, approval, Runner, evidence, audit and the kill
  switch never depend on which model is used.
- **Rate limits & budget**: step, tool-run, duration and worst-case
  cost limits per session; *(as built)* concurrency is one execution at a
  time; there is no per-target request-rate limiter.
- **Secrets**: never in the repo, logs or audit; *(as built)* read from
  the environment or the gitignored `.env` file (no Credential Manager).
- **Prompt injection**: tool/target output is always wrapped as
  untrusted data, never followed as instructions; every action is
  re-checked against scope and tier regardless of what the model (or the
  target) says.
- **Malicious tool output**: safe parsers only (e.g. `defusedxml` for
  Nmap XML), size caps, output escaped in reports.
- **Dependencies**: Runner versions pinned with hashes; *(as built)*
  `pip-audit` is not set up yet.

AVRA does not act outside its authorized scope, and does not attempt to
route around its own safety constraints or the model's refusals.
