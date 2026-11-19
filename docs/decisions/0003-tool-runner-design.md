# ADR 0003 — Tool Runner design (Phase 2)

- **Date:** 2026-11-04
- **Status:** Approved by the owner; implemented: milestones M1–M6
  done by 2026-11-06 (see "Milestones"); later Runner work is in ADR
  0007 (`http_probe`) and ADR 0012 (cancel / emergency stop)
- **Builds on:** ADR 0001 decisions 1, 2, 7, 13, 14; ADR 0002 (lab
  network risk).

## Decisions

1. **Location.** Runner code lives in `src/avra/runner/`. It reuses the
   existing scope validation (`avra.schemas.scope`, `avra.policy.scope`)
   and audit (`avra.storage.audit`) *code*, but its runtime configuration
   and policy enforcement are independent of the Windows core: its own
   config, its own trusted scope file on Kali, its own audit log.
2. **Dependencies — revised 2026-11-04: Starlette instead of FastAPI.**
   Introduced at M3.2 — not before; M1, M2 and M3.1 add none.
   *Why:* the HTTP layer must pass the raw JSON body straight to
   `Runner.handle()` so authorization has exactly one path; FastAPI's
   main value (automatic request-model binding, OpenAPI/`/docs`) is
   unused here, would have to be disabled, and current FastAPI pulls in
   extra packages (e.g. `opentelemetry-api`). Starlette — which FastAPI
   is built on — provides routing, streamed bodies and `TestClient`.
   *Candidate pins* (verify compatibility before installing; no
   `uv.lock` yet): `starlette==1.9.0`, `uvicorn==0.54.0` (no `[standard]`
   extras) as a `runner` optional dependency group; `httpx==0.28.1` in
   the dev group only (for `TestClient`). The Windows-side client
   library is decided at M6.
3. **Transport — revised 2026-11-04 (M4): SSH tunnel, Runner on
   loopback.** The Runner binds `127.0.0.1` on Kali and is not reachable
   on any VM network interface. Windows reaches it through an SSH local
   port forward as the dedicated `avra-tunnel` user, whose key is limited
   in `authorized_keys` (`restrict,port-forwarding,permitopen="127.0.0.1:8765",from="192.168.56.1"`)
   and by an sshd `Match` drop-in (local forwarding only, no listen, no
   unix sockets, no TTY). SSH provides encryption and server
   authentication (pinned host key); the bearer token stays as a second
   factor. This does not contradict ADR 0001 decision 2: SSH is only an
   encrypted pipe here — the tunnel account cannot run commands. The
   original plan (plain HTTP bound to `192.168.56.104`) is superseded.
   Never `0.0.0.0` either way (ADR 0002).
4. **Process limits from M2.** Subprocess timeouts, killing timed-out
   processes, and output-size caps ship in M2, not later.
5. **Default-deny, Runner-owned scope.** The Runner loads its own trusted
   scope file and never accepts a scope (or tier, or tool list, or raw
   arguments) from the requester. Schemas forbid unknown fields to
   enforce this at the input boundary.

6. **Minimal typed Tool Registry (approved 2026-11-04, built in M2).**
   The Runner core executes a request only by looking its tool name up
   in a small, static registry. Each entry holds exactly: the tool's
   name, its input schema (a strict Pydantic model), its action tier
   (fixed by the Runner), and a dedicated executor that builds that
   tool's argument list itself. Rules:
   - Unregistered tool name → denied and audited; nothing runs.
   - Registration happens in code, at import time — never from a
     request, config file, or the model.
   - Every registered tool still passes the Runner's independent
     default-deny scope check, timeout/kill and output caps; the core
     applies these, not each executor, so a new tool can't skip them.
   - No free-form arguments: a tool's schema is the full set of inputs.
   - Initially registers only `nmap_connect_scan`. Future tools (e.g.
     `http_request`) are added as a new schema + executor + one registry
     entry, without changing the Runner core.
   - Deliberately *not* a plugin framework: no dynamic loading, no
     entry points, no third-party tool packages.
7. **HTTP API shape (approved 2026-11-04, built in M3.2).** Two
   endpoints, **both authenticated**: `GET /v1/health` and
   `POST /v1/tools/run`. No unauthenticated endpoint exists. The HTTP
   layer authorizes nothing itself; it authenticates, bounds the request
   (size, content type, read time), and hands the raw JSON to
   `Runner.handle()`.
8. **Runner configuration and audit ownership (approved 2026-11-04,
   built in M3.1).** All settings come from the Runner's own environment
   and are validated fail-closed at startup (`avra.runner.config`):
   absolute paths, token file `0600` and owned by the Runner user,
   bind address an IPv4 literal and never a wildcard, executables not
   writable by the Runner user, existing audit log must pass hash-chain
   verification. `AuditLog.record()` is serialized by an in-process lock
   per file. That lock does **not** cover other processes, so the Runner
   must hold an exclusive OS-level lock (`avra.runner.audit_owner`,
   `<audit>.lock`) for its lifetime; a second Runner on the same log
   fails to start. The lock is advisory — it stops cooperating AVRA
   processes, not arbitrary programs; file permissions (M4) cover those.

Also fixed by design: the Runner builds the nmap argument list itself
(TCP connect scan, `-sT`, no DNS); requests carry only a canonical IPv4
literal, integer ports and a bounded timeout. No shell, ever
(`subprocess` with an argument list, `shell=False`). Tool tier is set by
the Runner (`nmap_connect_scan` = active-safe), not by the caller.

The runtime agent (Opus 5.5) reaches tools only through this Runner —
never SSH or a shell. Claude Code's SSH access to Kali (Development
Policy) is used only to deploy and debug the Runner.

## Transport security limitations (accepted, temporary)

> **Update (M4):** with the SSH-tunnel transport (decision 3, revised),
> the plaintext, server-authentication and slowloris items below no
> longer apply across the VM network — the Runner isn't on it. They
> remain true for anything already on Kali (local processes can reach
> `127.0.0.1:8765`, still token-gated) and are kept here as history.

- The bearer token and all request/response bodies travel unencrypted.
  Anything able to sniff the Host-only network could read or replay the
  token. Mitigation: that network contains only the host and the two lab
  VMs; the Runner is not bound to the Bridged interface.
- No server authentication: the client can't cryptographically verify it
  is talking to the real Runner.
- Revisit (TLS, or mutual TLS) before the Runner is ever reachable from
  any non-lab network, or if the lab gains other machines.
- **Host-only networking is not confidentiality.** It limits *who can
  reach* the Runner, not *who can read* the traffic: the Windows host,
  any process on it with packet-capture rights, and any VM attached to
  the same host-only adapter can observe the token and payloads.
  **Before M4 deployment, transport protection must be reviewed again**
  and the accepted risks re-confirmed by the owner in writing here.
- **Slow-header DoS (slowloris) — temporary host-only lab risk,
  accepted 2026-11-04, review required before M4.** Uvicorn has no
  timeout for receiving request *headers*, and the Runner caps concurrent
  connections (`limit_concurrency`), so a few connections that send
  headers very slowly can keep the Runner unavailable. Request *bodies*
  are bounded (16 KiB, 5 s read deadline) and unauthenticated requests
  never reach the body, but the header phase happens before the app is
  called and can't be fixed in the app. Exposure is limited to machines
  on the host-only network. Options if this matters later: a
  header-timeout-capable reverse proxy in front of the Runner, or
  firewall rules limiting the Runner port to the Windows host only.

## Milestones

| # | Content | Status |
|---|---|---|
| M1 | Strict request/response schemas + input validation tests | Done |
| M2 | Runner core: Tool Registry (decision 6), nmap argv builder, Runner-side scope check, timeouts/kill, output cap, audit — fake executor, no network | **Done** (commits `e603b1b`, `7dcd4f2`, `f07d1d5`, `3c217ca`). Notes at the time: In progress — M2.1 (registry + nmap argv builder) done; M2.2a (Runner scope enforcement: own scope via `AVRA_RUNNER_SCOPE_FILE`, fail closed, rejects scopes with empty `ports`/`allowed_tools`) done; M2.2b Part 1 (`SubprocessRunner`: no shell, fixed absolute executables, minimal env, timeouts + process-group kill, capped concurrent output) done, verified on Kali; M2.2b Part 2 (`Runner.handle`: audit → policy → execute → audit, `RunnerRejection`, fail closed on audit failure, no raw payload/output in audit) done |
| M3 | HTTP layer (Starlette/Uvicorn), token auth, `/v1/health`, `/v1/tools/run` | **Done** (commits `fea427f`, `19d6981`, `f9ce120`). Notes at the time: In progress — M3.1 (fail-closed `RunnerConfig`, thread-safe `AuditLog.record`, single-owner audit lock) done; M3.2 (Starlette app: bearer auth on every path, 16 KiB/5 s body bounds, generic errors, `http_rejected` audit with throttled auth failures, busy → 429) done; M3.3 (`python -m avra.runner`: config → audit-owner lock → hardened uvicorn → release; app-level 16 KiB header cap because h11's cap misses single-burst headers; uvicorn access log off so query strings never reach logs) done, verified over loopback only |
| M4 | Deploy to Kali (venv, non-root user, Runner scope file, manual start) | **Done through M4.5** (commits `418a929`, `122c5e2`, `347ad8e`, `7a71037` "M4.5 complete"; M4.6 status not recorded here). Notes at the time: In progress — M4.1 done: `--check` mode; `runner/deploy/` (fail-closed `install.sh`, `install-tunnel.sh`, sandboxed systemd unit with `IPAddressAllow=127.0.0.1 192.168.56.103`, hash-pinned requirements, README). Finding: Kali's `/usr/bin/nmap` is a wrapper adding `--privileged` for non-root and `/usr/lib/nmap/nmap` carries `cap_net_raw,cap_net_admin`; the Runner now uses the real binary and always passes `--unprivileged`. M4.3 done 2026-11-05 (owner ran `install.sh`; token placed without echo, hashes matched; `--check` exit 0). M4.4 code ready, not deployed: see "M4.4 — SSH tunnel account" below. M4.5–M4.6 not started |
| M5 | First real connect scan of `192.168.56.103:3000` — needs explicit owner approval | **Done** 2026-11-06 (owner-approved; Kali-side audit confirmed by the owner, `docs/dev-log.md`) |
| M6 | Windows-side client + CLI command, end to end | **Done** 2026-11-06 (commits `3187ea8` M6.1–M6.5, `7f62ef4` M6.6 first end-to-end CLI scan; ADR 0004) |

Out of this plan (each needs its own approval later): nmap XML parsing
(`defusedxml`), kill endpoint, TLS, systemd service, the home-lab scope
flag (ADR 0001 decision 13). *(Later status: nmap XML parsing done in M6
(ADR 0004); systemd service in M4; cancel and emergency-stop endpoints in
M8.7 (ADR 0012, deployed 2026-11-12). TLS and the home-lab scope flag are
not done.)*

## M4.4 — SSH tunnel account (2026-11-05)

Owner decisions: dedicated passphrase-free ED25519 runtime key
(`avra_runtime_ed25519`, fingerprint
`SHA256:<host-key-fingerprint>`) so AVRA can open
the tunnel unattended; staged approval of each deployment step.

Findings from reading OpenSSH 10.5p1 source (`servconf.c`,
`auth2-pubkey.c`), which replaced assumptions:

- An included file cannot leak its Match state: sshd saves it before
  each `Include` and restores it after every included file. A trailing
  `Match all` is therefore unnecessary and was not added.
- Values from matching Match blocks override globals regardless of
  position; among several matching blocks the first one read wins. The
  drop-in is installed as `10-avra-tunnel.conf` so it sorts before
  typical drop-ins (`20-systemd-userdb.conf`, `50-…`).
- `AuthorizedKeysCommand none` is accepted by the parser but not treated
  as unset (unlike e.g. `Banner none`): sshd would try to execute
  "none". Not used. Instead `AuthorizedKeysFile` is pinned in the Match
  block, and every sshd-level restriction applies to the account
  whichever key source is used. The global
  `AuthorizedKeysCommand userdbctl …` on Kali returns nothing for a
  plain system user.

Installer safeguards added: drop-in must be exactly one
`Match User avra-tunnel` block; refuse if `ssh.service` is inactive or
any sshd file already mentions `avra-tunnel`; 16 effective settings
checked for avra-tunnel from two source addresses; **byte-identical
before/after `sshd -T` snapshot** of the global config and of every
login-capable user from two addresses, checked before reload; reload
(never restart) and an `is-active` check after it; transactional
rollback as before.

Verification: `verify_tunnel.py` (Windows, stdlib) triggers every
forwarding request by connecting to the local listener and classifies
the `ssh -v` log into auth / listener / request-sent / server verdict,
so a local listener can never be mistaken for server authorization.
`test_tunnel_sshd_effective.py` runs the real `sshd -T` against a temp
copy of a Kali-like config (skipped on Windows; runs on Kali in M4.5).

Accepted risk: a passphrase-free key on Windows. Bounded by
`from="192.168.56.1"`, `permitopen="127.0.0.1:8765"`, `restrict`,
`ForceCommand nologin`, and the Runner token.

### M4.4 stage 4 failure and fix (2026-11-06)

The first live run of `install-tunnel.sh` stopped at step 4/5 with
"effective sshd setting missing … authenticationmethods publickey" and
rolled back cleanly (user, home and drop-in removed; the original config
was reloaded by the rollback; sshd never restarted).

Root cause: a wrong verification assumption, not a configuration
problem. OpenSSH 10.5p1's `sshd -T` prints keywords in canonical case
(`AuthenticationMethods publickey`); older releases print lower case.
The check grepped for exact lower-case lines. Reproduced on Kali as
`kali` (no sudo) with a temp copy of the live config: the Match block
matched and all 16 restrictions were in effect.

Fix: compare the keyword case-insensitively (lower-case the first field
only) and the value exactly, as a fixed-string whole-line match (it was
a regex before, so `.` in `127.0.0.1:8765` matched any character).
Restrictions and the before/after snapshot are unchanged. Regression
tests use real `sshd -T` output captured from OpenSSH 10.5p1 on the lab
VM (`tests/fixtures/sshd/`; in this public repository they are synthetic
equivalents in the same canonical form). The real-`sshd` test module had the same
assumption and now normalizes keywords the same way.

### M4.5 — live tunnel verification (2026-11-06)

All mandatory tunnel checks passed against the deployed account (details:
dev-log). Two findings about the evidence itself, both fixed in
`verify_tunnel.py`: (1) OpenSSH answers a *refused* direct-streamlocal
forward with the generic `connect failed: open failed` (not
"administratively prohibited"), indistinguishable client-side from a
failed connect — the verifier reports INCONCLUSIVE and the decisive
evidence is the server's `refused streamlocal port forward` log line;
(2) the Bridged-IP check must pin the host key via `HostKeyAlias`, or it
stops at host-key verification and never tests `from=`.

Open hardening items (not done, each needs approval): PAM starts a
systemd user manager for every tunnel login (`pam_systemd`); global SSH
authentication settings for the VM's other (non-tunnel) accounts are
tracked privately.

### M4.5 — Runner API and completion (2026-11-06)

Through the tunnel: authenticated health 200, unauthenticated / wrong
token 401, out-of-scope `ports:[22]` 403 at the policy stage with no
execution. **Finding:** `systemctl stop` wrote no `runner_stopped`
record — uvicorn re-raises the captured signal after its graceful
shutdown and, with default handlers restored, the process died before
`RunnerServer.run()` could record the stop (the audit-owner lock is an
flock, so the kernel still released it). Fix: `RunnerServer` installs
SIGTERM/SIGINT handlers around `server.run()` that only request a stop,
so the re-raised signal is harmless. Regression test runs a real Runner
in a child process and raises the signal. Deploying the fix needs a new
wheel on Kali (upgrade procedure, separate approval).

M4.5 is complete. Deferred, not run (non-blocking for M5): full test
suite on Kali in a throwaway venv (CRLF-guard and real-`sshd -T` tests);
`: > audit` truncation refused for `avra-runner`; second-instance exit 3;
`systemctl kill -s KILL` then restart with chain verification;
`systemctl show` sandbox properties.
