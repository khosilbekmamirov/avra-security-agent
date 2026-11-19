# ADR 0004 — Windows-side Runner client (Phase 2, M6)

_Status: accepted 2026-11-06 (owner). Implements M6.1–M6.5 of ADR 0003._

## Context

M5 proved the chain by hand (a scratch script): SSH tunnel → Runner API →
nmap → raw XML with a verified hash. M6 makes that chain a tested part of
the Orchestrator, with the Windows side enforcing its own policy and audit
instead of trusting the Runner (docs/architecture.md §8).

## Decisions (owner, 2026-11-06)

1. **HTTP client: stdlib `urllib`.** No new runtime dependency. The client
   only talks to `http://127.0.0.1:<port>` (the tunnel's local end), ignores
   proxy environment variables (the token must never reach a proxy) and
   never follows redirects.
2. **XML parser: `defusedxml==0.7.1`** (new runtime dependency). nmap output
   comes back from the lab and is treated as untrusted; defusedxml blocks
   entity expansion and external entities. Pure Python, no transitive deps.
3. **Token: the existing gitignored `.env`** (`AVRA_RUNNER_TOKEN`, or the
   same variable in the environment). Held in `RunnerToken`, whose repr/str
   are redacted; never logged, audited, or included in error messages.
   Windows Credential Manager may replace this later (separate decision).
4. **Runner lifecycle: manual.** The owner starts/stops `avra-runner` on
   Kali; the client only checks `/v1/health` before sending.

## Design

| Module | Role |
|---|---|
| `avra.runner_client.tunnel` | `SshTunnel`: fixed ssh argv (the M4.5-proven options), remote end constant `127.0.0.1:8765`, local end a free loopback port, ready = ssh `-v` "Local forwarding listening on 127.0.0.1 port <that port>". |
| `avra.runner_client.client` | `RunnerClient`: health + run; responses validated with the Runner's own strict schemas; request_id must match; output hash re-checked; response size capped. |
| `avra.policy.tools` | `authorize_tool_request`: Windows-side default-deny check of every (host, port) with the tool's tier and targets taken from the **same static Tool Registry** the Runner uses. |
| `avra.recon.nmap_xml` | `parse_nmap_xml` → typed `NmapReport`/`PortResult`; incomplete or unsafe XML is an error, never a partial result. Port states are observations, not findings. |
| `avra.storage.evidence` | Raw output stored once per request (exclusive create), named only from UUIDs, SHA-256 returned. |
| `avra.runner_client.scan` | One run: local policy → audit `tool_request_sent` (fail closed) → tunnel → health → run → verify → evidence → parse → audit `tool_result_received` (hashes, port states, evidence path; never token or raw output). |
| CLI `avra scan nmap-connect` | Shows tool/target/tunnel/scope, asks for confirmation (unless `--yes`), runs the above in a new or existing session. |

Audit events (per-session log `data/sessions/<id>.jsonl`):
`tool_request_denied_locally`, `tool_request_sent`, `tool_request_rejected`
(Runner refused; stage + reason), `tool_request_failed` (tunnel/transport),
`tool_result_received`.

## Consequences

- Two independent scope checks: Windows (the scope file passed with
  `--scope`) and Kali (the Runner's own). They can only disagree towards
  "denied".
- `runner/deploy/verify_tunnel.py` keeps its own copy of the ssh options so
  it stays runnable without the package (deploy tool); the two must be kept
  in step.
- No Anthropic API calls in M6 — the model is not involved yet.
- M6.6 (first live end-to-end run through the CLI) needs explicit owner
  approval, like every scan.

## Result (2026-11-06)

M6.6 run by the owner through the CLI: one scan of `192.168.56.103:3000`
→ `completed`, exit 0, hash verified, `open (syn-ack)`; Windows audit
chain intact; evidence bytes match the Runner's `output_sha256`. M6 is
complete on the Windows side; the Runner-side audit records are checked
by the owner (sudo).
