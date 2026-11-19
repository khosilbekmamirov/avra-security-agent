# ADR 0007 — Typed HTTP probe (Track A, M8.1)

_Status: **Accepted** (2026-11-09) — implemented offline (M8.1), deployed
to the Kali Runner (M8.2), owner CLI entry point and first owner-approved
live probe (M8.3, session `7e868faf-768d-49af-aea6-81dc9d435e20`). Every
acceptance item at the end is checked. Not exposed to the model; the Kali
Runner scope entry was rolled back after the run (default deny again)._

## Context

AVRA's only tool is `nmap_connect_scan` (`-sT`): it proves a TCP port is
open, never what answers. The next safe step towards service
identification is one fixed, passive HTTP request with the exact bytes
kept as evidence (M8 Stage 0; owner decisions: HTTP probe first, no
`nmap -sV`, per-action approval, no home-lab autonomy).

## Decision

### 1. Request contract (closed, nothing model-shaped)

`HttpProbeRequest` (strict Pydantic, unknown fields forbidden):

| Field | Rule |
|---|---|
| `tool` | literal `http_probe` |
| `request_id`, `session_id` | UUIDs |
| `host` | canonical **IPv4 literal** (same `validate_ipv4_target` as nmap: no hostnames, no loopback/multicast/link-local/reserved/broadcast) |
| `port` | one strict integer 1–65535 |
| `timeout_seconds` | strict integer 1–30 (default 10): total wall-clock budget of the probe |

There is **no** method, path, URL, header, body, scheme or proxy field. The
probe always sends exactly (HTTP/1.0 so the server does not chunk; `Host`
is the IP literal, never a name):

```
GET / HTTP/1.0\r\n
Host: <ip>:<port>\r\n
User-Agent: AVRA-http-probe/1 (owner-authorized lab)\r\n
Accept: */*\r\n
Connection: close\r\n
\r\n
```

Plain HTTP only (HTTPS needs its own design). No DNS (a raw `AF_INET`
socket connected to the literal), no proxy (no HTTP library; the child
environment is the Runner's minimal one), no redirect following (one
request, `Location` only recorded), **zero retries**.

### 2. Tool registration and enforcement

- Registry entry `http_probe`, **tier `passive`** (`docs/security.md`:
  "Plain GET requests"), scope target `(host, port)`.
- Default deny on both sides: the Windows client and the Runner each check
  the request against their own scope (tool, tier, host, port). No scope
  file lists `http_probe` today, so every request is denied until the owner
  adds it (separate approval). Per-action owner approval stays mandatory
  when it is later used; no home-lab autonomy.
- Executed like every Runner tool: a sandboxed subprocess (the systemd
  unit's `IPAddressAllow`, no capabilities, minimal environment, timeout +
  kill, capped output), fixed argv built by the registry:
  `http_probe --host <ip> --port <n> --timeout <s>`. Logical executable
  `http_probe` → trusted path `AVRA_RUNNER_EXEC_HTTP_PROBE` (console script
  `avra-http-probe`). The Runner refuses to start without it (fail closed).

### 3. Limits

| Limit | Value |
|---|---|
| Total probe time | `timeout_seconds` (≤ 30 s); Runner kills the process 10 s later |
| Connection attempts | 1 |
| Response bytes read | ≤ 262 144 (256 KiB), then stop: `truncated=true` |
| Header section (parse) | ≤ 16 384 bytes, ≤ 100 header lines, value ≤ 1 024 chars kept |
| Title | first `<title>` in the first 64 KiB of an HTML body, ≤ 200 chars |

### 4. Evidence: exact bytes, hashed, paired

The child prints one **pure-ASCII JSON envelope** (`format`
`avra-http-probe/1`): host, port, outcome, error class, the exact request
and response bytes **base64-encoded**, their SHA-256, byte counts,
`truncated`, `complete`, elapsed ms. ASCII means the Runner's UTF-8 handling
cannot alter a byte; the Runner hashes the envelope (`output_sha256`), the
Windows client re-checks that hash, stores the envelope as write-once
evidence `<request_id>.json`, then verifies: base64 decodes to bytes with
the stated SHA-256, the request bytes equal the fixed request for exactly
this host and port (pairing), and host/port equal the request's.

### 5. Interpretation (Windows side, deterministic, from evidence only)

Outcomes: `response_received`, `connection_refused`, `connect_timeout`,
`read_timeout` (partial bytes kept), `connection_reset`, `network_error`
(the last two keep any bytes received before the failure; only
`connection_refused`/`connect_timeout` must carry none). The envelope is
rejected on duplicate JSON keys, oversized integers, or flags that
contradict each other (`complete`/`truncated`/`outcome`/`error`, byte cap).
The parser records, never "repairs": status line validity, HTTP version,
status code, bounded reason, bounded headers, declared vs actual body
length, `is_redirect` + `Location` (not followed), binary content (NUL
bytes / non-text type), malformed reasons (bad status line, oversized or
unterminated header section, bad header line, truncated body, undecodable
text — decoded with replacement, never raised; conflicting
`Content-Length`, or any `Transfer-Encoding` — forbidden in a reply to
HTTP/1.0 — with the body kept as raw, undecoded bytes). The `<title>` scan
is a linear `find`, not a backtracking regex.

**Service-identity evidence, not identity:**

- `protocol_observed` — a syntactically valid HTTP status line came back
  from that `host:port`. This is the only thing the probe *establishes*.
- `indications` — **tentative, server-controlled** strings (`Server`,
  `X-Powered-By` headers, HTML `<title>`), each with its source. They are
  claims made by the server and are never treated as a confirmed product,
  version or vulnerability. A status code, banner or title alone never
  produces a finding.
- All server-controlled text is data: bounded, control characters
  escaped, never interpreted, never executed, never sent to the model in
  M8.1 (the tool is not in the model's tool list).

### 6. Audit

Runner side unchanged (`request_received`, `execution_started` with argv,
`execution_finished` with stdout hash). Windows side records
`tool_request_sent` and `tool_result_received` with outcome, status code,
hashes, byte counts, flags and indication *sources* — not header or body
text (that stays in the evidence file).

## Not in scope of M8.1

Deployment (M8.2), any scope change, live request (M8.3), CLI/model
exposure, report schema change (service identity in reports, M8.4), HTTPS,
other paths or methods, `nmap -sV`.

## Consequences

- New required Runner config variable `AVRA_RUNNER_EXEC_HTTP_PROBE`; the
  deployed Kali Runner must be upgraded with it (M8.2) or it refuses to
  start. `runner/deploy/runner.env.example` is updated in M8.2.
- Banner/title data can be spoofed by the server; only `protocol_observed`
  is relied on.
- A server that never closes the connection is cut at the timeout or byte
  cap (recorded as `read_timeout`/`truncated`).

## M8.3 — owner entry point and acceptance checklist

`avra probe http --scope … --host … --port … [--timeout 1-30]` is the only
way to send a probe. It refuses to run without an interactive terminal on
both ends (exit 2; no piping), has **no `--yes`**, shows the target, the
exact fixed request bytes and the Windows scope decision first, and asks
`Send this request?` with default **No** (EOF/Ctrl+C = No). A scope
denial never prompts; the denial is audited and nothing is sent. The
pipeline independently refuses any in-scope request whose `approval` is
not exactly `interactive_tty_confirm`, and records that value in
`tool_request_sent` only for a request the owner approved. The approval is
a terminal confirmation, not a cryptographic signature. The `nmap-connect`
command is unchanged.

Acceptance — all checked 2026-11-09, session
`7e868faf-768d-49af-aea6-81dc9d435e20`, request
`5c746502-d2e2-44a8-9180-c24cfa7c859c`:

- [x] CLI: TTY-only, explicit yes, no bypass; offline tests pass
      (`d17742e`; 13 CLI + 5 pipeline approval tests).
- [x] Scopes: dedicated gitignored Windows scope
      `scope/juice-shop.http-probe.scope.yaml` (only
      `192.168.56.103:3000`, `passive`, `http_probe`, expires 2026-11-30;
      research scope unchanged `52e28ed0…`, so the model never sees the
      tool). Kali Runner scope: second target entry appended by the owner
      (`ac4b8b18…` → `8e556f36…`, nmap entry byte-identical); owner policy
      check PASS (probe allowed only on .103:3000, nmap unchanged, other
      ports/hosts denied); scope hash re-confirmed in the post-run check.
- [x] Exactly one live request: Windows audit seq 1–3 `session_created` →
      `tool_request_sent` (`approval: interactive_tty_confirm`) →
      `tool_result_received`; no other session or evidence created that
      day; Kali audit seq 29–33 `runner_started` → `request_received` →
      `execution_started` (fixed argv, tier `passive`) →
      `execution_finished` (completed, exit 0) → `runner_stopped`; the
      only `http_probe` execution in the Kali log.
- [x] Evidence: request bytes equal the fixed request (sha256
      `0d989ff3…`); evidence sha256 `45985be6…1ea9` = Runner
      `output_sha256` = Kali `stdout_sha256`; response sha256 `6a8b7550…`,
      9,832 bytes, complete, not truncated.
- [x] Facts: HTTP/1.1 200, `text/html`, `protocol_observed`, body 9,393
      bytes = `Content-Length`, nothing malformed; only indication
      `html:title` = "OWASP Juice Shop", tentative; identity level stays
      `protocol_observed` — no product, version or vulnerability claim.
- [x] Both audit chains `verify()` True and contiguous (Windows 3 records;
      Kali 33 records, owner-run check).
- [x] `avra-runner` (inactive, disabled) and `juiceshop` (exited) stopped
      afterwards. Owner decision: Kali scope entry **reverted** to the
      original `ac4b8b181829b6ee6c9eb84b0749710402ca7b7433b29ccdc6c59d0ee64b4602`
      (owner-verified; `kali` cannot read the file). The Windows probe
      scope stays until it expires 2026-11-30 (inert while Kali denies).
- [x] Status DRAFT → Accepted, citing the session ID.

Remaining limits (accepted): plain HTTP, `GET /` only; banner/title are
server-controlled claims; the approval marker proves a terminal
confirmation on this Windows account, not the owner's identity (the audit
chain is unsigned, Track B); not exposed to the model (any exposure is a
separate decision with an eval baseline review); one live sample only.
