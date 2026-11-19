# ADR 0018 — M10.5 Read-only fetch of one discovered path (`http_get_path`)

_Status: Accepted for offline implementation (2026-11-13, owner's "M10.5 → M11" sprint
brief). Implemented and tested offline. **Deployed** on Kali by the owner on 2026-11-13 (see "Deployment"); no live
fetch has been run yet._

## Context

M10.1 lists what recorded responses *reference* (`referenced_not_fetched`). Nothing could
confirm that a referenced path exists, so research stopped at `GET /`.

## Decision

A new Runner tool **`http_get_path`**: one fixed `GET <path> HTTP/1.0` to one in-scope
IPv4 host and port.

**Request (`HttpGetPathRequest`).**
- Fields: `host`, `port`, `path`, `timeout_seconds`.
- No method, URL, header, body, query, scheme or proxy field. Unknown fields are refused.

**Path rules (`validate_http_path`).** Shared by the request schema, the scope schema, the
child program and the envelope parser. The path must:
- start with `/` and be at most 200 characters;
- use URL-safe characters only, so a query string, fragment, space or control character
  is impossible;
- contain no `//`, no `.` or `..` segment, and no backslash;
- not percent-encode `.`, `/`, `\`, `%` or NUL, and have no malformed `%` escape.

The server and the scope check therefore cannot disagree about which path is meant.

**Scope.**
- The tool has its own name: allowing `http_probe` does not allow path fetches.
- A target may list `http_paths` (prefixes). `http_get_path` needs a prefix match;
  an empty list means default deny.
  - `/api` allows `/api` and `/api/x`, never `/apix`.
  - `/app/` allows `/app/x`.
- Both the Windows check (`authorize_tool_request`) and the Runner's own check
  (`RunnerPolicy.check`) apply the path through the registry's `scope_path`.
- The host must be a canonical IPv4 literal. Loopback, link-local (including
  `169.254.169.254` metadata), multicast and reserved addresses are refused, as for
  every tool.

**Execution.**
- The same `avra-http-probe` child with a new `--path` argument (raw IPv4 socket, no
  DNS, no proxy, no retries).
- Exactly one request, then one bounded read (256 KiB, 30 s maximum).
- **Redirects are recorded, never followed.** An off-scope `Location` (for example the
  metadata service) appears in the web surface as an external origin.
- The envelope (`avra-http-get-path/1`) carries the path. On Windows it must pair with
  the request: same path, and request bytes exactly `request_bytes(host, port, path)`.

**Pipeline.**
- `run_http_probe(..., path=...)`, with the same gates as the probe: local scope,
  `APPROVAL_INTERACTIVE_TTY` only, kill switch, terminal audit records.
- Evidence is write-once and hash-checked. `tool_request_sent` and
  `tool_result_received` record the path.

**Evidence and rules.**
- `HttpObservation.path` is recorded.
- The header rules judge only the `GET /` response; a fetched path is "not the GET /
  response".
- The web surface marks a path `fetched` with its HTTP status and evidence id, adds
  references found in the fetched content (resolved relative to that path), and keeps
  `referenced_not_fetched` for the rest.

**Research loop (opt-in).** `avra research --verification --web-research --allow-http-get`
offers `propose_http_get_path` (prompt suffix `+get`). Gates, in order, before the owner is
asked:
1. duplicate check;
2. tool-run budget;
3. **the path must be in the recorded web surface** (the model cannot invent targets);
4. scope check (tool + prefix);
5. kill switch.

Then come the owner's approval in a real terminal, the kill switch again, and the pipeline.
- After a fetch, the engine, the surface and the board refresh; a run that adds no
  evidence is flagged.
- The board suggests `http_get_path` as the next action for an observed, unfetched
  endpoint hypothesis.
- Owner command: `avra probe http --path /x` (same interactive confirmation; no `--yes`).

**Reporting.**
- The trace shows the path and HTTP status of each fetch.
- Reports and chat keep these apart:
  - referenced endpoint;
  - fetched endpoint;
  - verified observation;
  - configuration weakness;
  - unverified hypothesis;
  - confirmed vulnerability.
- A 200 response proves only that the path answers.

## Deployment (DONE by the owner, 2026-11-13: wheel `69613f69…`, scope `7f2ad34a…`, snapshot `AVRA-M10.5-PreDeploy`; first live fetch not yet run)

1. Build the wheel from this commit with LF endings (`runner/deploy/README.md`, "Offline
   wheel-only upgrade") into `dist/m10.5/`, and record its SHA-256.
2. Owner, on Kali (sudo): back up, then install the wheel exactly as in that procedure,
   run `--check`, and restart `avra-runner`.
   - No new executable: `http_get_path` uses the existing `AVRA_RUNNER_EXEC_HTTP_PROBE`
     child.
   - `runner.env` and the systemd unit are unchanged.
3. Owner: add to the Kali Runner scope for `192.168.56.103:3000`, tier `passive`:
   - `http_get_path` in `allowed_tools`;
   - a narrow `http_paths` list, for example `["/main.js", "/rest/", "/api/"]`.

   Mirror this in the Windows scope file used with `avra research`.
4. Until then the deployed Runner refuses the request (`unknown_tool`), and the old
   child refuses `--path` (usage error). Both fail closed.

## Tests

`tests/verification/test_m105_http_get_path.py` (44 tests) covers:
- path validation, prefix semantics, both scope checks, and metadata/loopback hosts;
- the child's single fixed request, argv and envelope pairing;
- the pipeline end to end over a scripted socket, the evidence loader and the surface;
- that header rules ignore non-root fetches;
- that an off-scope redirect is recorded and never followed;
- refusals without a prefix or approval;
- research-loop gates: not in the surface, scope, owner decline, duplicate, opt-in;
- the board suggestion.

The registry's pinned tool lists were updated (`test_runner_registry.py`,
`test_runner_http.py`).
