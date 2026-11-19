# ADR 0005 — Model in the loop: proposals only (Phase 3 start, M7)

_Status: accepted 2026-11-06 (owner). M7.1–M7.8 implemented and verified
live in the lab (see "Live results" at the end); M7.8 final verdict PASS
WITH WARNINGS (2026-11-08). Next: M7.9 (report integrity & accuracy)._

## Decisions (owner)

1. Official `anthropic` Python SDK, pinned `anthropic==2.6.0` (pulls in
   `httpx2`, `jiter`, `sniffio`, `truststore`, `opentelemetry-api`).
2. Model `claude-opus-5-5`, configurable; effort `medium` (set explicitly —
   it is this model's default too, and thinking can't be disabled on it).
3. API key: `ANTHROPIC_API_KEY` in the gitignored `.env` (or environment),
   passed explicitly to the SDK so no other credential source is used.
4. Session defaults: **$0.50 budget, 10 model steps**; also 5 executed tool
   runs and 30 minutes (all bounded in `SessionLimits`).
5. **No refusal fallback.** `client.messages.create` (non-beta) has no
   `fallbacks` parameter; a `refusal` is audited (category, explanation)
   and the session stops. Never retried on another model (CLAUDE.md).
6. **Owner approval before every executable tool request.** No `--yes` on
   `avra research`. (ADR 0001 decision 13's home-lab autonomy needs the
   scope-schema flag, which is still not built.)

## The boundary: the model proposes, code decides

| Model may | Model may not |
|---|---|
| `propose_nmap_connect_scan(host, ports, timeout_seconds, explanation)` | run anything, name flags, build commands, reach a shell |
| `record_observation`, `record_hypothesis` (stored as **unverified**) | set a finding's status |
| `finish_session(summary)` | change scope, budget, tier or approval rules |

Per proposal: strict Pydantic validation → duplicate check → tool-run
limit → Windows-side scope policy (`authorize_tool_request`; denied →
returned to the model, owner never asked) → **owner sees the explanation
and approves or declines** → the unchanged M6 pipeline
(`run_nmap_connect_scan`: local policy again, fail-closed audit, tunnel,
Runner's own policy, hash/evidence/parse). Results return to the model as
a structured summary (no raw XML) inside `<untrusted_tool_output>`, JSON
with `<`/`>` escaped so the data cannot close the wrapper.

## Cost control

- Before every call: `messages.count_tokens` → worst case = counted input
  × the dearest input rate (cache write) + full `max_tokens` (4096) of
  output. If it exceeds the remaining budget the call is not sent
  (`budget_stop`). After the call, actual `usage` (input, output, cache
  write, cache read) is priced and added. Prices: `avra.llm.config.PRICES`
  ($4 / $20 / $5 / $0.20 per MTok for Opus 5.5), updated by hand.
- Every call is audited: model, request id, effort, prompt version,
  stop reason, usage, cost, running total. The CLI prints the session
  total and token breakdown.
- SDK retries bounded (allowed 0–3), 120 s per request. Default `0` since
  2026-11-07 (owner, before M7.6): a failed or timed-out attempt returns no
  usage, so a retried attempt could be billed without being counted.
- First user message carries the owner's validated authorization context:
  the scope-level `description` (environment) and each target's `description`
  are sent as factual DATA (the system prompt says to treat them as data, not
  instructions) and are never consulted by the ScopeChecker, so they cannot
  grant or widen authorization (M7.7).
- Prompt caching: frozen, versioned system prompt (`m7-v2`: adds the
  authorized-context framing and an accurate `active-safe` tier description) +
  fixed tool
  list; top-level `cache_control: ephemeral`.
- `max_tokens` stop → no tool runs, session stops (truncated tool input is
  never executed).

## Alternatives considered

- SDK Tool Runner (beta helper): rejected for now — a manual loop keeps the
  policy and approval gates in our code and avoids a beta dependency.
- Server-side refusal fallback: rejected (CLAUDE.md, owner decision 5).
- Sending raw nmap XML to the model: rejected — more tokens and a larger
  prompt-injection surface; the parsed summary carries what's needed.

## Consequences / risks

- With $0.50 and a 4096-token output cap, the worst-case estimate (~$0.10
  per call at ~3k input tokens) can stop a session after ~4–5 calls even
  when actual spend is lower; that's the intended conservative behaviour.
- `max_tokens` 4096 includes thinking at effort `medium`; if sessions stop
  with `max_tokens`, raise it (it also raises the per-call worst case).
- Tests use a scripted fake provider and real SDK types — the first real
  API behaviour is only seen in M7.6.

## Live results (M7.6–M7.8)

All sessions: lab only (`192.168.56.103:3000`, `nmap_connect_scan`,
`active-safe`), `claude-opus-5-5`, effort `medium`, $0.50 budget, 5 steps,
5 tool runs, 30 min, SDK retries 0, fallbacks disabled.

| Date | Session | Prompt | Outcome | Cost (USD) |
|---|---|---|---|---|
| 2026-11-07 | `5ca44629…` | m7-v1 | `refusal` (category `cyber`) at step 1; stopped, nothing ran, not retried | 0.007861 |
| 2026-11-07 | `f2ebab88…` | m7-v2 | `finished`, 4 calls, 1 owner-approved scan, 3000/tcp open | 0.035853 |
| 2026-11-08 | `4460bea8-d974-406c-bb65-75c3be0a899f` | m7-v2 | `finished`, 4 calls, 1 owner-approved scan, 3000/tcp open; report PASS | 0.035976 |

The refusal was handled exactly as decision 5 requires (audited, session
stopped, no other model). The response was M7.7: the authorized-context
framing (scope `description` fields as data) and prompt `m7-v2`, which
grant no authorization.

**M7.8 Stage 5 (2026-11-08) — final verdict PASS WITH WARNINGS.**
Offline before the live run: 677 passed / 20 skipped (skips are
POSIX/Kali-only), eval baseline 22/22. Session `4460bea8`:

- Verified (evidence-backed): host up; 3000/tcp `open` (`syn-ack`);
  evidence `19f10bf3-…xml` SHA-256 `94f5813a…df9` = audit = Runner hash;
  nmap argv exactly the fixed flags (`--unprivileged -sT -Pn -n
  --max-retries 1 --host-timeout 60s -p 3000`); owner approval logged
  before the request, and the request id is only created after approval.
- Not verified: the service identity. nmap's `ppp` label is a port-table
  guess (`method=table`, `conf=3`, `service_identified=false`). "OWASP
  Juice Shop (Node.js HTTP)" is the model's **unverified hypothesis**
  (based on the scope description and the default port). No vulnerability
  was tested or found.
- Windows audit: 14 events, chain valid. Kali Runner audit: 26 events,
  chain valid, contiguous; the request is events 24–26; no denial or error
  events. Report rebuilt offline from audit + evidence = stored report;
  passive validator PASS; four tamper controls → INVALID as expected.
- Cost reconciles exactly: tokens in 10 / out 962 / cache write 3041 /
  cache read 7453 → $0.035976.

Known defects (to fix in M7.9 — Report Integrity & Accuracy):

- **D1** `evidence_confidence=supported` is set by any verified open port;
  it ignores service identity, so it can overstate a "which services"
  answer.
- **D2** Report generation and its hash are not in the audit chain; the
  report is written with a plain overwrite after `research_stopped`.
- **D3** Free-text model claims are not checked (by design; the summary is
  non-authoritative).
- **D4** Report lacks metadata (timestamp, model, prompt version, cost).
- **D5** The report reads the *current* scope file; enforced fields and a
  scope hash are not in the audit, so a later scope edit breaks
  byte-exact rebuilds.
- **D6** `write_text` on Windows converts LF to CRLF; any report hash must
  cover the exact bytes written.

Status (2026-11-08): D2 and D6 fixed in M7.9.1, D4 and D5 fixed in M7.9.2
(ADR 0006: attested report storage, scope snapshot, schema-2 metadata,
offline replay, `avra report verify`). D1 and D3 remain open.
