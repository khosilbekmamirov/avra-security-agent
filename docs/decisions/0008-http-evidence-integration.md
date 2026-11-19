# ADR 0008 — HTTP evidence integration (M8.4)

_Status: **Accepted** (2026-11-09). The owner accepted the recommended
answer to every open decision: D1 (a) no model exposure, D2 report
schema 5, D3 probes only before the session's first report, D4 offline
acceptance with the recorded M8.3 evidence and no live run. Design only;
nothing is implemented yet._

_Update 2026-11-09: the owner's M8.4 mandate re-scoped M8.4 to the
Verification Engine (ADR 0009). ADR 0009 delivers §1 (a typed, hash-bound
HTTP observation built only from verified evidence) inside
`avra.verification.evidence`, without changing `replay.py` or the report
schema. §2 (replay dispatch by tool), §3 (schema 5) and the claim-check
extension remain open and are the candidate next milestone. D1–D4 stand._

## Context

M8.1–M8.3 (ADR 0007) delivered a typed, owner-only HTTP probe. Its result
is stored as write-once evidence (`<request_id>.json`, envelope
`avra-http-probe/1`) and parsed deterministically into `HttpResponseFacts`
(`src/avra/recon/http_probe.py`). The only fact the probe establishes is
`protocol_observed`. `Server`, `X-Powered-By` and `<title>` are tentative
`indications` controlled by the server.

Today none of this reaches a research report:

- Reports (schema 4) have `service_identity`, but nothing can set it to
  anything other than `unidentified` or `not_applicable`. No probe result
  feeds into it.
- `reporting/replay.py` rebuilds a report from audit + evidence. It treats
  **every** `tool_request_sent` as an `NmapConnectScanRequest`
  (`_request()` reads `ports`). An `http_probe` event in the same run would
  fail replay or be misread. This must be fixed before probes and reports
  can share a session.
- The research model has no HTTP tool and sees no HTTP facts.

The owner's direction (2026-11-09): M8.4 connects existing HTTP evidence
to the research/report path **without** confirming anything as a
vulnerability. M8.5 (Verification Engine core) and M8.6 (first lab
verification) come after. M8.4 must therefore produce evidence records that
M8.5 can consume without a redesign.

## Decision (proposed)

### 1. A typed, hash-bound HTTP observation

A new frozen, `extra="forbid"` record, built **only** from verified
evidence:

| Field | Source |
|---|---|
| `request_id`, `session_id` | audit `tool_request_sent` / `tool_result_received` |
| `host`, `port` | request (must equal the envelope's) |
| `evidence_sha256` | audit record; re-checked against the file bytes |
| `outcome` | envelope (`response_received`, `connection_refused`, …) |
| `facts` | `HttpResponseFacts`, re-parsed from the evidence bytes, never copied from the audit |

Rules:

- Built by replaying the audit chain and re-reading the evidence file. If
  the hash does not match, or the request/response pairing fails, the
  observation is **rejected** and reported as a problem. It is never
  "repaired". This is the same rule as nmap evidence today
  (`check_evidence`).
- It carries no free text from the model. Server-controlled strings stay
  bounded and escaped, as `parse_http_response` already does.
- It is an *observation*, not a finding. It has no severity and no
  vulnerability status.

### 2. Replay distinguishes tools

`replay.py` dispatches on the audit event's `tool` field (`nmap_connect_scan`
or `http_probe`), using that tool's typed request schema. An unknown tool
causes replay to fail closed. Reports already recorded with schemas 1–4
must still rebuild byte-for-byte (regression tests on existing fixtures).

### 3. Report: per-port protocol evidence (schema 5)

- Each verified open port gets `identity_level`: `none` or
  `protocol_observed`, with the `request_id` of the probe that established
  it.
- The aggregate `service_identity` counts a port as identified **only at
  protocol level**: "something on this port speaks HTTP". The report text
  states that no product, version or vulnerability was identified.
- `indications` are shown in a separate "server claims (unverified)"
  section with their source. They never change `service_identity`,
  `evidence_confidence` or any status.
- A probe whose `host:port` is not a verified open port in the same run is
  still listed, as "probe outside scanned ports". It does not change
  exposure.
- `claims.py` reference checks learn HTTP `request_id`s, so a model note
  citing a probe resolves (or is flagged) like an nmap reference.

### 4. Ordering of probes and research in a session

The owner runs `avra probe http --session <id>` on an existing session. The
report for that session is (re)generated afterwards and covers the audit
chain up to `report_generated`. **D3** decides whether probes are allowed
only between runs or also after a report has been published.

### 5. Model exposure — **D1, owner decision**

| Option | What the model sees | Risk | Cost |
|---|---|---|---|
| **a. None in M8.4 (recommended)** | Nothing new. Observations reach only the deterministic report. | None added | 0 API tokens |
| b. Structured fields only | status, header *names*, content type, sizes, hashes, `identity_level` | Low: no server text | small |
| c. + server text excerpt, marked untrusted | (b) + bounded `Server`/title/body excerpt | **Prompt injection** from the target; spoofed banners | higher |

Recommendation: **(a)** for M8.4. It keeps M8.4 free of LLM code and of
new attack surface. Exposure to the model is decided together with M8.5,
once the Verification Engine defines what the model may *propose* about an
observation. Option (c) is not recommended at any stage without a separate
ADR.

## Not in scope of M8.4

- Any new tool, any change to the Runner, its policy, the scope files or
  tiers.
- The model requesting probes (no new model tool).
- Any live request. Tests use fixtures and the recorded M8.3 evidence
  copied as a fixture. **D4** decides whether one live acceptance run is
  wanted at the end.
- `confirmed` / `rejected` statuses, severity, CVE/CWE mapping (M8.5+).
- HTTPS, other paths or methods, following redirects.

## Owner decisions (answered 2026-11-09: recommended option for each)

- **D1** — Model exposure: (a) / (b) / (c) above. Recommended: (a).
- **D2** — Report schema 5 as described in §3. The alternative is keeping
  schema 4 and putting HTTP data in an appendix outside the attested
  report, which is weaker because it is not covered by `avra report
  verify`. Recommended: schema 5.
- **D3** — Probes only before the session's first report, or also later
  (later means a new report version supersedes the old one). Recommended:
  before the first report only. It is simpler and nothing published
  changes meaning.
- **D4** — Acceptance: offline only, or plus one owner-approved live run
  that repeats M8.3 inside a research session. Recommended: offline plus
  replay of the M8.3 evidence. A live run only if the owner wants it, under
  the M8.3 per-action approval and scope rollback.

## Risks

- **Replay regression** — changing `replay.py` could alter how old reports
  rebuild. Mitigation: byte-for-byte regression tests on stored schema 1–4
  fixtures before any change.
- **Over-reading the probe** — "HTTP observed" could be read as "service
  identified". Mitigation: wording fixed in the schema and checked by
  tests.
- **Spoofed indications** — the server controls them. Mitigation: shown
  only as unverified claims, never used in any status.
- **Scope creep into M8.5** — no verdicts in M8.4. Mitigation: no status
  field exists on the observation.

## Consequences

- Reports can, for the first time, say *what kind of thing* answers on a
  port, limited to protocol level.
- M8.5 gets a ready, hash-bound evidence type to write hypotheses and checks
  against.
- Report schema bumps to 5 (if D2 is accepted). `avra report verify` must
  support it, and older schemas stay verifiable.

## Acceptance checklist (to be filled when implemented)

- [x] Owner answers D1–D4; status moves to Accepted (2026-11-09).
- [ ] Replay dispatches by tool; schemas 1–4 fixtures rebuild unchanged.
- [ ] HTTP observation built only from verified evidence; tamper tests
      (hash, pairing, host/port mismatch) fail closed.
- [ ] Schema 5 report with per-port `identity_level` and an unverified
      indications section; `avra report verify` passes on it.
- [ ] Claim checks resolve HTTP `request_id` references.
- [ ] Full offline test suite passes; no API calls in tests.
- [ ] `docs/NEXT_SESSION.md`, `CLAUDE.md`, `docs/architecture.md` updated.
