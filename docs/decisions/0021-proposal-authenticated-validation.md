# ADR 0021 — PROPOSAL: controlled authenticated validation (not approved, not implemented)

_Status: **Proposed** (2026-11-13). Nothing here is implemented or authorized. It records
what AVRA would need before any credentialed or state-aware check could run live, so the
owner can decide deliberately. Builds on ADR 0017 M10.4 (fixture-only checks) and ADR 0018
(read-only path fetch)._

## Why

The highest-value open hypotheses in the lab are access-control questions, such as an IDOR
on baskets or unauthenticated API reads. `GET /` and anonymous path fetches cannot decide
them. The fixture-only checks `idor.cross_account_object_access` and
`input.marker_reflection` already define deterministic verdicts. What is missing is a safe
way to collect the two exchanges they need.

## Proposed design (each item needs its own owner approval)

1. **Synthetic lab accounts, created by the owner, never by AVRA.** For example
   `synthetic-user-a` and `synthetic-user-b` in Juice Shop, each with one known object that
   carries a data marker (`SYNTH-…`).
   - Credentials live only in a Runner-side secret file (root-owned, 0600, like the Runner
     token).
   - They never reach Windows, the model, the audit log or reports. Records refer to
     accounts by name only.
2. **A new Runner tool `http_get_as`.** One fixed `GET <path>` with the session token of a
   named synthetic account.
   - The Runner logs in itself, with a fixed login request defined in the Runner config,
     not by the model.
   - Scope adds `accounts: [synthetic-user-a, synthetic-user-b]` and `http_paths` per
     target; default deny.
   - Still GET only: no body, no query, no redirects.
   - The login is the only state-changing request, and it is fixed, owner-configured and
     audited.
3. **A `validation_run` pipeline.**
   - The engine asks for exactly the exchanges a check declares (owner + other account,
     same path).
   - Each exchange is one approved `http_get_as`.
   - The resulting `RECORDED-LAB` fixture is built by AVRA from hash-checked evidence, never
     typed in.
   - The existing deterministic check decides; only that path can produce
     `lab_finding: true`.
4. **Marker reflection.** A separate tool, `http_get_marker`: one GET with a single
   AVRA-generated marker (`AVRA` + 16 hex + `"'<>`) in one owner-allowlisted parameter. The
   marker grammar is fixed; the model can choose neither the value nor the parameter.
5. **Approval.** Owner approval per run (`/approve`), as now. Live validation stays
   impossible until `live_authorization()` is changed by its own ADR. That is the single
   switch, and a flag cannot bypass it.

## Explicitly out of scope even then

- Writes (POST/PUT/DELETE) other than the fixed login.
- Payloads beyond the fixed marker.
- Brute force and credential guessing.
- Real user accounts, and any host other than the lab's Juice Shop.

## Open questions for the owner

- Are you willing to create and maintain two synthetic Juice Shop accounts (they reset when
  the container is recreated)?
- Should the login be allowed to change state on the target at all (it creates a session),
  or only through a pre-issued token the owner pastes into the Runner secret file?
- Which paths would you allow first (for example `/rest/basket/` only)?
