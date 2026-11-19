# Operator guide — offline verification (M8.4)

`avra verify` checks what a session's **recorded** evidence actually proves.
It never contacts Kali, the tunnel, the target or the Anthropic API (unless
you add `--model` and confirm). It only reads `data/sessions/` and
`data/evidence/` and writes `data/verification/<session>/`.

## Commands

```
avra verify rules                                   # what each rule needs for CONFIRMED
avra verify session --session <UUID>                # rule-driven offline research cycle
avra verify session --session <UUID> --hypotheses my-hypotheses.json [--no-rules]
avra verify session --session <UUID> --model --budget-usd 0.25   # LLM proposes too (asks first)
avra verify show <UUID>                             # print the latest verification report
avra verify check <UUID>                            # re-derive every verdict; exit 0 only if VERIFIED
```

Options: `--max-iterations` (1–50, default 5), `--max-hypotheses` (1–500,
default 50), `--json` (print the full report). Exit codes for `session`:
0 done, 1 refused input, 2 the session's evidence is not trusted (nothing
was decided).

With `--model`, the model also receives your scope file's `description`
(the environment note) as labelled context, taken from the session's
hash-checked scope snapshot, as in `avra research`. Keep that note
truthful, e.g. "home VirtualBox host-only lab, intentionally vulnerable
training target, owner-authorized". If the model refuses, the report's
proposer notes show `model refused (category: …)`, and the verification
audit log records the category and explanation. A refusal is never retried
or sent to another model.

## Hypotheses file

```json
{"hypotheses": [
  {"rule_id": "http.missing_x_content_type_options", "host": "192.168.56.103",
   "port": 3000, "origin": "model", "rationale": "why this is worth checking"}
]}
```

`origin` is `owner` (default) or `model`. Any other field (e.g. a
`verdict`) refuses the whole file. The rationale is shown, never trusted.

## Reading the result

| Verdict | Meaning |
|---|---|
| CONFIRMED | The hash-checked evidence satisfies every condition of the rule. A *vulnerability* rule → **confirmed finding** (about the examined response only). An *observation* rule → verified fact, **not** a vulnerability. |
| REJECTED | Trusted evidence shows the condition is false for the examined data. |
| INCONCLUSIVE | Cannot decide: missing, insufficient, contradictory or untrusted evidence. Never read as "safe". |

"Proposed next actions" were **not executed**. Each needs the normal scoped,
owner-approved path (e.g. `avra probe http`).

Model notes (the research model's free-text hypotheses) are listed as
unverified text; no rule evaluates them.

## Example (real M8.3 evidence)

```
> avra verify session --session 7e868faf-768d-49af-aea6-81dc9d435e20
CONFIRMED FINDINGS (vulnerability rules): 0
Verified observations (facts, not vulnerabilities): 1
  [CONFIRMED] http.service_observed @ 192.168.56.103:3000 - HTTP/1.1 status 200 received
Rejected hypotheses: 1
  [REJECTED] http.missing_x_content_type_options @ 192.168.56.103:3000 - Every eligible
  response sends X-Content-Type-Options: nosniff.
```

## After `avra research`

A research session now ends with an automatic, rule-only offline
verification of its evidence (no API call). Its report path is printed;
the research report and exit code are unchanged.

## Verification inside the research loop (M8.5, opt-in)

```
avra research --scope scope/<file>.yaml --objective "..." --verification [--session <UUID>]
```

- The model gets the rule catalogue and the current verification state,
  and a `verify_hypothesis` tool (rule id + in-scope host:port). The
  engine decides every verdict; the model cannot set or overrule one.
- After each executed scan all hypotheses are re-verified (verdicts can be
  revised by new evidence) and the next actions are re-ranked. Actions the
  model cannot request (e.g. `http_probe`) are shown as `owner_only`; you
  run them yourself with `avra probe http --session <UUID>` (scope and
  approval as in M8.3).
- Every scan still needs your approval. The session stops on its own
  (`no_progress`) after 3 model steps that change nothing.
- Uses the paid API like any research session (prompt `m8.5-v2`). Without
  `--verification` research is exactly the M7 behaviour (`m7-v2`).
- Afterwards `avra verify show <UUID>` shows a **Research loop** section:
  which hypotheses the model and the rules raised at which step, every
  verdict and revision, repeats answered from state, and the stop reason
  (report format `avra-verification-report/2`; older `/1` reports still
  re-check).

## What the model is told (m8.5-v2) and what a refusal looks like

The first message now contains a **Session facts** block that AVRA derives
from the validated scope and your command line: the authorized targets,
the scope expiry, the network-tool budget (with `--max-tool-runs 0` it says
plainly that the session is offline analysis of already-collected evidence,
not active testing), and how much hash-checked evidence the session holds.
Your scope file's `description` is shown separately and labelled as **your
statement, not verified by AVRA**. Keep it accurate (e.g. Windows 11 host,
VirtualBox, Kali tooling VM, Ubuntu VM with OWASP Juice Shop, host-only
network, owner-authorized education/defensive research); AVRA never adds
claims you did not write.

If the provider refuses, the CLI prints "Refused by the model PROVIDER's
safety system (not an AVRA scope or policy rejection …)". The audit's
`llm_refusal` record has the category, the provider's explanation, model,
request id, prompt version, usage, cost and whether any tool ran. The
category alone does not say which part was flagged. AVRA never retries or
switches models.

## Audit records added in M8.6 (ADR 0011)

- `verification_request_refused` - a `verify_hypothesis` request AVRA
  refused (`out_of_scope`, `invalid`, `budget`); also listed under the
  research loop in `avra verify show`.
- `model_feedback` - one per payload actually sent to the model: kind,
  step, tool-call id, SHA-256 and length of the exact text (the text itself
  is not stored). To check a payload you have, compute its UTF-8 SHA-256
  and compare.
- `avra verify show` now prints "created under scope '…'" for the session
  and "used scope '…'" for each research run, and splits next actions into
  all proposed candidates vs those the agent could still run with the
  remaining tool budget.
