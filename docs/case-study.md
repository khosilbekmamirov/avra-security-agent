# Case study: AVRA — keeping an AI agent inside safe boundaries

*Khosilbek Mamirov · independent lab project · 2026*

## 1. The problem

Language models are good at reading scanner output and suggesting what to check next. They
are also confidently wrong, easy to steer with text hidden in the data they read, and unsafe
to give a shell. I wanted an assistant that is useful for authorized security research
without trusting the model with anything that matters: what to touch, whether to run it, or
whether a finding is real.

## 2. My role

I defined the goals and safety rules, made each architecture decision (23 written ADRs),
built and operated the lab (Windows 11 host, VirtualBox host-only network, Kali Linux Runner,
Ubuntu + Docker running OWASP Juice Shop), deployed the Runner, approved and ran every live
action and reviewed the results. Most of the code was written with Claude Code as an AI
pair-programmer under a written protocol (small increments, tests before "done", ADR per
decision, no live action without my approval).

## 3. Architecture in one paragraph

A Windows CLI (`avra`) holds the policy layer, the deterministic planner, the Verification
Engine and all records. A model — the Anthropic API or a local model on llama.cpp — only
reads evidence and proposes one typed action. Approved actions travel as strict JSON requests
through a restricted SSH tunnel to a small HTTP service on Kali (the Runner), which checks its
own scope and runs nmap or a fixed HTTP request with a fixed argument list. Results come back
with SHA-256 hashes and are recorded in hash-chained audit logs.

## 4. Security controls and why

| Control | Why |
|---|---|
| Separate Linux Runner with typed requests | the model's text never becomes a command line; Windows never runs tools itself |
| Scope checked on both sides | a mistake or compromise on one side is not enough to reach a new target |
| Human approval in a real terminal, once per action, plus `y/N` | a model (or text the model read) cannot approve anything; "yes" in chat is just chat |
| Deterministic verdicts | the model's claims are hypotheses until evidence rules decide; contradictions stay INCONCLUSIVE |
| Request id ↔ evidence SHA-256 ↔ audit record | every claim in a report can be traced to the exact bytes that support it |
| Hash-chained, single-writer audit logs (+ optional HMAC anchors) | edits, deletions or reordering are detected |
| Persistent kill switch + Runner-side cancel | stopping must survive restarts and reach the machine actually running the job |
| Event-sourced investigation state, "at most once" | a crash never causes an action to repeat by itself |

## 5. Problems solved (examples)

- **Context overflow with a small local model.** Chats failed with `request exceeds the
  available context size (4096)`. Measurement showed two causes: the model server had split
  its context across 4 parallel slots, and AVRA sent every tool schema and long history on
  every message (a greeting cost 2112 tokens). I added context-window detection, exact token
  counting with the server's tokenizer, an output reserve, evidence-preserving compaction and
  a bounded retry. A greeting now costs ~780 tokens and the overflow no longer reproduces in
  the evaluation set.
- **Unwanted action proposals.** The model offered new scans when asked only to explain
  existing results. A deterministic intent gate now offers the action tool only for an
  explicit request; "no live scans" or "yes, but don't run it" always fail closed.
- **Honest capability reporting.** The assistant confused "exists in code" with "tested
  live". Capabilities now carry separate, dated statuses (implemented / offline-tested /
  live-validated / not tested / disabled).
- **Interrupt safety.** Windows Ctrl+C cancels the exact Runner job; an interrupted tunnel
  process cannot outlive the client; a job that already answered is never cancelled.

## 6. Testing

About 2,100 automated offline tests (pytest) covering scope enforcement, Runner input
validation, audit integrity, cancellation, prompt-injection handling, approval logic and the
chat agent, plus Linux-only tests for the systemd Runner. Live validations in the lab:
nmap connect scans, HTTP probes and the Runner's cancel API, each owner-approved and
recorded. Details: [`TESTING.md`](TESTING.md).

## 7. Limitations

Lab-only, one target application, single operator. Some implemented features
(`http_get_path`, `avra investigate`, the Runner emergency stop) have not been exercised live
yet. The local 27B model is slow (~25–40 s per answer) and not fluent in Uzbek.

## 8. Where to look

- `README.md` — overview, status table, offline demo
- `docs/decisions/` — architecture decision records
- `src/avra/policy/`, `src/avra/runner/` — scope and Runner
- `src/avra/verification/` — Verification Engine
- `src/avra/research/investigation.py` — investigation state machine
- `src/avra/chat/` — conversational agent, context budget, intent gate
- `tests/security/` — security regression tests
