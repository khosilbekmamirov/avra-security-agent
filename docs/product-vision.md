# AVRA — Product vision & engineering principles

Permanent statement of what AVRA is ultimately for. How it is built lives
in `docs/architecture.md`; safety rules in `docs/security.md`; decisions
in `docs/decisions/`. This file says *why*, and what "good" will mean.

## Goal

A technically serious, autonomous, evidence-driven vulnerability research
system — not an educational toy, not an Nmap wrapper, not a security
chatbot. It must eventually justify the time, money and compute invested
in it with measurable results.

Aspirational benchmark: research capability comparable to advanced
model-driven agents publicly reported to have found real vulnerabilities
in major codebases (e.g. web browsers). This is a direction to measure
against, **not** a claim about AVRA's current or guaranteed ability.

## Research directions

Two complementary directions, sharing one reasoning, orchestration,
evidence and policy architecture where practical:

1. **Dynamic web application research** (first — current roadmap):
   attack surface discovery, HTTP/API testing, adaptive investigation,
   evidence-based verification against a running target.
2. **Source code vulnerability research** (long-term): exploring and
   understanding large codebases, static analysis and program reasoning,
   hypothesis generation, controlled test-case generation, fuzzing,
   root-cause analysis, reproducible verification (e.g. a crashing input
   plus sanitizer report).

API, server and other domains come later, only after results justify
them.

## What AVRA should eventually do

Within explicitly authorized boundaries, with minimal human intervention:
map an attack surface, form hypotheses, choose tools based on evidence,
plan next steps, **safely verify** suspected vulnerabilities, separate
confirmed findings from hypotheses and false positives, keep reproducible
evidence, write professional reports, and learn from past investigations
through controlled, auditable mechanisms (data, never self-modifying
behavior).

## Stages

| Stage | Where | Gate to move on |
|---|---|---|
| A — Home lab | Intentionally vulnerable apps in the lab (Juice Shop first) | Measured results on defined benchmarks (see Metrics), not "it ran" |
| B — Authorized real-world testing | Real systems, only with written authorization, documented scope and operational safeguards | Owner's explicit decision + scope/legal groundwork; never inferred |
| C — Possible commercial product | Offered to companies | Only if A and B show real effectiveness, reliability and value. **Not assumed.** |

## Differentiation priorities (in order)

1. Autonomous, evidence-driven investigation
2. Adaptive, multi-step planning
3. Reliable verification
4. Low false-positive rate
5. Reproducibility and complete audit trails
6. Efficient use of local and cloud models
7. Extensible tool integration
8. Professional, actionable reports
9. Measurable performance and efficiency

No claim of superiority over existing scanners or AI agents without
comparative benchmark evidence.

## Metrics

Verified vulnerabilities found · precision / false-positive rate ·
coverage on defined benchmarks · human interventions per investigation ·
wall-clock time · token and API cost (per session and per verified
finding) · reproducibility across repeated runs · comparison against
established tools on the same targets.

## Capability status

Every capability is exactly one of four levels. Never present one level
as a higher one.

- **Implemented** — code + passing tests in the repo.
- **Planned** — on the approved roadmap (ADRs / architecture doc).
- **Long-term ambition** — a goal, not yet designed or scheduled.
- **Demonstrated** — measured on a defined benchmark, results recorded.

| Capability | Status (2026-11-08, after M7.9) |
|---|---|
| Scope validation, default-deny check, CLI | Implemented |
| Hash-chained audit log | Implemented |
| Tool Runner schemas, Tool Registry, Runner-side scope enforcement (M1–M2.2a) | Implemented |
| Tool Runner execution, HTTP layer, Kali deploy, SSH tunnel (Phase 2, ADR 0003/0004) | Implemented — used live |
| LLM gateway with cost logging (ADR 0005) | Implemented — used live |
| Orchestrator / agent loop: model proposes, owner approves each scan | Implemented — used live (M7.6–M7.8) |
| Evidence-grounded report + passive validator (M7.8) | Implemented |
| Report integrity: attested reports, offline replay/verification, owner-approved recovery, exposure vs identity, deterministic model-claim checks (M7.9, ADR 0006) | Implemented — tested offline; Linux recovery path untested; not semantic or cryptographic verification |
| Verification Engine (confirming findings), offline research cycle, verification in the research loop (ADR 0009/0010) | Implemented — tested offline; two real-model runs on recorded evidence (M8.5); 3 rules, no real vulnerability confirmed |
| Offline prompt/workflow evaluation harness (M7.8; 28 scenarios today) | Implemented |
| Benchmark harness / metrics | Planned (not yet designed) |
| Evidence-driven web research (M10, ADR 0017): web surface from recorded responses, structured hypothesis board (engine-decided states), adaptive `--web-research` loop, passive validation rules, fixture-only IDOR / marker-reflection checks | Implemented — tested offline; demonstrated with the local Bonsai model on recorded Juice Shop evidence (no tool executed); live validation disabled |
| Read-only fetch of discovered same-origin paths (`http_get_path`, M10.5, ADR 0018) | Implemented — tested offline only; not deployed on Kali |
| Authenticated or marker requests (live validation) | Planned — needs Runner tool, synthetic accounts, scope change and owner ADR |
| Conversational agent `avra chat` (M11, ADR 0019): persistent conversations, evidence-aware answers, plans, one-action `/approve` | Implemented — demonstrated with the local Bonsai model on recorded evidence (no live action run) |
| Source code research: code navigation, static analysis, fuzzing, root-cause analysis | Long-term ambition |
| Research memory across investigations | Long-term ambition |
| Local/cloud model routing | Long-term ambition |
| Any research result | Demonstrated: **none yet** (live lab runs so far are integration tests — one open port on a known target, no vulnerability tested) |

## Engineering principles

- AI reasoning stays separate from tool execution; the model proposes,
  code authorizes (independent policy checks on both sides).
- Safety is enforced in code, never only by prompts.
- Tools are modular, typed plug-ins; adding one must not touch the core.
- Model access goes through a provider abstraction; no lock-in to one
  vendor's request formats beyond the adapter.
- Evidence and audit come first: every claim links to stored evidence.
- Testable, maintainable engineering over impressive demos. Don't
  optimize for passing phases — optimize for useful, measurable research.
- Don't overengineer early milestones; do avoid dead ends.

## Known architectural gaps (review of 2026-11-04)

No serious conflict found with the approved roadmap; Phase 2 stays as in
ADR 0003. These gaps need attention at the indicated point:

1. **HTTP is the core primitive for web research, not Nmap.** Port
   scanning is a small part of web-app work; crawling, crafted requests
   and verification payloads are most of it. The Runner should grow a
   small tool registry (name → schema, tier, executor) in M2 so an
   `http_request` tool slots in right after Phase 2 without core changes.
2. **Adaptive planning vs. a fixed pipeline.** ADR 0001 decision 5's
   state machine must allow loops (verify → more recon → new hypothesis)
   under step/token budgets, not a one-pass linear sequence. Address
   when the Orchestrator is designed (Phase 3).
3. **No benchmark harness yet.** Without ground truth, precision and
   coverage can't be measured. Juice Shop exposes its own challenge
   status, a usable ground truth for Stage A. Design the harness before
   or alongside the Verification Engine, not after.
4. **Scope is host/port only, IPv4 only.** Web research needs URL/path
   and method-level scope and rate limits; Stage B needs hostnames with
   DNS pinning and TLS. Expect a versioned scope schema later.
5. **Model routing.** ADR 0001 decision 6 (Opus only, no tiering) is
   right for now, but the gateway must record model, tokens and cost per
   call from day one so routing to cheaper/local models can be decided
   later from data.
6. **Audit log scales O(n) per write** (re-reads the file to find the
   tail). Fine now; fix before long autonomous sessions.
7. **Source code research needs (review of 2026-11-04).** Nothing built
   so far blocks it — policy, audit, the typed registry and the
   model/tool separation are domain-neutral. Three things must not get
   baked in as network-only assumptions:
   - *Scope targets.* Scope and `scope_targets` are host/port-shaped. A
     code target is a repository at a pinned commit plus a build/run
     environment. The versioned scope schema (item 4) should add a target
     kind rather than overload host/port.
   - *Long-running work.* The Runner is synchronous with a 300 s cap.
     Builds, static analysis of large codebases, and fuzzing run for
     minutes to days; they will need a job model (submit / status /
     result / cancel) next to the current request model.
   - *Executing untrusted code.* Building a target, running its tests,
     fuzz harnesses and generated test cases execute code AVRA doesn't
     trust — a much larger risk than scanning. This needs a dedicated
     sandbox (no network, resource limits, disposable), not the Kali
     Runner VM. Action tiers also describe network intrusiveness only;
     code execution risk will need its own axis.
   Also expect: read-only code-navigation tools (search, symbol lookup,
   file ranges) as ordinary registry tools; much higher token use per
   investigation, so cost logging (item 5) matters more; and CPU-heavy
   fuzzing beyond current hardware.
8. **External risks, not code problems:** cloud models may refuse some
   security tasks (a refusal is a normal, logged outcome — never routed
   around); local models on current hardware are much weaker; Stage C
   would need provider usage-policy review, legal terms and an
   independent security audit.
