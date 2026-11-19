# ADR 0015 — Local LLM provider and the `avra assess` vertical slice

_Status: Accepted (2026-11-13, owner's development-first brief). Implemented on
branch `feat/avra-local-mvp`. Builds on ADR 0013 (provider seam) and ADR 0009
(Verification Engine)._

## Context

The owner wants a demonstrable MVP: lab target → scope check → nmap via the
Runner → evidence → AI analysis → verification → report. It should preferably
use a local model (RTX 4060 8 GB, 16 GB RAM).

ADR 0013 had already reserved the provider names `ollama` and
`local-openai-compatible`, but did not implement them.

The research loop (ADR 0005/0010) is interactive and tool-calling, and it
needs the live Runner for every step. Small local models are unreliable at
multi-step tool calling.

## Decisions

1. **Local provider.** `avra.llm.local.LocalOpenAICompatibleProvider` serves
   both names. It talks to an OpenAI-compatible `/v1/chat/completions` endpoint
   (Ollama, LM Studio, llama.cpp `server`).
   - It implements the existing `LLMProvider` protocol. It translates AVRA's
     Anthropic-shaped messages and tools to OpenAI chat format and back, so the
     research loop, `ModelProposer` and `assess` run unchanged.
   - **Loopback only:** `base_url` must be 127.0.0.1, ::1 or localhost, with
     no credentials. Lab data never leaves the machine through this provider.
   - **No new dependency:** stdlib `urllib`, no proxies, no redirects.
   - The kill switch gates every call. A local model has no API cost (price 0),
     but step and time budgets still apply.
   - **Configuration:** `--provider/--model/--base-url` flags, overriding
     `AVRA_LLM_PROVIDER`, `AVRA_LLM_MODEL` and `AVRA_LLM_BASE_URL`. With nothing
     set, the Anthropic default is unchanged.
   - There is still no fallback between providers.
2. **`ClaudeProvider` sends `tool_choice` only with tools.** A tool-less
   analysis call must not send it.
3. **`avra assess`** is a single-pass command. It reuses existing parts only:
   - **Steps:** scope check (`authorize_tool_request`) → evidence → the
     Verification Engine per session (`run_verification`, rules only) → a
     deterministic fact sheet → **one** model call → validated analysis →
     Markdown and JSON report.
   - **Evidence sources:** `--scan` runs one nmap scan through the existing,
     audited pipeline, or `--session` (repeatable) uses existing hash-checked
     evidence.
   - **The model gets no tools.** Its reply is validated with Pydantic.
     Hypotheses about a host:port not covered by the evidence are dropped and
     listed as dropped. Every model hypothesis is shown as **UNVERIFIED**.
     Confirmed findings come only from the engine.
   - **Audit:** its own hash-chained log,
     `data/assessments/<session>/assessment-audit.jsonl`. It records the scope
     decision, the verification report hashes, the request and response hashes
     of the model call, usage, and the report file hashes. Reports are written
     once and never overwritten.
   - **Model failures:** a server that is down, a refusal or invalid JSON never
     stop the report. It is written without AI analysis and says why.
   - **Combining sessions:** each session is verified on its own. An open
     question in one session that another session decided is removed, and so
     is a proposed probe that was already done.

## Not changed

Policy, scope schema, Runner, tunnel, audit, kill switch and the Verification
Engine rules are all unchanged. The research loop's behaviour with Anthropic is
also unchanged.

## Limits

- **No local runtime is installed yet.** The provider is tested against a
  scripted loopback OpenAI-compatible server over real HTTP. A real local-model
  run needs Ollama (or similar) plus a model, which is a multi-GB download and
  needs owner approval. Suggested models for 8 GB VRAM: `qwen2.5:7b-instruct`
  (Q4, about 4.7 GB) or `llama3.2:3b` (about 2 GB).
- **A live `--scan` needs the operational Runner running.** It is inactive by
  design, and starting it needs the owner's sudo.
- Token counts for local models are estimates (about 3 chars per token).

## Addendum (2026-11-13): local-model benchmark

`tests/eval/model_bench/` compares local models on the same AVRA tasks and the
same hardware. It is model-agnostic: it uses `LocalOpenAICompatibleProvider` and
refuses non-loopback servers and paid providers.

- **Inputs:** `facts.json`, frozen and reproducible (a test rebuilds it). It is
  built by the real scan pipeline and Verification Engine from the recorded lab
  evidence: real sessions 4460bea8 and 7e868faf, plus the m5/m7 nmap fixtures.
  Three injection variants are labelled.
- **24 cards:**
  - analysis ×8: the real `assess` prompt;
  - exact-answer extraction ×6;
  - tool selection ×5: the real m7-v2 research prompt and tool definitions,
    with scope, budget and exploitation-request cases;
  - prompt injection ×5: in the HTTP title, the Server header and a tool
    result, plus a system-prompt-leak attempt.
- **Grading is deterministic:**
  - JSON validity;
  - no hallucinated targets or out-of-scope IPs;
  - no unverified "confirmed" claims (regex, negation-aware);
  - no offensive content;
  - exact answers;
  - tool allowed, input schema-valid, proposal in scope.
  Each card ships a reference reply and known-bad replies; the harness tests
  prove each grader accepts the reference and catches each bad reply.
- **Performance:** per-call latency, end-to-end tokens/s, cold start, and peak
  GPU memory (polled with `nvidia-smi`).
- **Run it:**
  `python -m tests.eval.model_bench --model <name> --base-url http://127.0.0.1:<port> --repeat 3`,
  then `--compare a.json b.json`. Results go to `data/eval/model-bench/`
  (gitignored).
- **Provider change:** inline `<think>…</think>` reasoning is stripped from
  local-model answers.

## Addendum (2026-11-13): Bonsai 2 27B integrated; passive findings are weaknesses

**Bonsai 2 27B PTQ1_0 runs as AVRA's local model.**
- **Runtime:** PrismML llama.cpp `prism-b12128-d7b2896`, Windows CUDA 12.4, on
  `127.0.0.1:8080`. The model file and runtime archives were hash-verified.
- **Measured:** 6.1 GB VRAM peak, about 36 tok/s generation.
- **Works through the existing provider:** JSON mode, research tool calls
  (valid and in scope), `avra assess`, and offline `avra research
  --verification --web-rules`.
- **Recommended reasoning setting:**
  `AVRA_LLM_EXTRA_BODY=@tests/eval/model_bench/profiles/bonsai-reasoning-medium.json`.
  An assessment takes 44 s with it, against 96 s at the default.
- **Measurements:** `data/eval/bonsai/integration-20261113.md`.

**Opt-in web-header rule pack** (`web_registry()`): missing CSP, missing
clickjacking protection, CORS `*`, version disclosure.
- Same strict eligibility as the nosniff rule.
- `default_registry()` is unchanged.
- Used by `assess` (`--rules web`, the default), `verify session --web-rules`
  and `research --verification --web-rules`. The post-run verification uses the
  same rule set as the loop.

**Configuration weaknesses are not vulnerabilities.** CONFIRMED verdicts of the
header rules (including nosniff) are reported as *confirmed configuration
weaknesses (not proven exploitable)*:
- separately in the fact sheet (`confirmed_weaknesses`);
- in the prompt (`assess-v3`, rule 6);
- in the report and the CLI output.

Their fixes are vetted, fixed text with CWE/OWASP references. Model advice is
labelled "(AI, unverified)".
