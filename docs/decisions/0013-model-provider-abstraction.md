# ADR 0013 — Model provider abstraction: Claude API today, selectable providers later

_Status: **Accepted** (2026-11-12, M8.7 Stage 8). Minimal seam implemented
offline; no local model installed, downloaded or run; no new dependency;
the Anthropic provider remains the default and only implemented one._

## Context

The owner wants AVRA to be able to use a locally hosted model later (e.g.
Bonsai or a Qwen-family model through a local runtime) once the host has
more RAM (today ~16 GB; an upgrade of +16 GB is planned, not done). AVRA's
value is in its research, policy, execution, evidence and audit layers;
replacing the model must not mean rewriting them, and must never weaken
them.

## What the code already does (review, 2026-11-12)

The research core already depends only on a small protocol
(`avra.llm.provider.LLMProvider`):

```
config: LLMConfig
count_input_tokens(system, messages, tools) -> int
complete(system, messages, tools) -> LLMResponse
```

`LLMResponse` is provider-neutral data: `stop_reason`, `text`,
`tool_uses` (`ToolUse(id, name, input)`), `usage` (`TokenUsage`), `model`,
`request_id`, `history_content` (opaque, appended back unchanged),
`refusal_category/explanation`, `raw_block_types`. `ResearchSession` and
`ModelProposer` use only this; hundreds of offline tests drive them with
fake providers. Everything that enforces safety is OUTSIDE the provider:

| Layer | Where | Depends on the model? |
|---|---|---|
| Tool-call validation | `avra.llm.tools.validate_tool_input` (strict Pydantic) | No — model output is untrusted input |
| Scope / tier | `avra.policy`, Runner `RunnerPolicy` (twice) | No |
| Human approval | `ResearchSession.approve` | No |
| Execution | M6 pipelines → Runner (typed argv, sandbox) | No |
| Budget | `worst_case_call_cost` before every call, step/tool/duration limits | Needs a cost model (below) |
| Evidence / verdicts | Verification Engine (deterministic) | No |
| Audit | `AuditLog` (+ HMAC anchors) | No |
| Kill switch | gate checkpoints + `ClaudeProvider` defence in depth | No (checkpoints are in the loop) |

Anthropic-specific assumptions found:

1. **Construction is hardcoded** — the CLI built `ClaudeProvider` directly.
2. **`LLMConfig` assumes a paid, priced model** (`PRICES`, Anthropic
   "effort" levels, SDK retries/timeouts).
3. **Message shape is Anthropic's** — `system` text blocks, `tool_result`
   blocks keyed by `tool_use_id`, assistant `history_content` passthrough,
   the stop-reason vocabulary (`tool_use`, `end_turn`, `max_tokens`,
   `refusal`), and an exact `count_tokens` endpoint.
4. **The provider identity was not audited** (only the model id).

## Decision

1. **Explicit provider selection** (implemented): `LLMConfig.provider`,
   default `"anthropic"`, validated. `avra.llm.factory.create_provider(cfg)`
   is the single construction point (the CLI uses it). Known future ids
   (`"local-openai-compatible"`, `"ollama"`) are **recognized but not
   implemented**: selecting one raises `LLMConfigError` ("not implemented
   yet; no fallback"). Unknown ids are rejected. There is **no automatic
   fallback** between providers and **no switching inside a session** (one
   provider object per session).
2. **Audit**: `research_started` records `provider` (with `model`). Report
   schemas are unchanged (the field is audit-only).
3. **Adapters normalize, the core does not change**: a future provider is
   an adapter that accepts AVRA's (Anthropic-shaped) request structure and
   returns an `LLMResponse` with the normalized stop reasons and `ToolUse`
   objects. Tool calls stay subject to `validate_tool_input`; a malformed
   tool call is an `llm_tool_invalid`, never an execution.
4. **Everything in the safety table above stays provider-independent** and
   is never delegated to a model, local or not.

## Future local-model integration (roadmap — NOT implemented)

Prerequisites before any code: the RAM upgrade actually installed and
measured; the runtime and model chosen by the owner; an ADR amendment.

- **Transport**: a local runtime (e.g. Ollama, or any OpenAI-compatible
  local server) reached over **loopback only by default**; endpoint from
  validated configuration with an explicit allowlist — never from model
  output; no proxy; bounded response size.
- **Adapter duties**: translate system/messages/tools to the runtime's
  format; normalize tool calls (JSON-schema validated, one call per step
  like `disable_parallel_tool_use`); map stop reasons; treat unparseable
  output as an error, not text.
- **Capability discovery**: at session start, check the runtime is up and
  the model supports tool calling + the needed context length; refuse the
  session otherwise (no silent degrade).
- **Token accounting**: local runtimes may lack exact counting; use a
  conservative estimate (e.g. bytes/3, rounded up) and a hard context
  budget below the model's window; record `usage_estimated: true`.
- **Cost and resources**: price 0 is not "unlimited" — replace the USD
  budget with explicit local budgets: max wall time per call (request
  deadline), max output tokens, max calls per session, and the host's
  RAM/CPU headroom checked before starting.
- **Cancellation / kill switch**: the loop's checkpoints already stop
  further calls; the adapter must honour a per-call deadline so an in-flight
  local generation cannot outlive the session (and the local runtime must
  be stoppable without affecting other processes).
- **Prompt templates**: keep prompts versioned per provider/model
  (`prompt_version`) and re-run the offline eval harness (28 scenarios)
  before any real use; do not assume Claude-level tool-calling reliability.
- **Model sizing**: decided only after the upgraded RAM/VRAM is verified —
  no recommendation is made now.

## Consequences

- Claude remains the default; behaviour, prompts, budgets and reports are
  unchanged (regression-tested).
- Adding a local provider later = one adapter module + a factory entry +
  config/pricing semantics for "local", plus eval runs — no change to the
  research loop, policy, Runner, evidence, audit or kill switch.
- Limitation: the request/response shape is still Anthropic-flavoured; the
  adapter carries the translation cost. Revisit only if a second provider
  is actually implemented.
