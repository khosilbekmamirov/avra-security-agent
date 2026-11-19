"""Model settings, prices and session limits (M7.1, ADR 0005).

Everything that costs money or bounds the agent lives here, as plain
frozen values the owner can read. Prices are USD per 1M tokens, copied by
hand from Anthropic's pricing page — update them there first, then here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_MODEL = "claude-opus-5-5"
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")


@dataclass(frozen=True)
class ModelPrice:
    input: float
    output: float
    cache_write: float  # 5-minute cache write (1.25x input)
    cache_read: float


# Checked 2026-11-06 (Claude API reference, cached 2026-10-06).
PRICES: dict[str, ModelPrice] = {
    "claude-opus-5-5": ModelPrice(input=4.00, output=20.00, cache_write=5.00, cache_read=0.20),
}


class LLMConfigError(Exception):
    pass


# ADR 0013: explicit provider selection, never guessed, no fallback.
# ADR 0015: the two local providers are implemented (avra.llm.local) - an
# OpenAI-compatible chat endpoint on THIS machine's loopback only (Ollama,
# LM Studio, llama.cpp server). FUTURE_PROVIDERS stays for later additions.
DEFAULT_PROVIDER = "anthropic"
LOCAL_PROVIDERS = frozenset({"ollama", "local-openai-compatible"})
IMPLEMENTED_PROVIDERS = frozenset({"anthropic"}) | LOCAL_PROVIDERS
FUTURE_PROVIDERS: frozenset[str] = frozenset()
DEFAULT_LOCAL_BASE_URL = {"ollama": "http://127.0.0.1:11434",
                          "local-openai-compatible": "http://127.0.0.1:8080"}
LOCAL_PRICE = ModelPrice(input=0.0, output=0.0, cache_write=0.0, cache_read=0.0)

# Environment overrides (CLI flags win over these; these win over defaults).
ENV_PROVIDER, ENV_MODEL, ENV_BASE_URL = "AVRA_LLM_PROVIDER", "AVRA_LLM_MODEL", "AVRA_LLM_BASE_URL"
ENV_EXTRA_BODY = "AVRA_LLM_EXTRA_BODY"  # local only: JSON object, or @path to a JSON file
LOCAL_DEFAULT_TIMEOUT = 600.0  # a local reasoning model can think for minutes


@dataclass(frozen=True)
class LLMConfig:
    model: str = DEFAULT_MODEL
    effort: str = "medium"
    provider: str = DEFAULT_PROVIDER
    max_tokens: int = 4096  # per call; includes thinking — bounds worst-case output cost
    # SDK retries (429/5xx/connection), bounded. 0 for the first live sessions
    # (owner, 2026-11-07): a timed-out or failed attempt reports no usage, so
    # each retry could be billed without being counted against the budget.
    max_retries: int = 0
    timeout_seconds: float = 120.0  # per HTTP request
    base_url: str | None = None  # local providers only; loopback-only (avra.llm.local)
    extra_body_json: str | None = None  # local only: server-specific request fields (JSON)

    def __post_init__(self) -> None:
        if self.provider not in IMPLEMENTED_PROVIDERS | FUTURE_PROVIDERS:
            raise LLMConfigError(f"unknown model provider {self.provider!r}; known: "
                                 f"{sorted(IMPLEMENTED_PROVIDERS | FUTURE_PROVIDERS)}")
        if self.provider not in IMPLEMENTED_PROVIDERS:
            return  # rejected by avra.llm.factory.create_provider (no fallback)
        if self.provider in LOCAL_PROVIDERS:
            self._check_local()
            return
        if self.base_url is not None or self.extra_body_json is not None:
            raise LLMConfigError("base_url / extra body apply to local providers only")
        if self.model not in PRICES:
            raise LLMConfigError(f"no price configured for model {self.model!r}; "
                                 "add it to avra.llm.config.PRICES first")
        if self.effort not in EFFORT_LEVELS:
            raise LLMConfigError(f"effort must be one of {EFFORT_LEVELS}")
        if not 256 <= self.max_tokens <= 16_000:
            raise LLMConfigError("max_tokens must be in [256, 16000]")
        if not 0 <= self.max_retries <= 3:
            raise LLMConfigError("max_retries must be in [0, 3]")
        if not 5 <= self.timeout_seconds <= 300:
            raise LLMConfigError("timeout_seconds must be in [5, 300]")

    def _check_local(self) -> None:
        from avra.llm.local import validate_base_url  # loopback-only rule lives there

        if not self.model or len(self.model) > 200 or any(c.isspace() for c in self.model):
            raise LLMConfigError("local model name must be 1-200 characters without spaces")
        if not 256 <= self.max_tokens <= 16_000:
            raise LLMConfigError("max_tokens must be in [256, 16000]")
        if not 5 <= self.timeout_seconds <= 900:  # a cold local model load can be slow
            raise LLMConfigError("timeout_seconds must be in [5, 900] for a local model")
        validate_base_url(self.resolved_base_url)
        if self.extra_body_json is not None:
            try:
                ok = isinstance(__import__("json").loads(self.extra_body_json), dict)
            except ValueError:
                ok = False
            if not ok:
                raise LLMConfigError(f"{ENV_EXTRA_BODY} must be a JSON object")

    @property
    def extra_body(self) -> dict:
        import json

        return json.loads(self.extra_body_json) if self.extra_body_json else {}

    @property
    def is_local(self) -> bool:
        return self.provider in LOCAL_PROVIDERS

    @property
    def resolved_base_url(self) -> str:
        return self.base_url or DEFAULT_LOCAL_BASE_URL.get(self.provider, "")

    @property
    def price(self) -> ModelPrice:
        # A local model costs no API money; budgets still bound steps and time.
        return LOCAL_PRICE if self.is_local else PRICES[self.model]

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **overrides) -> LLMConfig:
        """``AVRA_LLM_PROVIDER`` / ``AVRA_LLM_MODEL`` / ``AVRA_LLM_BASE_URL``;
        explicit non-None ``overrides`` (CLI flags) win. Nothing set -> the
        Anthropic default, exactly as before."""
        import os

        env = os.environ if env is None else env
        provider = overrides.pop("provider", None) or env.get(ENV_PROVIDER) or DEFAULT_PROVIDER
        model = overrides.pop("model", None) or env.get(ENV_MODEL)
        base_url = overrides.pop("base_url", None) or env.get(ENV_BASE_URL)
        kw = {k: v for k, v in overrides.items() if v is not None}
        extra = kw.pop("extra_body_json", None) or env.get(ENV_EXTRA_BODY)
        if extra and extra.startswith("@"):
            from pathlib import Path

            extra = Path(extra[1:]).read_text(encoding="utf-8-sig")
        if provider in LOCAL_PROVIDERS:
            kw.setdefault("timeout_seconds", LOCAL_DEFAULT_TIMEOUT)
            if extra:
                kw["extra_body_json"] = extra
        if model is None:
            if provider in LOCAL_PROVIDERS:
                raise LLMConfigError(f"provider {provider!r} needs a model name "
                                     f"(--model or {ENV_MODEL})")
            model = DEFAULT_MODEL
        return cls(model=model, provider=provider,
                   base_url=base_url if provider in LOCAL_PROVIDERS else None, **kw)


@dataclass(frozen=True)
class SessionLimits:
    budget_usd: float = 0.50
    max_steps: int = 10  # model calls
    max_tool_runs: int = 5  # executed (owner-approved) tool requests
    max_duration_seconds: int = 1800

    def __post_init__(self) -> None:
        if not 0 < self.budget_usd <= 5.0:
            raise LLMConfigError("budget_usd must be in (0, 5.00]")
        if not 1 <= self.max_steps <= 50:
            raise LLMConfigError("max_steps must be in [1, 50]")
        if not 0 <= self.max_tool_runs <= 20:
            raise LLMConfigError("max_tool_runs must be in [0, 20]")
        if not 60 <= self.max_duration_seconds <= 7200:
            raise LLMConfigError("max_duration_seconds must be in [60, 7200]")


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def cost_usd(self, price: ModelPrice) -> float:
        return (self.input_tokens * price.input
                + self.output_tokens * price.output
                + self.cache_creation_input_tokens * price.cache_write
                + self.cache_read_input_tokens * price.cache_read) / 1_000_000

    def as_dict(self) -> dict[str, int]:
        return {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cache_creation_input_tokens": self.cache_creation_input_tokens,
                "cache_read_input_tokens": self.cache_read_input_tokens}


def worst_case_call_cost(price: ModelPrice, counted_input_tokens: int, max_tokens: int) -> float:
    """Upper bound for one call: every input token billed as a cache WRITE
    (the most expensive input rate) and the full max_tokens of output."""
    return (counted_input_tokens * max(price.input, price.cache_write)
            + max_tokens * price.output) / 1_000_000


@dataclass
class Spend:
    """Running totals for one research session."""

    usd: float = 0.0
    calls: int = 0
    tokens: dict[str, int] = field(default_factory=lambda: TokenUsage().as_dict())

    def add(self, usage: TokenUsage, price: ModelPrice) -> float:
        cost = usage.cost_usd(price)
        self.usd += cost
        self.calls += 1
        for k, v in usage.as_dict().items():
            self.tokens[k] += v
        return cost
