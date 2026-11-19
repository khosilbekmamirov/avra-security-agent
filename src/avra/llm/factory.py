"""The single place that turns validated configuration into a model provider
(ADR 0013).

Claude API today; selectable providers later; same AVRA core. The research
loop, policy, Runner, evidence, audit and kill switch depend only on the
``LLMProvider`` protocol, never on a concrete provider.

Rules:
- the provider is chosen explicitly (``LLMConfig.provider``), never
  guessed and never switched inside a session;
- a provider that is recognized but not implemented (e.g. a future local
  model) fails here with ``LLMConfigError`` — there is NO automatic fallback
  to another (paid or local) provider;
- an unknown provider never gets this far (``LLMConfig`` rejects it).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from avra.llm.config import IMPLEMENTED_PROVIDERS, LLMConfig, LLMConfigError
from avra.llm.provider import ApiKey, LLMProvider


def _anthropic(cfg: LLMConfig, *, api_key: ApiKey | None, env_file: Path | None,
               killswitch: Any) -> LLMProvider:
    from avra.llm.provider import ClaudeProvider, load_api_key

    key = api_key if api_key is not None else load_api_key(env_file=env_file)
    if killswitch is None:  # ClaudeProvider then uses the machine's own latch
        return ClaudeProvider(cfg, key)
    return ClaudeProvider(cfg, key, killswitch=killswitch)


def _local(cfg: LLMConfig, *, api_key: ApiKey | None, env_file: Path | None,
           killswitch: Any) -> LLMProvider:
    """ADR 0015: loopback OpenAI-compatible server (Ollama, LM Studio, llama.cpp).
    No key; ``api_key``/``env_file`` are ignored on purpose."""
    from avra.llm.local import LocalOpenAICompatibleProvider

    return LocalOpenAICompatibleProvider(cfg, killswitch=killswitch, extra_body=cfg.extra_body)


ProviderBuilder = Callable[..., LLMProvider]
_BUILDERS: dict[str, ProviderBuilder] = {"anthropic": _anthropic, "ollama": _local,
                                         "local-openai-compatible": _local}


def ensure_supported(cfg: LLMConfig) -> None:
    """Refuse an unimplemented provider WITHOUT building anything (no client,
    no key) - so the CLI can refuse before asking the owner for consent."""
    if cfg.provider not in IMPLEMENTED_PROVIDERS or cfg.provider not in _BUILDERS:
        raise LLMConfigError(f"model provider {cfg.provider!r} is not implemented yet "
                             "(ADR 0013); no fallback to another provider")


def create_provider(cfg: LLMConfig, *, api_key: ApiKey | None = None,
                    env_file: Path | None = None, killswitch: Any = None) -> LLMProvider:
    """Build exactly the provider ``cfg`` names, or raise ``LLMConfigError``."""
    ensure_supported(cfg)
    return _BUILDERS[cfg.provider](cfg, api_key=api_key, env_file=env_file,
                                   killswitch=killswitch)
