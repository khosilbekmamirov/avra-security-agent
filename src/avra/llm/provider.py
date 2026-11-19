"""LLM provider interface and the Claude implementation (M7.1, ADR 0005).

``LLMProvider`` is what the Orchestrator talks to; ``ClaudeProvider`` is the
only implementation (official ``anthropic`` SDK). It is the single place
that touches the SDK, so tests replace it with a scripted fake and never
call the API.

What it deliberately does NOT do:
- no refusal fallback: it uses ``client.messages.create`` (non-beta), which
  has no ``fallbacks`` parameter at all — a refusal comes back as
  ``stop_reason == "refusal"`` and the caller stops (CLAUDE.md);
- no forced tool use (``tool_choice`` any/tool is a 400 on this model);
  ``auto`` with one call at a time (``disable_parallel_tool_use``);
- no secrets in errors, logs or repr.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from avra.llm.config import LLMConfig, TokenUsage

API_KEY_ENV = "ANTHROPIC_API_KEY"


class LLMProviderError(Exception):
    """The model call failed. ``retryable`` says whether waiting could help;
    the message never contains the API key."""

    def __init__(self, message: str, *, retryable: bool = False, request_id: str | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.request_id = request_id


class ApiKey:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str) or len(value) < 20 or any(c.isspace() for c in value):
            raise LLMProviderError(f"{API_KEY_ENV} looks malformed")
        self._value = value

    def reveal(self) -> str:  # only for handing to the SDK client
        return self._value

    def __repr__(self) -> str:
        return "ApiKey(<redacted>)"

    __str__ = __repr__


def load_api_key(env: Mapping[str, str] | None = None, env_file: Path | None = None) -> ApiKey:
    """``ANTHROPIC_API_KEY`` from the environment, else from the gitignored
    ``.env``. Passed explicitly to the SDK so no other credential source
    (profiles, auth tokens) is picked up silently."""
    env = os.environ if env is None else env
    value = env.get(API_KEY_ENV, "").strip()
    if not value and env_file is not None and env_file.is_file():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, sep, rest = line.partition("=")
            if sep and key.strip() == API_KEY_ENV:
                value = rest.strip().strip('"').strip("'")
                break
    if not value:
        raise LLMProviderError(f"{API_KEY_ENV} is not set (environment or .env)")
    return ApiKey(value)


@dataclass(frozen=True)
class ToolUse:
    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    stop_reason: str
    text: str
    tool_uses: tuple[ToolUse, ...]
    usage: TokenUsage
    model: str
    request_id: str | None
    history_content: Any  # the assistant content to append back unchanged
    refusal_category: str | None = None
    refusal_explanation: str | None = None
    raw_block_types: tuple[str, ...] = field(default_factory=tuple)


class LLMProvider(Protocol):
    config: LLMConfig

    def count_input_tokens(self, *, system: list[dict], messages: list[dict],
                           tools: list[dict]) -> int: ...

    def complete(self, *, system: list[dict], messages: list[dict],
                 tools: list[dict]) -> LLMResponse: ...


TOOL_CHOICE = {"type": "auto", "disable_parallel_tool_use": True}


def _tool_args(tools: list[dict]) -> dict:
    """``tool_choice`` only together with tools: a tool-less call (``avra assess``
    analysis) must not send ``tool_choice`` (the API rejects it without tools)."""
    return {"tools": tools, "tool_choice": TOOL_CHOICE} if tools else {}


def _usage(u: Any) -> TokenUsage:
    return TokenUsage(
        input_tokens=int(getattr(u, "input_tokens", 0) or 0),
        output_tokens=int(getattr(u, "output_tokens", 0) or 0),
        cache_creation_input_tokens=int(getattr(u, "cache_creation_input_tokens", 0) or 0),
        cache_read_input_tokens=int(getattr(u, "cache_read_input_tokens", 0) or 0),
    )


def parse_message(message: Any) -> LLMResponse:
    """SDK ``Message`` → ``LLMResponse``. Tool inputs are copied as plain
    dicts (validated later with Pydantic, never trusted as-is)."""
    texts, uses, types = [], [], []
    for block in message.content:
        types.append(block.type)
        if block.type == "text":
            texts.append(block.text)
        elif block.type == "tool_use":
            uses.append(ToolUse(id=block.id, name=block.name,
                                input=dict(block.input) if isinstance(block.input, dict) else {}))
    details = getattr(message, "stop_details", None)
    return LLMResponse(
        stop_reason=message.stop_reason or "unknown",
        text="\n".join(texts).strip(),
        tool_uses=tuple(uses),
        usage=_usage(message.usage),
        model=message.model,
        request_id=getattr(message, "_request_id", None),
        history_content=message.content,
        refusal_category=getattr(details, "category", None) if details else None,
        refusal_explanation=getattr(details, "explanation", None) if details else None,
        raw_block_types=tuple(types),
    )


class ClaudeProvider:
    def __init__(self, config: LLMConfig, api_key: ApiKey, *, client: Any = None,
                 killswitch: Any = None) -> None:
        from avra.control.killswitch import KillSwitch

        self.config = config
        self._killswitch = killswitch if killswitch is not None else KillSwitch()
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key.reveal(),
                                         max_retries=config.max_retries,
                                         timeout=config.timeout_seconds)
        self._client = client

    def _translate(self, exc: Exception) -> LLMProviderError:
        import anthropic

        rid = getattr(getattr(exc, "response", None), "headers", {}) or {}
        rid = rid.get("request-id") if hasattr(rid, "get") else None
        if isinstance(exc, anthropic.AuthenticationError):
            return LLMProviderError("Anthropic rejected the API key (401)", request_id=rid)
        if isinstance(exc, anthropic.PermissionDeniedError):
            return LLMProviderError("API key lacks permission (403)", request_id=rid)
        if isinstance(exc, anthropic.BadRequestError):
            return LLMProviderError(f"request rejected (400): {getattr(exc, 'message', '')[:300]}",
                                    request_id=rid)
        if isinstance(exc, anthropic.RateLimitError):
            return LLMProviderError("rate limited (429) after retries", retryable=True, request_id=rid)
        if isinstance(exc, anthropic.APITimeoutError):
            return LLMProviderError("model call timed out", retryable=True)
        if isinstance(exc, anthropic.APIStatusError):
            return LLMProviderError(f"API error ({exc.status_code}) after retries",
                                    retryable=exc.status_code >= 500, request_id=rid)
        if isinstance(exc, anthropic.APIConnectionError):
            return LLMProviderError("cannot reach the Anthropic API", retryable=True)
        return LLMProviderError(f"unexpected model-call failure: {type(exc).__name__}")

    def _kill_switch_gate(self, phase: str) -> None:
        """M8.7 Stage 3, defence in depth: no API request of any kind while
        the local kill switch blocks - whoever the caller is."""
        from avra.control.killswitch import KillSwitchEngaged

        try:
            self._killswitch.check(f"anthropic_api:{phase}")
        except KillSwitchEngaged as exc:
            raise LLMProviderError(f"{exc}; no API request was made") from None

    def count_input_tokens(self, *, system, messages, tools) -> int:
        import anthropic

        self._kill_switch_gate("count_tokens")
        try:
            result = self._client.messages.count_tokens(
                model=self.config.model, system=system, messages=messages,
                **_tool_args(tools),
            )
        except anthropic.APIError as exc:
            raise self._translate(exc) from None
        return int(result.input_tokens)

    def complete(self, *, system, messages, tools) -> LLMResponse:
        import anthropic

        self._kill_switch_gate("create_message")
        try:
            message = self._client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=system,
                messages=messages,
                **_tool_args(tools),
                output_config={"effort": self.config.effort},
                cache_control={"type": "ephemeral"},
            )
        except anthropic.APIError as exc:
            raise self._translate(exc) from None
        return parse_message(message)
