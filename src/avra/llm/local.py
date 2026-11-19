"""Local model provider (ADR 0015): an OpenAI-compatible chat endpoint on THIS
machine - Ollama (``/v1/chat/completions``), LM Studio, llama.cpp ``server``.

It implements the same ``LLMProvider`` protocol as ``ClaudeProvider``, so the
research loop, the verification proposer and ``avra assess`` work unchanged:

- requests arrive in AVRA's (Anthropic-shaped) form: ``system`` text blocks,
  ``messages`` whose content is a string or a list of ``text`` / ``tool_use`` /
  ``tool_result`` blocks, and ``tools`` with ``input_schema``;
- they are translated to OpenAI chat messages + ``tools`` (function calling);
- the answer is translated back into an ``LLMResponse`` whose
  ``history_content`` is a list of plain Anthropic-style block dicts, so the
  caller can append it to ``messages`` exactly as it does for Claude.

Safety properties:
- loopback only: ``base_url`` must be http://127.0.0.1 / ::1 / localhost - lab
  data never leaves the machine through this provider, and AVRA never talks to
  a remote "local" endpoint by mistake;
- standard library HTTP only (no new dependency), no proxies, no redirects;
- the local kill switch gates every request, as for the Claude provider;
- no credentials (a local server needs none); no fallback to another provider.
"""

from __future__ import annotations

import ipaddress
import json
import re
import urllib.error
import urllib.request
import uuid
from typing import Any
from urllib.parse import urlsplit

from avra.llm.config import LLMConfig, LLMConfigError, TokenUsage
from avra.llm.provider import LLMProviderError, LLMResponse, ToolUse

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
FINISH_TO_STOP = {"stop": "end_turn", "tool_calls": "tool_use", "function_call": "tool_use",
                  "length": "max_tokens", "content_filter": "refusal"}


class ContextOverflowError(LLMProviderError):
    """The server refused the request because the prompt does not fit its context window
    (llama.cpp ``exceed_context_size_error``). Nothing was generated, so the request can be
    rebuilt smaller and sent again; it never ran any tool."""

    def __init__(self, message: str, *, prompt_tokens: int | None = None,
                 context_tokens: int | None = None) -> None:
        super().__init__(message, retryable=False)
        self.prompt_tokens, self.context_tokens = prompt_tokens, context_tokens


def _overflow(detail: str) -> ContextOverflowError | None:
    """Recognise a context-size refusal in an HTTP 400 body (llama.cpp / OpenAI shapes)."""
    try:
        err = json.loads(detail).get("error") or {}
    except (ValueError, AttributeError):
        err = {}
    text = f"{err.get('type', '')} {err.get('message', '')} {detail}".lower()
    if not ("exceed_context_size" in text or "context size" in text
            or "context_length_exceeded" in text or "maximum context length" in text):
        return None

    def _int(v):
        return v if isinstance(v, int) else None

    n_prompt, n_ctx = _int(err.get("n_prompt_tokens")), _int(err.get("n_ctx"))
    if n_prompt is None:
        m = re.search(r"request \((\d+) tokens\)", text)
        n_prompt = int(m.group(1)) if m else None
    if n_ctx is None:
        m = re.search(r"context size \((\d+) tokens\)", text)
        n_ctx = int(m.group(1)) if m else None
    return ContextOverflowError(
        f"the request ({n_prompt or '?'} tokens) does not fit the local model's context "
        f"window ({n_ctx or '?'} tokens)", prompt_tokens=n_prompt, context_tokens=n_ctx)


def validate_base_url(url: str) -> str:
    """Accept only plain-HTTP loopback URLs with no path tricks or credentials."""
    parts = urlsplit(url or "")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise LLMConfigError(f"local model base_url must be http(s)://<loopback>:<port>, got {url!r}")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise LLMConfigError("local model base_url must not contain credentials, query or fragment")
    host = parts.hostname
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        except ValueError:
            raise LLMConfigError(
                f"local model base_url host {host!r} is not loopback; AVRA only talks to a "
                "model server on this machine (127.0.0.1, ::1 or localhost)") from None
    return url.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow a redirect off-box
        return None


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(_text_of(b.get("text", b.get("content", ""))) if isinstance(b, dict)
                         else str(b) for b in content)
    return "" if content is None else json.dumps(content, sort_keys=True, default=str)


def _block(b: Any) -> dict:
    """Accept dict blocks (ours) and SDK-like objects (type/text/id/name/input attributes)."""
    if isinstance(b, dict):
        return b
    return {k: getattr(b, k) for k in ("type", "text", "id", "name", "input") if hasattr(b, k)}


def to_openai_messages(system: list[dict], messages: list[dict]) -> list[dict]:
    out: list[dict] = []
    sys_text = "\n\n".join(_text_of(b.get("text", "")) for b in system or [] if isinstance(b, dict))
    if sys_text.strip():
        out.append({"role": "system", "content": sys_text})
    for m in messages:
        role, content = m.get("role"), m.get("content")
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        blocks = [_block(b) for b in content or []]
        if role == "assistant":
            texts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
            calls = [{"id": b.get("id") or f"call_{uuid.uuid4().hex[:12]}", "type": "function",
                      "function": {"name": b.get("name", ""),
                                   "arguments": json.dumps(b.get("input") or {}, sort_keys=True)}}
                     for b in blocks if b.get("type") == "tool_use"]
            msg: dict = {"role": "assistant", "content": "\n".join(t for t in texts if t) or None}
            if calls:
                msg["tool_calls"] = calls
            out.append(msg)
            continue
        texts = []
        for b in blocks:  # user turn: tool results become role=tool messages, in order
            if b.get("type") == "tool_result":
                out.append({"role": "tool", "tool_call_id": b.get("tool_use_id", ""),
                            "content": _text_of(b.get("content"))})
            elif b.get("type") == "text":
                texts.append(b.get("text", ""))
        if texts:
            out.append({"role": role or "user", "content": "\n".join(texts)})
    return out


def to_openai_tools(tools: list[dict]) -> list[dict]:
    return [{"type": "function", "function": {"name": t["name"],
                                              "description": t.get("description", ""),
                                              "parameters": t.get("input_schema") or
                                              {"type": "object", "properties": {}}}}
            for t in tools or []]


def parse_chat_completion(data: dict, model: str) -> LLMResponse:
    try:
        choice = data["choices"][0]
        msg = choice.get("message") or {}
    except (KeyError, IndexError, TypeError):
        raise LLMProviderError("local model returned no choices") from None
    text = (msg.get("content") or "").strip() if isinstance(msg.get("content"), str) else ""
    # Reasoning models (Qwen3.x, DeepSeek-R1 style) may inline their thinking; it is
    # never the answer. Separate reasoning fields (reasoning_content) are ignored.
    text = _THINK.sub("", text).strip()
    uses, history = [], []
    if text:
        history.append({"type": "text", "text": text})
    for call in msg.get("tool_calls") or []:
        fn = call.get("function") or {}
        raw = fn.get("arguments")
        if isinstance(raw, dict):
            args = raw
        else:
            try:
                args = json.loads(raw or "{}")
            except (TypeError, ValueError):
                args = {}  # invalid JSON from the model: validated (and refused) later
        if not isinstance(args, dict):
            args = {}
        use = ToolUse(id=call.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                      name=str(fn.get("name", "")), input=args)
        uses.append(use)
        history.append({"type": "tool_use", "id": use.id, "name": use.name, "input": use.input})
    finish = choice.get("finish_reason") or "stop"
    stop = FINISH_TO_STOP.get(finish, finish)
    if uses and stop == "end_turn":  # some servers report "stop" with tool calls
        stop = "tool_use"
    u = data.get("usage") or {}
    return LLMResponse(
        stop_reason=stop, text=text, tool_uses=tuple(uses),
        usage=TokenUsage(input_tokens=int(u.get("prompt_tokens") or 0),
                         output_tokens=int(u.get("completion_tokens") or 0)),
        model=str(data.get("model") or model), request_id=data.get("id"),
        history_content=history, raw_block_types=tuple(b["type"] for b in history))


class LocalOpenAICompatibleProvider:
    """``LLMProvider`` for a loopback OpenAI-compatible server. ``opener`` is
    injectable for tests (default: urllib without proxies or redirects)."""

    PROTECTED_KEYS = frozenset({"model", "messages", "tools", "stream", "max_tokens"})

    def __init__(self, config: LLMConfig, *, killswitch: Any = None, opener: Any = None,
                 extra_body: dict | None = None) -> None:
        from avra.control.killswitch import KillSwitch

        if not config.is_local:
            raise LLMConfigError(f"{config.provider!r} is not a local provider")
        bad = set(extra_body or {}) & self.PROTECTED_KEYS
        if bad:
            raise LLMConfigError(f"extra_body may not override {sorted(bad)}")
        # Server-specific request fields (e.g. reasoning_effort, chat_template_kwargs,
        # min_p) - used by the model benchmark to control reasoning models.
        self.extra_body = dict(extra_body or {})
        self.config = config
        self.base_url = validate_base_url(config.resolved_base_url)
        self._killswitch = killswitch if killswitch is not None else KillSwitch()
        self._opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                             _NoRedirect())
        self._ctx_cache: int | None | bool = False   # False = not asked yet
        self._tokenize_ok: bool | None = None

    def _gate(self, phase: str) -> None:
        from avra.control.killswitch import KillSwitchEngaged

        try:
            self._killswitch.check(f"local_llm:{phase}")
        except KillSwitchEngaged as exc:
            raise LLMProviderError(f"{exc}; no model request was made") from None

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(self.base_url + path, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self._opener.open(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read(2000).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - the body is only a diagnostic hint
                detail = ""
            if exc.code == 400 and (over := _overflow(detail)) is not None:
                raise over from None
            hint = " (is the model pulled/loaded?)" if exc.code == 404 else ""
            raise LLMProviderError(f"local model server answered HTTP {exc.code}{hint}: "
                                   f"{detail[:300]}", retryable=exc.code >= 500) from None
        except TimeoutError:
            raise LLMProviderError(f"local model call timed out after "
                                   f"{self.config.timeout_seconds:.0f}s", retryable=True) from None
        except (urllib.error.URLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise LLMProviderError(f"cannot reach the local model server at {self.base_url} "
                                   f"({reason}); is it running?", retryable=True) from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise LLMProviderError("local model response too large")
        try:
            data = json.loads(raw)
        except ValueError:
            raise LLMProviderError("local model server returned invalid JSON") from None
        if not isinstance(data, dict):
            raise LLMProviderError("local model server returned an unexpected JSON shape")
        return data

    def count_input_tokens(self, *, system, messages, tools) -> int:
        """No paid budget to protect; a conservative estimate (~3 chars/token)
        keeps the loop's bookkeeping meaningful without an extra request."""
        size = len(json.dumps([to_openai_messages(system, messages), to_openai_tools(tools)],
                              default=str))
        return max(1, size // 3)

    # M14.5: chat may cap a call's output below config.max_tokens so that prompt + output
    # always fit the server's window. Callers check this flag (test fakes lack it).
    supports_output_cap = True

    def context_window(self) -> int | None:
        """The server's per-request context size (llama.cpp ``GET /props``), cached.
        ``None`` if the server does not say (e.g. Ollama) - the caller then uses a
        configured or conservative default."""
        if self._ctx_cache is not False:
            return self._ctx_cache
        value = None
        req = urllib.request.Request(self.base_url + "/props", method="GET")
        try:
            with self._opener.open(req, timeout=min(10.0, self.config.timeout_seconds)) as resp:
                data = json.loads(resp.read(_MAX_RESPONSE_BYTES))
            gen = data.get("default_generation_settings") or {}
            n = gen.get("n_ctx", data.get("n_ctx"))
            value = n if isinstance(n, int) and 512 <= n <= 10_000_000 else None
        except (urllib.error.URLError, OSError, ValueError, AttributeError):
            value = None
        self._ctx_cache = value
        return value

    def exact_input_tokens(self, *, system, messages, tools) -> int | None:
        """Exact prompt size from the server's own chat template and tokenizer
        (llama.cpp ``/apply-template`` + ``/tokenize``; two cheap local requests, no
        generation). ``None`` if unsupported - remembered, so it is tried only once."""
        if self._tokenize_ok is False:
            return None
        self._gate("tokenize")
        body: dict = {"messages": to_openai_messages(system, messages)}
        if tools:
            body["tools"] = to_openai_tools(tools)
        try:
            prompt = self._post("/apply-template", body).get("prompt")
            if not isinstance(prompt, str):
                raise LLMProviderError("no prompt")
            toks = self._post("/tokenize", {"content": prompt}).get("tokens")
            if not isinstance(toks, list):
                raise LLMProviderError("no tokens")
        except LLMProviderError:
            self._tokenize_ok = False
            return None
        self._tokenize_ok = True
        return len(toks)

    def complete(self, *, system, messages, tools, max_tokens: int | None = None,
                 plain_text: bool = False) -> LLMResponse:
        self._gate("chat_completion")
        cap = (self.config.max_tokens if max_tokens is None
               else max(64, min(int(max_tokens), self.config.max_tokens)))
        body: dict = {"model": self.config.model,
                      "messages": to_openai_messages(system, messages),
                      "max_tokens": cap, "temperature": 0.1, "stream": False}
        if tools:
            body["tools"] = to_openai_tools(tools)
        elif not plain_text:
            # Tool-less calls in AVRA (avra assess) ask for one JSON object. Chat passes
            # plain_text=True (M14.5): a greeting has no tools but wants prose, not JSON.
            body["response_format"] = {"type": "json_object"}
        body.update(self.extra_body)
        return parse_chat_completion(self._post("/v1/chat/completions", body), self.config.model)

    def list_models(self) -> list[str]:
        """Installed model names (``GET /v1/models``) - for a friendly preflight."""
        req = urllib.request.Request(self.base_url + "/v1/models", method="GET")
        try:
            with self._opener.open(req, timeout=min(10.0, self.config.timeout_seconds)) as resp:
                data = json.loads(resp.read(_MAX_RESPONSE_BYTES))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise LLMProviderError(f"cannot reach the local model server at {self.base_url} "
                                   f"({getattr(exc, 'reason', exc)}); is it running?",
                                   retryable=True) from None
        return sorted(str(m.get("id")) for m in data.get("data", []) if isinstance(m, dict))
