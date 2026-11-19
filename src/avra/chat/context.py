"""Bounded, evidence-preserving context management for ``avra chat`` (M14.5).

Why: a local model has a small context window (Bonsai on llama.cpp was run with 4096 tokens
per slot). Before M14.5 every chat request carried the full system prompt, every tool schema
and ~9000 characters of history, so a plain "Salom!" cost ~3200-3400 prompt tokens and a
``get_investigation`` result pushed requests past the window (HTTP 400
``exceed_context_size_error``). The output tokens the model needs (including its hidden
reasoning) were not reserved at all.

What this module does (pure, deterministic, no model call):

* :class:`ContextBudget` - window = prompt limit + reserved output + safety margin.
* :func:`compact_data` - shrinks a tool result's MODEL-FACING form in explicit, marked steps.
  Identifier fields (:data:`PROTECTED_KEYS`: target, port, tool, request id, evidence hash,
  verdict, state, approval/action ids ...) are never shortened or rewritten; list items that
  are dropped are counted, and their state/verdict values are tallied, so a contradiction
  (e.g. 4x open + 1x closed) stays visible. The stored evidence is never touched - only the
  copy sent to the model.

The agent uses these to fit each request BEFORE it is sent, and fails with a clear message if
it cannot (it never silently truncates the owner's message).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Fields whose values are never shortened, re-worded or dropped from a kept item.
PROTECTED_KEYS = frozenset({
    "session_id", "request_id", "evidence", "evidence_id", "evidence_sha256", "sha256",
    "report_sha256", "log_head_sha256", "target", "targets", "host", "port", "ports", "path",
    "tool", "kind", "rule", "rule_id", "verdict", "status", "state", "tcp_state",
    "latest_state", "state_counts", "conflicting", "outcome", "status_code",
    "audit_chain_valid", "evidence_trusted", "action_id", "approval", "scope",
    "scope_allows", "confirmed", "rejected", "inconclusive", "verdict_counts", "error",
    "fixture", "note", "legend", "message", "missing_evidence", "scan_count",
})
# State-like fields tallied for list items that had to be dropped.
_TALLY_KEYS = ("verdict", "tcp_state", "state", "outcome", "status")
# (max string chars, max list items, project list dicts to protected keys only)
_LEVELS = ((None, None, False), (240, 10, False), (120, 6, True), (60, 3, True),
           (40, 2, True))


class ContextBudgetError(Exception):
    """The request cannot be made to fit the model's context window."""


@dataclass(frozen=True)
class ContextBudget:
    context_tokens: int    # the model server's window (per request / slot)
    output_tokens: int     # reserved for the reply, including hidden reasoning
    margin_tokens: int     # tokenizer / chat-template uncertainty
    source: str = "configured"

    @property
    def input_limit(self) -> int:
        return self.context_tokens - self.output_tokens - self.margin_tokens

    @classmethod
    def for_window(cls, context_tokens: int, max_output: int, *, exact_count: bool,
                   source: str = "configured") -> ContextBudget:
        """Reserve at most a third of a small window for output (never more than the
        configured ``max_output``) and a margin: 3% with an exact tokenizer count, 5% when
        the count is only an estimate (the estimator itself errs ~15-25% high)."""
        if context_tokens < 1024:
            raise ContextBudgetError(f"context window {context_tokens} is too small for chat "
                                     "(need at least 1024 tokens)")
        output = max(256, min(int(max_output), context_tokens // 3))
        margin = max(64, int(context_tokens * (0.03 if exact_count else 0.05)))
        return cls(int(context_tokens), output, margin, source)

    def as_dict(self) -> dict:
        return {"context_tokens": self.context_tokens, "output_tokens": self.output_tokens,
                "margin_tokens": self.margin_tokens, "input_limit": self.input_limit,
                "source": self.source}


def estimate_tokens(system: list[dict], messages: list[dict], tools: list[dict]) -> int:
    """Conservative prompt-size estimate when no tokenizer is available.

    Measured on Bonsai's tokenizer (2026-11-19): English prompt text ~4.2 chars/token, tool
    JSON schemas ~4.0, Uzbek conversation and evidence JSON (UUIDs, hashes) ~2.1-2.5. The
    divisors below are deliberately lower, so the estimate errs on the large side; chat
    templates add per-message and per-tool overhead on top."""
    sys_chars = sum(len(str(b.get("text", ""))) for b in system or [] if isinstance(b, dict))
    tool_chars = len(json.dumps(tools or [], default=str))
    msg_chars = len(json.dumps(messages or [], ensure_ascii=False, default=str))
    overhead = 16 * len(messages or []) + 40 * len(tools or []) + 32
    return int(sys_chars / 3.2 + tool_chars / 3.2 + msg_chars / 2.0) + overhead


def _size(data: Any) -> int:
    return len(json.dumps(data, ensure_ascii=True, sort_keys=True, default=str))


def _shrink(value: Any, level: tuple, key: str | None = None) -> Any:
    max_str, max_items, project = level
    if key in PROTECTED_KEYS and not isinstance(value, (list, dict)):
        return value
    if isinstance(value, str):
        if max_str is not None and len(value) > max_str:
            return value[:max_str] + f"...[+{len(value) - max_str} chars]"
        return value
    if isinstance(value, dict):
        return {k: _shrink(v, level, k) for k, v in value.items()}
    if isinstance(value, list):
        items = value
        if project:
            items = [{k: v for k, v in x.items() if k in PROTECTED_KEYS} or x
                     if isinstance(x, dict) else x for x in items]
        # a list under a protected key (evidence ids, ports, targets) is kept whole
        kept = items if max_items is None or key in PROTECTED_KEYS else items[:max_items]
        out = [_shrink(x, level, key if not isinstance(x, (dict, list)) else None)
               for x in kept]
        dropped = items[len(kept):]
        if dropped:
            marker: dict[str, Any] = {"_omitted_items": len(dropped)}
            for tk in _TALLY_KEYS:
                vals = [str(x[tk]) for x in dropped if isinstance(x, dict) and tk in x]
                if vals:
                    marker[f"_omitted_{tk}_counts"] = {v: vals.count(v) for v in sorted(set(vals))}
            out.append(marker)
        return out
    return value


def compact_data(data: Any, max_chars: int, *, full_record_hint: str = "") -> tuple[Any, dict]:
    """Return the least-compacted form of ``data`` whose JSON fits ``max_chars``.

    Every compaction is explicit: the result carries ``_compacted`` (level, original size and
    where the complete record lives). If even the strongest level does not fit, the strongest
    form is returned with ``fits=False`` so the caller can decide (it never cuts JSON text
    mid-way)."""
    original = _size(data)
    if original <= max_chars:
        return data, {"level": 0, "original_chars": original, "chars": original, "fits": True}
    best, size = data, original
    for i, level in enumerate(_LEVELS[1:], 1):
        best = _shrink(data, level)
        if isinstance(best, dict):
            best = {**best, "_compacted": {
                "level": i, "original_chars": original,
                "why": "shortened for the model's context window; stored evidence unchanged",
                "full_record": full_record_hint or "the owner can run /details"}}
        size = _size(best)
        if size <= max_chars:
            return best, {"level": i, "original_chars": original, "chars": size, "fits": True}
    return best, {"level": len(_LEVELS) - 1, "original_chars": original, "chars": size,
                  "fits": False}


def protected_values(data: Any) -> set[str]:
    """Every ``key=value`` pair under a protected key, recursively (test/assert helper)."""
    out: set[str] = set()

    def walk(v: Any, key: str | None = None) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, k)
        elif isinstance(v, list):
            for x in v:
                walk(x, key)
        elif key in PROTECTED_KEYS:
            out.add(f"{key}={v}")

    walk(data)
    return out
