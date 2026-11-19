"""Local conversation memory for ``avra chat`` (M11.2, ADR 0019).

One conversation = two files under ``data/chat/``:

* ``<name>.jsonl``        - the conversation: one JSON object per line
                            (``user`` / ``assistant`` text, ``avra_note`` records AVRA wrote
                            itself, e.g. the result of an approved action);
* ``<name>.audit.jsonl``  - the hash-chained AVRA audit log of that conversation (model calls
                            with token usage, tool calls, proposed/approved/denied actions).

Rules:
* chat text is NEVER evidence: it is stored and shown as conversation, and the agent reads
  evidence only through the read-only knowledge tools;
* obvious secrets (API keys, bearer tokens, ``password=...``) are redacted before writing;
* approvals are NOT stored as permissions: a pending action lives only in memory for one
  run of ``avra chat``; resuming a conversation can never execute anything;
* the history sent to the model is bounded; older turns are compacted deterministically
  into a short note (no extra model call).
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass
from pathlib import Path

NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
MAX_TEXT = 20_000
_SECRETS = (
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|avra_runner_token|"
               r"anthropic_api_key)\b(\s*[:=]\s*)\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
)


class ChatStoreError(Exception):
    pass


def redact(text: str) -> str:
    out = text
    for pat in _SECRETS:
        out = pat.sub(lambda m: (m.group(1) + m.group(2) + "[REDACTED]")
                      if m.re.groups >= 2 else "[REDACTED]", out)
    return out


def chat_dir(root: Path) -> Path:
    return Path(root) / "chat"


def valid_name(name: str) -> str:
    name = str(name).strip().lower()
    if not NAME.fullmatch(name):
        raise ChatStoreError("conversation names: 1-41 characters, a-z 0-9 _ - "
                             "(starting with a letter or digit)")
    return name


@dataclass(frozen=True)
class Message:
    role: str      # user | assistant | avra_note
    content: str
    ts: str
    meta: dict


class Conversation:
    def __init__(self, root: Path, name: str) -> None:
        self.name = valid_name(name)
        self.dir = chat_dir(root)
        self.path = self.dir / f"{self.name}.jsonl"
        self.audit_path = self.dir / f"{self.name}.audit.jsonl"

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    def append(self, role: str, content: str, **meta) -> Message:
        if role not in ("user", "assistant", "avra_note"):
            raise ChatStoreError(f"unknown role {role!r}")
        self.dir.mkdir(parents=True, exist_ok=True)
        msg = Message(role, redact(str(content))[:MAX_TEXT],
                      dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), dict(meta))
        line = json.dumps({"role": msg.role, "content": msg.content, "ts": msg.ts,
                           "meta": msg.meta}, ensure_ascii=False, sort_keys=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
        return msg

    def messages(self) -> list[Message]:
        if not self.exists:
            return []
        out = []
        for i, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                out.append(Message(str(d["role"]), str(d["content"]), str(d.get("ts", "")),
                                   dict(d.get("meta") or {})))
            except (ValueError, KeyError, TypeError):
                raise ChatStoreError(f"{self.path.name} line {i} is not a valid record") from None
        return out

    def model_history(self, max_chars: int = 9000, keep_turns: int = 6, *,
                      reply_chars: int | None = None, include_note: bool = True) -> list[dict]:
        """The bounded history for the model: the newest ``keep_turns`` exchanges verbatim
        (within ``max_chars``); older ones compacted into one short note. AVRA notes are
        passed as clearly labelled user-side records, never as instructions.

        M14.5: ``reply_chars`` shortens EARLIER assistant replies (never the owner's words,
        never AVRA records) with an explicit marker - old model prose is the least valuable
        and, with a weak model, the most likely to carry its own mistakes forward.
        ``include_note=False`` drops the compacted-earlier note (the tightest budget). The
        newest exchange (the owner's current message) is always kept whole; the stored
        conversation is never changed."""
        keep_turns = max(1, keep_turns)
        msgs = [m for m in self.messages() if m.role in ("user", "assistant", "avra_note")]
        turns: list[list[Message]] = []
        for m in msgs:
            if m.role == "user" or not turns:
                turns.append([m])
            else:
                turns[-1].append(m)
        recent, used = [], 0
        for turn in reversed(turns):
            size = sum(len(m.content) for m in turn)
            if len(recent) >= keep_turns or (recent and used + size > max_chars):
                break
            recent.insert(0, turn)
            used += size
        older = turns[:len(turns) - len(recent)]
        out: list[dict] = []
        if older and include_note:
            asked = [t[0].content.replace("\n", " ")[:120] for t in older
                     if t[0].role == "user"][-12:]
            out.append({"role": "user", "content": (
                "[AVRA: earlier part of this conversation, compacted - "
                f"{len(older)} older exchange(s). The user had asked: "
                + " | ".join(asked) + "]")})
            out.append({"role": "assistant", "content": "Understood."})
        elif older:
            out.append({"role": "user", "content": (
                f"[AVRA: {len(older)} earlier exchange(s) omitted to fit the model's context "
                "window; the stored conversation is unchanged.]")})
            out.append({"role": "assistant", "content": "Understood."})
        for turn in recent:
            for m in turn:
                if m.role == "avra_note":
                    out.append({"role": "user", "content": f"[AVRA record, not the user]: "
                                                           f"{m.content}"})
                    out.append({"role": "assistant", "content": "Noted."})
                elif (m.role == "assistant" and reply_chars is not None
                      and len(m.content) > reply_chars):
                    out.append({"role": "assistant", "content": (
                        m.content[:reply_chars] + f" [...earlier reply shortened by AVRA, "
                        f"{len(m.content) - reply_chars} chars omitted]")})
                else:
                    out.append({"role": m.role, "content": m.content})
        # providers need alternating roles starting with user
        merged: list[dict] = []
        for m in out:
            if merged and merged[-1]["role"] == m["role"]:
                merged[-1] = {"role": m["role"],
                              "content": merged[-1]["content"] + "\n\n" + m["content"]}
            else:
                merged.append(dict(m))
        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": "[AVRA: conversation resumed]"})
        return merged


def list_conversations(root: Path) -> list[dict]:
    d = chat_dir(root)
    if not d.is_dir():
        return []
    rows = []
    for p in sorted(d.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True):
        if p.name.endswith(".audit.jsonl") or not NAME.fullmatch(p.stem):
            continue
        try:
            msgs = Conversation(root, p.stem).messages()
        except ChatStoreError:
            rows.append({"name": p.stem, "messages": None, "error": "unreadable"})
            continue
        first = next((m.content for m in msgs if m.role == "user"), "")
        rows.append({"name": p.stem, "messages": len(msgs),
                     "last": msgs[-1].ts if msgs else "", "first_question": first[:80]})
    return rows
