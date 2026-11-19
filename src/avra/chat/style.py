"""Terminal presentation for ``avra chat`` (M13.1).

Presentation ONLY. Nothing here reads or changes AVRA state, verdicts, scope, audit records
or approval decisions - colour is never authority. The Styler:

* sanitises every piece of text it is given FIRST (strips ESC and other control characters),
  so model output, tool results and evidence can never inject ANSI escape sequences, even
  through a raw writer; our own colour codes are added AFTER sanitising, only from fixed
  constants here;
* emits ANSI only when colour is enabled (a real TTY, ``NO_COLOR`` unset, ``TERM`` not
  ``dumb``); otherwise it returns clean plain text;
* falls back to ASCII markers when the stream encoding is not UTF-8 (Windows consoles).

Keep it minimal: a small palette, light Markdown, no banners or animation.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

RESET = "\x1b[0m"

# Role -> SGR code. USER cyan, AVRA green, SYSTEM muted gray; yellow for approvals/warnings,
# red for errors, gray for unverified model text. Verdict colours mirror the engine's meaning.
_ROLE = {
    "user": "36", "avra": "32", "system": "90",
    "approval": "33", "warning": "33", "pending": "33", "inconclusive": "33",
    "success": "32", "verified": "32", "confirmed": "32",
    "rejected": "90", "error": "31", "unverified": "90",
    "heading": "1;32", "bold": "1", "code": "36",
}

_CODE = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^(\s*)[-*]\s+(.*)$")


def supports_color(stream: Any, env: dict[str, str]) -> bool:
    """True only for a real TTY with colour not disabled. ``NO_COLOR`` (any value) and
    ``TERM=dumb`` disable it; ``AVRA_FORCE_COLOR`` forces it on (demos/tests)."""
    if "NO_COLOR" in env:
        return False
    if env.get("TERM", "").lower() == "dumb":
        return False
    if env.get("AVRA_FORCE_COLOR"):
        return True
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - a stream without isatty() is treated as non-TTY
        return False


def _unicode_ok(stream: Any) -> bool:
    enc = (getattr(stream, "encoding", None) or "").lower()
    return "utf" in enc


class Styler:
    def __init__(self, *, enabled: bool, unicode_ok: bool = True) -> None:
        self.enabled = enabled
        self.unicode_ok = unicode_ok

    @classmethod
    def from_stream(cls, stream: Any, env: dict[str, str]) -> Styler:
        return cls(enabled=supports_color(stream, env), unicode_ok=_unicode_ok(stream))

    # --- sanitation (always first) --------------------------------------------------------

    @staticmethod
    def sanitize(text: Any) -> str:
        """Keep printable text plus newlines and tabs; drop every character that could steer
        a terminal. This blocks ANSI/escape-sequence injection from untrusted text (model
        output, tool results, evidence). Our own colour is added only AFTER this.

        M13.2 F4: besides C0 controls and DEL, this now also drops the C1 range
        (U+0080-U+009F, where 0x9B is an 8-bit CSI equivalent) and Unicode format and
        line/paragraph separators (categories Cf/Zl/Zp) - including the bidirectional
        overrides U+202A-202E and U+2066-2069 that can visually reorder a path or a verdict
        in the terminal - and lone surrogates (Cs)."""
        out = []
        for c in str(text):
            if c in "\n\t":
                out.append(c)
                continue
            # category Cc covers C0, C1 and DEL; Cf the bidi/format chars; Zl/Zp the
            # line/paragraph separators; Cs surrogates. None of these are safe to echo.
            if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
                continue
            out.append(c)
        return "".join(out)

    # --- colour ---------------------------------------------------------------------------

    def _wrap(self, text: str, role: str) -> str:
        code = _ROLE.get(role)
        if not self.enabled or code is None:
            return text
        return f"\x1b[{code}m{text}{RESET}"

    def paint(self, text: Any, role: str) -> str:
        """Sanitise ``text`` then colour it for ``role``. Safe for untrusted content."""
        return self._wrap(self.sanitize(text), role)

    def marker(self, role: str) -> str:
        glyph = {"user": "❯", "avra": "●", "system": "·"}.get(role, "")
        if not self.unicode_ok:
            glyph = {"user": ">", "avra": "*", "system": "-"}.get(role, "")
        label = {"user": "YOU", "avra": "AVRA", "system": "SYSTEM"}.get(role, "")
        return f"{label} {glyph}".strip()

    def prompt(self) -> str:
        return self._wrap(f"{self.marker('user')} ", "user")

    # --- light Markdown -------------------------------------------------------------------

    def _inline(self, text: str) -> str:
        if self.enabled:
            text = _CODE.sub(lambda m: self._wrap(m.group(1), "code"), text)
            return _BOLD.sub(lambda m: self._wrap(m.group(1), "bold"), text)
        return _BOLD.sub(r"\1", _CODE.sub(r"\1", text))

    def markdown(self, text: Any) -> str:
        """Render **bold**, `code`, '- ' bullets and '#' headings for a terminal. Sanitises
        first; when colour is off, formatting markers are stripped to clean text."""
        out: list[str] = []
        bullet = "•" if self.unicode_ok else "-"
        for line in self.sanitize(text).split("\n"):
            mh = _HEADING.match(line)
            mb = _BULLET.match(line)
            if mh:
                out.append(self._wrap(mh.group(2), "heading"))
            elif mb:
                out.append(f"{mb.group(1)}{bullet} {self._inline(mb.group(2))}")
            else:
                out.append(self._inline(line))
        return "\n".join(out)
