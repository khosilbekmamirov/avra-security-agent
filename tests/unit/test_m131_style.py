"""M13.1: terminal presentation (Styler). Pure unit tests - no agent, model, data or network.

Colour is presentation only; these tests assert ANSI appears when enabled, never otherwise,
that untrusted text cannot inject escape sequences, and that Markdown renders readably."""

from __future__ import annotations

from avra.chat.style import Styler, supports_color

ESC = "\x1b"


class _Stream:
    def __init__(self, tty: bool, encoding: str = "utf-8"):
        self._tty, self.encoding = tty, encoding

    def isatty(self) -> bool:
        return self._tty


# --- supports_color --------------------------------------------------------------------------

def test_supports_color_rules():
    tty, notty = _Stream(True), _Stream(False)
    assert supports_color(tty, {}) is True
    assert supports_color(notty, {}) is False                 # non-TTY
    assert supports_color(tty, {"NO_COLOR": ""}) is False      # NO_COLOR, any value
    assert supports_color(tty, {"NO_COLOR": "1"}) is False
    assert supports_color(tty, {"TERM": "dumb"}) is False      # dumb terminal
    assert supports_color(notty, {"AVRA_FORCE_COLOR": "1"}) is True  # forced (demos/tests)


def test_object_without_isatty_is_non_tty():
    assert supports_color(object(), {}) is False


# --- sanitation / escape-injection -----------------------------------------------------------

def test_sanitize_strips_escapes_keeps_newlines_tabs():
    s = Styler(enabled=True)
    out = s.sanitize("a\x1b[31mRED\x07\x00b\nc\td")
    assert ESC not in out and "\x07" not in out and "\x00" not in out
    assert out == "a[31mREDb\nc\td"  # ESC gone; the now-inert '[31m' text remains


def test_paint_and_markdown_never_pass_through_injected_escapes():
    for enabled in (True, False):
        s = Styler(enabled=enabled)
        hostile = "ignore me\x1b[2J\x1b[31mHACKED\x1b[0m"
        painted = s.paint(hostile, "avra")
        md = s.markdown(hostile)
        # the injected sequences are gone; any ESC present is only our own wrapper
        assert "\x1b[2J" not in painted and "\x1b[2J" not in md
        assert "\x1b[31mHACKED" not in painted and "\x1b[31mHACKED" not in md
        if not enabled:
            assert ESC not in painted and ESC not in md


# --- colour on/off ---------------------------------------------------------------------------

def test_paint_colours_only_when_enabled():
    assert Styler(enabled=True).paint("hi", "user") == "\x1b[36mhi\x1b[0m"   # cyan
    assert Styler(enabled=True).paint("hi", "avra") == "\x1b[32mhi\x1b[0m"   # green
    assert Styler(enabled=True).paint("hi", "error") == "\x1b[31mhi\x1b[0m"  # red
    assert Styler(enabled=True).paint("hi", "system") == "\x1b[90mhi\x1b[0m"  # gray
    assert Styler(enabled=False).paint("hi", "user") == "hi"                 # plain fallback


def test_markers_unicode_and_ascii():
    assert Styler(enabled=False, unicode_ok=True).marker("user") == "YOU ❯"
    assert Styler(enabled=False, unicode_ok=False).marker("user") == "YOU >"
    assert Styler(enabled=False, unicode_ok=False).marker("avra") == "AVRA *"
    assert Styler(enabled=False, unicode_ok=False).marker("system") == "SYSTEM -"


# --- markdown --------------------------------------------------------------------------------

def test_markdown_enabled_renders_bold_code_bullets_headings():
    s = Styler(enabled=True, unicode_ok=True)
    assert s.markdown("**b**") == "\x1b[1mb\x1b[0m"
    assert s.markdown("`c`") == "\x1b[36mc\x1b[0m"
    assert s.markdown("- item").startswith("• ")
    assert s.markdown("# Title") == "\x1b[1;32mTitle\x1b[0m"


def test_markdown_disabled_strips_markers_to_plain_text():
    s = Styler(enabled=False, unicode_ok=False)
    assert s.markdown("**bold** and `code`") == "bold and code"
    assert s.markdown("- one\n- two") == "- one\n- two"
    assert s.markdown("## Heading") == "Heading"
    assert ESC not in s.markdown("**x** `y` # z")


def test_unicode_text_is_preserved():
    s = Styler(enabled=False)
    uz = "Oxirgi holat: YOPIQ, xizmatni tekshiring"
    assert s.sanitize(uz) == uz and s.markdown(uz) == uz


def test_sanitize_strips_c1_controls_and_bidi_overrides():
    # M13.2 F4: besides C0/DEL, the sanitizer must drop the C1 range (U+0080-U+009F, where
    # 0x9B is an 8-bit CSI) and Unicode bidi/format and line/paragraph separators, which can
    # steer or visually reorder terminal output. Legitimate Uzbek/Cyrillic text stays.
    # Built with chr() so the source file holds no ambiguous/invisible literal characters.
    bad_points = [0x9B, 0x202E, 0x2066, 0x2069, 0x2028, 0x2029, 0x00AD, 0x200B]
    s = Styler(enabled=True)
    csi, rlo, lri, pdi = chr(0x9B), chr(0x202E), chr(0x2066), chr(0x2069)
    hostile = f"ok{csi}31mRED{rlo}EVIL{lri}x{pdi}z"
    out = s.sanitize(hostile)
    for cp in bad_points:
        assert chr(cp) not in out
    assert out == "ok31mREDEVILxz"  # only the inert visible characters remain
    # a lone surrogate (category Cs) is dropped, not raised on
    assert s.sanitize("a" + chr(0xD800) + "b") == "ab"
    # normal content, including non-Latin letters (category Lo), is untouched
    cjk = chr(0x4E2D)  # a CJK letter: not a control/format/separator, must survive
    assert s.sanitize("Natija " + cjk + " ok") == "Natija " + cjk + " ok"
