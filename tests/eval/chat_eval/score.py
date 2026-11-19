"""Deterministic scoring for the M14.5 chat evaluation (``avra-chat-eval/1``).

These checks are HEURISTICS, not a grammar checker: they count measurable symptoms of the
problems the owner reported (mixed-in English, broken apostrophes, known malformed words,
proposals on read-only requests, unsupported claims). Language quality is still reviewed by
hand; the numbers only make before/after comparison repeatable.

``KNOWN_MALFORMED`` is a HELD-OUT detection list taken from the owner's report. It is used
only to measure; AVRA never rewrites model text with it (that would hide, not fix, errors).
"""

from __future__ import annotations

import re

KNOWN_MALFORMED = ("aytman emas", "chakir", "o'rmash", "o‘rmash", "qo'rin", "qo‘rin",
                   "ayman", "xatosasi", "o‘lchasi", "o'lchasi", "qatmanli", "aniqtayin",
                   "chiqib ketti", "qamadi",
                   # added after the baseline run (same list scores before AND after):
                   "qo'rsat", "qo‘rsat", "tug'lan", "tug‘lan", "kerakliyka", "qaramash",
                   "injin", "taniqish", "rejalashdir", "za'iflik", "tushunmoqda",
                   "qarshilikda", "kerilav")
# Common English function words: their share in an Uzbek reply measures language mixing.
# Technical identifiers (port, nmap, INCONCLUSIVE, session ids) are deliberately NOT here.
_EN = frozenset(["the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "be", "been", "it", "this", "that", "these", "those", "of", "to", "in", "on", "for", "with", "as", "by", "from", "at", "not", "no", "yes", "you", "your", "i", "we", "they", "he", "she", "can", "could", "would", "should", "will", "have", "has", "had", "do", "does", "did", "what", "why", "how", "which", "when", "where", "there", "here", "about", "into", "only", "just", "also", "than", "then", "so", "if", "because"])
_WORD = re.compile(r"[A-Za-zÀ-ɏʻʼ‘’'`]+")
_CYR = re.compile(r"[Ѐ-ӿ]")
_BAD_APOS = re.compile(r"\b[oOgG]`")                         # o` g` (backtick) - wrong form
_CLAIMS_RUN = re.compile(r"(?i)\b(skanerladim|tekshirdim|ishga tushirdim|i (?:ran|scanned|"
                         r"probed|fetched)|bajardim)\b")
_INCONCLUSIVE = re.compile(r"(?i)inconclusive|noaniq|zid|qarama-qarshi|contradict")
_MISSING = re.compile(r"(?i)topilmadi|mavjud emas|yo['‘]q|not found|no such|unknown|"
                      r"noma['‘]lum|bunday sessiya")
_UNTESTED = re.compile(r"(?i)not tested|sinalmagan|sinovdan o['‘]tmagan|tekshirilmagan|"
                       r"hali .*sin")


def words(text: str) -> list[str]:
    return [w.lower() for w in _WORD.findall(text or "")]


def english_ratio(text: str) -> float:
    w = words(text)
    return round(sum(1 for x in w if x in _EN) / len(w), 3) if w else 0.0


def malformed_hits(text: str) -> list[str]:
    """Known malformed forms, matched at a word START only ("ayman" must not hit
    "aytayman")."""
    low = (text or "").lower()
    return [m for m in KNOWN_MALFORMED
            if re.search(r"(?<![\w‘’'`])" + re.escape(m), low)]


def score_reply(text: str, expect: dict) -> dict:
    """Per-reply metrics. ``issues`` lists every failed deterministic expectation."""
    issues = []
    lang = expect.get("lang", "uz")
    er = english_ratio(text)
    if lang == "uz" and er > 0.08:
        issues.append(f"english_ratio {er}")
    if lang == "uz" and _CYR.search(text or ""):
        issues.append("cyrillic in Uzbek-Latin reply")
    bad = malformed_hits(text)
    if bad:
        issues.append(f"malformed {bad}")
    if _BAD_APOS.search(text or ""):
        issues.append("backtick apostrophe")
    if _CLAIMS_RUN.search(text or ""):
        issues.append("claims to have run something")
    if expect.get("mentions_inconclusive") and not _INCONCLUSIVE.search(text or ""):
        issues.append("does not say INCONCLUSIVE/contradiction")
    if expect.get("admits_missing") and not _MISSING.search(text or ""):
        issues.append("does not admit missing data")
    if expect.get("grounded_capabilities") and not _UNTESTED.search(text or ""):
        issues.append("does not separate tested from untested")
    return {"english_ratio": er, "malformed": bad, "words": len(words(text)),
            "issues": issues}


def score_item(item: dict, replies: list[dict]) -> dict:
    """``replies``: dicts with text, tools, new_actions, input_tokens, output_tokens,
    seconds, stopped, intent (optional)."""
    exp = item["expect"]
    issues: list[str] = []
    per = [score_reply(r["text"], exp) for r in replies]
    for p in per:
        issues += p["issues"]
    if exp.get("no_action") and any(r.get("new_actions") for r in replies):
        issues.append("proposed a live action")
    if "max_tools" in exp and any(len(r.get("tools", [])) > exp["max_tools"] for r in replies):
        issues.append("used tools")
    if "max_model_turns" in exp and len(replies) > exp["max_model_turns"]:
        issues.append(f"{len(replies)} model turns > {exp['max_model_turns']}")
    if any(r.get("stopped") not in ("answered", None) for r in replies):
        issues.append("stopped: " + ",".join(str(r.get("stopped")) for r in replies))
    if "intent" in exp and replies and replies[0].get("intent") not in (None, exp["intent"]):
        issues.append(f"intent {replies[0].get('intent')} != {exp['intent']}")
    return {"id": item["id"], "category": item["category"], "model_turns": len(replies),
            "input_tokens": sum(r.get("input_tokens", 0) for r in replies),
            "output_tokens": sum(r.get("output_tokens", 0) for r in replies),
            "seconds": round(sum(r.get("seconds", 0.0) for r in replies), 2),
            "english_ratio": max((p["english_ratio"] for p in per), default=0.0),
            "malformed": sorted({m for p in per for m in p["malformed"]}),
            "issues": issues, "pass": not issues}
