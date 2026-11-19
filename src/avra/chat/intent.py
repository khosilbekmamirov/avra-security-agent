"""Deterministic intent gate for ``avra chat`` (M14.5).

The owner's message is classified by fixed word lists - no model call. The result only ever
NARROWS what the model is offered this turn:

* GREETING                      -> no tools at all (a greeting needs no evidence);
* GENERAL_QUESTION              -> a capability question gets capability + session-list
                                   tools only; any other question gets read-only tools;
* EXPLAIN / SUMMARIZE / COMPARE /
  READ_ONLY_INVESTIGATION / PLAN /
  AMBIGUOUS                     -> read-only evidence tools; NO action tool;
* LIVE_ACTION_REQUEST           -> read-only tools + ``request_action`` (still only a
                                   PROPOSAL; the owner's /approve and the terminal [y/N]
                                   confirmation are unchanged).

Fail-closed rules: an explicit "no live / don't run / bajarma" anywhere in the message wins
over any action word; an action word inside a question ("what scan could we do?") is
planning, not a request; anything unclear is AMBIGUOUS, which never offers the action tool.
Nothing here can grant execution: approvals are handled only by ``/approve`` and the REPL's
one-shot yes/no context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class Intent(StrEnum):
    GREETING = "GREETING"
    GENERAL_QUESTION = "GENERAL_QUESTION"
    EXPLAIN = "EXPLAIN"
    SUMMARIZE = "SUMMARIZE"
    COMPARE = "COMPARE"
    READ_ONLY_INVESTIGATION = "READ_ONLY_INVESTIGATION"
    PLAN = "PLAN"
    LIVE_ACTION_REQUEST = "LIVE_ACTION_REQUEST"
    AMBIGUOUS = "AMBIGUOUS"


def normalize(text: str) -> str:
    t = (text or "").lower()
    for ch in ("‘", "’", "ʻ", "ʼ", "`", "´"):
        t = t.replace(ch, "'")
    return re.sub(r"\s+", " ", t).strip()


def _rx(*parts: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{p})" for p in parts))


_GREET_WORDS = frozenset(["salom", "assalomu", "alaykum", "assalom", "hello", "hi", "hey", "hayrli", "kun", "tong", "kech", "rahmat", "raxmat", "thanks", "thank", "you", "yaxshi", "zo'r", "ok", "okay", "qalaysiz", "qalesan", "qalaysan", "qandaysiz", "yaxshimisiz", "yaxshimisan", "xayr", "hammasi", "good", "morning", "evening", "bye", "privet", "привет", "спасибо"])

# "No live activity at all" (no scans, read-only, only recorded evidence): even a PROPOSAL is
# withheld. These always win (fail closed).
_NO_ACTIVITY = _rx(
    r"\bno (live|new|network) ", r"\bno (scan|scans|probe|probes|requests?)\b",
    r"\b(do not|don't|dont|never|without) (scan|scanning|probe|probing|touch|contact)",
    r"\bread[- ]only\b", r"\boffline only\b", r"\bonly (the )?(recorded|existing|stored) ",
    r"\bskanerlama", r"\b(scan|skaner|scaner|skan) qilma", r"\btekshirma", r"\byuborma",
    r"\bhech (narsa|nima|qanday)[^.?!]{0,40}(skaner|tarmoq|yubor)",
    r"\bjonli[^.?!]{0,30}(yo'q|emas|kerak emas|qilma)", r"\bfaqat (mavjud|yozilgan|saqlangan|"
    r"oldingi) ", r"\bfaqat dalil", r"\bfaqat tushuntir", r"\bfaqat o'qi",
    r"\btaklif (qilma|kerak emas)", r"\b(do not|don't|dont) (propose|suggest)")
# "Do not EXECUTE" - compatible with asking for a proposal (a proposal never executes), but
# without an explicit propose verb it also withholds the action tool.
_NO_EXEC = _rx(
    r"\b(do not|don't|dont|never|without) (run|running|execute|executing|send|sending|start)",
    r"\bnot (yet|now)\b", r"\bbajarma", r"\bishga tushirma", r"\bboshlama",
    r"\bhech (narsa|nima|qanday)[^.?!]{0,40}(bajar|ishga tushir)")
_PROPOSE = _rx(r"\btaklif qil", r"\bpropose\b", r"\bsuggest (a|an|one|the) (new )?"
               r"(scan|probe|check|action)", r"\btaklifini (ber|tayyorla)")

# Explicit requests to propose / run a live action.
_LIVE = _rx(
    r"\b(scan|rescan|probe|fetch|re-?run)\b", r"\bnmap\b[^?]*\b(qil|run|ishga|o'tkaz|yubor)",
    r"\bskaner(la|lash|ni|ini)?\b", r"\bscaner", r"\bskanla", r"\b(scan|skan|skaner) qil",
    r"\b(nmap_connect_scan|http_probe|http_get_path|request_action)\b",
    r"\btaklif qil", r"\bpropose\b", r"\bsuggest (a|an|one|the) (new )?(scan|probe|check|action)",
    r"\bishga tushir", r"\bbajar\b", r"\bbajaring\b", r"\bo'tkaz(ing)?\b",
    r"\btekshiruv(ini|ni)? (qil|o'tkaz|bajar)", r"\b(get|so'rov) yubor")

_QUESTION = _rx(r"\?\s*$", r"^(what|why|how|which|when|where|who|can|could|should|is|are|do|"
                r"does)\b", r"\b(nima|nega|nimaga|qanday|qaysi|qachon|qayer|kim|nechta|"
                r"mumkinmi|bo'ladimi|kerakmi)\b", r"\b(mi|mu)\?")
_PLAN = _rx(r"\b(plan|next step|what next|what should|what could|what can we)\b",
            r"\breja\b", r"\bkeyingi (qadam|bosqich)", r"\bkeyin nima",
            r"\bnima qilish (kerak|mumkin)", r"\bqanday (tekshiruv|qadam|reja)",
            r"\bnima qilamiz")
_COMPARE = _rx(r"\bcompar", r"\bsolishtir", r"\bfarq", r"\bversus\b", r"\bvs\.?\b",
               r"\bdifference")
_SUMMARIZE = _rx(r"\bsummar", r"\bxulosa", r"\bqisqacha", r"\bumumlashtir", r"\boverview\b",
                 r"\bdigest\b", r"\bnatijalar(ini|ni)? ko'rsat")
_EXPLAIN = _rx(r"\bexplain", r"\btushuntir", r"\bnega\b", r"\bnimaga\b", r"\bwhy\b",
               r"\bsabab", r"\bma'nosi", r"\bmeaning", r"\bnima degani", r"\bnima\?$",
               r"\bnima\b.*\?$", r"\bwhat (is|are|does)\b")
_INVESTIGATE = _rx(r"\b(analy[sz]|tahlil)", r"\bdalil", r"\bevidence", r"\bsessiya",
                   r"\bsession", r"\binvestigation", r"\bverdict", r"\bhukm", r"\bport",
                   r"\b(ochiq|yopiq|open|closed|filtered)\b",
                   r"\bnatija", r"\bresult", r"\bko'rsat", r"\bshow\b", r"\blist\b",
                   r"\bro'yxat", r"\bhisobot", r"\breport", r"\binconclusive", r"\bnoaniq",
                   r"\bweb surface", r"\bendpoint")
_CAPABILITY = _rx(r"\b(vazifang|vazifasi|kimsan|nima qila olasan|qila olasan|nimalar qila|"
                  r"what can you|who are you|capabilit|imkoniyat|vosita|tools?\b|asbob)")


@dataclass(frozen=True)
class IntentResult:
    intent: Intent
    no_live: bool                      # the owner explicitly ruled out live activity
    live_words: bool                   # an action word appeared (maybe negated / asked)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    narrow: bool = False               # a capability question: the small tool set is enough

    @property
    def allows_action_tool(self) -> bool:
        return self.intent is Intent.LIVE_ACTION_REQUEST and not self.no_live


def classify(text: str) -> IntentResult:
    t = normalize(text)
    if not t:
        return IntentResult(Intent.AMBIGUOUS, False, False, ("empty",))
    words = [w for w in re.split(r"[^\w']+", t) if w]
    propose = bool(_PROPOSE.search(t))
    no_exec = bool(_NO_EXEC.search(t))
    # a proposal request may say "don't run it yet"; any other no-exec / no-activity wins
    no_live = bool(_NO_ACTIVITY.search(t)) or (no_exec and not propose)
    live = bool(_LIVE.search(t))
    question = bool(_QUESTION.search(t))
    reasons: list[str] = []
    if no_live:
        reasons.append("explicit no-live directive")
    if words and len(words) <= 5 and all(w in _GREET_WORDS for w in words):
        return IntentResult(Intent.GREETING, no_live, live, ("greeting words only",))
    # Short yes/no-like replies carry no task of their own: never an action request.
    if len(words) <= 4 and any(w in ("ha", "xa", "yes", "ok", "okay", "mayli", "xo'p",
                                     "yo'q", "no") for w in words):
        return IntentResult(Intent.AMBIGUOUS, no_live, live, (*reasons, "bare yes/no"))
    if live and not no_live and (propose or not question):
        return IntentResult(Intent.LIVE_ACTION_REQUEST, False, True,
                            ("explicit action request",))
    evidence_words = bool(_INVESTIGATE.search(t))
    if live and question and not no_live:
        reasons.append("action word inside a question: not a request")
    if _PLAN.search(t) or (live and question and not evidence_words):
        return IntentResult(Intent.PLAN, no_live, live, (*reasons, "planning"))
    if _COMPARE.search(t):
        return IntentResult(Intent.COMPARE, no_live, live, (*reasons, "compare"))
    if _SUMMARIZE.search(t):
        return IntentResult(Intent.SUMMARIZE, no_live, live, (*reasons, "summarize"))
    if _CAPABILITY.search(t) and not evidence_words:
        return IntentResult(Intent.GENERAL_QUESTION, no_live, live, (*reasons, "capability"),
                            narrow=True)
    if _EXPLAIN.search(t):
        return IntentResult(Intent.EXPLAIN, no_live, live, (*reasons, "explain"))
    if evidence_words:
        return IntentResult(Intent.READ_ONLY_INVESTIGATION, no_live, live,
                            (*reasons, "evidence words"))
    if question:
        return IntentResult(Intent.GENERAL_QUESTION, no_live, live, (*reasons, "question"))
    return IntentResult(Intent.AMBIGUOUS, no_live, live, (*reasons, "no clear task"))


# Tool sets per intent (names only; the agent intersects with what is actually available).
GENERAL_TOOLS = ("get_capabilities", "list_investigations")
READ_TOOLS = ("get_capabilities", "list_investigations", "summarize_investigation",
              "get_investigation", "explain_verdict", "get_web_surface",
              "get_research_history", "plan_next_steps", "run_offline_verification",
              "evaluate_validation_fixture")


def tools_for(result: IntentResult) -> tuple[str, ...]:
    if result.intent is Intent.GREETING:
        return ()
    if result.narrow:
        return GENERAL_TOOLS
    if result.allows_action_tool:
        return (*READ_TOOLS, "request_action")
    return READ_TOOLS
