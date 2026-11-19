"""Terminal loop for ``avra chat`` (M11.1/M11.6, ADR 0019).

Plain text in, plain text out; slash commands are handled HERE (never by the model):

  /help                 this help
  /exit, /quit          leave (Ctrl+C at the prompt also leaves)
  /list                 saved conversations
  /history [n]          the last n messages of this conversation (default 10)
  /pending              live actions the model proposed in this run
  /summary [id]         concise, evidence-grounded digest of an investigation (no model call)
  /details [id]         the full recorded evidence and engine verdicts (read-only, no model call)
  /approve <id>         run ONE pending action once (real terminal only; shows the exact
                        request and asks again)
  /deny <id>            decline a pending action
  /scope                the authorized target(s) and permitted operations of the bound scope
  /runner               authenticated read-only Runner health check (real terminal only; the
                        ONLY chat command that contacts Kali; shows the Windows/Kali tool overlap)
  /status               model, conversation, scope, context budget, data paths
  \"\"\"                   start / end a multi-line message (or just paste several lines)

Ctrl+C while the model is answering cancels that answer and returns to the prompt.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from avra.chat import knowledge as kb
from avra.chat.agent import ChatAgent, PendingAction
from avra.chat.store import list_conversations
from avra.chat.style import Styler

# M13 Goal 3: the exact, explicit tokens accepted as yes/no, and ONLY inside an active
# approval context. Deterministic and local - the LLM never interprets approval.
#
# YES is accepted only for a CLEAN, unqualified affirmation: a contradicting no-token, a
# qualifier ("ha, lekin bajarma" / "yes but not now"), or any unknown word makes the reply
# ambiguous, and ambiguous NEVER authorizes execution (it falls through to ordinary chat).
# NO fails safe: a denial token with no yes-token is a decline even amid other words.
_YES = {"ha", "xa", "yes", "y", "ok", "okay", "tasdiqlayman", "tasdiqla", "tasdiq",
        "roziman", "davom"}
_NO = {"yo'q", "yoq", "no", "n", "bekor", "rad", "yomon", "stop"}
# Words that make a yes/no reply conditional or hedged - treated as ambiguous.
_QUALIFIER = {"lekin", "ammo", "biroq", "but", "however", "although", "faqat", "agar",
              "if", "balki", "maybe", "perhaps", "hozircha", "keyin", "later", "shoshma"}
# Harmless politeness words allowed alongside a clean YES.
_FILLER = {"iltimos", "please", "rahmat", "thanks", "thank", "yaxshi"}
_STATE_UZ = {"open": "OCHIQ", "closed": "YOPIQ", "filtered": "FILTRLANGAN",
             "open|filtered": "OCHIQ/FILTRLANGAN"}
_VERDICT_UZ = {"INCONCLUSIVE": "NOANIQ", "CONFIRMED": "TASDIQLANGAN",
               "REJECTED": "RAD ETILGAN", "not_evaluated": "BAHOLANMAGAN"}

HELP = __doc__.split("\n\n", 1)[1].split("Ctrl+C while", 1)[0].rstrip()


class Repl:
    def __init__(self, agent: ChatAgent, *, read: Callable[[str], str],
                 write: Callable[[str], None], interactive: bool,
                 confirm: Callable[[str], bool], data_root, status: dict,
                 runner_status: Callable[[], dict] | None = None,
                 styler: Styler | None = None,
                 more_input: Callable[[], str | None] | None = None) -> None:
        self.agent, self.read, self.write = agent, read, write
        self.interactive, self.confirm = interactive, confirm
        self.data_root, self.status = data_root, status
        # M13.1: presentation only. Default is a disabled (plain-text) styler, so tests and
        # non-TTY output stay colourless; the CLI passes a TTY-aware one. Colour never
        # affects authorization, verdicts or state.
        self.st = styler if styler is not None else Styler(enabled=False)
        # M12.3 option B: owner-invoked, authenticated, read-only Runner health check.
        # Never called automatically; only the /runner command triggers it.
        self.runner_status = runner_status
        # M13 Goal 3: id of the single action the owner may confirm with a natural "ha"/"yes"
        # on the VERY NEXT input. Set only from validated app state (this run's new proposal),
        # never from model text; consumed by exactly one input; None most of the time.
        self._approval_ctx: str | None = None
        # M14.5 (Issue F): a paste of several lines used to become several model turns, one
        # per line ("Tasks:", "1. ...", "2. ..."). ``more_input`` returns a line that is
        # ALREADY waiting in the terminal (the rest of a paste) or None; the CLI wires it to
        # the console buffer. Such lines are joined into one message.
        self.more_input = more_input
        # an unfinished message ("Vazifalar:") held until the owner continues
        self._held: str | None = None

    def banner(self) -> None:
        s = self.status
        self.write(self.st.paint(
            f"AVRA chat - model {s['model']} via {s['provider']}"
            f"{' (local, no API cost)' if s.get('local') else ' (PAID API)'}", "avra"))
        self.write(self.st.paint(
            f"Conversation: {self.agent.conv.name} "
            f"({'resumed, ' + str(s['messages']) + ' messages' if s['messages'] else 'new'})"
            f" - scope: {s['scope'] or 'none (live actions disabled)'}", "system"))
        for line in kb.scope_summary(self.agent.checker):
            self.write(self.st.paint(line, "system"))
        self.write(self.st.paint(
            "Type /help for commands, /exit to leave. Verified facts come from AVRA's "
            "engine; the model's own ideas are labelled as hypotheses.", "system"))

    def run(self) -> int:
        self.banner()
        while True:
            try:
                line = self.read("\n" + self.st.prompt())
            except (EOFError, KeyboardInterrupt):
                self.write("\nBye.")
                return 0
            line = self._gather(line)
            if line is None:
                continue
            # M13 Goal 3: an active approval context consumes exactly this one input. A plain
            # "ha"/"yes" here (and only here) runs the just-proposed action through the SAME
            # gated path as /approve; anything else clears the context and is handled normally,
            # so ordinary chat, model output or stored text can never approve.
            if (self._approval_ctx is not None and not line.startswith("/")
                    and self._resolve_natural_approval(line)):
                continue
            if line.startswith("/"):
                self._approval_ctx = None
                if self.command(line) == "exit":
                    self.write("Bye.")
                    return 0
                continue
            try:
                reply = self.agent.ask(line)
            except KeyboardInterrupt:
                self.write("(interrupted)")
                continue
            self.write("")
            self.write(self.st.paint(self.st.marker("avra"), "avra"))
            self.write(self.st.markdown(reply.text))
            tools = f" | tools: {', '.join(reply.tool_calls)}" if reply.tool_calls else ""
            self.write(self.st.paint(
                f"{self.st.marker('system')} {reply.model_calls} model call(s) | "
                f"{reply.seconds:.1f}s | {reply.input_tokens} in / {reply.output_tokens} out"
                f"{tools}", "system"))
            self._offer_natural_approval(reply)

    # --- M14.5 (Issue F): one message per paste, unfinished messages, echoed UI chrome ---

    _BLOCK = '"""'
    # Lines of AVRA's own terminal output that an owner may paste back by accident.
    _CHROME = re.compile(r"^\s*(?:YOU\s*❯|AVRA\s*●|SYSTEM\s*·|[❯●·]\s)|"
                         r"^\s*(?:\[pending\] |Model error: |APPROVAL REQUIRED\b|"
                         r"\d+ model call\(s\) \|)")
    _UNFINISHED = re.compile(r"(?:[:;,]|\.\.\.|…|\b(?:va|and|hamda|lekin|but|then|keyin))"
                             r"\s*$", re.IGNORECASE)

    def _gather(self, first: str) -> str | None:
        """Turn raw input into ONE message, or None when nothing should reach the model."""
        lines = [first]
        if first.strip() == self._BLOCK:                 # explicit multi-line block
            lines = []
            while True:
                try:
                    nxt = self.read("... ")
                except (EOFError, KeyboardInterrupt):
                    break
                if nxt.strip() == self._BLOCK:
                    break
                lines.append(nxt)
        elif self.more_input is not None and not first.strip().startswith("/"):
            while (nxt := self.more_input()) is not None:  # the rest of a paste
                lines.append(nxt)
        kept, dropped = [], 0
        for ln in lines:
            m = self._CHROME.match(ln)
            if m is None:
                kept.append(ln)
                continue
            dropped += 1
            rest = ln[m.end():].strip() if re.match(r"^\s*YOU\s*❯", ln) else ""
            if rest:
                kept.append(rest)  # "YOU ❯ question" pasted back: keep only the question
        if dropped:
            self.write(self.st.paint(
                f"(AVRA'ning o'z terminal chiqishi aniqlandi: {dropped} qator modelga "
                "yuborilmadi.)", "system"))
        text = "\n".join(kept).strip()
        if self._held is not None:
            if not text:                                  # empty line: send what is held
                text, self._held = self._held, None
                return text
            if text.startswith("/"):                      # a command drops the held text
                self._held = None
                return text
            text, self._held = self._held + "\n" + text, None
        if not text:
            return None
        if not text.startswith("/") and len(text) <= 400 and self._UNFINISHED.search(text):
            self._held = text                             # e.g. "Vazifalar:" - wait for more
            self.write(self.st.paint(
                "(Xabar tugallanmaganga o'xshaydi - davomini yozing. Shu holicha yuborish "
                "uchun bo'sh qator yuboring.)", "system"))
            return None
        return text

    def command(self, line: str) -> str | None:
        parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in ("/exit", "/quit"):
            return "exit"
        if cmd == "/help":
            self.write(HELP)
        elif cmd == "/list":
            rows = list_conversations(self.data_root)
            for r in rows:
                self.write(f"  {r['name']:<24} {r.get('messages')} msgs  last {r.get('last', '')}"
                           f"  \"{r.get('first_question', '')}\"")
            if not rows:
                self.write("  (no saved conversations)")
        elif cmd == "/history":
            n = int(args[0]) if args and args[0].isdigit() else 10
            for m in self.agent.conv.messages()[-n:]:
                who = {"user": "you", "assistant": "avra", "avra_note": "AVRA record"}[m.role]
                self.write(f"[{m.ts}] {who}: {m.content[:500]}")
        elif cmd == "/pending":
            acts = list(self.agent.pending.values())
            for a in acts:
                self.write(f"  {a.describe()} [{a.status}] - why: {a.reason}")
            if not acts:
                self.write("  (no proposed actions in this run)")
        elif cmd == "/summary":
            self._show_summary(args[0] if args else "latest")
        elif cmd == "/details":
            self._show_details(args[0] if args else "latest")
        elif cmd == "/approve":
            if not args:
                self.write("Usage: /approve <id>")
            elif not self.interactive:
                self.write("Refused: approving a live action needs a real terminal. Nothing ran.")
            else:
                self.write(self.agent.approve(args[0], self._confirm_action))
        elif cmd == "/deny":
            self.write(self.agent.deny(args[0]) if args else "Usage: /deny <id>")
        elif cmd == "/scope":
            for line in kb.scope_summary(self.agent.checker):
                self.write(line)
        elif cmd == "/runner":
            self._runner_check()
        elif cmd == "/status":
            for k, v in self.status.items():
                self.write(f"  {k}: {v}")
            for line in kb.scope_summary(self.agent.checker):
                self.write(f"  {line}")
            try:
                b = self.agent.budget()
                self.write(f"  context: window {b.context_tokens} tokens ({b.source}), "
                           f"{b.output_tokens} reserved for answers, prompt limit "
                           f"{b.input_limit}")
            except Exception as exc:  # noqa: BLE001 - status display only
                self.write(f"  context: unknown ({type(exc).__name__})")
            self.write(f"  conversation file: {self.agent.conv.path}")
            self.write(f"  conversation audit: {self.agent.conv.audit_path}")
        else:
            self.write(f"Unknown command {cmd}. Type /help.")
        return None

    def _runner_check(self) -> None:
        """M12.3 option B: owner-invoked, authenticated, read-only Runner health check.

        This is the only chat command that contacts Kali. It sends no tool run, changes
        nothing, and reports the overlap between what the Windows scope permits and what the
        Kali Runner actually registers, so the owner sees the real intersection in force."""
        if not self.interactive:
            self.write(self.st.paint(
                "Refused: the Runner status check needs a real terminal. Nothing was sent.",
                "warning"))
            return
        if self.runner_status is None:
            self.write(self.st.paint("No Runner is configured for this chat (start it with "
                                     "--scope and a reachable Kali host).", "warning"))
            return
        self.write(self.st.paint(
            "Contacting the Runner (authenticated, read-only health check)...", "system"))
        try:
            info = self.runner_status()
        except Exception as exc:  # noqa: BLE001 - report, never crash the chat
            self.agent.runner_check = f"checked this run: FAILED ({type(exc).__name__})"
            self.write(self.st.paint(f"Runner status failed: {exc}", "error"))
            return
        tools = [str(t) for t in info.get("tools", [])]
        # M14.5: a grounded runtime fact for get_capabilities (this run only)
        self.agent.runner_check = ("checked this run: reachable; Kali tools "
                                   + (", ".join(tools) or "(none)"))
        self.write(self.st.paint(
            f"Runner reachable. Kali-registered tools: {', '.join(tools) or '(none)'}", "success"))
        checker = self.agent.checker
        if checker is not None:
            scope_tools = sorted({t for tgt in checker.scope.targets for t in tgt.allowed_tools})
            both = sorted(set(tools) & set(scope_tools))
            self.write(self.st.paint(
                f"Windows scope permits: {', '.join(scope_tools) or '(none)'}", "system"))
            self.write(self.st.paint(
                f"Usable here (Windows AND Kali): {', '.join(both) or '(none)'}", "system"))
            only_win = sorted(set(scope_tools) - set(tools))
            if only_win:
                self.write(self.st.paint("In scope but NOT registered on Kali (cannot run): "
                                         f"{', '.join(only_win)}", "warning"))

    # --- M13 Goal 2: deterministic, read-only presentation (no model call) ----------------

    def _show_summary(self, ref: str) -> None:
        try:
            s = kb.summary(kb.resolve_session(ref))
        except kb.KnowledgeError as exc:
            self.write(self.st.paint(f"Topilmadi: {exc}", "error"))
            return
        for line in self._render_summary_uz(s):
            if line.startswith("Tekshiruv natijasi"):
                self.write(self.st.paint(line, "heading"))
            elif line.startswith("DIQQAT"):
                self.write(self.st.paint(line, "error"))
            elif line.startswith("Umumiy xulosa"):
                role = ("inconclusive" if "NOANIQ" in line else
                        "verified" if "TASDIQLANGAN" in line else
                        "rejected" if "RAD ETILGAN" in line else "system")
                self.write(self.st.paint(line, role))
            else:
                self.write(self.st.sanitize(line))  # neutral but still sanitised

    def _show_details(self, ref: str) -> None:
        import json

        try:
            data = kb.investigation(kb.resolve_session(ref))
        except kb.KnowledgeError as exc:
            self.write(self.st.paint(f"Topilmadi: {exc}", "error"))
            return
        # sanitise: evidence/tool strings in the dump must not carry terminal escapes
        self.write(self.st.sanitize(json.dumps(data, indent=2, ensure_ascii=False,
                                                default=str)))

    def _render_summary_uz(self, s: dict) -> list[str]:
        out = [f"Tekshiruv natijasi - sessiya {s['session_id'][:8]}"]
        if not s["audit_chain_valid"]:
            out.append("DIQQAT: audit zanjiri buzilgan - natijalarga ishonmang.")
        if not s["evidence_trusted"]:
            out.append("DIQQAT: dalillar ishonchli emas.")
        ps = s["port_status"]
        if ps:
            out.append(f"Manzil: {', '.join(ps['targets'])}")
            if ps["latest_state"]:
                out.append(f"Oxirgi holat: {_STATE_UZ.get(ps['latest_state'], ps['latest_state'])}")
            counts = ", ".join(f"{n} marta {_STATE_UZ.get(st, st)}"
                               for st, n in ps["state_counts"].items())
            out.append(f"Skanerlar: {counts} (jami {ps['scan_count']})")
            out.append(f"Umumiy xulosa: {_VERDICT_UZ.get(ps['verdict'], ps['verdict'])}")
            if ps["conflicting"]:
                out.append("Sabab: natijalar bir-biriga zid.")
        else:
            out.append("Ishonchli skaner dalili yo'q.")
        for h in s["http"]:
            out.append(f"HTTP {h['path']} -> {h['outcome']} (status {h['status_code']})")
        vc = s["verdict_counts"]
        if vc["configuration_weaknesses"]:
            out.append(f"Konfiguratsiya zaifliklari: {vc['configuration_weaknesses']} ta "
                       "(zaiflashuv, isbotlangan ekspluatatsiya emas)")
        if vc["confirmed_vulnerabilities"]:
            out.append(f"Tasdiqlangan zaifliklar: {vc['confirmed_vulnerabilities']} ta")
        out.append(f"Tavsiya: {self._uz_next_step(s)}")
        out.append(f"To'liq dalillar uchun: /details {s['session_id'][:8]}")
        return out

    def _uz_next_step(self, s: dict) -> str:
        ps = s["port_status"]
        if ps is None:
            return "Hali ishonchli skaner dalili yo'q: ruxsat etilgan nmap_connect_scan o'tkazing."
        v = ps["verdict"]
        if v == "INCONCLUSIVE" or ps["conflicting"]:
            return "Avval maqsadli xizmat ishlayotganini tekshiring, so'ng qayta skaner qiling."
        if v == "CONFIRMED":
            return "Port ochiq tasdiqlangan; kerak bo'lsa '/' uchun http_probe taklif qiling."
        if v == "REJECTED":
            return "Port ochiq kuzatilmadi; xizmat ishlashi kerakligini tasdiqlang."
        return "Yozilgan dalillarni ko'rib chiqing."

    # --- M13 Goal 3: natural, deterministic approval (reuses the gated /approve path) ------

    def _offer_natural_approval(self, reply) -> None:
        """After a turn, arm a one-shot yes/no context ONLY for a single in-scope proposal
        that this run just created (validated app state, never model text)."""
        if not self.interactive or reply.stopped != "answered":
            return
        acts = [a for a in reply.new_actions if a.status == "pending" and a.scope_allows]
        if len(acts) == 1:
            a = acts[0]
            self._approval_ctx = a.id
            self.write("")
            self.write(self.st.paint("APPROVAL REQUIRED", "approval"))
            self.write(self.st.paint(f"       Action: {self._uz_action(a)}", "approval"))
            self.write(self.st.paint(f"       Target: {a.host}:{a.port}{a.path}", "approval"))
            self.write(self.st.paint(f"       ID:     {a.id}", "approval"))
            self.write(self.st.paint(
                f"       ha = tasdiqlash | yo'q = rad etish | /approve {a.id}", "approval"))
        elif len(acts) > 1:
            ids = ", ".join(a.id for a in acts)
            self.write(self.st.paint(
                f"\nBir nechta taklif bor ({ids}). Aniq tanlang: /approve <id>.", "warning"))

    def _resolve_natural_approval(self, line: str) -> bool:
        """Consume the one-shot approval context. Returns True if yes/no was acted on; False
        (context already cleared) means the input is ordinary chat."""
        ctx, self._approval_ctx = self._approval_ctx, None
        verdict = self._interpret_yes_no(line)
        if verdict == "yes":
            if not self.interactive:
                self.write("Refused: approving a live action needs a real terminal. Nothing ran.")
            else:
                self.write(self.agent.approve(ctx, self._confirm_action))
            return True
        if verdict == "no":
            self.write(self.agent.deny(ctx))
            return True
        return False

    @staticmethod
    def _interpret_yes_no(line: str) -> str | None:
        """Deterministic, fail-closed yes/no. Ambiguous input returns None and authorizes
        nothing: a reply with both a yes- and a no-token, a qualifier ("ha, lekin bajarma"),
        or any unknown word next to "ha"/"yes" is NOT an approval. NO fails safe - a denial
        token with no yes-token is a decline even amid other words."""
        t = line.strip().lower().replace("‘", "'").replace("’", "'") \
            .replace("ʻ", "'").replace("ʼ", "'")
        words = [w for w in re.split(r"[\s,.!;:?]+", t) if w]
        if not words:
            return None
        has_yes = any(w in _YES for w in words)
        has_no = any(w in _NO for w in words)
        if has_yes and has_no:                       # contradictory
            return None
        if any(w in _QUALIFIER for w in words):      # conditional / hedged
            return None
        if has_no:                                   # denial fails safe
            return "no"
        if has_yes and all(w in _YES or w in _FILLER for w in words):
            return "yes"                             # clean, unqualified affirmation only
        return None

    def _uz_action(self, a: PendingAction) -> str:
        if a.kind == "nmap_connect_scan":
            return f"nmap TCP connect skaner ({a.host}:{a.port})"
        if a.kind == "http_get_path":
            return f"'GET {a.path}' passiv ({a.host}:{a.port})"
        return f"'GET /' http_probe passiv ({a.host}:{a.port})"

    def _confirm_action(self, act: PendingAction) -> bool:
        # Second, mandatory terminal gate. Colour is cosmetic; the confirm() answer decides.
        self.write(self.st.paint(f"About to run: {act.describe()}", "approval"))
        self.write(self.st.paint(f"  Why (model): {act.reason}", "approval"))
        self.write(self.st.paint(
            "  Path: Windows scope check -> audited pipeline -> SSH tunnel -> Runner "
            "(re-checks its own scope). The kill switch stops it.", "system"))
        try:
            return self.confirm("  Send this request now? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            return False
