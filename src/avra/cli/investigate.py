"""`avra investigate` (M14.2, ADR 0022 Option A): drive one persistent investigation.

The deterministic planner chooses each candidate action, the owner approves each live
action in a real terminal (fingerprint prefix + a second confirmation), the existing audited
pipeline runs it with the request id recorded beforehand, and the engine re-analyses. An
optional model only explains (UNVERIFIED text). Keep this file ASCII-only (Windows consoles).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import typer

investigate_app = typer.Typer(help="M14: persistent, owner-approved investigations "
                                   "(planner chooses, owner approves, engine decides).")

EXIT_PAUSED = 2  # waiting for an owner decision; resume later


def _root() -> Path:
    return Path(os.environ.get("AVRA_DATA_DIR", "data")) / "investigations"


def _m():
    from avra.cli import main  # late import: tests monkeypatch main's factories

    return main


def _refuse(msg: str, code: int = 1):
    typer.secho(f"Refused: {msg}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


def _scope(scope: Path):
    from avra.policy.scope import ScopeChecker, ScopeError, load_scope

    try:
        checker = ScopeChecker(load_scope(scope))
    except ScopeError as exc:
        _refuse(str(exc))
    return checker, hashlib.sha256(Path(scope).read_bytes()).hexdigest()


def _scope_check(checker):
    from avra.chat import knowledge as kb

    return lambda tool, host, port, path: kb.scope_allows(checker, tool, host, port, path)


def _kill_reason() -> str | None:
    try:
        st = _m()._killswitch().status()
    except Exception as exc:  # noqa: BLE001 - an unreadable gate is a blocking gate
        return f"kill switch unreadable ({type(exc).__name__})"
    return st.detail if st.blocking else None


def _decide_factory(interactive: bool):
    from avra.chat.style import Styler
    from avra.research.controller import DEFER, DENY, Decision

    def say(text: str) -> None:
        # M13.2 F4 sanitiser: server-controlled paths and model text reach this approval
        # screen, so C1/bidi/format characters are dropped too (no prompt spoofing)
        _m()._say(Styler.sanitize(text))

    def decide(act, explanation):
        say("")
        say("Proposed by the deterministic planner (nothing has been sent):")
        say(f"  {act.describe()}")
        say(f"  why: {act.reason}")
        say(f"  expects: {act.expected_evidence}")
        if explanation:
            say("  model explanation (UNVERIFIED, not evidence): " + explanation[:800])
        if not interactive:
            say("Not a real terminal: the proposal stays pending. Resume with "
                "`avra investigate resume <id> --scope <file>` in a terminal.")
            return DEFER
        typed = typer.prompt(f"Type the first 12 characters of fingerprint {act.fingerprint[:12]}"
                             " to approve, 'later' to pause, anything else denies",
                             default="", show_default=False).strip()
        if typed.lower() == "later":
            return DEFER
        if typed != act.fingerprint[:12]:
            return DENY
        if not typer.confirm(f"Send this ONE {act.tier} request to {act.host}:{act.port}"
                             f"{act.path} now?", default=False):
            return DENY
        return Decision.approve(act.fingerprint)
    return decide


def _explainer(explain: bool, model, provider_name, base_url):
    if not explain:
        return None
    m = _m()
    from avra.llm.config import LLMConfig, LLMConfigError
    from avra.llm.factory import create_provider, ensure_supported
    from avra.llm.provider import LLMProviderError, load_api_key
    from avra.research.controller import model_explainer

    try:
        cfg = LLMConfig.from_env(model=model, provider=provider_name, base_url=base_url,
                                 effort="low")
        ensure_supported(cfg)
        if not cfg.is_local and (not m._interactive() or not typer.confirm(
                f"Explanations by {cfg.model} use the PAID Anthropic API. Continue?",
                default=False)):
            _refuse("paid explanations not confirmed; run without --explain or use a local "
                    "model")
        api_key = None if cfg.is_local else load_api_key(env_file=m._env_file())
        return model_explainer(create_provider(cfg, api_key=api_key))
    except (LLMConfigError, LLMProviderError) as exc:
        _refuse(str(exc))


def _drive(inv, *, checker, kali: str, key: Path | None, max_actions: int, explainer) -> None:
    from avra.chat import knowledge as kb
    from avra.research.controller import (
        Controller,
        Ports,
        analyze_session,
        evidence_verifier,
    )
    from avra.research.investigation import Investigation

    m = _m()

    def execute(act, request_id: str) -> dict:
        shim = SimpleNamespace(kind=act.tool, session_id=inv.session_id, host=act.host,
                               port=act.port, path=act.path)
        return m._chat_execute(shim, checker=checker, kali=kali, key=key, request_id=request_id)

    ports = Ports(analyze=lambda: analyze_session(inv.session_id, checker),
                  scope_check=_scope_check(checker),
                  decide=_decide_factory(m._interactive()),
                  execute=execute,
                  verify_evidence=evidence_verifier(kb.data_dir() / "sessions",
                                                    kb.data_dir() / "evidence", inv.session_id),
                  kill_reason=_kill_reason, explain=explainer, notify=m._say)
    try:
        res = Controller(inv, ports, max_actions=max_actions).run()
    except KeyboardInterrupt:
        # we still hold the run lock: reconcile now, so the log says INTERRUPTED at once
        with contextlib.suppress(Exception):
            Investigation.load(_root(), inv.investigation_id)
        typer.secho("Interrupted. Any action that had started is recorded as INTERRUPTED and "
                    "will never be re-run; the investigation is FAILED.", fg=typer.colors.YELLOW,
                    err=True)
        raise typer.Exit(code=130) from None
    typer.echo(f"Investigation {inv.investigation_id}: {res.state.value} - {res.message}")
    if res.paused:
        raise typer.Exit(code=EXIT_PAUSED)


def _locked_load(investigation_id: str):
    from avra.research.investigation import Investigation, InvestigationError, run_lock

    stack = contextlib.ExitStack()
    try:
        stack.enter_context(run_lock(_root(), investigation_id))
        return stack, Investigation.load(_root(), investigation_id)
    except InvestigationError as exc:
        stack.close()
        _refuse(str(exc))
    except ValueError:
        stack.close()
        _refuse("not a valid investigation id")


def _resolve_id(ref: str) -> str:
    ref = ref.strip().lower()
    root = _root()
    files = sorted(root.glob("*.jsonl")) if root.is_dir() else []
    hits = [p.stem for p in files if p.stem.startswith(ref)] if len(ref) >= 6 else []
    if len(hits) != 1:
        _refuse(f"{'no' if not hits else 'more than one'} investigation matches {ref!r} "
                "(use at least 6 characters)")
    return hits[0]


@investigate_app.command("start")
def investigate_start(
    session: str = typer.Argument(..., help="Session UUID, a 6+ char prefix, or 'latest'."),
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Scope file; bound to the investigation by its SHA-256."),
    objective: str = typer.Option(..., "--objective", help="What to find out (plain text)."),
    max_actions: int = typer.Option(3, "--max-actions", min=1, max=10,
                                    help="Live actions this investigation may execute."),
    explain: bool = typer.Option(False, "--explain", help="Ask a model to explain each "
                                 "proposal (UNVERIFIED text; it chooses nothing)."),
    model: str = typer.Option(None, "--model"), provider_name: str = typer.Option(
        None, "--provider"), base_url: str = typer.Option(None, "--base-url"),
    kali: str = typer.Option("192.168.56.104", "--kali"),
    key: Path = typer.Option(None, "--key"),
) -> None:
    """Create an investigation for a recorded session and drive it until it needs you."""
    from avra.chat import knowledge as kb
    from avra.research.investigation import Investigation, run_lock

    m = _m()
    checker, scope_sha = _scope(scope)
    try:
        sid = kb.resolve_session(session)
    except kb.KnowledgeError as exc:
        _refuse(str(exc))
    m._refuse_if_kill_switch("cli:investigate")
    explainer = _explainer(explain, model, provider_name, base_url)
    inv = Investigation.create(_root(), objective=objective, session_id=sid,
                               scope_name=checker.scope.session_name)
    with run_lock(_root(), inv.investigation_id):
        inv.note("scope_bound", {"scope_sha256": scope_sha,
                                 "session_name": checker.scope.session_name,
                                 "expires_at": checker.scope.expires_at.isoformat(),
                                 "max_actions": max_actions})
        typer.echo(f"Investigation {inv.investigation_id} created for session {sid}.")
        _drive(inv, checker=checker, kali=kali, key=key, max_actions=max_actions,
               explainer=explainer)


@investigate_app.command("resume")
def investigate_resume(
    investigation: str = typer.Argument(..., help="Investigation id (6+ char prefix)."),
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Must be byte-identical to the scope it was started with."),
    explain: bool = typer.Option(False, "--explain"),
    model: str = typer.Option(None, "--model"), provider_name: str = typer.Option(
        None, "--provider"), base_url: str = typer.Option(None, "--base-url"),
    kali: str = typer.Option("192.168.56.104", "--kali"),
    key: Path = typer.Option(None, "--key"),
) -> None:
    """Continue an investigation (an interrupted action is never re-run)."""
    m = _m()
    checker, scope_sha = _scope(scope)
    inv_id = _resolve_id(investigation)
    m._refuse_if_kill_switch("cli:investigate")
    explainer = _explainer(explain, model, provider_name, base_url)
    stack, inv = _locked_load(inv_id)
    with stack:
        bound = next((n["data"] for n in inv.notes if n["kind"] == "scope_bound"), None)
        if bound is None or bound.get("scope_sha256") != scope_sha:
            _refuse("this scope file is not the one the investigation was started with")
        _drive(inv, checker=checker, kali=kali, key=key,
               max_actions=int(bound.get("max_actions") or 3), explainer=explainer)


@investigate_app.command("cancel")
def investigate_cancel(investigation: str = typer.Argument(...)) -> None:
    """End an investigation as CANCELLED; pending proposals are denied."""
    from avra.research.investigation import InvState

    stack, inv = _locked_load(_resolve_id(investigation))
    with stack:
        if inv.terminal:
            _refuse(f"investigation already ended ({inv.state.value})")
        for act in inv.pending():
            inv.deny(act.action_id, by="owner_cancel")
        inv.note("stop", {"to": "CANCELLED", "reason": "cancelled by the owner"})
        inv.transition(InvState.CANCELLED, "cancelled by the owner")
        typer.echo(f"Investigation {inv.investigation_id}: CANCELLED.")


@investigate_app.command("list")
def investigate_list() -> None:
    """Investigations on this machine (read-only)."""
    from avra.research.investigation import Investigation, InvestigationError

    root = _root()
    for p in sorted(root.glob("*.jsonl")) if root.is_dir() else []:
        try:
            inv = Investigation.load(root, p.stem, reconcile=False)
            typer.echo(f"{inv.investigation_id}  {inv.state.value:<16} "
                       f"{len(inv.actions)} action(s)  {_m()._console_safe(inv.objective[:60])}")
        except (InvestigationError, ValueError, OSError) as exc:
            typer.echo(f"{p.stem}  UNREADABLE ({type(exc).__name__})")


@investigate_app.command("show")
def investigate_show(investigation: str = typer.Argument(...)) -> None:
    """Phase history and actions (read-only; writes nothing)."""
    from avra.research.investigation import Investigation, InvestigationError

    say = _m()._say
    try:
        inv = Investigation.load(_root(), _resolve_id(investigation), reconcile=False)
    except InvestigationError as exc:
        _refuse(str(exc))
    say(f"Investigation {inv.investigation_id} [{inv.state.value}]")
    say(f"Objective: {inv.objective}")
    say(f"Session: {inv.session_id}  scope: {inv.scope_name}")
    for frm, to, why in inv.history:
        say(f"  {frm} -> {to}: {why}")
    for a in inv.actions.values():
        say(f"  action {a.describe()} {a.status.value}"
            + (f" request {a.request_id}" if a.request_id else "")
            + (f" evidence {a.evidence_sha256[:16]}" if a.evidence_sha256 else ""))
    if any(a.status.value == "EXECUTING" for a in inv.actions.values()):
        say("  note: an action is recorded as started; `resume` will mark it INTERRUPTED "
            "(never re-run) unless it is still running in another terminal.")


@investigate_app.command("report")
def investigate_report(
    investigation: str = typer.Argument(...),
    scope: Path = typer.Option(None, "--scope", exists=True, readable=True,
                               help="Optional: lets NOT TESTED steps show scope readiness."),
) -> None:
    """M14.3: write an evidence-driven report (JSON + Markdown). Read-only otherwise."""
    from avra.chat import knowledge as kb
    from avra.research.controller import analyze_session
    from avra.research.investigation import Investigation, InvestigationError
    from avra.research.investigation_report import build_report, write_report

    try:
        inv = Investigation.load(_root(), _resolve_id(investigation), reconcile=False)
    except InvestigationError as exc:
        _refuse(str(exc))
    checker = _scope(scope)[0] if scope is not None else None
    try:
        analysis = analyze_session(inv.session_id, checker)
        audit_ok = analysis.audit_valid
    except kb.KnowledgeError:
        analysis, audit_ok = None, None
    jp, mp = write_report(_root(), build_report(inv, analysis, session_audit_valid=audit_ok))
    typer.echo(f"Report written:\n  {mp}\n  {jp}")
