"""AVRA CLI: scope validation, session audit, one typed tool via the Kali
Runner (M6), and model-driven research where the model only proposes and
the owner approves every executable step (M7, ADR 0005).

Keep this file ASCII-only: Windows consoles (cp1254/cp437) can't print
characters like arrows (see test_cli_source_is_ascii_for_windows_consoles).
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import uuid
from pathlib import Path

import typer

from avra.policy.scope import ScopeError, load_scope
from avra.storage.audit import AuditError, AuditLog

app = typer.Typer(
    help="AVRA - AI Vulnerability Research Agent "
    "(scope + audit; one typed tool via the Kali Runner, owner-confirmed)."
)
session_app = typer.Typer(help="Manage research sessions.")
app.add_typer(session_app, name="session")


def _sessions_dir() -> Path:
    """Where session audit logs live. Overridable via AVRA_DATA_DIR (tests)."""
    return Path(os.environ.get("AVRA_DATA_DIR", "data")) / "sessions"


def _env_file() -> Path:
    """The ``.env`` holding AVRA_RUNNER_TOKEN / ANTHROPIC_API_KEY (M13.2 F3).

    Previously every caller read ``Path(".env")`` relative to the current working directory,
    so running ``avra`` from another folder would silently read a different - possibly
    untrusted - ``.env``. Resolution order now:

    1. ``AVRA_ENV_FILE`` if set (an explicit path the owner controls);
    2. the project root's ``.env`` - the first ancestor of this file that contains
       ``pyproject.toml`` (the repo root when run from a source checkout);
    3. ``.env`` in the current directory, unchanged, when no project root is found
       (e.g. an installed wheel), so the existing run-from-repo-root behaviour is preserved.

    The value is still read only through ``load_token`` / ``load_api_key``, which never echo
    it. This changes only WHERE the file is looked for, never how the secret is handled."""
    override = os.environ.get("AVRA_ENV_FILE")
    if override:
        return Path(override)
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent / ".env"
    return Path(".env")


EXIT_KILL_SWITCH = 3  # a command refused because the local kill switch blocks


def _killswitch():
    """This machine's kill switch (tests replace this factory)."""
    from avra.control.killswitch import KillSwitch
    from avra.storage.keys import restrict_windows_acl

    return KillSwitch(acl=restrict_windows_acl)


def _refuse_if_kill_switch(operation: str) -> None:
    """Before any prompt or setup for executable/paid work: fail closed."""
    ks = _killswitch()
    st = ks.status()
    if st.blocking:
        ks.deny(operation, st)
        typer.secho(f"Refused: AVRA kill switch is {st.latch.value} ({st.detail}). Nothing was "
                    "started, sent or asked. See `avra kill --status`.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=EXIT_KILL_SWITCH)


def _print_kill_status(ks, st) -> None:
    from avra.control.killswitch import REMOTE_NOTICE, Latch

    colour = {Latch.DISENGAGED: typer.colors.GREEN, Latch.ENGAGED: typer.colors.YELLOW}
    typer.secho(f"Kill switch: {st.latch.value} - {_console_safe(st.detail)}",
                fg=colour.get(st.latch, typer.colors.RED))
    typer.echo(f"Latch file:  {ks.state_path}")
    if st.audit is None:
        typer.echo("Control audit: none yet")
    else:
        typer.echo(f"Control audit: hash chain {st.audit.describe()} (unkeyed; anchored only if "
                   f"you sealed it: avra audit seal --log \"{ks.audit_path}\")")
    for note in st.notes:
        typer.echo(f"  note: {note}")
    active = ks.active_work()
    typer.echo(f"Local work registered as running: {len(active)}"
               + (f" ({'; '.join(active)[:300]})" if active else ""))
    last = ks.last_remote_stop()
    if last is None:
        typer.echo("Runner emergency stop: never requested from this machine.")
    else:
        typer.echo(f"Runner emergency stop (last request, {last['ts']}): {last['event']} "
                   f"[{last.get('category')}; latch {last.get('latch', 'unknown')}]. The Runner's "
                   "state can only be known by asking it; this machine never resets it.")
    if st.blocking:
        typer.secho(REMOTE_NOTICE, fg=typer.colors.YELLOW)


EXIT_REMOTE_UNCONFIRMED = 4  # local stop engaged; the Runner's stop is NOT confirmed


def _remote_emergency_stop(kali: str, key: Path | None):
    """One bounded, stop-only emergency stop on the Runner (tests replace
    this). Never raises for Runner/transport problems."""
    from avra.runner.schemas import EmergencyReason
    from avra.runner_client.client import RunnerClientError, StopCallResult, load_token
    from avra.runner_client.stop import remote_emergency_stop
    from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig, TunnelError

    try:
        token = load_token(env_file=_env_file())
        cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
    except (RunnerClientError, TunnelError) as exc:  # messages never contain secrets
        return StopCallResult("config", detail=str(exc)[:200])
    return remote_emergency_stop(reason=EmergencyReason.LOCAL_KILL_SWITCH, token=token,
                                 tunnel_cfg=cfg)


def _report_remote_stop(ks, res) -> bool:
    """Print + record the remote result. True only if the Runner confirmed a
    durable, audited STOPPED latch."""
    data = {"category": res.category, "http_status": res.http_status,
            "detail": (res.detail or "")[:200]}
    if res.emergency is not None:
        e = res.emergency
        data.update(outcome=e.outcome, latch=e.latch, durable=e.durable,
                    runner_audit_recorded=e.audit_recorded, active_job=e.active_job)
    if res.category == "ok" and res.emergency_confirmed and res.emergency.audit_recorded:
        ks.record_event("remote_emergency_stop_confirmed", data)
        typer.secho(f"REMOTE EMERGENCY STOP CONFIRMED (Runner latch STOPPED, durable; "
                    f"active job: {res.emergency.active_job}).", fg=typer.colors.GREEN)
        return True
    if res.category == "ok":
        e = res.emergency
        ks.record_event("remote_emergency_stop_not_durable", data)
        typer.secho(f"REMOTE EMERGENCY STOP NOT DURABLY CONFIRMED (Runner latch {e.latch}, "
                    f"durable={e.durable}, Runner audit recorded={e.audit_recorded}, active "
                    f"job: {e.active_job}).", fg=typer.colors.RED)
        return False
    if res.category == "unsupported":
        ks.record_event("remote_emergency_stop_unsupported", data)
        typer.secho("REMOTE STOP UNSUPPORTED OR UNCONFIRMED: the Runner has no emergency-stop "
                    "endpoint (an older build). The remote job may still be running.",
                    fg=typer.colors.RED)
        return False
    ks.record_event("remote_emergency_stop_unconfirmed", data)
    typer.secho(f"REMOTE EMERGENCY STOP UNCONFIRMED ({res.category}"
                + (f", HTTP {res.http_status}" if res.http_status else "") + "). The remote job "
                "may still be running until the Runner's own timeout.", fg=typer.colors.RED)
    return False


@app.command()
def kill(
    status: bool = typer.Option(False, "--status", help="Read-only: show the latch state."),
    reset: bool = typer.Option(False, "--reset",
                               help="Owner only, interactive: disengage the LOCAL latch "
                                    "(never the Runner's; never restarts work)."),
    reason: str = typer.Option(None, "--reason", help="Why (engage only; reset asks for it)."),
    local_only: bool = typer.Option(False, "--local-only",
                                    help="Engage only this machine's latch; do not contact "
                                         "the Runner."),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key for the tunnel."),
) -> None:
    """Emergency stop: engage this machine's persistent latch FIRST, then ask
    the Kali Runner (stop-only tunnel) to engage its own persistent stop.
    Local and remote results are reported separately. Exit 0 = both
    confirmed; 4 = local engaged, remote NOT confirmed; 1 = local failure."""
    from avra.control.killswitch import REMOTE_NOTICE, KillSwitchError, Latch

    if status and reset:
        typer.secho("Use either --status or --reset.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    ks = _killswitch()
    if status:
        st = ks.status()
        _print_kill_status(ks, st)
        raise typer.Exit(code={Latch.DISENGAGED: 0, Latch.ENGAGED: EXIT_KILL_SWITCH}.get(
            st.latch, 1))
    if reset:
        if reason is not None or local_only:
            typer.secho("--reset asks for the reason interactively and is always local.",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        _kill_reset(ks)
        return

    # 1-3. Local latch FIRST (durable, read back, recorded).
    local_ok, local_audit_ok = False, False
    try:
        res = ks.engage(reason or "operator emergency stop (avra kill)", by="cli")
        local_ok, local_audit_ok = True, res.audit_recorded
        typer.secho("LOCAL STOP ENGAGED" + ("" if res.changed else " (it was already engaged)")
                    + ": no new AVRA tool runs, tunnels for them, approvals or model calls on "
                    "this machine (persistent).", fg=typer.colors.YELLOW)
        active = ks.active_work()
        if active:
            typer.echo(f"{len(active)} local operation(s) were already running and stop at "
                       f"their next checkpoint: {'; '.join(active)[:300]}")
        for note in res.notes:
            typer.secho(f"  note: {note}", fg=typer.colors.RED)
        if not res.audit_recorded:
            typer.secho("The local control audit record FAILED (the latch itself is engaged).",
                        fg=typer.colors.RED, err=True)
    except ValueError as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    except KillSwitchError as exc:
        st = ks.status()
        typer.secho(f"LOCAL STOP FAILED: {exc} (latch now {st.latch.value}; "
                    f"{'still blocks' if st.blocking else 'does NOT block'} new work).",
                    fg=typer.colors.RED, err=True)

    if local_only:
        typer.secho("REMOTE: not attempted (--local-only). " + REMOTE_NOTICE,
                    fg=typer.colors.YELLOW)
        raise typer.Exit(code=0 if local_ok and local_audit_ok else 1)

    # 4-6. Stop-only remote request. Even after a LOCAL failure it is safe to
    # try: this path can only stop work on the Runner, never start any.
    if not local_ok:
        typer.echo("Trying the Runner's emergency stop anyway (it can only stop work).")
    ks.record_event("remote_emergency_stop_requested", {"kali": kali,
                                                        "local_latch": ks.status().latch.value})
    try:
        remote = _remote_emergency_stop(kali, key)
    except KeyboardInterrupt:
        from avra.runner_client.client import StopCallResult

        remote = StopCallResult("interrupted", detail="operator interrupted the remote stop")
    remote_ok = _report_remote_stop(ks, remote)
    if not local_ok or not local_audit_ok:
        raise typer.Exit(code=1)
    if not remote_ok:
        raise typer.Exit(code=EXIT_REMOTE_UNCONFIRMED)


def _kill_reset(ks) -> None:
    from avra.control.killswitch import KillSwitchError, Latch

    if not _interactive():
        typer.secho("Refused: reset needs an interactive terminal (no piping, no flags). "
                    "Nothing changed.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    st = ks.status()
    _print_kill_status(ks, st)
    if st.latch is not Latch.ENGAGED:
        typer.secho(f"Refused: only a valid ENGAGED latch can be reset (it is "
                    f"{st.latch.value}). Nothing changed.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.secho("This cannot establish whether a job is still running on the Kali Runner. "
                "Reset does NOT restart any earlier session or tool; new work must be started "
                "explicitly.", fg=typer.colors.YELLOW)
    typer.secho("This resets ONLY this machine's latch. It does NOT reset the Kali Runner's "
                "emergency stop: a Runner that was stopped stays STOPPED until the owner resets "
                "it locally on Kali (runner/deploy/README.md).", fg=typer.colors.YELLOW)
    try:
        why = typer.prompt("Reason for the reset", default="", show_default=False).strip()
        typed = typer.prompt('Type RESET to disengage', default="", show_default=False)
    except typer.Abort:
        typer.echo("Cancelled - still ENGAGED.")
        raise typer.Exit(code=1) from None
    if not why:
        typer.secho("Refused: a reason is required. Still ENGAGED.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=1)
    if typed.strip() != "RESET":
        typer.echo("Cancelled - still ENGAGED.")
        raise typer.Exit(code=1)
    try:
        res = ks.reset(why, by="cli")
    except (KillSwitchError, ValueError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    typer.secho(f"Kill switch: {res.status.latch.value} (local only). Nothing was restarted; "
                "the Runner's emergency stop is unchanged.", fg=typer.colors.GREEN)


@app.command("check-scope")
def check_scope(
    scope: Path = typer.Argument(..., exists=True, readable=True),
) -> None:
    """Validate a scope file without creating a session."""
    try:
        loaded = load_scope(scope)
    except ScopeError as exc:
        typer.secho(f"Invalid: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.secho("Valid.", fg=typer.colors.GREEN)
    typer.echo(
        f"{loaded.session_name}: {len(loaded.targets)} target(s), "
        f"expires {loaded.expires_at.isoformat()}"
    )


@session_app.command("new")
def session_new(
    scope: Path = typer.Option(
        ..., "--scope", exists=True, readable=True, help="Path to a scope YAML file."
    ),
    name: str = typer.Option(
        None, "--name", help="Optional human-readable label for this session."
    ),
) -> None:
    """Validate a scope file and start a new session (no tools run yet)."""
    try:
        loaded = load_scope(scope)
    except ScopeError as exc:
        typer.secho(f"Scope rejected: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    session_id = str(uuid.uuid4())
    audit = AuditLog(_sessions_dir() / f"{session_id}.jsonl")
    audit.record(
        "session_created",
        {
            "session_id": session_id,
            "label": name,
            "scope_file": str(scope),
            "scope_session_name": loaded.session_name,
            "scope_expires_at": loaded.expires_at.isoformat(),
            "target_count": len(loaded.targets),
        },
    )

    typer.secho(f"Session {session_id} created.", fg=typer.colors.GREEN)
    typer.echo(
        f"Scope: {loaded.session_name} ({len(loaded.targets)} target(s)), "
        f"expires {loaded.expires_at.isoformat()}"
    )
    typer.echo(f"Audit log: {audit.path}")


@session_app.command("show")
def session_show(session_id: str) -> None:
    """Print the full audit trail for a session and check its integrity."""
    path = _sessions_dir() / f"{session_id}.jsonl"
    audit = AuditLog(path)
    check = audit.verify_detailed()
    if not check.exists or (check.ok and check.record_count == 0):
        typer.secho(
            f"No audit log found for session {session_id} at {path}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    try:
        records = audit.read_all()
    except AuditError:  # unparseable or unreadable: show the diagnosis only
        typer.secho(f"Chain integrity: BROKEN ({check.describe()})", fg=typer.colors.RED)
        raise typer.Exit(code=1) from None

    for rec in records:
        typer.echo(f"[{rec.seq}] {rec.ts}  {rec.event}  {rec.data}")

    typer.secho(
        f"Chain integrity: {'OK' if check.ok else 'BROKEN'}"
        + ("" if check.ok else f" ({check.describe()})"),
        fg=typer.colors.GREEN if check.ok else typer.colors.RED,
    )
    if not check.ok:
        raise typer.Exit(code=1)


scan_app = typer.Typer(help="Run one typed tool through the Kali Tool Runner (M6).")
app.add_typer(scan_app, name="scan")


def _evidence_dir() -> Path:
    return Path(os.environ.get("AVRA_DATA_DIR", "data")) / "evidence"


def _open_session(scope_file: Path, loaded, session: str | None) -> tuple[uuid.UUID, AuditLog]:
    if session is not None:
        try:
            session_id = uuid.UUID(session)
        except ValueError:
            typer.secho("--session must be a session UUID", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1) from None
        audit = AuditLog(_sessions_dir() / f"{session_id}.jsonl")
        check = audit.verify_detailed()
        if not check.exists or (check.ok and check.record_count == 0):
            typer.secho(f"No audit log for session {session_id}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        if not check.ok:
            typer.secho(f"Session audit chain is BROKEN - refusing ({check.describe()})",
                        fg=typer.colors.RED, err=True)
            raise typer.Exit(code=1)
        return session_id, audit
    session_id = uuid.uuid4()
    audit = AuditLog(_sessions_dir() / f"{session_id}.jsonl")
    audit.record("session_created", {
        "session_id": str(session_id), "label": "scan", "scope_file": str(scope_file),
        "scope_session_name": loaded.session_name,
        "scope_expires_at": loaded.expires_at.isoformat(), "target_count": len(loaded.targets),
    })
    return session_id, audit


@scan_app.command("nmap-connect")
def scan_nmap_connect(
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Orchestrator scope file (checked before anything is sent)."),
    host: str = typer.Option(..., "--host", help="Target IPv4 address (must be in scope)."),
    port: list[int] = typer.Option(..., "--port", help="Port to check; repeat for several."),
    timeout: int = typer.Option(60, "--timeout", help="Tool timeout in seconds."),
    session: str = typer.Option(None, "--session", help="Existing session UUID (else a new one)."),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key (default ~/.ssh/avra_runtime_ed25519)."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt."),
) -> None:
    """One TCP connect scan via SSH tunnel -> Kali Runner. Both sides check scope."""
    _refuse_if_kill_switch("cli:scan nmap-connect")
    from avra.policy.scope import ScopeChecker
    from avra.runner.schemas import RejectionStage
    from avra.runner_client.client import RunnerClientError, load_token
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig, TunnelError

    try:
        loaded = load_scope(scope)
        token = load_token(env_file=_env_file())
        tunnel_cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
    except (ScopeError, RunnerClientError, TunnelError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None

    typer.echo("Tool:   nmap_connect_scan (active-safe, TCP connect, fixed flags)")
    typer.echo(f"Target: {host} ports {', '.join(map(str, port))}, timeout {timeout}s")
    typer.echo(f"Via:    avra-tunnel@{kali} -> 127.0.0.1:8765 (Runner re-checks its own scope)")
    typer.echo(f"Scope:  {loaded.session_name} ({scope})")
    if not yes and not typer.confirm("Send this request?", default=False):
        typer.echo("Cancelled - nothing sent.")
        raise typer.Exit(code=1)

    session_id, audit = _open_session(scope, loaded, session)
    try:
        outcome = run_nmap_connect_scan(
            checker=ScopeChecker(loaded), audit=audit, session_id=session_id, host=host,
            ports=port, timeout_seconds=timeout, token=token,
            evidence_root=_evidence_dir(), tunnel_cfg=tunnel_cfg, notify=_say,
        )
    except ValueError as exc:  # request validation (pydantic) - nothing was sent
        typer.secho(f"Invalid request: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None

    typer.echo(f"Session: {session_id}  request: {outcome.request.request_id}")
    if not outcome.allowed_locally:
        typer.secho(f"Denied by local policy: {outcome.local_reason}", fg=typer.colors.RED)
    elif outcome.rejection is not None:
        colour = typer.colors.RED if outcome.rejection.stage is RejectionStage.SCOPE else typer.colors.YELLOW
        typer.secho(f"Rejected by Runner ({outcome.rejection.stage.value}): "
                    f"{outcome.rejection.reason}", fg=colour)
    elif outcome.result is not None:
        r = outcome.result
        typer.echo(f"Runner: {r.status.value}, exit {r.exit_code}, sha256 {r.output_sha256}")
        typer.echo(f"Hash verified: {outcome.hash_verified}")
        if outcome.report is not None:
            for h in outcome.report.hosts:
                for p in h.ports:
                    typer.echo(f"  {h.address}:{p.port}/{p.protocol}  {p.state}  ({p.reason})")
        if outcome.evidence is not None:
            typer.echo(f"Evidence: {outcome.evidence.path}")
    for err in outcome.errors:
        typer.secho(f"Error: {err}", fg=typer.colors.RED, err=True)
    typer.echo(f"Audit log: {audit.path}")
    raise typer.Exit(code=0 if outcome.ok else 1)


probe_app = typer.Typer(help="One owner-approved typed probe via the Kali Tool Runner (M8.3).")
app.add_typer(probe_app, name="probe")


@probe_app.command("http")
def probe_http(
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Orchestrator scope file (checked before anything is sent)."),
    host: str = typer.Option(..., "--host", help="Target IPv4 address (must be in scope)."),
    port: int = typer.Option(..., "--port", help="Target TCP port (must be in scope)."),
    timeout: int = typer.Option(10, "--timeout", help="Total probe time budget, 1-30 s."),
    session: str = typer.Option(None, "--session", help="Existing session UUID (else a new one)."),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key (default ~/.ssh/avra_runtime_ed25519)."),
    path: str = typer.Option(None, "--path",
                             help="M10.5: fetch this same-origin path instead of / (tool "
                                  "http_get_path; the scope must list it and the path prefix)."),
) -> None:
    """One fixed 'GET / HTTP/1.0' (ADR 0007), or with --path one fixed 'GET <path>' (M10.5,
    ADR 0018). Owner-only: needs a real terminal and an explicit 'y' (default No). There is
    deliberately no --yes."""
    _refuse_if_kill_switch("cli:probe http")
    from pydantic import ValidationError

    from avra.policy.scope import ScopeChecker
    from avra.policy.tools import authorize_tool_request
    from avra.runner.schemas import HttpGetPathRequest, HttpProbeRequest, RejectionStage
    from avra.runner.tools.http_probe import request_bytes
    from avra.runner_client import http_probe as pipeline
    from avra.runner_client.client import RunnerClientError, load_token
    from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig, TunnelError

    if not _interactive():
        typer.secho("Refused: `avra probe http` needs an interactive terminal for the owner's "
                    "confirmation (no piping, no --yes). Nothing sent.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=2)
    try:
        loaded = load_scope(scope)
        token = load_token(env_file=_env_file())
        tunnel_cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
        preview = (HttpProbeRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                    host=host, port=port, timeout_seconds=timeout)
                   if path is None else
                   HttpGetPathRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                      host=host, port=port, path=path,
                                      timeout_seconds=timeout))
    except ValidationError as exc:
        typer.secho(f"Invalid request ({exc.error_count()} error(s)). Nothing sent.",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    except (ScopeError, RunnerClientError, TunnelError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None

    checker = ScopeChecker(loaded)
    decision = authorize_tool_request(checker, preview)
    typer.echo(f"Tool:    {preview.tool.value} (passive; one fixed request, no redirects/retries)")
    typer.echo(f"Target:  {preview.host}:{preview.port}, time budget {preview.timeout_seconds}s")
    typer.echo("Request (exact bytes):")
    for line in request_bytes(preview.host, preview.port,
                              path or "/").decode("ascii").split("\r\n")[:-1]:
        typer.echo(f"    {line}" if line else "    <blank line>")
    typer.echo(f"Via:     avra-tunnel@{kali} -> 127.0.0.1:8765 (Runner re-checks its own scope)")
    typer.echo(f"Scope:   {loaded.session_name} ({scope})")
    typer.echo(f"Windows policy: {'ALLOWED' if decision.allowed else 'DENIED'} - {decision.reason}")

    if decision.allowed:
        try:
            confirmed = typer.confirm("Send this request?", default=False)
        except typer.Abort:  # EOF / Ctrl+C at the prompt
            confirmed = False
        if not confirmed:
            typer.echo("Cancelled - nothing sent.")
            raise typer.Exit(code=1)
        approval = pipeline.APPROVAL_INTERACTIVE_TTY
    else:
        approval = None  # the pipeline records the denial; nothing is sent

    session_id, audit = _open_session(scope, loaded, session)
    outcome = pipeline.run_http_probe(
        checker=checker, audit=audit, session_id=session_id, host=preview.host,
        port=preview.port, timeout_seconds=preview.timeout_seconds, token=token,
        evidence_root=_evidence_dir(), tunnel_cfg=tunnel_cfg, approval=approval,
        notify=_say, path=path,
    )

    typer.echo(f"Session: {session_id}  request: {outcome.request.request_id}")
    if not outcome.allowed_locally:
        typer.secho(f"Denied by local policy: {outcome.local_reason}. Nothing sent.",
                    fg=typer.colors.RED)
    elif outcome.rejection is not None:
        colour = (typer.colors.RED if outcome.rejection.stage is RejectionStage.SCOPE
                  else typer.colors.YELLOW)
        typer.secho(f"Rejected by Runner ({outcome.rejection.stage.value}): "
                    f"{outcome.rejection.reason}", fg=colour)
    elif outcome.result is not None:
        r = outcome.result
        typer.echo(f"Runner: {r.status.value}, exit {r.exit_code}, sha256 {r.output_sha256}")
        typer.echo(f"Hash verified: {outcome.hash_verified}")
        if outcome.envelope is not None:
            e = outcome.envelope
            typer.echo(f"Probe outcome: {e.outcome}, {e.response_bytes} bytes, complete "
                       f"{e.complete}, truncated {e.truncated}, response sha256 "
                       f"{e.response_sha256}")
        f = outcome.facts
        if f is not None:
            typer.echo(f"HTTP: protocol_observed={f.protocol_observed} status={f.status_code} "
                       f"version={f.http_version} binary={f.binary} redirect={f.is_redirect}")
            for ind in f.indications:
                typer.echo(f"  TENTATIVE {ind.source}: {_console_safe(ind.value)}")
            if f.indications:
                typer.echo(f"  ({f.indication_note})")
            for m in f.malformed:
                typer.echo(f"  malformed: {m}")
        if outcome.evidence is not None:
            typer.echo(f"Evidence: {outcome.evidence.path}")
    for err in outcome.errors:
        typer.secho(f"Error: {err}", fg=typer.colors.RED, err=True)
    typer.echo(f"Audit log: {audit.path}")
    raise typer.Exit(code=0 if outcome.ok else 1)


def _console_safe(text: str) -> str:
    """Model text shown on a Windows console: no control characters (except
    newlines/tabs) and nothing the console encoding can't print."""
    import sys

    cleaned = "".join(c for c in str(text) if c in "\n\t" or (ord(c) >= 32 and ord(c) != 127))
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    return cleaned.encode(enc, errors="replace").decode(enc, errors="replace")


def _say(text: str, **style) -> None:
    typer.secho(_console_safe(text), **style)


@app.command()
def research(
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Orchestrator scope file (default deny)."),
    objective: str = typer.Option(..., "--objective", help="What to investigate (max 1000 chars)."),
    budget_usd: float = typer.Option(0.50, "--budget-usd", help="Hard session budget in USD."),
    max_steps: int = typer.Option(10, "--max-steps", help="Maximum model calls."),
    max_tool_runs: int = typer.Option(5, "--max-tool-runs", help="Maximum executed tool requests."),
    model: str = typer.Option(None, "--model",
                              help="Model id (Anthropic: must have a price; local: the "
                                   "installed model name). Env: AVRA_LLM_MODEL."),
    effort: str = typer.Option("medium", "--effort", help="low|medium|high|xhigh|max"),
    provider_name: str = typer.Option(None, "--provider",
                                      help="anthropic | ollama | local-openai-compatible "
                                           "(ADR 0013/0015; no fallback). Env: AVRA_LLM_PROVIDER."),
    base_url: str = typer.Option(None, "--base-url",
                                 help="Local model server, loopback only. Env: AVRA_LLM_BASE_URL."),
    session: str = typer.Option(None, "--session", help="Existing session UUID (else a new one)."),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key for the tunnel."),
    verification: bool = typer.Option(
        False, "--verification",
        help="M8.5: run the Verification Engine inside the loop (its own versioned "
             "prompt, verify_hypothesis tool, verdict feedback, no-progress stop)."),
    web_rules: bool = typer.Option(False, "--web-rules",
                                   help="With --verification: add the passive web-header rule "
                                        "pack to the engine's catalogue (ADR 0015)."),
    context_budget: int = typer.Option(
        None, "--context-budget",
        help="M9.2: max prompt tokens; older tool results are elided above it. Default: "
             "5000 for local models (fits an 8K server context), off for Anthropic."),
    allow_http_probe: bool = typer.Option(
        False, "--allow-http-probe",
        help="M9.1 (ADR 0016): the model may also PROPOSE passive HTTP probes (one fixed "
             "GET /). Scope must allow http_probe; you approve each one in a real terminal."),
    allow_http_get: bool = typer.Option(
        False, "--allow-http-get",
        help="M10.5 (ADR 0018), with --web-research: the model may PROPOSE one read-only GET "
             "of a path from the recorded web surface. Scope must allow http_get_path and the "
             "path prefix; you approve each one in a real terminal."),
    web_research: bool = typer.Option(
        False, "--web-research",
        help="M10 (ADR 0017), with --verification: give the model the web surface of the "
             "recorded responses and a structured hypothesis board whose states only the "
             "engine decides. Read-only: nothing new is fetched or submitted."),
) -> None:
    """Model-driven lab research. The model only PROPOSES typed tool calls;
    you approve every executable one; both scope checks still apply."""
    _refuse_if_kill_switch("cli:research")
    from avra.control.killswitch import KillSwitchEngaged
    from avra.core.research import ProposalView, ResearchSession
    from avra.llm.config import LLMConfig, LLMConfigError, SessionLimits
    from avra.llm.factory import create_provider, ensure_supported
    from avra.llm.provider import LLMProviderError, load_api_key
    from avra.policy.scope import ScopeChecker
    from avra.runner_client.client import RunnerClientError, load_token
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig, TunnelError

    if web_research and not verification:
        typer.secho("Refused: --web-research needs --verification.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=1)
    if allow_http_get and not web_research:
        typer.secho("Refused: --allow-http-get needs --web-research.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=1)
    try:
        loaded = load_scope(scope)
        cfg = LLMConfig.from_env(model=model, provider=provider_name, base_url=base_url,
                                 effort=effort)
        limits = SessionLimits(budget_usd=budget_usd, max_steps=max_steps,
                               max_tool_runs=max_tool_runs)
        # An unknown/unimplemented provider is refused here, before any prompt,
        # with no fallback (ADR 0013). Nothing is built yet: no client exists
        # before the owner consents to the session.
        ensure_supported(cfg)
        api_key = None if cfg.is_local else load_api_key(env_file=_env_file())
        # Offline analysis (--max-tool-runs 0) never reaches the Runner: no token needed.
        runner_token = load_token(env_file=_env_file()) if max_tool_runs > 0 else None
        tunnel_cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
    except (ScopeError, LLMConfigError, LLMProviderError, RunnerClientError, TunnelError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None

    if cfg.is_local:
        typer.echo(f"Model:     {cfg.model} via {cfg.provider} at {cfg.resolved_base_url} "
                   f"(local, no API cost; max {cfg.max_tokens} output tokens/call)")
    else:
        typer.echo(f"Model:     {cfg.model} (effort {cfg.effort}, max {cfg.max_tokens} "
                   "output tokens/call)")
    typer.echo(f"Limits:    ${limits.budget_usd:.2f}, {limits.max_steps} model steps, "
               f"{limits.max_tool_runs} tool runs, {limits.max_duration_seconds // 60} min")
    typer.echo(f"Scope:     {loaded.session_name} ({scope})")
    _say(f"Objective: {objective}")
    typer.echo("The model can only propose. You will be asked before anything runs.")
    if verification:
        typer.echo("Verification: ON - the deterministic engine checks the model's structured "
                   f"hypotheses offline and alone decides verdicts (prompt {_verify_prompt()}).")
    question = ("Start this session (local model, no API cost)?" if cfg.is_local
                else "Start this session (it uses the paid Anthropic API)?")
    if not typer.confirm(question, default=False):
        typer.echo("Cancelled - no API call made.")
        raise typer.Exit(code=1)

    session_id, audit = _open_session(scope, loaded, session)
    checker = ScopeChecker(loaded)

    def approve(view: ProposalView) -> bool:
        typer.echo("")
        if view.tool == "http_get_path":
            typer.secho(f"Proposal (step {view.step}): http_get_path {view.host}:{view.ports[0]}"
                        f" (one fixed 'GET {view.path} HTTP/1.0', read-only)",
                        fg=typer.colors.YELLOW)
        elif view.tool == "http_probe":
            typer.secho(f"Proposal (step {view.step}): http_probe {view.host}:{view.ports[0]} "
                        "(one fixed 'GET / HTTP/1.0')", fg=typer.colors.YELLOW)
        else:
            typer.secho(f"Proposal (step {view.step}): nmap_connect_scan {view.host} "
                        f"ports {', '.join(map(str, view.ports))}, timeout {view.timeout_seconds}s",
                        fg=typer.colors.YELLOW)
        _say(f"  Why: {view.explanation}")
        typer.echo(f"  Local policy: {view.policy}")
        if view.tool in ("http_probe", "http_get_path") and not _interactive():
            typer.echo("  An HTTP probe needs a real terminal for the owner's approval: declined.")
            return False
        try:
            return typer.confirm("  Run this scan?" if view.tool == "nmap_connect_scan"
                                 else "  Send this request?", default=False)
        except typer.Abort:
            raise KeyboardInterrupt from None

    def execute(p):
        if runner_token is None:  # offline session: the loop's budget already forbids runs
            raise RuntimeError("no tool runs are allowed in an offline (--max-tool-runs 0) session")
        outcome = run_nmap_connect_scan(
            checker=checker, audit=audit, session_id=session_id, host=p.host,
            ports=list(p.ports), timeout_seconds=p.timeout_seconds, token=runner_token,
            evidence_root=_evidence_dir(), tunnel_cfg=tunnel_cfg, notify=_say,
        )
        if outcome.report is not None:
            for h in outcome.report.hosts:
                for port in h.ports:
                    _say(f"  {h.address}:{port.port}/{port.protocol}  {port.state}  ({port.reason})")
        for err in outcome.errors:
            _say(f"  Error: {err}", fg=typer.colors.RED)
        return outcome

    import hashlib

    def execute_http(p):
        from avra.runner_client.http_probe import (
            APPROVAL_INTERACTIVE_TTY,
            run_http_probe,
        )

        if runner_token is None:
            raise RuntimeError("no tool runs are allowed in an offline (--max-tool-runs 0) session")
        # reached only after approve() returned True in a real terminal (checked there)
        outcome = run_http_probe(
            checker=checker, audit=audit, session_id=session_id, host=p.host, port=p.port,
            timeout_seconds=10, token=runner_token, evidence_root=_evidence_dir(),
            tunnel_cfg=tunnel_cfg, approval=APPROVAL_INTERACTIVE_TTY, notify=_say)
        if outcome.facts is not None:
            _say(f"  HTTP {outcome.facts.status_code} {outcome.facts.reason}, "
                 f"title {outcome.facts.title[:80]!r} (server claim)")
        for err in outcome.errors:
            _say(f"  Error: {err}", fg=typer.colors.RED)
        return outcome

    def execute_http_get(p):
        from avra.runner_client.http_probe import (
            APPROVAL_INTERACTIVE_TTY,
            run_http_probe,
        )

        if runner_token is None:
            raise RuntimeError("no tool runs are allowed in an offline (--max-tool-runs 0) session")
        # reached only after approve() returned True in a real terminal (checked there)
        outcome = run_http_probe(
            checker=checker, audit=audit, session_id=session_id, host=p.host, port=p.port,
            timeout_seconds=10, token=runner_token, evidence_root=_evidence_dir(),
            tunnel_cfg=tunnel_cfg, approval=APPROVAL_INTERACTIVE_TTY, notify=_say, path=p.path)
        if outcome.facts is not None:
            _say(f"  HTTP {outcome.facts.status_code} for {p.path} "
                 f"({outcome.facts.content_type[:40] or 'no content type'})")
        for err in outcome.errors:
            _say(f"  Error: {err}", fg=typer.colors.RED)
        return outcome

    provider = create_provider(cfg, api_key=api_key)  # after consent (no early client)
    try:
        result = ResearchSession(
            provider=provider, checker=checker, audit=audit, session_id=session_id,
            limits=limits, approve=approve, execute=execute, notify=_say,
            scope_file_sha256=hashlib.sha256(scope.read_bytes()).hexdigest(),
            verification=(_verification_loop(web_rules, validation=web_research)
                          if verification else None),
            http_probe=execute_http if allow_http_probe else None,
            context_budget_tokens=context_budget or (5000 if cfg.is_local else None),
            web_research=web_research,
            http_get=execute_http_get if allow_http_get else None,
        ).run(objective)
    except KillSwitchEngaged as exc:  # engaged between the CLI check and the start
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=EXIT_KILL_SWITCH) from None
    if result.stop_reason.value == "kill_switch":
        typer.secho("Stopped by the LOCAL kill switch. No further model call or tool run was "
                    "made; nothing resumes after a reset.", fg=typer.colors.YELLOW)

    typer.echo("")
    typer.echo(f"Session {session_id}: stopped ({result.stop_reason.value}) - {result.detail}")
    if result.stop_reason.value == "refusal":
        _say("Refused by the model PROVIDER's safety system (not an AVRA scope or policy "
             f"rejection; {result.detail}). Tool runs: {result.tool_runs}. AVRA does not "
             "retry or switch models; the category alone does not say which part of the "
             "request was flagged. Details: llm_refusal in the audit log.",
             fg=typer.colors.YELLOW)
    if result.final_summary:
        _say(f"Summary: {result.final_summary}")
    t = result.spend.tokens
    typer.echo(f"Cost: ${result.spend.usd:.4f} over {result.spend.calls} call(s); tokens in "
               f"{t['input_tokens']} / out {t['output_tokens']} / cache write "
               f"{t['cache_creation_input_tokens']} / cache read {t['cache_read_input_tokens']}")
    typer.echo(f"Tool runs: {result.tool_runs} (proposals {result.proposals})")
    typer.echo(f"Audit log: {audit.path}")

    _finish_report(result, session_id=session_id, audit=audit)
    run = _auto_verify(session_id, web_rules=verification and (web_rules or web_research),
                       validation=web_research)
    if run is not None:
        _research_report(run, session_id=session_id, audit=audit)
    raise typer.Exit(code=0 if result.stop_reason.value in ("finished", "end_turn",
                                                            "no_progress") else 1)


def _verify_prompt() -> str:
    """The prompt version the verification mode really uses (never a literal)."""
    from avra.llm.prompts import PROMPT_VERSION_VERIFY

    return PROMPT_VERSION_VERIFY


def _verification_loop(web_rules: bool = False, validation: bool = False):
    from avra.verification.loop import LoopConfig, VerificationLoop

    return VerificationLoop(LoopConfig(evidence_root=_evidence_dir()),
                            registry=_rule_registry(web_rules, validation))


def _rule_registry(web_rules: bool, validation: bool = False):
    """None = the pinned default rules; --web-rules = header pack; --web-research (M10.4)
    = header pack + passive validation rules."""
    if validation:
        from avra.verification.rules import validation_registry

        return validation_registry()
    return _web_registry() if web_rules else None


def _verification_dir() -> Path:
    return Path(os.environ.get("AVRA_DATA_DIR", "data")) / "verification"


def _research_report(run, *, session_id: uuid.UUID, audit) -> None:
    """M9.3: one consolidated Markdown report for the run (best-effort, never changes
    the research result): engine verdicts + research trace + UNVERIFIED model text."""
    from avra import assessment as asm

    try:
        facts = asm.build_facts(run.report, run.evidence, _evidence_dir())
        trace = asm.research_trace(audit.read_all())
        meta = {"generated_at": dt_now_iso(), "verification_report": str(run.report_path),
                "audit_file": str(audit.path)}
        path = asm.write_research_report(_assessments_dir() / str(session_id), meta, facts,
                                         run.report, trace)
    except (OSError, KeyError, ValueError) as exc:
        _say(f"Research report skipped: {exc}", fg=typer.colors.YELLOW)
        return
    typer.secho(f"Research report: {path}", fg=typer.colors.GREEN)


def _auto_verify(session_id: uuid.UUID, web_rules: bool = False, validation: bool = False):
    """M8.4: after a research session, run the offline verification cycle on
    its evidence (deterministic rule proposer only: no API call, no network).
    Best-effort: a failure here never changes the research result."""
    from avra.verification.cycle import RuleBasedProposer
    from avra.verification.report import VerificationRunError, run_verification

    try:
        run = run_verification(sessions_dir=_sessions_dir(), evidence_root=_evidence_dir(),
                               verification_root=_verification_dir(),
                               session_id=str(session_id), proposers=[RuleBasedProposer()],
                               registry=_rule_registry(web_rules, validation))
    except (VerificationRunError, OSError, ValueError) as exc:
        _say(f"Offline verification skipped: {exc}", fg=typer.colors.YELLOW)
        return None
    r = run.report
    from avra.assessment import CONFIG_WEAKNESS_RULES

    weak = sum(1 for f in r["confirmed_findings"] if f["rule_id"] in CONFIG_WEAKNESS_RULES)
    vulns = len(r["confirmed_findings"]) - weak
    typer.echo(f"Offline verification: {vulns} confirmed vulnerability(ies), {weak} configuration "
               "weakness(es) (not proven exploitable), "
               f"{len(r['verified_observations'])} verified observation(s), "
               f"{len(r['rejected'])} rejected, {len(r['inconclusive'])} inconclusive, "
               f"{len(r['proposed_next_actions'])} proposed next action(s) (not run)")
    typer.echo(f"Verification report: {run.report_path}  (avra verify show {session_id})")
    return run


# Exit code when the run finished but its report could not be stored as an
# attested, published file (M7.9.1). Distinct from 1 (session did not finish cleanly).
EXIT_REPORT_NOT_PUBLISHED = 3


def _finish_report(result, *, session_id: uuid.UUID, audit: AuditLog) -> None:
    """Build the evidence-grounded report (never model prose), validate it,
    then store it as an attested, immutable file (avra.reporting.store).
    Scope, objective and metadata come from the audit log (M7.9.2) - the
    same records `avra report verify` replays later.
    A validation verdict is only shown as a result once the report is
    attested; otherwise it is labelled in-memory only and the CLI exits 3."""
    from avra.reporting import Verdict, build_report, validate_report
    from avra.reporting.replay import (
        ReplayError,
        trusted_prior_evidence,
        trusted_report_inputs,
    )
    from avra.reporting.store import ReportStoreError, store_report

    try:
        scope, objective, metadata, schema = trusted_report_inputs(audit, session_id)
        if schema >= 5:  # verified earlier evidence of this session (same as replay)
            result = dataclasses.replace(result, prior_evidence=trusted_prior_evidence(
                audit, session_id, _evidence_dir()))
    except ReplayError as exc:
        _say(f"Report NOT built: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=EXIT_REPORT_NOT_PUBLISHED) from None
    report = build_report(result, session_id=session_id, scope=scope, objective=objective,
                          metadata=metadata, schema_version=schema)
    validation = validate_report(report, result)
    typer.echo(f"Outcome: execution={report.execution_status.value}, "
               f"coverage={report.coverage.value}, "
               f"evidence={report.evidence_confidence.value}")
    if report.port_exposure is not None and report.service_identity is not None:
        typer.echo(f"         port exposure={report.port_exposure.value}, "
                   f"service identity={report.service_identity.value} "
                   "(a port-number label is never an identification)")
    if report.prior_session_evidence:  # M8.6 (G1): display only, no schema change
        typer.echo(f"         earlier evidence of this session: "
                   f"{len(report.prior_session_evidence)} item(s) the model may cite; NOT "
                   "counted in this run's coverage/exposure (those reflect this run's "
                   "own tool runs). Protocol-level results: avra verify show "
                   f"{session_id}")
    if report.claim_checks is not None:
        cc = report.claim_checks
        typer.echo(f"         claim checks on model text: {cc.references_checked} "
                   f"reference(s), {len(cc.reference_mismatches)} unresolved, "
                   f"{len(cc.ambiguous_references)} ambiguous, "
                   f"{len(cc.suspicious_assertions)} suspicious assertion(s) "
                   "(informational; passing is not proof the text is true)")
    try:
        stored = store_report(report, validation, audit=audit, session_id=session_id,
                              directory=audit.path.parent)
    except ReportStoreError as exc:
        # The store's message states precisely whether an audit claim exists.
        _say(f"Report NOT published: {exc}", fg=typer.colors.RED, err=True)
        typer.secho(f"Report validation (in-memory only, NOT a verified result): "
                    f"{validation.verdict.value}", fg=typer.colors.RED)
        raise typer.Exit(code=EXIT_REPORT_NOT_PUBLISHED) from None
    typer.echo(f"Report: {stored.path}")
    typer.echo(f"Report sha256: {stored.sha256} (attested in audit, seq {stored.audit_seq})")
    if stored.temp_left is not None:
        _say(f"Note: temp name could not be removed (same bytes): {stored.temp_left}",
             fg=typer.colors.YELLOW)
    colour = {Verdict.PASS: typer.colors.GREEN, Verdict.INCOMPLETE: typer.colors.YELLOW,
              Verdict.INVALID: typer.colors.RED}[validation.verdict]
    typer.secho(f"Report validation: {validation.verdict.value}", fg=colour)
    for reason in validation.reasons:
        _say(f"  - {reason}", fg=colour)


report_app = typer.Typer(help="Research reports: read-only verification (M7.9.2).")
app.add_typer(report_app, name="report")


@report_app.command("verify")
def report_verify(
    session: str = typer.Argument(..., help="Session UUID."),
) -> None:
    """Read-only: re-check the audit chain and evidence, then rebuild every
    research run's report offline and compare it with the attested file.
    Writes nothing, calls nothing, runs nothing. Exit 0 only if VERIFIED."""
    from avra.reporting.replay import verify_session

    try:
        session_id = uuid.UUID(session)
    except ValueError:
        typer.secho("session must be a session UUID", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None
    sc = verify_session(_sessions_dir(), _evidence_dir(), session_id)
    typer.echo(f"Session {sc.session_id}")
    typer.echo(f"  Audit integrity:    {sc.audit}")
    typer.echo(f"  Evidence integrity: {sc.evidence}")
    for rc in sc.runs:
        typer.echo(f"  Run (research_started seq {rc.started_seq}):")
        _say(f"    Attestation:          {rc.attestation}")
        _say(f"    Publication:          {rc.publication}")
        _say(f"    Reproduction:         {rc.reproduction}")
        _say(f"    Integrity:            {rc.integrity}")
        _say(f"    Metadata consistency: {rc.metadata}")
        _say(f"    Report validation:    {rc.validator}")
    for note in sc.notes:
        _say(f"  Note: {note}")
    for problem in sc.problems:
        _say(f"  Problem: {problem}", fg=typer.colors.RED)
    if sc.verified:
        typer.secho("Result: VERIFIED (integrity, metadata and report validation all PASS)",
                    fg=typer.colors.GREEN)
    elif sc.integrity_verified:
        typer.secho("Result: NOT VERIFIED - integrity holds, but metadata consistency and/or "
                    "report validation is not PASS", fg=typer.colors.RED)
    else:
        typer.secho("Result: NOT VERIFIED", fg=typer.colors.RED)
    raise typer.Exit(code=0 if sc.verified else 1)


def _interactive() -> bool:
    """A real terminal on both ends (recovery must be confirmed by a person)."""
    import sys

    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


@report_app.command("recover")
def report_recover(
    session: str = typer.Argument(..., help="Session UUID."),
) -> None:
    """Publish attested-but-unpublished reports, ONE AT A TIME, each only after
    you approve its exact audit seq and SHA-256. Interactive only; there is no
    --yes. Never overwrites; refuses anything that changed since you approved.
    Exit 0: every approved report published and audited; 1: partial or failed;
    2: refused / nothing to do."""
    from avra.reporting.store import (
        PublicationState,
        RecoveryStatus,
        ReportStoreError,
        complete_publication,
        report_states,
        unfinished_recoveries,
    )

    try:
        session_id = uuid.UUID(session)
    except ValueError:
        typer.secho("session must be a session UUID", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None
    if not _interactive():
        typer.secho("Refused: recovery needs an interactive terminal; nothing done.",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    log = _sessions_dir() / f"{session_id}.jsonl"
    if not log.is_file() or log.is_symlink():
        typer.secho("Refused: no audit log for this session; nothing done.",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    audit = AuditLog(log)
    try:
        states = report_states(audit, log.parent)
        if not audit.verify():
            raise ReportStoreError("session audit chain does not verify")
    except ReportStoreError as exc:
        _say(f"Refused: {exc}; nothing done.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None

    for seq in unfinished_recoveries(audit):
        _say(f"Note: recovery authorized at audit seq {seq} has no completion or failure "
             "record (interrupted?). Run `avra report verify` to see the report's state.",
             fg=typer.colors.YELLOW)
    candidates = []
    for st in states:
        if st.state is PublicationState.RECOVERABLE:
            candidates.append(st)
        else:
            label = st.report_file or "(invalid event)"
            _say(f"Not recoverable (left untouched): seq {st.event_seq} {label}: "
                 f"{st.state.value}{' - ' + st.detail if st.detail else ''}")
    if not candidates:
        typer.echo("Nothing to recover.")
        raise typer.Exit(code=2)

    approved = set()
    for st in candidates:
        typer.echo("")
        typer.echo(f"Attested but unpublished report (audit seq {st.event_seq}):")
        typer.echo(f"  file:   {st.report_file}")
        typer.echo(f"  sha256: {st.sha256}")
        try:
            if typer.confirm("  Publish this exact report?", default=False):
                approved.add((st.event_seq, st.sha256))
        except typer.Abort:
            typer.echo("Aborted; nothing done.")
            raise typer.Exit(code=2) from None
    if not approved:
        typer.echo("Nothing approved; nothing done.")
        raise typer.Exit(code=2)

    try:
        outcomes = complete_publication(
            audit, log.parent, authorized=frozenset(approved),
            confirmation="owner approved each report interactively (avra report recover)")
    except ReportStoreError as exc:
        _say(f"Refused: {exc}; nothing done.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from None
    colours = {RecoveryStatus.PUBLISHED: typer.colors.GREEN}
    for o in outcomes:
        _say(f"seq {o.event_seq} {o.report_file}: {o.status.value.upper()}"
             f"{' - ' + o.detail if o.detail else ''}",
             fg=colours.get(o.status, typer.colors.RED))
    ok = all(o.status is RecoveryStatus.PUBLISHED for o in outcomes)
    raise typer.Exit(code=0 if ok else 1)


verify_app = typer.Typer(help="Offline evidence verification: hypotheses -> deterministic "
                              "verdicts (M8.4). Never sends a network request.")
app.add_typer(verify_app, name="verify")

EXIT_UNTRUSTED_SESSION = 2


def _load_hypotheses_file(path: Path) -> list:
    """{"hypotheses": [{"rule_id", "host", "port", "params"?, "rationale"?,
    "origin"?: "owner"|"model"}]} - strict; any bad entry refuses the file."""
    import json

    from avra.verification.models import Hypothesis, Origin

    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("hypotheses") if isinstance(data, dict) else None
    if not isinstance(items, list) or not 1 <= len(items) <= 200:
        raise ValueError('expected {"hypotheses": [...]} with 1-200 entries')
    out = []
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict) or set(item) - {"rule_id", "host", "port", "params",
                                                      "rationale", "origin"}:
            raise ValueError(f"entry {i}: unexpected shape or fields")
        origin = item.get("origin", "owner")
        if origin not in ("owner", "model"):
            raise ValueError(f"entry {i}: origin must be 'owner' or 'model'")
        out.append(Hypothesis.create(rule_id=item["rule_id"], host=item["host"],
                                     port=item["port"], params=item.get("params") or {},
                                     rationale=str(item.get("rationale", "")),
                                     origin=Origin(origin)))
    return out


@verify_app.command("session")
def verify_session_cmd(
    session: str = typer.Option(..., "--session", help="Session UUID (data/sessions/<id>.jsonl)."),
    hypotheses: Path = typer.Option(None, "--hypotheses", exists=True, readable=True,
                                    help="JSON file of owner/AI-supplied hypotheses."),
    rules_proposer: bool = typer.Option(True, "--rules/--no-rules",
                                        help="Let the rules propose follow-up hypotheses."),
    use_model: bool = typer.Option(False, "--model",
                                   help="Also let the LLM propose hypotheses (paid API; asks)."),
    budget_usd: float = typer.Option(0.25, "--budget-usd", help="Model budget for --model."),
    max_iterations: int = typer.Option(5, "--max-iterations", help="Research rounds (1-50)."),
    max_hypotheses: int = typer.Option(50, "--max-hypotheses", help="Verified hypotheses cap."),
    as_json: bool = typer.Option(False, "--json", help="Print the report JSON."),
    web_rules: bool = typer.Option(False, "--web-rules",
                                   help="Also apply the passive web-header rule pack (ADR 0015)."),
) -> None:
    """Verify a session's recorded evidence offline: no Kali, tunnel, target or
    network. Writes data/verification/<session>/ (report + its audit log)."""
    import json

    from avra.verification.cycle import Budget, RuleBasedProposer, StaticProposer
    from avra.verification.report import (
        VerificationRunError,
        render_text,
        run_verification,
    )

    try:
        budget = Budget(max_iterations=max_iterations, max_hypotheses=max_hypotheses)
        proposers = []
        if hypotheses is not None:
            proposers.append(StaticProposer(_load_hypotheses_file(hypotheses)))
        if rules_proposer:
            proposers.append(RuleBasedProposer())
        if use_model:
            proposers.append(_model_proposer(budget_usd))
        if not proposers:
            raise ValueError("nothing to verify: use --rules and/or --hypotheses/--model")
        run = run_verification(sessions_dir=_sessions_dir(), evidence_root=_evidence_dir(),
                               verification_root=_verification_dir(), session_id=session,
                               proposers=proposers, budget=budget,
                               registry=_web_registry() if web_rules else None)
    except (VerificationRunError, ValueError, OSError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    if as_json:
        typer.echo(json.dumps(run.report, indent=2, sort_keys=True))
    else:
        for line in render_text(run.report):
            _say(line)
    typer.echo(f"Report: {run.report_path}")
    typer.echo(f"Report sha256: {run.report_sha256}  (audit: {run.audit_path})")
    if not run.evidence.trusted:
        _say("Session evidence is NOT trusted (see excluded evidence): nothing was decided.",
             fg=typer.colors.RED)
        raise typer.Exit(code=EXIT_UNTRUSTED_SESSION)


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise typer.BadParameter(f"{name} must be an integer") from None
    if not 1024 <= value <= 10_000_000:
        raise typer.BadParameter(f"{name} must be in [1024, 10000000]")
    return value


def _pasted_line(wait: float = 0.05) -> str | None:
    """M14.5 (Issue F): a line that is ALREADY waiting in the console (the rest of a paste),
    or None. Typing is never waited for longer than ``wait`` seconds, so a single typed line
    is sent as before. Windows: the console input buffer (msvcrt); POSIX: select()."""
    import sys
    import time

    try:
        if os.name == "nt":
            import msvcrt

            end = time.monotonic() + wait
            while time.monotonic() < end:
                if msvcrt.kbhit():
                    return input()
                time.sleep(0.005)
            return None
        import select

        ready, _, _ = select.select([sys.stdin], [], [], wait)
        return sys.stdin.readline().rstrip("\n") if ready else None
    except (EOFError, OSError, ValueError):
        return None


@app.command("chat")
def chat_cmd(
    name: str = typer.Argument("default", help="Conversation name (resumed if it exists)."),
    new: bool = typer.Option(False, "--new", help="Refuse to resume: the name must be unused."),
    list_: bool = typer.Option(False, "--list", help="List saved conversations and exit."),
    show: bool = typer.Option(False, "--show", help="Print this conversation and exit."),
    scope: Path = typer.Option(None, "--scope", exists=True, readable=True,
                               help="Bind a scope file: needed before any live action can be "
                                    "proposed or approved. Without it, chat is read-only."),
    model: str = typer.Option(None, "--model", help="Model id. Env: AVRA_LLM_MODEL."),
    provider_name: str = typer.Option(None, "--provider",
                                      help="anthropic | ollama | local-openai-compatible "
                                           "(no fallback). Env: AVRA_LLM_PROVIDER."),
    base_url: str = typer.Option(None, "--base-url",
                                 help="Local model server, loopback only. Env: AVRA_LLM_BASE_URL."),
    effort: str = typer.Option("medium", "--effort", help="low|medium|high|xhigh|max"),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key for the tunnel."),
    context_tokens: int = typer.Option(
        None, "--context-tokens", min=1024, max=10_000_000,
        help="The model server's context window in tokens (default: asked from a llama.cpp "
             "server, else 4096 for a local model). Env: AVRA_LLM_CONTEXT_TOKENS."),
) -> None:
    """M11 (ADR 0019): talk with AVRA. It reads your recorded investigations, explains
    verdicts and plans next steps. It can only PROPOSE live actions; you run one with
    /approve <id> in a real terminal. Conversations live in data/chat/."""
    import sys

    from avra.chat.agent import ChatAgent
    from avra.chat.repl import Repl
    from avra.chat.store import ChatStoreError, Conversation, list_conversations
    from avra.chat.style import Styler
    from avra.control.killswitch import KillSwitch
    from avra.llm.config import LLMConfig, LLMConfigError
    from avra.llm.factory import create_provider, ensure_supported
    from avra.llm.provider import LLMProviderError, load_api_key
    from avra.policy.scope import ScopeChecker

    root = Path(os.environ.get("AVRA_DATA_DIR", "data"))
    if list_:
        for r in list_conversations(root):
            typer.echo(f"{r['name']:<24} {r.get('messages')} msgs  last {r.get('last', '')}  "
                       f"\"{r.get('first_question', '')}\"")
        return
    try:
        conv = Conversation(root, name)
        if show:
            for m in conv.messages():
                _say(f"[{m.ts}] {m.role}: {m.content}")
            typer.echo(f"({conv.path})")
            return
        if new and conv.exists:
            raise ChatStoreError(f"conversation {conv.name!r} already exists (drop --new to "
                                 "resume it)")
        cfg = LLMConfig.from_env(model=model, provider=provider_name, base_url=base_url,
                                 effort=effort)
        ensure_supported(cfg)
        checker = ScopeChecker(load_scope(scope)) if scope is not None else None
    except (ChatStoreError, ScopeError, LLMConfigError, LLMProviderError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    _refuse_if_kill_switch("cli:chat")
    if not cfg.is_local and (not _interactive() or not typer.confirm(
            f"Chat with {cfg.model} uses the PAID Anthropic API. Continue?", default=False)):
        typer.echo("Cancelled - no API call made.")
        raise typer.Exit(code=1)
    api_key = None if cfg.is_local else load_api_key(env_file=_env_file())
    with contextlib.suppress(AttributeError, OSError):
        sys.stdout.reconfigure(encoding="utf-8")  # Uzbek / Russian text on Windows consoles

    def executor(act):
        return _chat_execute(act, checker=checker, kali=kali, key=key)

    agent = ChatAgent(create_provider(cfg, api_key=api_key), conv, checker=checker,
                      executor=executor if checker is not None else None,
                      fixtures_dir=Path("tests") / "fixtures" / "validation",
                      killswitch=KillSwitch(),
                      context_tokens=context_tokens or _env_int("AVRA_LLM_CONTEXT_TOKENS"))
    status = {"model": cfg.model, "provider": cfg.provider, "local": cfg.is_local,
              "messages": len(conv.messages()), "data": str(root / "chat"),
              "scope": (f"{checker.scope.session_name} ({scope})" if checker else None)}
    # M12.3 option B: /runner triggers this; nothing else contacts Kali. Only wired when a
    # scope is bound, so a read-only chat never reaches the Runner.
    runner_status = (lambda: _chat_runner_status(kali=kali, key=key)) if checker else None
    # M13.1: a TTY-aware styler plus a raw writer. The styler has already sanitised and
    # coloured each line; typer.echo(color=...) carries our own ANSI through (and handles
    # Windows VT / stripping) without re-stripping it the way _say would.
    styler = Styler.from_stream(sys.stdout, os.environ)

    def _writer(text: str) -> None:
        typer.echo(text, color=styler.enabled)

    def _reader(prompt_text: str) -> str:
        typer.echo(prompt_text, nl=False, color=styler.enabled)
        return input()

    repl = Repl(agent, read=_reader, write=_writer, interactive=_interactive(),
                confirm=lambda q: typer.confirm(q.strip(), default=False),
                data_root=root, status=status, runner_status=runner_status, styler=styler,
                more_input=_pasted_line if _interactive() else None)
    raise typer.Exit(code=repl.run())


def _chat_runner_status(*, kali: str, key: Path | None) -> dict:
    """M12.3 option B: one authenticated, read-only ``/v1/health`` call through the tunnel.

    Raises ``RuntimeError`` with an actionable, secret-free message on any failure; the token
    is never echoed. Reached only from the REPL ``/runner`` command in a real terminal."""
    from avra.runner_client.client import (
        RunnerAuthError,
        RunnerClient,
        RunnerClientError,
        load_token,
    )
    from avra.runner_client.tunnel import DEFAULT_KEY, SshTunnel, TunnelConfig, TunnelError

    try:
        token = load_token(env_file=_env_file())
        cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
        with SshTunnel(cfg) as base:
            return RunnerClient(base, token).health()
    except RunnerAuthError:
        raise RuntimeError("the Runner rejected the token (401). Check AVRA_RUNNER_TOKEN in .env "
                           "matches the Kali Runner.") from None
    except TunnelError as exc:
        raise RuntimeError(f"the SSH tunnel could not be established ({type(exc).__name__}). "
                           "Check the Kali host-only network and the runtime SSH key.") from None
    except RunnerClientError as exc:
        raise RuntimeError(f"could not reach the Runner ({exc}). Check avra-runner is running on "
                           "Kali and the tunnel is up.") from None
    except Exception as exc:  # noqa: BLE001 - M12.3 F1: any OTHER failure must stay secret-free.
        # The three handlers above raise RuntimeError from inside their own except blocks, so
        # those never reach here. This catch-all fulfils the docstring's "on any failure"
        # promise: an unexpected exception surfaces only its TYPE name (never its message, which
        # in principle could carry sensitive text), so the token or other secrets cannot leak to
        # the terminal through the /runner path.
        raise RuntimeError(f"the Runner status check failed unexpectedly "
                           f"({type(exc).__name__}). Nothing was sent; check the Runner, the "
                           "tunnel and the host-only network.") from None


def _chat_execute(act, *, checker, kali: str, key: Path | None,
                  request_id: str | None = None) -> dict:
    """Run ONE owner-approved chat action through the existing audited pipeline of its
    session. Reached only from /approve in a real terminal after a second confirmation.

    On any failure it returns ``ok: False`` with an actionable, secret-free ``message`` (the
    Runner token is never echoed), so the owner is told what to check rather than a bare
    exception name. The scan/probe pipelines already fold transport and auth errors into
    ``out.errors``; token/tunnel setup errors are caught here."""
    from avra.chat.store import redact
    from avra.runner_client.client import RunnerClientError, load_token
    from avra.runner_client.http_probe import APPROVAL_INTERACTIVE_TTY, run_http_probe
    from avra.runner_client.scan import run_nmap_connect_scan
    from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig

    audit = AuditLog(_sessions_dir() / f"{act.session_id}.jsonl")
    if not audit.verify():
        return {"ok": False, "stage": "audit",
                "message": "the session audit chain is not valid; refusing to run."}
    try:
        token = load_token(env_file=_env_file())
    except RunnerClientError as exc:
        return {"ok": False, "stage": "token", "message": f"Runner token unavailable: {exc}."}
    tunnel_cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
    sid = uuid.UUID(act.session_id)
    # M14.2: an investigation passes the request id it recorded BEFORE sending
    rid = uuid.UUID(request_id) if request_id else None
    if act.kind == "nmap_connect_scan":
        out = run_nmap_connect_scan(checker=checker, audit=audit, session_id=sid,
                                    host=act.host, ports=[act.port], timeout_seconds=60,
                                    token=token, evidence_root=_evidence_dir(),
                                    tunnel_cfg=tunnel_cfg, notify=_say, request_id=rid)
        result = {"ok": out.ok, "request_id": str(out.request.request_id),
                  # M13.2 F2: redact error strings at the source, before they enter act.result
                  # (persisted to the conversation) and the audit record (which is not redacted
                  # downstream). Safe today - pipeline errors carry no token - but defence in depth.
                  "errors": [redact(e) for e in out.errors[:3]],
                  "evidence_sha256": out.evidence.sha256 if out.evidence else None}
    else:
        out = run_http_probe(checker=checker, audit=audit, session_id=sid, host=act.host,
                             port=act.port, timeout_seconds=10, token=token,
                             evidence_root=_evidence_dir(), tunnel_cfg=tunnel_cfg,
                             approval=APPROVAL_INTERACTIVE_TTY, notify=_say,
                             path=act.path or None, request_id=rid)
        result = {"ok": out.ok, "request_id": str(out.request.request_id),
                  "http_status": out.facts.status_code if out.facts else None,
                  "errors": [redact(e) for e in out.errors[:3]],  # M13.2 F2: redact at source
                  "local_policy": out.local_reason,
                  "evidence_sha256": out.evidence.sha256 if out.evidence else None}
    if not result["ok"]:
        result["message"] = _runner_failure_hint(result.get("errors") or [])
    return result


def _runner_failure_hint(errors: list[str]) -> str:
    """Turn a pipeline's recorded error strings into one actionable, secret-free line.

    The pipelines fold ``RunnerAuthError``/``RunnerClientError``/``TunnelError`` into
    ``errors`` as ``'<ClassName>: <message>'``; none of those messages contains the token."""
    joined = " ".join(errors)
    if "RunnerAuthError" in joined or "(401)" in joined:
        return ("the Runner rejected the token (authentication failed). Check AVRA_RUNNER_TOKEN "
                "in .env matches the Kali Runner. Nothing ran.")
    if "cannot reach the Runner" in joined or "ConnectionRefused" in joined:
        return ("could not reach the Runner. Check the SSH tunnel is up (127.0.0.1:8765), "
                "avra-runner is running on Kali, and the host-only network is connected.")
    if "TunnelError" in joined:
        return ("the SSH tunnel could not be established. Check the Kali host is reachable on "
                "the host-only network and the runtime SSH key is correct.")
    if "kill switch" in joined:
        return "the local kill switch is engaged; nothing ran. Reset it with `avra kill --reset`."
    if "cancelled by the Runner" in joined:
        return "the Runner cancelled the job; no evidence was produced."
    return ("the action did not complete. Check the Runner is running, the tunnel is up, the "
            "scope allows it on both sides, the target is up, and the kill switch is off.")


validate_app = typer.Typer(help="M10.4: controlled validation checks, evaluated OFFLINE on "
                                "fixtures only. Live validation is disabled.")
app.add_typer(validate_app, name="validate")


@validate_app.command("list")
def validate_list_cmd() -> None:
    """List the validation checks, what a live run would need, and their status."""
    from avra.verification.validation import CHECKS, LIVE_REFUSAL

    for c in CHECKS.values():
        d = c.describe()
        typer.echo(f"{d['id']}  ({d['vuln_class']}; roles: {', '.join(d['roles'])}; "
                   f"state-changing: {'yes' if d['state_changing'] else 'no'})")
        _say(f"  {d['title']}")
        _say(f"  live execution: DISABLED - would need: {'; '.join(d['live_requires'])}")
    typer.echo(LIVE_REFUSAL)


@validate_app.command("fixture")
def validate_fixture_cmd(
    file: Path = typer.Option(..., "--file", exists=True, readable=True, dir_okay=False,
                              help="An avra-validation-fixture/1 JSON file."),
    as_json: bool = typer.Option(False, "--json", help="Print the result JSON."),
) -> None:
    """Evaluate ONE fixture with its deterministic check. Sends nothing. A SIMULATED-FIXTURE
    result is never a lab finding. Each run is appended to data/validation/validation-audit.jsonl."""
    import json

    from avra.verification.validation import (
        ValidationFixtureError,
        load_fixture,
        validate,
    )

    try:
        raw = file.read_bytes()
        fx = load_fixture(raw.decode("utf-8"))
        result = validate(fx)
    except (ValidationFixtureError, UnicodeDecodeError, OSError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    audit = AuditLog(_verification_dir().parent / "validation" / "validation-audit.jsonl")
    audit.record("validation_run", {
        "check_id": result.check_id, "check_version": result.check_version,
        "fixture_file_sha256": hashlib_sha256(raw), "fixture_sha256": result.fixture_sha256,
        "fixture_label": result.fixture_label, "target": result.target,
        "verdict": result.verdict.value, "reason_code": result.reason_code,
        "lab_finding": result.lab_finding, "result_sha256": result.sha256(),
        "live_execution": "disabled"})
    if as_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    tag = "SIMULATED - not a lab finding" if result.simulated else result.fixture_label
    typer.echo(f"{result.check_id} on {result.target}: {result.verdict.value} "
               f"({result.reason_code}) [{tag}]")
    _say(f"  {result.reason}")
    for c in result.criteria:
        _say(f"  - {c['criterion_id']}: {c['outcome']} {c['detail']}")
    for lim in result.limitations:
        _say(f"  limitation: {lim}")
    typer.echo(f"Result sha256: {result.sha256()}  (audit: {audit.path})")


def hashlib_sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


@app.command("web-surface")
def web_surface_cmd(
    session: str = typer.Option(..., "--session", help="Session UUID (data/sessions/<id>.jsonl)."),
    as_json: bool = typer.Option(False, "--json", help="Print the full surface JSON."),
) -> None:
    """M10.1: list the same-origin endpoints, forms, scripts and API candidates that
    a session's RECORDED http_probe responses reference. Offline and read-only: no
    request is sent, nothing is fetched, no form is submitted, no script runs."""
    import json

    from avra.recon.web_surface import surface_digest, surfaces_from_evidence
    from avra.verification.evidence import load_session_evidence

    try:
        uuid.UUID(session)
        ev = load_session_evidence(_sessions_dir(), _evidence_dir(), session)
    except (ValueError, OSError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    if not ev.trusted:
        _say("Session evidence is NOT trusted: no web surface is derived from it.",
             fg=typer.colors.RED)
        raise typer.Exit(code=EXIT_UNTRUSTED_SESSION)
    surfaces, issues = surfaces_from_evidence(ev, _evidence_dir())
    for i in issues:
        _say(f"Excluded evidence {i.request_id}: {i.code}", fg=typer.colors.YELLOW)
    if as_json:
        typer.echo(json.dumps([s.model_dump(mode="json") for s in surfaces], indent=2,
                              sort_keys=True))
        return
    if not surfaces:
        typer.echo("No trusted http_probe responses in this session: nothing to list.")
        return
    for s in surfaces:
        d = surface_digest(s, limit=200)
        typer.echo(f"{s.origin}  ({len(s.endpoints)} endpoint reference(s), "
                   f"surface sha256 {d['surface_sha256'][:16]}...)")
        for e in d["endpoints"]:
            keys = f" ?{','.join(e['query_keys'])}" if e.get("query_keys") else ""
            _say(f"  {e['path']}{keys}  [{', '.join(e['kinds'])}]  via {e['source']}")
        for f in d["forms"]:
            _say(f"  form {f['method']} {f['action']} fields: {', '.join(f['fields'])}")
        if s.external_origins:
            _say(f"  not followed (other origins): {', '.join(s.external_origins)}")
        if d["flags"]:
            _say(f"  flags: {', '.join(d['flags'])}", fg=typer.colors.YELLOW)
        typer.echo(f"  {d['note']}")


def _web_registry():
    from avra.verification.rules import web_registry

    return web_registry()


def _model_proposer(budget_usd: float):
    from avra.llm.config import LLMConfig
    from avra.llm.factory import create_provider
    from avra.verification.model_proposer import ModelProposer

    _refuse_if_kill_switch("cli:verify session --model")
    if not _interactive():
        raise ValueError("--model needs an interactive terminal to confirm the paid API use")
    cfg = LLMConfig()
    typer.echo(f"--model: {cfg.model} proposes hypotheses (budget ${budget_usd:.2f}); "
               "the engine alone decides verdicts.")
    if not typer.confirm("Use the paid Anthropic API for hypothesis proposals?", default=False):
        raise ValueError("cancelled - no API call made")
    return ModelProposer(create_provider(cfg, env_file=_env_file()),
                         budget_usd=budget_usd)


@verify_app.command("show")
def verify_show_cmd(session: str = typer.Argument(..., help="Session UUID.")) -> None:
    """Print the latest verification report for a session (read-only)."""
    import json

    from avra.verification.report import check_verification, render_text

    out = check_verification(sessions_dir=_sessions_dir(), evidence_root=_evidence_dir(),
                             verification_root=_verification_dir(), session_id=session)
    if not out.integrity_ok:
        # Never display a report whose bytes are not the ones the audit attests.
        typer.secho("Report NOT shown - integrity not established: "
                    + ("; ".join(out.problems) or "no report"), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if out.status != "VERIFIED":
        _say("WARNING: this report's file is intact, but its verdicts do NOT reproduce from "
             "the current evidence. Do not rely on it:", fg=typer.colors.RED)
        for p in out.problems:
            _say(f"  problem: {p}", fg=typer.colors.RED)
    for line in render_text(json.loads(out.report_path.read_bytes())):
        _say(line)
    typer.echo(f"Report: {out.report_path}  integrity/re-check: {out.status}")
    raise typer.Exit(code=0 if out.status == "VERIFIED" else 1)


@verify_app.command("check")
def verify_check_cmd(session: str = typer.Argument(..., help="Session UUID.")) -> None:
    """Re-derive every recorded verdict from the evidence and compare bytes.
    Exit 0 only if VERIFIED (audit chain, report hash and every result match)."""
    from avra.verification.report import check_verification

    out = check_verification(sessions_dir=_sessions_dir(), evidence_root=_evidence_dir(),
                             verification_root=_verification_dir(), session_id=session)
    colour = typer.colors.GREEN if out.status == "VERIFIED" else typer.colors.RED
    typer.secho(f"Verification check: {out.status} ({out.reproduced} result(s) reproduced)",
                fg=colour)
    if out.report_path is not None:
        typer.echo(f"Report: {out.report_path} sha256 {out.report_sha256}")
    for p in out.problems:
        _say(f"  problem: {p}", fg=typer.colors.RED)
    for n in out.notes:
        _say(f"  note: {n}", fg=typer.colors.YELLOW)
    raise typer.Exit(code=0 if out.status == "VERIFIED" else 1)


@verify_app.command("rules")
def verify_rules_cmd() -> None:
    """List the registered verification rules and what each needs for CONFIRMED."""
    from avra.verification.rules import default_registry

    for r in default_registry().rules():
        typer.echo(f"{r.id} (v{r.version}, {r.kind.value}"
                   f"{', severity ' + r.severity if r.kind.value == 'vulnerability' else ''})")
        typer.echo(f"  {r.title}")
        typer.echo(f"  CONFIRMED requires: {r.confirmed_requires}")


audit_app = typer.Typer(help="Audit integrity: HMAC anchors over audit logs (M8.7, ADR 0012).")
app.add_typer(audit_app, name="audit")


def _audit_keyring(state: Path):
    """The DPAPI key ring (tests replace this to inject a fake protector)."""
    from avra.storage.keys import Keyring

    return Keyring(state)


def _audit_store():
    from avra.storage.anchors import AnchorStore, state_dir

    state = state_dir()
    keyring = _audit_keyring(state)
    return state, keyring, AnchorStore(state, keyring)


def _audit_target(session: str | None, log: Path | None) -> Path:
    if (session is None) == (log is None):
        typer.secho("Give exactly one of: a session UUID, or --log PATH.", fg=typer.colors.RED,
                    err=True)
        raise typer.Exit(code=1)
    if log is not None:
        return log
    try:
        sid = uuid.UUID(session)
    except ValueError:
        typer.secho("session must be a UUID", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    return _sessions_dir() / f"{sid}.jsonl"


def _print_log_verification(v) -> None:
    from avra.storage.anchors import Severity

    colour = {Severity.OK: typer.colors.GREEN, Severity.WARNING: typer.colors.YELLOW,
              Severity.FAILURE: typer.colors.RED}
    typer.echo(f"Log:            {v.log_id}")
    typer.secho(f"Hash chain:     {'valid' if v.chain.ok else 'BROKEN'} - {v.chain.describe()} "
                "(unkeyed; detects edits, not truncation or rewrite)",
                fg=typer.colors.GREEN if v.chain.ok else typer.colors.RED)
    typer.secho(f"Anchor (HMAC):  {v.status.value} - {v.detail}", fg=colour[v.severity])
    for note in v.notes:
        typer.echo(f"  note: {note}")


@audit_app.command("keygen")
def audit_keygen(
    rotate: bool = typer.Option(False, "--rotate",
                                help="Add a new active key; older keys stay for verification."),
) -> None:
    """Create the audit anchor key (owner only, interactive). Never automatic."""
    from avra.storage.anchors import AnchorError, create_key
    from avra.storage.keys import AnchorKeyError

    if not _interactive():
        typer.secho("Refused: keygen needs an interactive terminal (no piping). Nothing created.",
                    fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    state, keyring, store = _audit_store()
    typer.echo(f"State directory: {state}")
    typer.echo("This creates a random 256-bit HMAC key, encrypted with Windows DPAPI for THIS "
               "Windows user only, and restricts the keys folder to this user and SYSTEM.")
    typer.echo("If the key is lost (profile reset, other machine), existing anchors can no longer "
               "be verified. The key is never printed.")
    if rotate:
        typer.echo("Rotation: the current key is kept (retired) so older anchors still verify.")
    try:
        confirmed = typer.confirm("Create the key now?", default=False)
    except typer.Abort:
        confirmed = False
    if not confirmed:
        typer.echo("Cancelled - no key created.")
        raise typer.Exit(code=1)
    try:
        key_id = create_key(state, keyring, store, rotate=rotate)
    except (AnchorError, AnchorKeyError, OSError) as exc:
        typer.secho(f"Refused: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    typer.secho(f"Key created. Key id (not secret): {key_id}", fg=typer.colors.GREEN)


@audit_app.command("status")
def audit_status() -> None:
    """Read-only: key ids, anchor store integrity, head witness."""
    from avra.storage.anchors import EXIT_CODES, severity
    from avra.storage.keys import AnchorKeyError

    state, keyring, store = _audit_store()
    typer.echo(f"State directory: {state}")
    try:
        entries = keyring.entries()
        for e in entries:
            typer.echo(f"Key {e.key_id}  {e.status}  created {e.created_at}  ({e.scope})")
    except AnchorKeyError as exc:
        typer.echo(f"Keys: {exc}")
    st = store.load()
    sev = severity(st.status)
    typer.secho(f"Anchor store: {st.status.value} - {st.detail}",
                fg={0: typer.colors.GREEN, 2: typer.colors.YELLOW}.get(EXIT_CODES[sev],
                                                                      typer.colors.RED))
    typer.echo(f"Anchors: {len(st.anchors)}; head witness at: "
               f"{'n/a' if st.witness_seq is None else st.witness_seq}")
    for note in st.notes:
        typer.echo(f"  note: {note}")
    raise typer.Exit(code=EXIT_CODES[sev])


@audit_app.command("seal")
def audit_seal(
    session: str = typer.Argument(None, help="Session UUID (data/sessions/<uuid>.jsonl)."),
    log: Path = typer.Option(None, "--log", help="Any AVRA audit log path instead."),
) -> None:
    """Explicitly anchor the CURRENT head of one audit log (never automatic)."""
    from avra.storage.anchors import AnchorError

    path = _audit_target(session, log)
    _state, _keyring, store = _audit_store()
    try:
        res = store.seal(path)
    except AnchorError as exc:
        typer.secho(f"NOT sealed ({exc.status.value}): {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from None
    if res.anchor is None:
        typer.echo(f"Already sealed at record {res.audit_seq}; no new anchor written.")
    else:
        typer.secho(f"Sealed: records 1..{res.audit_seq} anchored as anchor "
                    f"{res.anchor.anchor_seq} (key {res.anchor.key_id}).", fg=typer.colors.GREEN)
        typer.echo("Records added later are not covered until the next seal.")


@audit_app.command("verify")
def audit_verify(
    session: str = typer.Argument(None, help="Session UUID."),
    log: Path = typer.Option(None, "--log", help="Any AVRA audit log path instead."),
    all_logs: bool = typer.Option(False, "--all",
                                  help="Every anchored log plus every session log."),
) -> None:
    """Read-only: unkeyed hash chain AND HMAC anchor check, reported separately.
    Exit 0 VERIFIED; 2 not (fully) anchored; 1 tampering/damage/key problem."""
    from avra.storage.anchors import log_identity

    _state, _keyring, store = _audit_store()
    state = store.load()
    if not all_logs:
        v = store.verify_log(_audit_target(session, log), state)
        _print_log_verification(v)
        raise typer.Exit(code=v.exit_code)
    if session is not None or log is not None:
        typer.secho("--all takes no session or --log", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    paths = {log_identity(p): p for p in sorted(_sessions_dir().glob("*.jsonl"))} \
        if _sessions_dir().is_dir() else {}
    for a in state.anchors:
        paths.setdefault(a.log_id, Path(a.log_id))
    if not paths:
        typer.echo(f"Anchor store: {state.status.value} - {state.detail}")
        typer.echo("No audit logs found.")
        raise typer.Exit(code=1 if not state.usable else 2)
    worst = 0
    for _id, p in sorted(paths.items()):
        v = store.verify_log(p, state)
        _print_log_verification(v)
        typer.echo("")
        worst = max(worst, {0: 0, 2: 1, 1: 2}[v.exit_code])
    raise typer.Exit(code={0: 0, 1: 2, 2: 1}[worst])


def _assessments_dir() -> Path:
    return Path(os.environ.get("AVRA_DATA_DIR", "data")) / "assessments"


@app.command()
def assess(
    scope: Path = typer.Option(..., "--scope", exists=True, readable=True,
                               help="Orchestrator scope file (default deny)."),
    target: str = typer.Option(..., "--target", help="Lab target IPv4 (must be in scope)."),
    port: list[int] = typer.Option(..., "--port", help="Target port; repeat for several."),
    scan: bool = typer.Option(False, "--scan",
                              help="Run ONE nmap connect scan now via the Kali Runner "
                                   "(needs the Runner up and AVRA_RUNNER_TOKEN)."),
    sessions: list[str] = typer.Option(None, "--session",
                                       help="Session UUID with recorded evidence; repeat to "
                                            "combine sessions. With --scan, the first one "
                                            "records the new scan."),
    provider_name: str = typer.Option(None, "--provider",
                                      help="anthropic | ollama | local-openai-compatible. "
                                           "Env: AVRA_LLM_PROVIDER."),
    model: str = typer.Option(None, "--model", help="Model name. Env: AVRA_LLM_MODEL."),
    base_url: str = typer.Option(None, "--base-url",
                                 help="Local model server (loopback only). Env: AVRA_LLM_BASE_URL."),
    timeout: float = typer.Option(None, "--llm-timeout", help="Seconds per model call."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Deterministic report only, no model call."),
    rule_pack: str = typer.Option("web", "--rules",
                                  help="Verification rules: 'web' (default rules + passive web-header "
                                       "pack) or 'default' (the M8.4 rule set only)."),
    yes: bool = typer.Option(False, "--yes", help="Skip the scan confirmation (never the paid-API one)."),
    kali: str = typer.Option("192.168.56.104", "--kali", help="Kali host-only IPv4 address."),
    key: Path = typer.Option(None, "--key", help="Runtime SSH key for the tunnel."),
) -> None:
    """Scope check -> evidence -> Verification Engine -> AI analysis -> report.

    The model only interprets; verdicts come from the deterministic engine and
    every AI hypothesis is reported as UNVERIFIED (ADR 0015)."""
    import hashlib

    _refuse_if_kill_switch("cli:assess")
    from avra import assessment as asm
    from avra.llm.config import LLMConfig, LLMConfigError
    from avra.llm.factory import create_provider, ensure_supported
    from avra.llm.provider import LLMProviderError
    from avra.policy.scope import ScopeChecker
    from avra.policy.tools import authorize_tool_request
    from avra.runner.schemas import NmapConnectScanRequest
    from avra.verification.cycle import RuleBasedProposer
    from avra.verification.report import VerificationRunError, run_verification

    def refuse(msg: str, code: int = 1):
        typer.secho(f"Refused: {msg}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=code)

    # 1. Scope: deterministic, before anything else, for every requested port.
    try:
        loaded = load_scope(scope)
        checker = ScopeChecker(loaded)
        probe = NmapConnectScanRequest(request_id=uuid.uuid4(), session_id=uuid.uuid4(),
                                       host=target, ports=port, timeout_seconds=60)
    except ScopeError as exc:
        refuse(str(exc))
    except ValueError as exc:
        refuse(f"invalid target: {exc}")
    decision = authorize_tool_request(checker, probe)
    typer.echo(f"Scope:    {loaded.session_name} - {target} ports "
               f"{', '.join(map(str, port))}: {'ALLOWED' if decision.allowed else 'DENIED'} "
               f"({decision.reason})")
    if not decision.allowed:
        refuse("target is not in the scope file; nothing was scanned or analyzed")
    sessions = list(sessions or [])
    try:
        sessions = list(dict.fromkeys(str(uuid.UUID(s)) for s in sessions))
    except ValueError:
        refuse("--session must be a UUID")
    if not scan and not sessions:
        refuse("choose --scan (new evidence) or --session <uuid> (existing evidence)")

    # 2. Model configuration (validated now, so a bad flag fails before any scan).
    provider = None
    if not no_ai:
        try:
            kw = {"timeout_seconds": timeout} if timeout else {}
            cfg = LLMConfig.from_env(provider=provider_name, model=model, base_url=base_url, **kw)
            ensure_supported(cfg)
        except LLMConfigError as exc:
            refuse(str(exc))
        if cfg.is_local:
            typer.echo(f"AI:       {cfg.model} via {cfg.provider} at {cfg.resolved_base_url} "
                       "(local, no API cost)")
        else:
            typer.echo(f"AI:       {cfg.model} via the PAID Anthropic API (one call)")
            if not typer.confirm("Use the paid Anthropic API for the analysis?", default=False):
                refuse("cancelled - no API call made")
        try:
            provider = create_provider(cfg, env_file=_env_file())
        except (LLMConfigError, LLMProviderError) as exc:
            refuse(str(exc))
        if cfg.is_local:
            try:
                installed = provider.list_models()
                if installed and cfg.model not in installed:
                    _say(f"Warning: model {cfg.model!r} is not in the server's list "
                         f"({', '.join(installed[:8])}); the call will likely fail.",
                         fg=typer.colors.YELLOW)
            except LLMProviderError as exc:
                _say(f"Warning: {exc} - the report will be produced without AI analysis.",
                     fg=typer.colors.YELLOW)
    else:
        typer.echo("AI:       off (--no-ai)")

    # 3. Evidence: a fresh scan through the existing, audited pipeline - or recorded evidence.
    if scan:
        from avra.runner_client.client import RunnerClientError, load_token
        from avra.runner_client.scan import run_nmap_connect_scan
        from avra.runner_client.tunnel import DEFAULT_KEY, TunnelConfig, TunnelError

        try:
            runner_token = load_token(env_file=_env_file())
            tunnel_cfg = TunnelConfig(kali_host=kali, key_path=key or DEFAULT_KEY)
        except (RunnerClientError, TunnelError) as exc:
            refuse(str(exc))
        typer.echo(f"Scan:     nmap_connect_scan {target} ports {', '.join(map(str, port))} "
                   f"via avra-tunnel@{kali} (the Runner re-checks its own scope)")
        if not yes and not typer.confirm("Send this scan request?", default=False):
            refuse("cancelled - nothing sent")
        session_id, saudit = _open_session(scope, loaded, sessions[0] if sessions else None)
        outcome = run_nmap_connect_scan(
            checker=checker, audit=saudit, session_id=session_id, host=target, ports=port,
            timeout_seconds=60, token=runner_token, evidence_root=_evidence_dir(),
            tunnel_cfg=tunnel_cfg, notify=_say)
        for err in outcome.errors:
            _say(f"  Scan error: {err}", fg=typer.colors.RED)
        if outcome.result is None:
            refuse(f"the scan produced no result (session {session_id}); see its audit log")
        source = f"live nmap_connect_scan, request {outcome.request.request_id}"
        sessions = list(dict.fromkeys([str(session_id), *sessions]))
        if len(sessions) > 1:
            source += f" + recorded evidence of {len(sessions) - 1} other session(s)"
    else:
        source = (f"recorded evidence of {len(sessions)} session(s) (no new scan)")
    sid = sessions[0]  # the assessment is filed under the first session

    # 4. Deterministic verification of each session's hash-checked evidence.
    from avra.verification.rules import default_registry, web_registry

    if rule_pack not in ("web", "default"):
        refuse("--rules must be 'web' or 'default'")
    registry = web_registry() if rule_pack == "web" else default_registry()
    runs = []
    for s in sessions:
        try:
            runs.append(run_verification(sessions_dir=_sessions_dir(), evidence_root=_evidence_dir(),
                                         verification_root=_verification_dir(), session_id=s,
                                         proposers=[RuleBasedProposer()], registry=registry))
        except (VerificationRunError, OSError) as exc:
            refuse(f"session {s}: {exc}")
    facts = asm.merge_facts([asm.build_facts(r.report, r.evidence, _evidence_dir()) for r in runs])
    wanted = {(target, p) for p in port}
    facts["targets"] = [t for t in facts["targets"] if (t["host"], t["port"]) in wanted]
    for key_ in ("verified", "confirmed_findings", "confirmed_weaknesses", "inconclusive",
                 "next_actions"):
        facts[key_] = [x for x in facts[key_]
                       if tuple(x["target"].rsplit(":", 1)) in {(h, str(p)) for h, p in wanted}]
    if not facts["targets"]:
        _say(f"Warning: session {sid} holds no trusted evidence for {target} "
             f"{', '.join(map(str, port))}.", fg=typer.colors.YELLOW)
    typer.echo(f"Verified: {len(facts['confirmed_findings'])} confirmed vulnerability(ies), "
               f"{len(facts['confirmed_weaknesses'])} configuration weakness(es) (not proven "
               "exploitable), "
               f"{len(facts['verified'])} verified observation(s), "
               f"{len(facts['inconclusive'])} inconclusive "
               f"({len(runs)} verification report(s): {', '.join(r.report_path.name for r in runs)})")

    # 5. One model call (or none), then the report.
    try:
        audit = asm.open_audit(_assessments_dir(), sid)
    except ValueError as exc:
        refuse(str(exc))
    audit.record("assessment_started", {
        "session_id": sid, "target": target, "ports": list(port), "scope_file": str(scope),
        "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        "scope_decision": decision.reason, "evidence_source": source,
        "sessions": sessions,
        "verification_reports": [{"session_id": s, "report": r.report_path.name,
                                  "sha256": r.report_sha256} for s, r in zip(sessions, runs)],
        "ai": None if provider is None else {"provider": provider.config.provider,
                                             "model": provider.config.model}})
    if provider is None:
        result = asm.AnalysisOutcome(status="skipped")
    else:
        typer.echo("Analysis: asking the model (one call; it cannot run anything)...")
        result = asm.run_analysis(provider, facts, audit)
        colour = typer.colors.GREEN if result.status == "ok" else typer.colors.YELLOW
        _say(f"Analysis: {result.status}"
             + (f" - {result.detail}" if result.detail else f" ({result.seconds}s)"), fg=colour)
    meta = {"generated_at": dt_now_iso(), "scope_name": loaded.session_name,
            "scope_file": str(scope), "scope_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
            "evidence_source": source,
            "verification_reports": [str(r.report_path) for r in runs],
            "target": target, "ports": list(port)}
    limits = {"limitations": sorted({x for r in runs for x in r.report.get("limitations", [])})}
    files = asm.write_assessment(_assessments_dir() / sid, audit, meta, facts, limits, result)
    typer.echo("")
    typer.secho(f"Report:   {files.markdown}", fg=typer.colors.GREEN)
    typer.echo(f"JSON:     {files.json}")
    typer.echo(f"Audit:    {files.audit}")


def dt_now_iso() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat()


# M14.2 (ADR 0022): `avra investigate` lives in its own module; registered last so it can
# reuse this module's helpers through late imports.
from avra.cli.investigate import investigate_app

app.add_typer(investigate_app, name="investigate")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
