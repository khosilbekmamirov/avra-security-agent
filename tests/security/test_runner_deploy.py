"""Deployment artifacts (runner/deploy) — static checks that the files we
hand to the owner keep the agreed security properties (ADR 0003, M4.1).
Nothing here touches a VM."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from avra.runner import config as runner_config

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "runner" / "deploy"


def _unit() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in (DEPLOY / "avra-runner.service").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        out.setdefault(key, []).append(value)
    return out


def _env() -> dict[str, str]:
    lines = (DEPLOY / "runner.env.example").read_text(encoding="utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines if line.strip())


# --- systemd unit ---------------------------------------------------------


@pytest.mark.parametrize(
    "key,value",
    [
        ("User", "avra-runner"),
        ("Restart", "no"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("ProtectSystem", "strict"),
        ("ReadWritePaths", "/var/lib/avra-runner"),
        ("ProtectHome", "yes"),
        ("PrivateTmp", "yes"),
        ("PrivateDevices", "yes"),
        ("KillMode", "control-group"),
        ("IPAddressDeny", "any"),
        ("UMask", "0077"),
        ("EnvironmentFile", "/etc/avra-runner/runner.env"),
        ("ExecStart", "/opt/avra-runner/venv/bin/python -m avra.runner"),
    ],
)
def test_unit_directive(key, value):
    assert _unit()[key] == [value]


def test_unit_address_families_exclude_raw_and_ipv6():
    families = set(_unit()["RestrictAddressFamilies"][0].split())
    assert families == {"AF_INET", "AF_UNIX", "AF_NETLINK"}


def test_unit_ip_allowlist_matches_loopback_plus_scope_targets():
    allowed = set(_unit()["IPAddressAllow"][0].split())
    scope = yaml.safe_load((ROOT / "scope" / "example.scope.yaml").read_text(encoding="utf-8"))
    assert allowed == {"127.0.0.1"} | {t["host"] for t in scope["targets"]}


def test_unit_keeps_proc_net_readable_for_nmap():
    assert "ProcSubset" not in _unit()


# --- runner.env -----------------------------------------------------------


def test_env_binds_loopback_and_real_nmap_binary():
    env = _env()
    assert env["AVRA_RUNNER_BIND_HOST"] == "127.0.0.1"
    assert env["AVRA_RUNNER_EXEC_NMAP"] == "/usr/lib/nmap/nmap"  # not the wrapper
    assert runner_config._load_bind_host(env) == "127.0.0.1"
    assert runner_config._load_port(env) == 8765


def test_env_has_only_known_keys_and_absolute_paths():
    env = _env()
    known = {
        "AVRA_RUNNER_SCOPE_FILE", runner_config.TOKEN_FILE_ENV, runner_config.AUDIT_LOG_ENV,
        runner_config.BIND_HOST_ENV, runner_config.PORT_ENV, "AVRA_RUNNER_EXEC_NMAP",
        "AVRA_RUNNER_EXEC_HTTP_PROBE",
    }
    assert set(env) == known
    for key, value in env.items():
        if key.endswith(("_FILE", "_LOG")) or key.startswith("AVRA_RUNNER_EXEC_"):
            assert value.startswith("/")


def test_env_names_an_executable_for_every_registered_tool():
    """The Runner refuses to start unless every registry executable has an
    AVRA_RUNNER_EXEC_<NAME> entry (config._load_executables) — M8.2."""
    from avra.runner.registry import get_tool, registered_tools

    names = {get_tool(t).executable for t in registered_tools()}
    exec_keys = {k for k in _env() if k.startswith(runner_config.EXEC_ENV_PREFIX)}
    assert exec_keys == {runner_config.EXEC_ENV_PREFIX + n.upper() for n in names}


def test_env_http_probe_is_the_root_owned_venv_console_script():
    # Inside the root-owned Runner venv (install.sh: chown root, go-w), and
    # the exact console script pyproject.toml declares for the child.
    assert _env()["AVRA_RUNNER_EXEC_HTTP_PROBE"] == "/opt/avra-runner/venv/bin/avra-http-probe"
    import tomllib

    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["scripts"]
    assert scripts["avra-http-probe"] == "avra.runner.tools.http_probe:main"


def test_env_contains_no_token_value():
    text = (DEPLOY / "runner.env.example").read_text(encoding="utf-8")
    assert "AVRA_RUNNER_TOKEN=" not in text


# --- requirements ---------------------------------------------------------


def test_requirements_pinned_and_hashed():
    text = (DEPLOY / "requirements-runner.txt").read_text(encoding="utf-8")
    blocks = re.split(r"\n(?=[a-z])", text.strip())
    pins = {}
    for block in blocks:
        head = block.splitlines()[0]
        m = re.match(r"^([a-z0-9_.-]+)==([0-9][^ \\]*)", head)
        assert m, f"not pinned: {head}"
        assert "--hash=sha256:" in block, f"no hash: {head}"
        pins[m.group(1)] = m.group(2)
    assert pins["starlette"] == "1.9.0"
    assert pins["uvicorn"] == "0.54.0"
    assert "httpx" not in pins  # dev-only, never on the Runner


def test_requirements_match_pyproject_runner_pins():
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"starlette==1.9.0"' in py and '"uvicorn==0.54.0"' in py


# --- installer scripts ----------------------------------------------------


SCRIPTS = ["install.sh", "install-tunnel.sh"]


def _script(name: str) -> str:
    return (DEPLOY / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", SCRIPTS)
def test_scripts_fail_closed_and_never_start_things(name):
    text = _script(name)
    assert "set -Eeuo pipefail" in text
    assert 'id -u)" -eq 0 ]' in text
    assert "already exists" in text  # refuses to overwrite
    assert not re.search(r"systemctl\s+(start|enable|restart)", text)
    assert not re.search(r"\b(curl|wget)\b", text)
    assert "chmod 777" not in text and "NOPASSWD" not in text


# --- 1. CRLF ---------------------------------------------------------------


@pytest.mark.parametrize("name", SCRIPTS)
def test_crlf_guard_is_first_command_and_survives_crlf(name):
    second_line = _script(name).splitlines()[1]
    # Trailing "#": under CRLF the \r lands in a comment, so the guard still runs.
    assert second_line.startswith("if grep -q $'\\r' \"$0\"") and second_line.endswith("#")


def test_gitattributes_forces_lf_for_deploy_files():
    out = subprocess.run(
        ["git", "check-attr", "eol", "--", "runner/deploy/install.sh",
         "runner/deploy/avra-runner.service", "runner/deploy/sshd-avra-tunnel.conf"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    assert out.count("eol: lf") == 3


def _linux_like_bash() -> bool:
    """Git Bash/Cygwin strip CR in text mode, so CRLF can't be reproduced
    there; this test only means something with a real Linux bash + grep."""
    if shutil.which("bash") is None:
        return False
    ostype = subprocess.run(
        ["bash", "-c", "echo $OSTYPE"], capture_output=True, text=True, timeout=30
    ).stdout.strip()
    return ostype.startswith("linux")


@pytest.mark.skipif(
    not _linux_like_bash(), reason="needs Linux bash/grep (Windows bash ignores CR) — M4.5 on Kali"
)
@pytest.mark.parametrize("name", SCRIPTS)
def test_crlf_copy_refuses_before_doing_anything(tmp_path, name):
    crlf = tmp_path / name
    crlf.write_bytes(_script(name).replace("\n", "\r\n").encode())
    r = subprocess.run(["bash", crlf.as_posix()], capture_output=True, text=True, timeout=30)
    assert r.returncode == 1
    assert "CRLF line endings" in r.stderr
    assert "must be run as root" not in r.stderr  # stopped before anything else


# --- 2. rollback -------------------------------------------------------------


@pytest.mark.parametrize("name", SCRIPTS)
def test_rollback_on_any_nonzero_exit(name):
    text = _script(name)
    assert "trap rollback EXIT" in text and "trap 'exit 130' INT TERM" in text
    assert "trap '' INT TERM" in text  # rollback itself can't be interrupted
    assert '[ "$rc" -eq 0 ] && return 0' in text
    assert "UNDO=()  # success" in text


def _code_lines(text: str) -> list[str]:
    """Logical code lines: backslash continuations joined, comments and
    blank lines dropped."""
    joined = re.sub(r"\\\n\s*", " ", text)
    out = []
    for ln in joined.splitlines():
        ln = ln.strip()
        if ln and not ln.startswith("#"):
            out.append(ln)
    return out


@pytest.mark.parametrize("name", SCRIPTS)
def test_no_eval(name):
    assert not any(re.search(r"\beval\b", ln) for ln in _code_lines(_script(name)))


def _lib(text: str) -> str:
    start = text.index("# --- rollback (begin)")
    end = text.index("# --- rollback (end) ---")
    return text[start:end]


def test_rollback_lib_identical_in_both_scripts():
    assert _lib(_script("install.sh")) == _lib(_script("install-tunnel.sh"))


@pytest.mark.parametrize("name", SCRIPTS)
def test_rollback_only_registered_after_preexistence_checks(name):
    text = _script(name)
    first_undo = text.index("\non_undo ")
    last_refusal = text.rindex("already exists — refusing")
    assert last_refusal < first_undo  # nothing pre-existing can be on the undo list


@pytest.mark.parametrize("name", SCRIPTS)
def test_undo_registered_right_after_atomic_creation(name):
    """Every `on_undo X` must name a defined undo function and directly
    follow a creation that fails if the target exists."""
    code = _code_lines(_script(name))
    atomic = re.compile(r"^(useradd |mkdir -m \S+ \S+$|\( set -C; cat -- )")
    calls = [i for i, ln in enumerate(code) if ln.startswith("on_undo ")]
    assert calls
    for i in calls:
        fn = code[i].split()[1]
        assert re.search(rf"^{fn}\(\)", _script(name), re.M), f"{fn} not defined"
        assert atomic.match(code[i - 1]), f"{fn} not preceded by atomic create: {code[i - 1]}"
    assert "mkdir -p" not in _script(name)


# --- 3. input integrity -------------------------------------------------------


@pytest.mark.parametrize("name", SCRIPTS)
def test_bundle_integrity_checks(name):
    text = _script(name)
    assert 'stat -c %u "$HERE")" -eq 0' in text  # root-owned bundle dir
    assert "& 8#022) == 0" in text  # not group/other-writable
    assert '[ ! -L "$p" ]' in text  # no symlinks
    assert "sha256sum --strict --quiet -c SHA256SUMS" in text
    assert "is not listed in SHA256SUMS" in text
    assert '"$ANSWER" = "YES"' in text and "< /dev/tty" in text
    assert '[ "$#" -eq 0 ]' in text  # no caller-supplied paths


def test_install_sh_pip_isolated_and_hash_verified():
    text = _script("install.sh")
    for flag in ("--isolated", "--no-input", "--index-url https://pypi.org/simple",
                 "--require-hashes", "--only-binary=:all:", "--no-deps --no-index",
                 "PYTHONNOUSERSITE=1"):
        assert flag in text
    assert "sshd" not in text and "/etc/ssh" not in text
    assert "/etc/avra-runner/token" not in text  # token is never written by the installer


def test_install_sh_append_only_audit_and_scope_allowlist_check():
    text = _script("install.sh")
    assert 'chattr +a "$AUDIT"' in text and "lsattr" in text
    assert "chattr -a" in text  # rollback can remove its own append-only file
    assert "scope targets not in the unit's IPAddressAllow" in text


def test_tunnel_script_restrictions():
    text = _script("install-tunnel.sh")
    for opt in ("restrict", "port-forwarding", "permitopen=", "from=", "command="):
        assert opt in text
    assert "WINDOWS_HOST=192.168.56.1" in text
    assert "RUNNER_ADDR=127.0.0.1:8765" in text
    assert "DROPIN=$DROPIN_DIR/10-avra-tunnel.conf" in text
    assert "--no-create-home" in text and "--create-home" not in text.replace("--no-create-home", "")
    assert "ssh-keygen -l -f" in text
    assert "PRIVATE KEY" in text  # refuses a private key in place of the .pub
    for want in ("allowtcpforwarding local", "permitopen $RUNNER_ADDR", "permitlisten none",
                 "allowstreamlocalforwarding no", "permittty no", "authenticationmethods publickey",
                 "forcecommand /usr/sbin/nologin", "gatewayports no", "permituserrc no",
                 "authorizedkeysfile $AUTH_KEYS", "passwordauthentication no",
                 "kbdinteractiveauthentication no", "x11forwarding no", "permittunnel no",
                 "allowagentforwarding no"):
        assert f'"{want}"' in text  # effective sshd -T check
    assert 'if sshd -t; then systemctl reload "$SSH_UNIT"; fi' in text  # rollback restores original
    assert 'systemctl reload "$SSH_UNIT"' in text
    assert not any("restart" in ln for ln in _code_lines(text))
    for opt in ("IdentitiesOnly=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no"):
        assert opt in text


def test_tunnel_script_checks_other_users_unchanged_before_reload():
    text = _script("install-tunnel.sh")
    assert "BEFORE=$(snapshot)" in text and "AFTER=$(snapshot)" in text
    assert '[ "$BEFORE" != "$AFTER" ]' in text
    # Baseline before the drop-in is written; comparison and syntax check before reload.
    assert text.index("BEFORE=$(snapshot)") < text.index('cat -- "$HERE/$DROPIN_NAME" > "$DROPIN"')
    reload_at = text.index('echo "[5/5] reloading sshd')
    assert text.index('[ "$BEFORE" != "$AFTER" ]') < reload_at
    assert text.index("sshd -t || die \"sshd -t failed with the drop-in\"") < reload_at
    assert 'sshd -T -C "user=$u,host=avra-check,addr=$a"' in text
    assert "root" in text and "CHECK_USERS" in text


def test_tunnel_script_refuses_preexisting_or_foreign_config():
    text = _script("install-tunnel.sh")
    assert '[ -e "$DROPIN" ] && die' in text
    assert '[ -e "$OLD_DROPIN" ] && die' in text
    assert "sshd configuration already mentions avra-tunnel" in text
    assert "systemctl is-active --quiet \"$SSH_UNIT\"" in text
    assert "drop-in must contain exactly one Match block" in text


def test_readme_token_not_echoed_and_tunnel_flags():
    text = (DEPLOY / "README.md").read_text(encoding="utf-8")
    assert "read -rs" in text
    for opt in ("IdentitiesOnly=yes", "StrictHostKeyChecking=yes", "ForwardAgent=no"):
        assert opt in text


# --- make_bundle.py -----------------------------------------------------------


def _load_bundle_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_bundle", DEPLOY / "make_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_make_bundle_writes_verifiable_manifest(tmp_path):
    import hashlib

    mb = _load_bundle_module()
    wheel = tmp_path / "avra-0.0.0-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04fake")
    scope = tmp_path / "s.yaml"
    scope.write_bytes(b"session_name: x\n")
    out = tmp_path / "bundle"
    digest = mb.build(out, wheel, scope)
    lines = (out / "SHA256SUMS").read_bytes().decode("ascii").splitlines()
    names = {line.split("  ", 1)[1] for line in lines}
    assert names == set(mb.DEPLOY_FILES) | {"scope.yaml", wheel.name}
    for line in lines:
        h, name = line.split("  ", 1)
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == h
    assert digest == hashlib.sha256((out / "SHA256SUMS").read_bytes()).hexdigest()
    assert b"\r" not in (out / "SHA256SUMS").read_bytes()


def test_make_bundle_refuses_crlf_and_bad_inputs(tmp_path):
    mb = _load_bundle_module()
    wheel = tmp_path / "avra-0.0.0-py3-none-any.whl"
    wheel.write_bytes(b"PK")
    crlf_scope = tmp_path / "s.yaml"
    crlf_scope.write_bytes(b"a: 1\r\n")
    with pytest.raises(mb.BundleError):
        mb.build(tmp_path / "b1", wheel, crlf_scope)
    good = tmp_path / "g.yaml"
    good.write_bytes(b"a: 1\n")
    with pytest.raises(mb.BundleError):
        mb.build(tmp_path / "b2", tmp_path / "not-a-wheel.zip", good)
    (tmp_path / "b3").mkdir()
    (tmp_path / "b3" / "junk").write_text("x")
    with pytest.raises(mb.BundleError):
        mb.build(tmp_path / "b3", wheel, good)


def _dropin_directives() -> list[str]:
    return [
        line.strip()
        for line in (DEPLOY / "sshd-avra-tunnel.conf").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_sshd_dropin_restrictions():
    lines = set(_dropin_directives())
    for required in (
        "Match User avra-tunnel",
        "AuthenticationMethods publickey",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "AuthorizedKeysFile /var/lib/avra-tunnel/.ssh/authorized_keys",
        "AllowTcpForwarding local",
        "PermitOpen 127.0.0.1:8765",
        "PermitListen none",
        "GatewayPorts no",
        "AllowStreamLocalForwarding no",
        "AllowAgentForwarding no",
        "X11Forwarding no",
        "PermitTTY no",
        "PermitTunnel no",
        "PermitUserRC no",
        "ForceCommand /usr/sbin/nologin",
    ):
        assert required in lines


def test_sshd_dropin_is_one_match_block_with_no_globals():
    directives = _dropin_directives()
    assert directives[0] == "Match User avra-tunnel"  # nothing global before it
    assert sum(d.split()[0] == "Match" for d in directives) == 1  # no "Match all" either
    keywords = [d.split()[0].lower() for d in directives]
    assert len(keywords) == len(set(keywords))  # no duplicated directive


def test_sshd_dropin_has_no_authorizedkeyscommand():
    # "none" isn't treated as unset for this option in OpenSSH 10.5 (M4.4 review).
    assert not any(d.lower().startswith("authorizedkeyscommand") for d in _dropin_directives())


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
@pytest.mark.parametrize("name", ["install.sh", "install-tunnel.sh"])
def test_scripts_parse(name):
    script = (DEPLOY / name).as_posix()
    subprocess.run(["bash", "-n", script], check=True, timeout=30)


# --- rollback failure injection (real bash, the scripts' own rollback lib) --

HARNESS = r"""
set -Eeuo pipefail
PROG=harness
die() { echo "$PROG: $*" >&2; exit 1; }
__LIB__
T=$1; MODE=$2
undo_a() { rm -rf -- "$T/a"; }
undo_b() { if [ "$MODE" = undo_fails ]; then return 1; fi; rm -rf -- "$T/b"; }
undo_c() { rm -rf -- "$T/c"; }
mkdir "$T/a"  # atomic: fails if it exists
on_undo undo_a
mkdir "$T/b"  # atomic: fails if it exists
on_undo undo_b
case "$MODE" in
  fail|undo_fails) false ;;
  die) die "injected" ;;
  int) kill -INT $$; sleep 2 ;;
  unknown_undo) on_undo undo_does_not_exist ;;
esac
mkdir "$T/c"  # atomic: fails if it exists
on_undo undo_c
UNDO=()  # success
"""


def _run_harness(tmp_path, mode, preexisting=()):
    lib = _lib(_script("install.sh"))
    script = tmp_path / "harness.sh"
    script.write_text(HARNESS.replace("__LIB__", lib), encoding="utf-8", newline="\n")
    work = tmp_path / "work"
    work.mkdir()
    for name in preexisting:
        (work / name).mkdir()
        (work / name / "precious.txt").write_text("keep me")
    r = subprocess.run(
        ["bash", script.as_posix(), work.as_posix(), mode],
        capture_output=True, text=True, timeout=30,
    )
    return r, {p.name for p in work.iterdir()}


needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


@needs_bash
@pytest.mark.parametrize("mode,rc", [("fail", 1), ("die", 1), ("int", 130), ("unknown_undo", 70)])
def test_failure_rolls_back_only_what_was_created(tmp_path, mode, rc):
    r, left = _run_harness(tmp_path, mode)
    assert r.returncode == rc, r.stderr
    assert left == set()
    assert "rolling back" in r.stderr


@needs_bash
def test_preexisting_resource_is_never_deleted(tmp_path):
    # "b" already exists: its atomic mkdir fails, so undo_b is never
    # registered — rollback removes only "a" and leaves "b" intact.
    r, left = _run_harness(tmp_path, "ok", preexisting=("b",))
    assert r.returncode != 0
    assert left == {"b"}
    assert (tmp_path / "work" / "b" / "precious.txt").read_text() == "keep me"


@needs_bash
def test_failing_undo_step_does_not_stop_the_rest(tmp_path):
    r, left = _run_harness(tmp_path, "undo_fails")
    assert r.returncode == 1
    assert left == {"b"}  # its undo failed; "a" was still rolled back
    assert "rollback step failed: undo_b" in r.stderr


@needs_bash
def test_success_keeps_everything(tmp_path):
    r, left = _run_harness(tmp_path, "ok")
    assert r.returncode == 0, r.stderr
    assert left == {"a", "b", "c"}
    assert "rolling back" not in r.stderr


def _bundle_inputs(tmp_path):
    wheel = tmp_path / "avra-0.0.0-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04fake")
    scope = tmp_path / "s.yaml"
    scope.write_bytes(b"session_name: x\n")
    return wheel, scope


PUB = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPL avra-runtime\n"


def test_make_bundle_includes_valid_pubkey(tmp_path):
    mb = _load_bundle_module()
    wheel, scope = _bundle_inputs(tmp_path)
    pub = tmp_path / "avra_runtime_ed25519.pub"
    pub.write_bytes(PUB)
    mb.build(tmp_path / "b", wheel, scope, pub)
    assert (tmp_path / "b" / mb.PUBKEY_NAME).read_bytes() == PUB
    assert mb.PUBKEY_NAME in (tmp_path / "b" / "SHA256SUMS").read_text()


@pytest.mark.parametrize(
    "name,content",
    [
        ("avra_runtime_ed25519", PUB),  # not a .pub file name
        ("k.pub", b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"),
        ("k.pub", PUB + PUB),  # two keys
        ("k.pub", b"ssh-rsa AAAAB3NzaC1yc2E avra\n"),  # wrong type
    ],
)
def test_make_bundle_refuses_bad_or_private_key(tmp_path, name, content):
    mb = _load_bundle_module()
    wheel, scope = _bundle_inputs(tmp_path)
    key = tmp_path / name
    key.write_bytes(content)
    with pytest.raises(mb.BundleError):
        mb.build(tmp_path / "b", wheel, scope, key)


@pytest.mark.parametrize(
    "content",
    [b"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n", b"targets: []\nAVRA_RUNNER_TOKEN=abc\n"],
)
def test_make_bundle_refuses_secrets_in_any_file(tmp_path, content):
    mb = _load_bundle_module()
    wheel, _ = _bundle_inputs(tmp_path)
    scope = tmp_path / "s.yaml"
    scope.write_bytes(content)
    with pytest.raises(mb.BundleError, match="secret"):
        mb.build(tmp_path / "b", wheel, scope)


def test_deploy_files_contain_no_secrets():
    mb = _load_bundle_module()
    for name in mb.DEPLOY_FILES:
        mb._refuse_secrets(name, (DEPLOY / name).read_bytes())  # raises on a secret-like pattern


# --- install-tunnel.sh: snapshot/compare logic in real bash, fake sshd -------

SNAPSHOT_HARNESS = r"""
set -Eeuo pipefail
die() { echo "harness: $*" >&2; exit 1; }
STATE=$1
WINDOWS_HOST=192.168.56.1
OTHER_ADDR=203.0.113.10
CHECK_USERS=(kali root)
# Fake sshd -T: output depends on a state file, so a test can "change" the
# effective config between the two snapshots, or make sshd fail.
sshd() {
  case "$(cat "$STATE")" in
    fail) return 1 ;;
    leak) if [ "$*" = "-T -C user=kali,host=avra-check,addr=192.168.56.1" ]; then echo "permittty no"; return 0; fi ;;
  esac
  echo "permittty yes ($*)"
}
__SNAPSHOT__
echo base > "$STATE"
BEFORE=$(snapshot) || die "could not read the effective sshd configuration"
cp "$STATE.next" "$STATE"
AFTER=$(snapshot) || die "could not read the effective sshd configuration"
if [ "$BEFORE" != "$AFTER" ]; then
  diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") >&2 || true
  die "the drop-in changed the effective configuration of other users or global settings"
fi
echo unchanged
"""


def _snapshot_fn() -> str:
    text = _script("install-tunnel.sh")
    start = text.index("snapshot() {")
    end = text.index("\n}\n", start) + 3
    return text[start:end]


@needs_bash
@pytest.mark.parametrize(
    "next_state,rc,needle",
    [("base", 0, "unchanged"), ("leak", 1, "changed the effective configuration"),
     ("fail", 1, "could not read")],
)
def test_snapshot_compare_detects_leaks_and_failures(tmp_path, next_state, rc, needle):
    script = tmp_path / "h.sh"
    script.write_text(SNAPSHOT_HARNESS.replace("__SNAPSHOT__", _snapshot_fn()),
                      encoding="utf-8", newline="\n")
    state = tmp_path / "state"
    (tmp_path / "state.next").write_text(next_state + "\n", encoding="utf-8", newline="\n")
    r = subprocess.run(["bash", script.as_posix(), state.as_posix()],
                       check=False, capture_output=True, text=True, timeout=30)
    assert r.returncode == rc, r.stderr
    assert needle in (r.stdout + r.stderr)


def test_snapshot_covers_global_and_each_user_from_two_addresses():
    fn = _snapshot_fn()
    assert 'echo "### global"' in fn and "sshd -T || return 1" in fn
    assert 'for a in "$WINDOWS_HOST" "$OTHER_ADDR"' in fn
    assert '|| return 1' in fn.split("sshd -T -C")[1]

def test_make_bundle_normalizes_windows_crlf_pubkey(tmp_path):
    mb = _load_bundle_module()
    wheel, scope = _bundle_inputs(tmp_path)
    pub = tmp_path / "avra_runtime_ed25519.pub"
    pub.write_bytes(PUB.replace(b"\n", b"\r\n"))  # as Windows ssh-keygen writes it
    mb.build(tmp_path / "b", wheel, scope, pub)
    assert (tmp_path / "b" / mb.PUBKEY_NAME).read_bytes() == PUB


def test_make_bundle_refused_build_leaves_nothing(tmp_path):
    mb = _load_bundle_module()
    wheel, scope = _bundle_inputs(tmp_path)
    bad = tmp_path / "k.pub"
    bad.write_bytes(b"ssh-rsa AAAA x\n")
    with pytest.raises(mb.BundleError):
        mb.build(tmp_path / "b", wheel, scope, bad)
    assert not (tmp_path / "b").exists()


# --- install-tunnel.sh: effective-settings check (M4.4 stage 4 regression) --
# Stage 4 failed on Kali: OpenSSH 10.5's `sshd -T` prints "AuthenticationMethods
# publickey" (canonical case), the installer grepped for the lower-case form.
# The fixtures are SYNTHETIC `sshd -T`-style output in OpenSSH 10.5p1's canonical form
# (an unrestricted baseline user, and the same baseline with this drop-in applied).
# They were modelled on real 10.5p1 output but contain no host-specific values.

FIXTURES = ROOT / "tests" / "fixtures" / "sshd"
TUNNEL_T = FIXTURES / "openssh-10.5p1-T-avra-tunnel.txt"
KALI_T = FIXTURES / "openssh-10.5p1-T-unrestricted.txt"  # an unrestricted user

CHECK_HARNESS = r"""
set -Eeuo pipefail
AUTH_KEYS=/var/lib/avra-tunnel/.ssh/authorized_keys
RUNNER_ADDR=127.0.0.1:8765
__CHECK__
EFFECTIVE=$(cat "$1")
if ! MISSING=$(check_effective "$EFFECTIVE"); then echo "MISSING: $MISSING"; exit 3; fi
echo "ALL PRESENT"
"""


def _check_block() -> str:
    text = _script("install-tunnel.sh")
    start = text.index("# --- effective-settings check (begin) ---")
    end = text.index("# --- effective-settings check (end) ---")
    return text[start:end]


def _run_check(tmp_path, effective: str):
    script = tmp_path / "check.sh"
    script.write_text(CHECK_HARNESS.replace("__CHECK__", _check_block()),
                      encoding="utf-8", newline="\n")
    data = tmp_path / "effective.txt"
    data.write_text(effective, encoding="utf-8", newline="\n")
    return subprocess.run(["bash", script.as_posix(), data.as_posix()],
                          check=False, capture_output=True, text=True, timeout=30)


def test_fixture_is_canonical_case_output():
    lines = TUNNEL_T.read_text(encoding="utf-8").splitlines()
    assert "AuthenticationMethods publickey" in lines
    assert "authenticationmethods publickey" not in lines  # the stage-4 trap


def test_old_lowercase_grep_fails_on_openssh_10_5_output():
    # Documents the root cause: the previous check could never pass on 10.5.
    lines = TUNNEL_T.read_text(encoding="utf-8").splitlines()
    assert "authenticationmethods publickey" not in lines


@needs_bash
def test_check_passes_on_openssh_10_5_canonical_output(tmp_path):
    r = _run_check(tmp_path, TUNNEL_T.read_text(encoding="utf-8"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ALL PRESENT" in r.stdout


@needs_bash
def test_check_passes_on_lowercase_output_of_older_openssh(tmp_path):
    text = TUNNEL_T.read_text(encoding="utf-8")
    lowered = "\n".join(
        (ln.split(" ", 1)[0].lower() + (" " + ln.split(" ", 1)[1] if " " in ln else ""))
        for ln in text.splitlines()
    ) + "\n"
    r = _run_check(tmp_path, lowered)
    assert r.returncode == 0, r.stdout + r.stderr


@needs_bash
def test_check_fails_for_kali_user_output(tmp_path):
    # An unrestricted user's config must never satisfy the tunnel checks.
    r = _run_check(tmp_path, KALI_T.read_text(encoding="utf-8"))
    assert r.returncode == 3
    assert "MISSING: authenticationmethods publickey" in r.stdout


@needs_bash
@pytest.mark.parametrize(
    "old,new",
    [
        ("PermitOpen 127.0.0.1:8765", "PermitOpen any"),  # wider value
        ("PermitOpen 127.0.0.1:8765", "PermitOpen 127.0.0.1:8765 127.0.0.1:22"),
        ("ForceCommand /usr/sbin/nologin", "ForceCommand none"),
        ("ForceCommand /usr/sbin/nologin", "ForceCommand /USR/SBIN/NOLOGIN"),  # values exact
        ("AllowTcpForwarding local", "AllowTcpForwarding yes"),
        ("PermitTTY no", "PermitTTY yes"),
        ("AuthenticationMethods publickey", "AuthenticationMethods any"),
        ("PermitOpen 127.0.0.1:8765", "PermitOpen 127.0.0.1x8765"),  # no regex wildcards
    ],
)
def test_check_fails_on_weaker_or_different_value(tmp_path, old, new):
    text = TUNNEL_T.read_text(encoding="utf-8")
    assert old in text.splitlines()
    r = _run_check(tmp_path, text.replace(old + "\n", new + "\n"))
    assert r.returncode == 3, r.stdout
    assert "MISSING:" in r.stdout


@needs_bash
def test_check_fails_when_setting_absent(tmp_path):
    text = TUNNEL_T.read_text(encoding="utf-8").replace("PermitListen none\n", "")
    r = _run_check(tmp_path, text)
    assert r.returncode == 3
    assert "MISSING: permitlisten none" in r.stdout


def test_kali_fixture_shows_dropin_did_not_leak():
    lines = KALI_T.read_text(encoding="utf-8").splitlines()
    for keep in ("X11Forwarding yes", "PermitTTY yes", "AllowTcpForwarding yes",
                 "ForceCommand none"):
        assert keep in lines


@pytest.mark.parametrize(
    "rel",
    ["runner/deploy/README.md", "README.md", "runner/deploy/install-tunnel.sh",
     "runner/deploy/sshd-avra-tunnel.conf"],
)
def test_docs_and_deploy_files_have_no_control_characters(rel):
    # Owner-facing commands are copy-pasted; a stray BEL/VT from a mangled
    # backslash (e.g. "\a" in "dist\avra-…") silently corrupts them.
    data = (ROOT / rel).read_bytes()
    assert not any(b < 32 and b not in (9, 10) for b in data)
