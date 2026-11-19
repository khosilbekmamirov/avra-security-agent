"""Effective-configuration tests for the avra-tunnel sshd drop-in (M4.4).

These run the real ``sshd -T`` (test mode: parses and prints the effective
configuration, opens no sockets, needs no root) against a throwaway copy of
a Kali-like ``sshd_config`` in ``tmp_path``. They prove, with OpenSSH's own
parser rather than our reading of it, that:

- the drop-in gives avra-tunnel every required restriction;
- the drop-in changes nothing for any other user, nor the global config
  (the same "before/after must be identical" check install-tunnel.sh does);
- the check would catch a drop-in that leaks a global directive.

They model Kali's Linux OpenSSH (PAM etc.), so they run only on Linux (Kali,
M4.5) and skip elsewhere - including a Windows host that has OpenSSH Server
installed, whose sshd rejects Linux-only options such as UsePAM.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DROPIN = ROOT / "runner" / "deploy" / "sshd-avra-tunnel.conf"


def _find_sshd() -> str | None:
    for candidate in ("/usr/sbin/sshd", shutil.which("sshd")):
        if candidate and Path(candidate).is_file():
            return str(Path(candidate).resolve())
    return None


SSHD = _find_sshd()
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or SSHD is None
    or shutil.which("ssh-keygen") is None,
    reason="needs Linux OpenSSH sshd + ssh-keygen (runs on Kali in M4.5)",
)

# Mirrors the directives found on the lab Kali VM during M4.4 stage 0:
# Include first, then global settings that the drop-in must not disturb.
MAIN_CONFIG = """\
Include {dropins}/*.conf
KbdInteractiveAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_* COLORTERM NO_COLOR
Subsystem sftp /usr/lib/openssh/sftp-server
HostKey {hostkey}
PidFile none
"""
USERDB_DROPIN = """\
AuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u
AuthorizedKeysCommandUser root
"""
REQUIRED = [
    "authenticationmethods publickey",
    "pubkeyauthentication yes",
    "passwordauthentication no",
    "kbdinteractiveauthentication no",
    "authorizedkeysfile /var/lib/avra-tunnel/.ssh/authorized_keys",
    "allowtcpforwarding local",
    "permitopen 127.0.0.1:8765",
    "permitlisten none",
    "gatewayports no",
    "allowstreamlocalforwarding no",
    "allowagentforwarding no",
    "x11forwarding no",
    "permittty no",
    "permittunnel no",
    "permituserrc no",
    "forcecommand /usr/sbin/nologin",
]
OTHER_USERS = ["kali", "root"]
ADDRS = ["192.168.56.1", "203.0.113.10"]


def _lab(tmp_path: Path, with_tunnel: bool, extra_dropin: str | None = None) -> Path:
    d = tmp_path / ("with" if with_tunnel else "without")
    dropins = d / "sshd_config.d"
    dropins.mkdir(parents=True)
    hostkey = d / "hostkey"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hostkey)],
        check=True, timeout=30,
    )
    (d / "sshd_config").write_text(
        MAIN_CONFIG.format(dropins=dropins, hostkey=hostkey), encoding="utf-8"
    )
    (dropins / "20-systemd-userdb.conf").write_text(USERDB_DROPIN, encoding="utf-8")
    if with_tunnel:
        shutil.copyfile(DROPIN, dropins / "10-avra-tunnel.conf")
    if extra_dropin is not None:
        (dropins / "10-avra-tunnel.conf").write_text(extra_dropin, encoding="utf-8")
    return d / "sshd_config"


def _sshd_T(config: Path, spec: str | None = None) -> str:
    cmd = [SSHD, "-T", "-f", str(config)]
    if spec:
        cmd += ["-C", spec]
    r = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    # Keywords are lower-cased (OpenSSH 10.5 prints canonical case, older
    # releases lower case — same normalization as install-tunnel.sh); values
    # stay exact. The HostKey line names the temp dir, which differs between
    # the two copies; everything else must match exactly.
    lines = []
    for ln in r.stdout.splitlines():
        key, sep, value = ln.partition(" ")
        lines.append(key.lower() + sep + value)
    return "\n".join(ln for ln in lines if not ln.startswith("hostkey "))


def _snapshot(config: Path) -> dict[str, str]:
    snap = {"global": _sshd_T(config)}
    for user in OTHER_USERS:
        for addr in ADDRS:
            snap[f"{user}@{addr}"] = _sshd_T(config, f"user={user},host=avra-check,addr={addr}")
    return snap


def test_syntax_ok_with_dropin(tmp_path):
    config = _lab(tmp_path, with_tunnel=True)
    r = subprocess.run([SSHD, "-t", "-f", str(config)], check=False, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("addr", ADDRS)
def test_tunnel_user_gets_every_restriction(tmp_path, addr):
    config = _lab(tmp_path, with_tunnel=True)
    effective = set(_sshd_T(config, f"user=avra-tunnel,host=avra-check,addr={addr}").splitlines())
    missing = [want for want in REQUIRED if want not in effective]
    assert not missing


def test_other_users_and_global_unchanged(tmp_path):
    before = _snapshot(_lab(tmp_path, with_tunnel=False))
    after = _snapshot(_lab(tmp_path, with_tunnel=True))
    for key in before:
        assert before[key] == after[key], f"drop-in changed effective config for {key}"


def test_kali_keeps_its_own_settings(tmp_path):
    effective = set(
        _sshd_T(_lab(tmp_path, with_tunnel=True), "user=kali,host=avra-check,addr=192.168.56.1")
        .splitlines()
    )
    assert "x11forwarding yes" in effective
    assert "allowtcpforwarding yes" in effective
    assert "forcecommand none" in effective
    assert "permittty yes" in effective


def test_leaking_dropin_is_detected(tmp_path):
    """Negative control: a drop-in with a global directive before its Match
    block must show up as a difference — the check is not vacuous."""
    leaky = "PermitTTY no\n" + DROPIN.read_text(encoding="utf-8")
    # Two separate labs (Stage 6: on Linux the shared folder made the second
    # _lab() fail with FileExistsError before anything was compared).
    before = _snapshot(_lab(tmp_path / "before", with_tunnel=False))
    after = _snapshot(_lab(tmp_path / "after", with_tunnel=False, extra_dropin=leaky))
    assert before != after


def test_match_block_does_not_extend_past_its_file(tmp_path):
    """OpenSSH restores the Match state after each included file, so the
    main file's global lines after the Include stay global (kali keeps
    X11Forwarding yes even though the drop-in's last Match is avra-tunnel)."""
    effective = _sshd_T(_lab(tmp_path, with_tunnel=True), "user=kali,host=avra-check,addr=192.168.56.1")
    assert "x11forwarding yes" in effective.splitlines()
