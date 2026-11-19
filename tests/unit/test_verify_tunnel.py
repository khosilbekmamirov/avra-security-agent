"""Unit tests for runner/deploy/verify_tunnel.py's log classifier (M4.4).

The live checks need the lab; these pin down how an ``ssh -v`` log is
turned into the four layers (auth / listener / request / verdict), using
log lines in the exact formats OpenSSH's client prints. The key property:
a local listener alone, or a forward that was never triggered, must never
be reported as "allowed" or "prohibited".
"""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "verify_tunnel", ROOT / "runner" / "deploy" / "verify_tunnel.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up by name
    spec.loader.exec_module(mod)
    return mod


vt = _load()

AUTH = 'debug1: Authenticated to 192.168.56.104 ([192.168.56.104]:22) using "publickey".\n'
LISTEN = (
    "debug1: Local connections to 127.0.0.1:50001 forwarded to remote address 127.0.0.1:22\n"
    "debug1: Local forwarding listening on 127.0.0.1 port 50001.\n"
)
REQ = "debug1: Connection to port 50001 forwarding to 127.0.0.1 port 22 requested.\n"
PROHIBITED = "channel 2: open failed: administratively prohibited: open failed\n"
REFUSED = "channel 2: open failed: connect failed: Connection refused\n"
DENIED = "kali@192.168.56.104: Permission denied (publickey).\n"
REMOTE = "Error: remote port forwarding failed for listen port 18765\n"


def test_prohibited_after_real_request():
    layers = vt.classify(AUTH + LISTEN + REQ + PROHIBITED, triggered=True)
    assert layers.auth is vt.Auth.OK
    assert layers.listener and layers.requested
    assert layers.verdict is vt.Verdict.PROHIBITED


def test_allowed_but_backend_down_is_distinct_from_prohibited():
    layers = vt.classify(AUTH + LISTEN + REQ + REFUSED, triggered=True)
    assert layers.verdict is vt.Verdict.ALLOWED_BACKEND_DOWN


def test_allowed_backend_up_needs_a_real_request():
    assert vt.classify(AUTH + LISTEN + REQ, triggered=True).verdict is vt.Verdict.ALLOWED_BACKEND_UP


@pytest.mark.parametrize("triggered", [True, False])
def test_listener_alone_proves_nothing(triggered):
    # Listener up but the request line never appeared: inconclusive, never "allowed".
    layers = vt.classify(AUTH + LISTEN, triggered=triggered)
    assert layers.listener is True
    assert layers.requested is False
    assert layers.verdict is vt.Verdict.NOT_REQUESTED


def test_untriggered_forward_is_not_allowed():
    layers = vt.classify(AUTH + LISTEN + REQ, triggered=False)
    assert layers.verdict is vt.Verdict.NOT_REQUESTED


def test_auth_failure_is_reported_as_auth_layer():
    layers = vt.classify(DENIED, triggered=False)
    assert layers.auth is vt.Auth.DENIED
    assert layers.verdict is vt.Verdict.NOT_REQUESTED


def test_remote_forward_denied():
    layers = vt.classify(AUTH + REMOTE, triggered=False)
    assert layers.verdict is vt.Verdict.REMOTE_FORWARD_DENIED


def test_unknown_open_failure_is_not_guessed():
    log = AUTH + LISTEN + REQ + "channel 2: open failed: resource shortage: no more sessions\n"
    assert vt.classify(log, triggered=True).verdict is vt.Verdict.UNKNOWN


def test_forward_check_requires_auth_and_request():
    layers = vt.classify(LISTEN + PROHIBITED, triggered=True)  # no auth line, no request line
    res = vt._forward_check("x", layers, {vt.Verdict.PROHIBITED})
    assert res.passed is False


def test_forward_check_passes_on_expected_verdict():
    layers = vt.classify(AUTH + LISTEN + REQ + PROHIBITED, triggered=True)
    assert vt._forward_check("x", layers, {vt.Verdict.PROHIBITED}).passed is True


def test_evidence_contains_only_relevant_lines():
    layers = vt.classify("debug1: noise\n" + AUTH + REQ + PROHIBITED, triggered=True)
    assert all("noise" not in ln for ln in layers.evidence)
    assert len(layers.evidence) == 3


def test_socks5_connect_request_bytes():
    assert vt.socks5_connect_request("10.66.7.103", 3000) == (
        b"\x05\x01\x00\x01" + socket.inet_aton("10.66.7.103") + b"\x0b\xb8"
    )


def test_tunnel_args_pin_key_and_disable_extras():
    args = vt.tunnel_args(Path("k"))
    joined = " ".join(args)
    for opt in ("BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none",
                "StrictHostKeyChecking=yes", "ForwardAgent=no", "ExitOnForwardFailure=yes"):
        assert opt in joined
    assert args[:2] == ["-F", "none"]
    assert "ExitOnForwardFailure=yes" not in " ".join(vt.tunnel_args(Path("k"), batch_only=True))


def test_checks_cover_required_cases():
    src = (ROOT / "runner" / "deploy" / "verify_tunnel.py").read_text(encoding="utf-8")
    body = src[src.index("def all_checks"):src.index("def main")]
    for case in ("check_dev_ssh", "check_allowed", "127.0.0.1:22", "JUICE_SHOP",
                 "localhost:", "[::1]:", "check_unix_socket", "check_socks",
                 "check_reverse", "check_shell", "check_pty", "check_sftp",
                 "check_runtime_key_not_for_kali", "check_bridged"):
        assert case in body


# --- M4.5 live findings -------------------------------------------------------
# On OpenSSH 10.5 a REFUSED direct-streamlocal forward reaches the client as
# the generic "connect failed: open failed" (server log: "refused streamlocal
# port forward"), identical to a failed connect to the path.

GENERIC = "channel 1: open failed: connect failed: open failed\n"
UNIX_REQ = "debug1: Connection to port 50001 forwarding to /var/run/docker.sock port -2 requested.\n"


def test_generic_open_failed_is_its_own_verdict():
    layers = vt.classify(AUTH + LISTEN + UNIX_REQ + GENERIC, triggered=True)
    assert layers.verdict is vt.Verdict.GENERIC_OPEN_FAILED


def test_generic_open_failed_never_counts_as_allowed():
    layers = vt.classify(AUTH + LISTEN + REQ + GENERIC, triggered=True)
    res = vt._forward_check(
        "x", layers, {vt.Verdict.ALLOWED_BACKEND_DOWN, vt.Verdict.ALLOWED_BACKEND_UP}
    )
    assert res.passed is False


def test_tcp_connection_refused_still_allowed_backend_down():
    assert vt.classify(AUTH + LISTEN + REQ + REFUSED, triggered=True).verdict is (
        vt.Verdict.ALLOWED_BACKEND_DOWN
    )


def test_result_status_values():
    assert vt.Result("a", True, "").status == "PASS"
    assert vt.Result("a", False, "").status == "FAIL"
    assert vt.Result("a", False, "", inconclusive=True).status == "INCONCLUSIVE"
