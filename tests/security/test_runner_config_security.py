"""RunnerConfig — fail-closed validation (ADR 0003, M3.1)."""

from __future__ import annotations

import os

import pytest

from avra.runner.config import RunnerConfigError, load_runner_config
from avra.storage.audit import AuditLog
from tests.unit.test_runner_config import PYTHON, TOKEN, make_env

POSIX = os.name == "posix"
PY_DIR_WRITABLE = POSIX and os.access(os.path.dirname(PYTHON), os.W_OK)


def _rejects(env):
    with pytest.raises(RunnerConfigError) as info:
        load_runner_config(env)
    msg = str(info.value)
    assert TOKEN not in msg  # never leak the secret
    return msg


@pytest.mark.parametrize(
    "var",
    [
        "AVRA_RUNNER_SCOPE_FILE",
        "AVRA_RUNNER_TOKEN_FILE",
        "AVRA_RUNNER_AUDIT_LOG",
        "AVRA_RUNNER_BIND_HOST",
        "AVRA_RUNNER_EXEC_NMAP",
        "AVRA_RUNNER_EXEC_HTTP_PROBE",  # ADR 0007: fails closed too
    ],
)
@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_required_setting_fails_closed(tmp_path, var, value):
    _rejects(make_env(tmp_path, **{var: value}))


@pytest.mark.parametrize(
    "var",
    [
        "AVRA_RUNNER_SCOPE_FILE",
        "AVRA_RUNNER_TOKEN_FILE",
        "AVRA_RUNNER_AUDIT_LOG",
        "AVRA_RUNNER_EXEC_NMAP",
        "AVRA_RUNNER_EXEC_HTTP_PROBE",  # ADR 0007: fails closed too
    ],
)
def test_relative_paths_rejected(tmp_path, var):
    _rejects(make_env(tmp_path, **{var: "relative/file"}))


# --- Scope ---------------------------------------------------------------


def test_invalid_scope_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("targets: []\n", encoding="utf-8")
    _rejects(make_env(tmp_path, AVRA_RUNNER_SCOPE_FILE=str(bad)))


# --- Token ---------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "",
        "short-token",
        "x" * 31,
        "x" * 513,
        "has whitespace " + "x" * 40,
        "tab\t" + "x" * 40,
        "line1\n" + "x" * 40,
    ],
)
def test_bad_token_content_rejected(tmp_path, content):
    env = make_env(tmp_path)
    path = env["AVRA_RUNNER_TOKEN_FILE"]
    with open(path, "w", encoding="ascii", newline="") as fh:
        fh.write(content)
    os.chmod(path, 0o600)
    _rejects(env)


def test_non_ascii_token_rejected(tmp_path):
    env = make_env(tmp_path)
    with open(env["AVRA_RUNNER_TOKEN_FILE"], "wb") as fh:
        fh.write("ü".encode() * 40)
    _rejects(env)


def test_missing_token_file_rejected(tmp_path):
    _rejects(make_env(tmp_path, AVRA_RUNNER_TOKEN_FILE=str(tmp_path / "nope")))


def test_token_path_is_directory_rejected(tmp_path):
    _rejects(make_env(tmp_path, AVRA_RUNNER_TOKEN_FILE=str(tmp_path)))


@pytest.mark.skipif(not POSIX, reason="POSIX permission model")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_token_file_permissions_too_open(tmp_path, mode):
    env = make_env(tmp_path)
    os.chmod(env["AVRA_RUNNER_TOKEN_FILE"], mode)
    msg = _rejects(env)
    assert "permissions" in msg


@pytest.mark.skipif(not POSIX, reason="symlinks need privileges on Windows")
def test_token_symlink_rejected(tmp_path):
    env = make_env(tmp_path)
    link = tmp_path / "token-link"
    link.symlink_to(env["AVRA_RUNNER_TOKEN_FILE"])
    _rejects(make_env(tmp_path, AVRA_RUNNER_TOKEN_FILE=str(link)))


def test_oversized_token_file_rejected_with_bounded_read(tmp_path):
    env = make_env(tmp_path)
    with open(env["AVRA_RUNNER_TOKEN_FILE"], "wb") as fh:
        fh.write(b"x" * 5_000_000)
    os.chmod(env["AVRA_RUNNER_TOKEN_FILE"], 0o600)
    _rejects(env)


@pytest.mark.skipif(not POSIX, reason="FIFOs are POSIX-only")
def test_fifo_token_path_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "token-fifo"
    os.mkfifo(fifo, 0o600)
    _rejects(make_env(tmp_path, AVRA_RUNNER_TOKEN_FILE=str(fifo)))


@pytest.mark.skipif(not POSIX, reason="symlinks need privileges on Windows")
def test_symlink_to_valid_token_rejected_at_open(tmp_path, monkeypatch):
    # Even if a pre-check were fooled, O_NOFOLLOW refuses the link itself.
    env = make_env(tmp_path)
    link = tmp_path / "swapped"
    link.symlink_to(env["AVRA_RUNNER_TOKEN_FILE"])
    msg = _rejects(make_env(tmp_path, AVRA_RUNNER_TOKEN_FILE=str(link)))
    assert "symlink" in msg


def test_token_never_shown_in_repr(tmp_path):
    from avra.runner.config import BearerToken

    tok = BearerToken(TOKEN)
    assert TOKEN not in repr(tok) and TOKEN not in str(tok)
    assert not tok.matches("ü" * 40)  # non-ASCII candidate never matches


def test_oversized_candidate_rejected_before_hashing(monkeypatch):
    import avra.runner.config as config

    tok = config.BearerToken(TOKEN)
    hashed = []
    real_sha = config.hashlib.sha256
    monkeypatch.setattr(
        config.hashlib, "sha256", lambda data=b"": hashed.append(len(data)) or real_sha(data)
    )
    assert not tok.matches("x" * (config.MAX_TOKEN_CHARS + 1))
    assert not tok.matches(b"x" * 1_000_000)
    assert not tok.matches(None)  # type: ignore[arg-type]
    assert hashed == []


# --- Audit path ----------------------------------------------------------


def test_audit_parent_missing_rejected(tmp_path):
    _rejects(make_env(tmp_path, AVRA_RUNNER_AUDIT_LOG=str(tmp_path / "no" / "a.jsonl")))


def test_audit_path_is_directory_rejected(tmp_path):
    env = make_env(tmp_path)
    os.makedirs(env["AVRA_RUNNER_AUDIT_LOG"])
    _rejects(env)


def test_tampered_existing_audit_log_rejected(tmp_path):
    env = make_env(tmp_path)
    log = AuditLog(env["AVRA_RUNNER_AUDIT_LOG"])
    log.record("a", {"x": 1})
    log.record("b", {"x": 2})
    path = env["AVRA_RUNNER_AUDIT_LOG"]
    text = open(path, encoding="utf-8").read().replace('"x": 1', '"x": 9')
    open(path, "w", encoding="utf-8").write(text)
    msg = _rejects(env)
    assert "verification" in msg


def test_garbage_audit_log_rejected(tmp_path):
    env = make_env(tmp_path)
    open(env["AVRA_RUNNER_AUDIT_LOG"], "w", encoding="utf-8").write("not json\n")
    _rejects(env)


@pytest.mark.skipif(not POSIX, reason="POSIX permission model")
def test_world_writable_audit_dir_rejected(tmp_path):
    env = make_env(tmp_path)
    os.chmod(os.path.dirname(env["AVRA_RUNNER_AUDIT_LOG"]), 0o777)
    _rejects(env)


# --- Bind address and port -----------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # wildcard
        "::",  # IPv6 wildcard
        "::1",
        "localhost",
        "kali.local",
        "192.168.56.0/24",
        "192.168.056.104",
        " 192.168.56.104",
        "224.0.0.1",
        "255.255.255.255",
        "169.254.1.1",
        "240.0.0.1",
    ],
)
def test_bad_bind_host_rejected(tmp_path, host):
    _rejects(make_env(tmp_path, AVRA_RUNNER_BIND_HOST=host))


@pytest.mark.parametrize(
    "port", ["0", "80", "1023", "65536", "70000", "abc", "08765", "8765.0", "-1", "８７６５"]
)
def test_bad_port_rejected(tmp_path, port):
    _rejects(make_env(tmp_path, AVRA_RUNNER_PORT=port))


# --- Executables ---------------------------------------------------------


def test_missing_executable_rejected(tmp_path):
    _rejects(make_env(tmp_path, AVRA_RUNNER_EXEC_NMAP=str(tmp_path / "nmap")))


def test_directory_as_executable_rejected(tmp_path):
    _rejects(make_env(tmp_path, AVRA_RUNNER_EXEC_NMAP=str(tmp_path)))


@pytest.mark.skipif(not POSIX, reason="POSIX permission model")
def test_writable_executable_rejected(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(fake, 0o755)  # owned + writable by the Runner user
    msg = _rejects(make_env(tmp_path, AVRA_RUNNER_EXEC_NMAP=str(fake)))
    assert "writable" in msg


@pytest.mark.skipif(not POSIX, reason="POSIX permission model")
def test_non_executable_file_rejected(tmp_path):
    fake = tmp_path / "nmap"
    fake.write_text("x", encoding="utf-8")
    os.chmod(fake, 0o644)
    _rejects(make_env(tmp_path, AVRA_RUNNER_EXEC_NMAP=str(fake)))
