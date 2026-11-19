"""Suite-wide isolation (M8.7 Stage 3, ADR 0012).

Every test gets its own AVRA state directory, so no test can read, create or
change the real ``%LOCALAPPDATA%\\AVRA`` (kill-switch latch, control audit,
anchor keys). Tests that need a specific location set AVRA_STATE_DIR again
in their own fixtures (later monkeypatches win). Subprocesses inherit it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

REAL_STATE_DIR = Path(os.environ.get("LOCALAPPDATA", "/nonexistent")) / "AVRA"


def real_state_snapshot() -> dict[str, tuple[int, int]]:
    """Path -> (size, mtime_ns) of everything in the REAL state dir. It may
    legitimately exist (created by real CLI use, e.g. the M8.7 Stage 7 live
    scan); what the suite must never do is create or change anything in it."""
    if not REAL_STATE_DIR.exists():
        return {}
    return {str(p.relative_to(REAL_STATE_DIR)): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in sorted(REAL_STATE_DIR.rglob("*"))}


# Taken when pytest imports this file, i.e. before any test runs.
REAL_STATE_AT_START = real_state_snapshot()


@pytest.fixture
def real_state_baseline():
    """(snapshot taken before any test ran, function to take one now)."""
    return REAL_STATE_AT_START, real_state_snapshot


@pytest.fixture(scope="session", autouse=True)
def _real_state_dir_untouched_by_suite():
    yield
    assert real_state_snapshot() == REAL_STATE_AT_START, \
        "the test suite created or changed files in the real %LOCALAPPDATA%\\AVRA"


@pytest.fixture(autouse=True)
def _isolated_avra_state(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("AVRA_STATE_DIR", str(tmp_path_factory.mktemp("avra-state")))


@pytest.fixture(autouse=True)
def _no_real_runner_access(monkeypatch):
    """M8.7 Stage 5: no test may read the real Runner token or start a real
    ssh tunnel to Kali - e.g. through `avra kill`'s remote emergency stop.
    The environment token wins over .env in ``load_token``; tests that need
    a tunnel inject their own ``popen``/factories, which stay unaffected."""
    from avra.runner_client import tunnel

    monkeypatch.setenv("AVRA_RUNNER_TOKEN", "test-only-runner-token-" + "x" * 24)

    def refuse(argv):
        raise tunnel.TunnelError("real ssh is disabled in the test suite")

    monkeypatch.setattr(tunnel, "_default_popen", refuse)
