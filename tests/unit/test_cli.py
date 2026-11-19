from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from avra.cli.main import app

runner = CliRunner()


def _write_scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "session_name": "cli-test",
                "expires_at": "2099-01-01T00:00:00Z",
                "targets": [
                    {
                        "host": "192.168.56.10",
                        "ports": [3000],
                        "allowed_tiers": ["passive"],
                        "allowed_tools": ["http_probe"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_check_scope_valid(tmp_path: Path) -> None:
    scope_path = _write_scope(tmp_path)
    result = runner.invoke(app, ["check-scope", str(scope_path)])
    assert result.exit_code == 0
    assert "Valid" in result.stdout


def test_check_scope_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["check-scope", str(tmp_path / "nope.yaml")])
    assert result.exit_code != 0


def test_session_new_and_show(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    scope_path = _write_scope(tmp_path)

    new_result = runner.invoke(
        app, ["session", "new", "--scope", str(scope_path), "--name", "demo"]
    )
    assert new_result.exit_code == 0, new_result.stdout
    assert "created" in new_result.stdout

    line = next(l for l in new_result.stdout.splitlines() if l.startswith("Session "))
    session_id = line.split()[1]

    show_result = runner.invoke(app, ["session", "show", session_id])
    assert show_result.exit_code == 0, show_result.stdout
    assert "session_created" in show_result.stdout
    assert "Chain integrity: OK" in show_result.stdout


def test_session_show_unknown_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AVRA_DATA_DIR", str(tmp_path / "data"))
    result = runner.invoke(app, ["session", "show", "does-not-exist"])
    assert result.exit_code != 0


def test_kill_status_on_a_fresh_machine_is_disengaged() -> None:
    # The placeholder is gone (M8.7 Stage 3); full coverage in test_killswitch.py.
    result = runner.invoke(app, ["kill", "--status"])
    assert result.exit_code == 0 and "Kill switch: DISENGAGED" in result.output
