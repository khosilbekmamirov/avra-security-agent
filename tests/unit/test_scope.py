from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from avra.policy.scope import ScopeChecker, ScopeError, load_scope
from avra.schemas.scope import ActionTier, Scope


def _future_iso(days: int = 30) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


def _past_iso(days: int = 1) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def _write_scope(tmp_path: Path, data: dict, name: str = "scope.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _valid_scope_dict(expires_at: str | None = None) -> dict:
    return {
        "session_name": "test-session",
        "expires_at": expires_at or _future_iso(),
        "targets": [
            {
                "host": "192.168.56.10",
                "description": "Juice Shop",
                "ports": [3000],
                "allowed_tiers": ["passive", "active-safe"],
                "allowed_tools": ["http_probe"],
            }
        ],
    }


def test_load_valid_scope(tmp_path: Path) -> None:
    path = _write_scope(tmp_path, _valid_scope_dict())
    scope = load_scope(path)
    assert scope.session_name == "test-session"
    assert len(scope.targets) == 1
    assert scope.targets[0].host == "192.168.56.10"
    assert not scope.is_expired


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "nope.yaml")


def test_empty_file_raises(tmp_path: Path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)


def test_invalid_yaml_raises(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("targets: [this is not: valid: yaml", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)


def test_no_targets_rejected(tmp_path: Path) -> None:
    data = _valid_scope_dict()
    data["targets"] = []
    path = _write_scope(tmp_path, data)
    with pytest.raises(ScopeError):
        load_scope(path)


def test_destructive_tier_rejected(tmp_path: Path) -> None:
    data = _valid_scope_dict()
    data["targets"][0]["allowed_tiers"].append("destructive")
    path = _write_scope(tmp_path, data)
    with pytest.raises(ScopeError):
        load_scope(path)


def test_invalid_port_rejected(tmp_path: Path) -> None:
    data = _valid_scope_dict()
    data["targets"][0]["ports"] = [70000]
    path = _write_scope(tmp_path, data)
    with pytest.raises(ScopeError):
        load_scope(path)


def test_expired_scope_rejected(tmp_path: Path) -> None:
    data = _valid_scope_dict(expires_at=_past_iso())
    path = _write_scope(tmp_path, data)
    with pytest.raises(ScopeError):
        load_scope(path)


def test_checker_allows_in_scope_request() -> None:
    scope = Scope.model_validate(_valid_scope_dict())
    checker = ScopeChecker(scope)
    decision = checker.check(
        host="192.168.56.10", port=3000, tool="http_probe", tier=ActionTier.PASSIVE
    )
    assert decision.allowed


def test_checker_denies_wrong_host() -> None:
    scope = Scope.model_validate(_valid_scope_dict())
    checker = ScopeChecker(scope)
    decision = checker.check(
        host="10.0.0.1", port=3000, tool="http_probe", tier=ActionTier.PASSIVE
    )
    assert not decision.allowed


def test_checker_denies_wrong_port() -> None:
    scope = Scope.model_validate(_valid_scope_dict())
    checker = ScopeChecker(scope)
    decision = checker.check(
        host="192.168.56.10", port=9999, tool="http_probe", tier=ActionTier.PASSIVE
    )
    assert not decision.allowed


def test_checker_denies_disallowed_tier() -> None:
    scope = Scope.model_validate(_valid_scope_dict())
    checker = ScopeChecker(scope)
    decision = checker.check(
        host="192.168.56.10", port=3000, tool="http_probe", tier=ActionTier.INTRUSIVE
    )
    assert not decision.allowed


def test_checker_denies_disallowed_tool() -> None:
    scope = Scope.model_validate(_valid_scope_dict())
    checker = ScopeChecker(scope)
    decision = checker.check(
        host="192.168.56.10", port=3000, tool="nmap_connect_scan", tier=ActionTier.PASSIVE
    )
    assert not decision.allowed
