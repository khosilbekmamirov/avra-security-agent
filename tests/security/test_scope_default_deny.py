"""Regression: empty/omitted ``ports`` or ``allowed_tools`` must never
broaden authorization (Phase 1 ScopeChecker fix)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from avra.cli.main import app
from avra.policy.scope import ScopeChecker, ScopeError, load_scope
from avra.schemas.scope import ActionTier, Scope, Target

VALID = {
    "session_name": "t",
    "expires_at": "2099-01-01T00:00:00Z",
    "targets": [
        {
            "host": "10.66.7.103",
            "ports": [3000],
            "allowed_tiers": ["passive", "active-safe"],
            "allowed_tools": ["http_probe"],
        }
    ],
}


def _variant(field, value):
    data = copy.deepcopy(VALID)
    if value is _OMIT:
        del data["targets"][0][field]
    else:
        data["targets"][0][field] = value
    return data


_OMIT = object()

BAD_VARIANTS = [
    ("ports", []),
    ("ports", _OMIT),
    ("allowed_tools", []),
    ("allowed_tools", _OMIT),
    ("allowed_tools", [""]),
    ("allowed_tools", ["  "]),
]


@pytest.mark.parametrize("field,value", BAD_VARIANTS)
def test_schema_rejects_empty_or_missing(field, value):
    with pytest.raises(ValidationError):
        Scope.model_validate(_variant(field, value))


@pytest.mark.parametrize("field,value", BAD_VARIANTS)
def test_load_scope_rejects_empty_or_missing(tmp_path: Path, field, value):
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump(_variant(field, value)), encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(path)


@pytest.mark.parametrize("field", ["ports", "allowed_tools"])
def test_cli_check_scope_rejects_empty_list(tmp_path: Path, field):
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump(_variant(field, [])), encoding="utf-8")
    result = CliRunner().invoke(app, ["check-scope", str(path)])
    assert result.exit_code != 0


def _unvalidated_scope(ports, tools):
    """A Scope that bypassed validation — ScopeChecker must still deny."""
    target = Target.model_construct(
        host="10.66.7.103",
        description="",
        ports=ports,
        allowed_tiers=[ActionTier.PASSIVE, ActionTier.ACTIVE_SAFE],
        allowed_tools=tools,
    )
    return Scope.model_construct(
        session_name="t",
        expires_at=Scope.model_validate(VALID).expires_at,
        targets=[target],
    )


@pytest.mark.parametrize(
    "ports,tools",
    [([], ["http_probe"]), ([3000], []), ([], [])],
)
@pytest.mark.parametrize("port", [3000, 22, 65535])
@pytest.mark.parametrize("tool", ["http_probe", "nmap_connect_scan", "bash"])
def test_checker_empty_lists_grant_nothing(ports, tools, port, tool):
    checker = ScopeChecker(_unvalidated_scope(ports, tools))
    decision = checker.check(
        host="10.66.7.103", port=port, tool=tool, tier=ActionTier.PASSIVE
    )
    assert not decision.allowed


def test_valid_scope_behavior_unchanged():
    checker = ScopeChecker(Scope.model_validate(VALID))
    ok = checker.check(
        host="10.66.7.103", port=3000, tool="http_probe", tier=ActionTier.PASSIVE
    )
    assert ok.allowed
    for kw in (
        {"port": 22, "tool": "http_probe"},
        {"port": 3000, "tool": "nmap_connect_scan"},
    ):
        assert not checker.check(
            host="10.66.7.103", tier=ActionTier.PASSIVE, **kw
        ).allowed
