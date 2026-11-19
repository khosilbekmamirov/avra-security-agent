"""Static, typed Tool Registry (ADR 0003, decision 6).

The Runner can only run a tool that is listed in ``_REGISTRY`` below.
The list is fixed in code at import time: there is deliberately no
``register()`` function, and nothing from a request, config file or the
model can add, replace or alter an entry.

Each entry fixes four things: the tool's name, its strict input schema,
its action tier (decided here, never by the caller), and a dedicated
executor that builds the argument list. The executable itself is also
fixed per entry, so an executor can't swap in a different program.

Each entry also declares ``scope_targets``: every (host, port) a request
would touch. The Runner policy (``avra.runner.policy``) checks all of
them before the executor is ever called. An HTTP tool would derive these
from its URL the same way.

Adding a tool later (e.g. ``http_request``) = one new schema, one new
executor module, one new entry here. The Runner core doesn't change.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel

from avra.runner.schemas import (
    HttpGetPathRequest,
    HttpProbeRequest,
    NmapConnectScanRequest,
    ToolName,
)
from avra.runner.tools import http_probe, nmap_connect_scan
from avra.schemas.scope import ActionTier


class UnknownToolError(Exception):
    """The requested tool name is not in the registry."""


@dataclass(frozen=True)
class ToolCommand:
    """What the Runner core will execute: argv list, never a shell string."""

    argv: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class ToolSpec:
    name: ToolName
    request_model: type[BaseModel]
    tier: ActionTier
    executable: str
    build_args: Callable[[Any], tuple[str, ...]]
    scope_targets: Callable[[Any], tuple[tuple[str, int], ...]]
    # M10.5: the path a request touches (checked against the target's http_paths), or None
    scope_path: Callable[[Any], str] | None = None

    def build_command(self, request: BaseModel) -> ToolCommand:
        """Turn a validated request into an argv list for this tool only."""
        if type(request) is not self.request_model:
            raise TypeError(
                f"{self.name.value} expects {self.request_model.__name__}, "
                f"got {type(request).__name__}"
            )
        args = self.build_args(request)
        if not isinstance(args, tuple) or not all(isinstance(a, str) for a in args):
            raise TypeError(f"{self.name.value} executor must return a tuple of str")
        return ToolCommand(
            argv=(self.executable, *args),
            timeout_seconds=request.timeout_seconds,
        )


_REGISTRY: Mapping[str, ToolSpec] = MappingProxyType(
    {
        ToolName.NMAP_CONNECT_SCAN.value: ToolSpec(
            name=ToolName.NMAP_CONNECT_SCAN,
            request_model=NmapConnectScanRequest,
            tier=ActionTier.ACTIVE_SAFE,
            executable="nmap",
            build_args=nmap_connect_scan.build_args,
            scope_targets=nmap_connect_scan.scope_targets,
        ),
        # ADR 0007: one fixed GET / over plain HTTP. Passive tier; still
        # default-deny until a scope file lists it (none does).
        ToolName.HTTP_PROBE.value: ToolSpec(
            name=ToolName.HTTP_PROBE,
            request_model=HttpProbeRequest,
            tier=ActionTier.PASSIVE,
            executable="http_probe",
            build_args=http_probe.build_args,
            scope_targets=http_probe.scope_targets,
        ),
        # M10.5 (ADR 0018): one fixed GET of one validated same-origin path. Same child
        # binary as http_probe (no new executable); its own name so a scope must list it
        # AND the path prefix (http_paths). Default deny.
        ToolName.HTTP_GET_PATH.value: ToolSpec(
            name=ToolName.HTTP_GET_PATH,
            request_model=HttpGetPathRequest,
            tier=ActionTier.PASSIVE,
            executable="http_probe",
            build_args=http_probe.build_get_path_args,
            scope_targets=http_probe.scope_targets,
            scope_path=http_probe.scope_path,
        ),
    }
)


def registered_tools() -> tuple[str, ...]:
    return tuple(_REGISTRY)


def get_tool(name: object) -> ToolSpec:
    """Look up a tool by exact name. Anything else raises UnknownToolError."""
    if not isinstance(name, str) or name not in _REGISTRY:
        raise UnknownToolError(f"unknown tool: {name!r}")
    return _REGISTRY[name]


def parse_request(payload: object) -> tuple[ToolSpec, BaseModel]:
    """Find the tool named in a raw request and validate it strictly.

    Raises UnknownToolError for a missing/unknown tool name and pydantic's
    ValidationError for anything the tool's schema rejects. Passing this
    does NOT authorize the request — the Runner's scope check does.
    """
    if not isinstance(payload, dict):
        raise UnknownToolError("request must be a JSON object with a 'tool' field")
    spec = get_tool(payload.get("tool"))
    return spec, spec.request_model.model_validate(payload)
