"""Canonical, hashable snapshot of the enforced scope (M7.9.2).

Recorded in ``research_started`` so a report can later be rebuilt from the
audit log alone, without re-reading a scope file that may have changed.
The snapshot is the scope model itself (``model_dump(mode="json")``), so it
contains exactly the fields the ScopeChecker enforced plus the owner's
descriptive text — never anything model-generated.
"""

from __future__ import annotations

import hashlib
import json
from importlib import metadata

from pydantic import ValidationError

from avra.schemas.scope import Scope

SNAPSHOT_FORMAT = 1


class SnapshotError(Exception):
    """A recorded scope snapshot is missing, altered or not canonical."""


def canonical_json(obj: object) -> bytes:
    """One byte representation per value: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def scope_snapshot(scope: Scope) -> dict:
    return scope.model_dump(mode="json")


def snapshot_sha256(snapshot: dict) -> str:
    return hashlib.sha256(canonical_json(snapshot)).hexdigest()


def scope_from_snapshot(snapshot: object, expected_sha256: object) -> Scope:
    """Rebuild the scope from a recorded snapshot, or fail closed."""
    if not isinstance(snapshot, dict) or not isinstance(expected_sha256, str):
        raise SnapshotError("scope snapshot or its hash is missing")
    try:
        actual = snapshot_sha256(snapshot)
    except (TypeError, ValueError) as exc:
        raise SnapshotError(f"scope snapshot is not serializable ({type(exc).__name__})") from None
    if actual != expected_sha256:
        raise SnapshotError("scope snapshot does not match its recorded hash")
    try:
        scope = Scope.model_validate(snapshot)
    except ValidationError:
        raise SnapshotError("scope snapshot is not a valid scope") from None
    if scope_snapshot(scope) != snapshot:
        raise SnapshotError("scope snapshot is not in canonical form")
    return scope


def avra_version() -> str:
    try:
        return metadata.version("avra")
    except metadata.PackageNotFoundError:
        return "unknown"
