"""File-based evidence storage (ADR 0001 stack, M6.5).

Raw tool output is stored exactly as received, once: a file is created
exclusively (never overwritten), named only from validated identifiers,
and its SHA-256 is returned so the audit log can bind to the bytes.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID


class EvidenceError(Exception):
    pass


@dataclass(frozen=True)
class EvidenceRef:
    path: Path
    sha256: str
    size: int


def store_evidence(root: Path, session_id: UUID, request_id: UUID, suffix: str,
                   data: bytes) -> EvidenceRef:
    if not isinstance(session_id, UUID) or not isinstance(request_id, UUID):
        raise EvidenceError("evidence names come only from UUIDs")
    if suffix not in (".xml", ".txt", ".json"):
        raise EvidenceError(f"unsupported evidence suffix: {suffix}")
    folder = Path(root) / str(session_id)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{request_id}{suffix}"
    try:
        # 'xb': fails if the file exists — evidence is never overwritten.
        with open(path, "xb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
    except FileExistsError:
        raise EvidenceError(f"evidence already exists: {path.name}") from None
    return EvidenceRef(path=path, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
