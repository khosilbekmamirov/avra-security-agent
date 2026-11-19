"""Controlled vulnerability validation framework (M10.4, ADR 0017).

Some hypotheses cannot be decided from one recorded ``GET /``: an IDOR needs the same
object requested as two different accounts; an input-handling check needs a request
that carries a marker. This module defines such checks and evaluates them
DETERMINISTICALLY on validation FIXTURES: recorded or synthetic request/response
exchanges in a strict, hash-checked format.

What this framework never does:

* send a request. There is no executor here. ``live_authorization`` always refuses:
  running a check live needs a new Runner tool, synthetic lab accounts, a scope change
  and the owner's separate authorization (a future ADR);
* accept a state-changing method (GET only), a real account (``synthetic-*`` only) or a
  free-form payload (markers follow a fixed, harmless grammar);
* turn a simulated result into a lab finding: every result carries the fixture's label,
  and ``lab_finding`` is true only for a ``RECORDED-LAB`` fixture with a CONFIRMED
  verdict (none exist yet).

Checks differ by design (not every vulnerability is verified the same way): each one
declares its own exchange roles, criteria and limitations.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from abc import ABC, abstractmethod
from typing import Literal
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from avra.runner.schemas import validate_ipv4_target
from avra.verification.models import Verdict, canonical_json, sha256_hex

FIXTURE_FORMAT = "avra-validation-fixture/1"
LABELS = ("SIMULATED-FIXTURE", "RECORDED-LAB")
MAX_BODY = 65_536
MAX_EXCHANGES = 6
LIVE_REFUSAL = ("Live validation is disabled: it needs a new Runner capability, synthetic lab "
                "accounts, a scope change and the owner's separate authorization (ADR 0017 "
                "M10.4). Only fixtures can be evaluated.")
_ACCOUNT = re.compile(r"^synthetic-[a-z0-9-]{1,40}$")
_PATH = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/?]{0,299}$")
MARKER_TOKEN = re.compile(r"^AVRA[0-9A-F]{16}$")
MARKER_PROBE = "\"'<>"  # four inert characters: shows whether output is encoded


class ValidationFixtureError(Exception):
    """The fixture is malformed, inconsistent or violates a safety constraint."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Exchange(_Strict):
    role: Literal["owner", "other_account", "anonymous", "marker"]
    account: str | None = None       # synthetic-* or None (anonymous / marker)
    method: Literal["GET"]           # nothing state-changing, ever
    path: str
    marker: str | None = None        # marker exchanges only
    status: int = Field(ge=100, le=599)
    content_type: str = Field(default="", max_length=100)
    body_b64: str
    body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("account")
    @classmethod
    def _synthetic(cls, v: str | None) -> str | None:
        if v is not None and not _ACCOUNT.fullmatch(v):
            raise ValueError("accounts must be predefined synthetic accounts (synthetic-...)")
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        if not _PATH.fullmatch(v):
            raise ValueError("path must be a same-origin path")
        return v

    def body(self) -> bytes:
        try:
            data = base64.b64decode(self.body_b64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError, ValueError):
            raise ValidationFixtureError("body is not valid base64") from None
        if len(data) > MAX_BODY:
            raise ValidationFixtureError("body exceeds 64 KiB")
        if hashlib.sha256(data).hexdigest() != self.body_sha256:
            raise ValidationFixtureError("body does not match its recorded SHA-256")
        return data


class FixtureTarget(_Strict):
    host: str
    port: int = Field(ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _ipv4(cls, v: str) -> str:
        return validate_ipv4_target(v)


class ValidationFixture(_Strict):
    format: Literal["avra-validation-fixture/1"]
    label: Literal["SIMULATED-FIXTURE", "RECORDED-LAB"]
    check: str = Field(max_length=80)
    target: FixtureTarget
    description: str = Field(default="", max_length=500)
    owner_marker: str | None = Field(default=None, max_length=80)  # synthetic data marker
    exchanges: tuple[Exchange, ...] = Field(min_length=1, max_length=MAX_EXCHANGES)

    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


class ValidationResult(_Strict):
    check_id: str
    check_version: str
    vuln_class: str
    verdict: Verdict
    reason_code: str
    reason: str
    criteria: tuple[dict, ...]
    target: str
    fixture_sha256: str
    fixture_label: str
    simulated: bool
    lab_finding: bool
    exchanges_used: tuple[int, ...]
    limitations: tuple[str, ...]
    live_execution: str = "disabled"

    def sha256(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


class ValidationCheck(ABC):
    id: str
    version: str = "1"
    title: str
    vuln_class: str
    description: str
    roles: tuple[str, ...]           # exchange roles the fixture must provide
    state_changing: bool = False     # every check in this ADR is read-only
    live_requires: tuple[str, ...]   # what a live run would need (never available here)
    limitations: tuple[str, ...] = ()

    def describe(self) -> dict:
        return {"id": self.id, "version": self.version, "title": self.title,
                "vuln_class": self.vuln_class, "roles": list(self.roles),
                "state_changing": self.state_changing, "live_execution": "disabled",
                "live_requires": list(self.live_requires), "description": self.description}

    @abstractmethod
    def evaluate(self, fx: ValidationFixture) -> tuple[Verdict, str, str, list[dict],
                                                       tuple[int, ...]]: ...


def _crit(cid: str, outcome: str, detail: str = "") -> dict:
    return {"criterion_id": cid, "outcome": outcome, "detail": detail[:300]}


def _one(fx: ValidationFixture, role: str) -> tuple[int, Exchange]:
    found = [(i, e) for i, e in enumerate(fx.exchanges) if e.role == role]
    if len(found) != 1:
        raise ValidationFixtureError(f"exactly one '{role}' exchange is required")
    return found[0]


class CrossAccountObjectAccess(ValidationCheck):
    id = "idor.cross_account_object_access"
    title = "Object readable by a different (synthetic) account"
    vuln_class = "broken_access_control"
    description = ("The same object path is requested as its owner and as a second synthetic "
                   "account. CONFIRMED when the second account receives the owner's object.")
    roles = ("owner", "other_account")
    live_requires = ("Runner tool for an authenticated GET of a chosen path",
                     "two predefined synthetic accounts and their test data in the lab app",
                     "scope change and the owner's per-run authorization")
    limitations = (("Only the recorded pair of requests is judged; other objects and methods "
                   "may behave differently."),
                   "A 2xx without the owner's data marker is not counted as a leak.")

    def evaluate(self, fx):
        io, owner = _one(fx, "owner")
        ix, other = _one(fx, "other_account")
        if owner.account is None or other.account is None or owner.account == other.account:
            raise ValidationFixtureError("owner and other_account need two different synthetic "
                                         "accounts")
        if owner.path != other.path:
            raise ValidationFixtureError("both exchanges must request the same object path")
        if not fx.owner_marker:
            raise ValidationFixtureError("owner_marker (synthetic data marker) is required")
        ob, xb = owner.body(), other.body()
        mark = fx.owner_marker.encode("utf-8")
        used = (io, ix)
        crit = [_crit("owner_baseline", "met" if 200 <= owner.status < 300 and mark in ob
                      else "not_met", f"owner status {owner.status}")]
        if not (200 <= owner.status < 300) or mark not in ob:
            return (Verdict.INCONCLUSIVE, "owner_baseline_invalid",
                    ("The owner's own request does not return the object with its marker, so the "
                    "comparison proves nothing."), crit, used)
        if other.status in (401, 403, 404):
            crit.append(_crit("cross_account_denied", "met", f"other status {other.status}"))
            return (Verdict.REJECTED, "access_denied",
                    f"The second account was refused (HTTP {other.status}).", crit, used)
        if 200 <= other.status < 300 and mark in xb:
            crit.append(_crit("cross_account_read", "met",
                              "the owner's data marker is in the second account's response"))
            return (Verdict.CONFIRMED, "cross_account_read",
                    "The second synthetic account received the owner's object (marker present).",
                    crit, used)
        crit.append(_crit("cross_account_read", "unknown", f"other status {other.status}"))
        return (Verdict.INCONCLUSIVE, "ambiguous_response",
                ("The second account's response neither denies access nor contains the owner's "
                "data marker."), crit, used)


class MarkerReflection(ValidationCheck):
    id = "input.marker_reflection"
    title = "Harmless marker reflected without HTML encoding"
    vuln_class = "xss"
    description = ("A request carries a fixed marker (AVRA + 16 hex digits + the four inert "
                   "characters \"'<>). CONFIRMED when the response reflects the marker with "
                   "those characters unencoded in an HTML body - an XSS indicator, not proof "
                   "that script executes.")
    roles = ("marker",)
    live_requires = ("Runner tool for a GET with one marker query parameter",
                     "scope change and the owner's per-run authorization")
    limitations = (("An indicator only: no script was executed and the reflection context "
                   "(attribute, script, text) is not analysed."),
                   "Only the recorded request/response is judged.")

    def evaluate(self, fx):
        i, ex = _one(fx, "marker")
        m = ex.marker or ""
        token = m[:-len(MARKER_PROBE)] if m.endswith(MARKER_PROBE) else ""
        if not MARKER_TOKEN.fullmatch(token):
            raise ValidationFixtureError("marker must be AVRA + 16 hex digits + the probe "
                                         "characters \"'<>")
        if m not in unquote(ex.path):
            raise ValidationFixtureError("the request path must carry the marker")
        body = ex.body().decode("utf-8", errors="replace")
        crit = [_crit("eligible_response", "met" if 200 <= ex.status < 300 else "not_met",
                      f"status {ex.status}")]
        if not 200 <= ex.status < 300:
            return Verdict.INCONCLUSIVE, "no_2xx_response", f"HTTP {ex.status}.", crit, (i,)
        if "html" not in ex.content_type.lower():
            crit.append(_crit("html_context", "not_met", ex.content_type or "no content type"))
            return (Verdict.REJECTED, "not_html",
                    ("The response is not HTML, so an unencoded reflection is not an XSS "
                    "indicator here."), crit, (i,))
        if m in body:
            crit.append(_crit("reflected_unencoded", "met", "marker + \"'<> appear verbatim"))
            return (Verdict.CONFIRMED, "reflected_unencoded",
                    "The marker is reflected with \"'<> unencoded in the HTML body.", crit, (i,))
        crit.append(_crit("reflected_unencoded", "not_met",
                          "token reflected, probe characters encoded or removed" if token in body
                          else "marker not reflected"))
        return (Verdict.REJECTED, "reflected_encoded" if token in body else "not_reflected",
                "The marker is reflected but its probe characters are encoded or removed."
                if token in body else "The marker is not reflected.", crit, (i,))


CHECKS: dict[str, ValidationCheck] = {c.id: c for c in (CrossAccountObjectAccess(),
                                                        MarkerReflection())}
CLASS_CHECKS: dict[str, str] = {c.vuln_class: c.id for c in CHECKS.values()}


def live_authorization(check_id: str) -> tuple[bool, str]:
    """Always refuses in this build. Kept as the single place a future, separately
    approved ADR would change - never bypassable by a flag."""
    return False, LIVE_REFUSAL


def load_fixture(text: str) -> ValidationFixture:
    try:
        return ValidationFixture.model_validate(json.loads(text))
    except (ValueError, ValidationError) as exc:
        raise ValidationFixtureError(f"not a valid {FIXTURE_FORMAT} fixture: "
                                     f"{str(exc)[:300]}") from None


def validate(fx: ValidationFixture) -> ValidationResult:
    check = CHECKS.get(fx.check)
    if check is None:
        raise ValidationFixtureError(f"unknown check {fx.check[:80]!r}")
    for e in fx.exchanges:
        e.body()  # every body is hash-checked, used or not (fail closed)
    verdict, code, reason, crit, used = check.evaluate(fx)
    simulated = fx.label == "SIMULATED-FIXTURE"
    return ValidationResult(
        check_id=check.id, check_version=check.version, vuln_class=check.vuln_class,
        verdict=verdict, reason_code=code, reason=reason, criteria=tuple(crit),
        target=f"{fx.target.host}:{fx.target.port}", fixture_sha256=fx.sha256(),
        fixture_label=fx.label, simulated=simulated,
        lab_finding=(not simulated and verdict is Verdict.CONFIRMED),
        exchanges_used=used, limitations=check.limitations)


def make_exchange(*, role: str, path: str, status: int, body: bytes, account: str | None = None,
                  content_type: str = "application/json", marker: str | None = None) -> dict:
    """Helper for building fixtures (tests, documentation examples)."""
    return {"role": role, "account": account, "method": "GET", "path": path, "marker": marker,
            "status": status, "content_type": content_type,
            "body_b64": base64.b64encode(body).decode("ascii"),
            "body_sha256": hashlib.sha256(body).hexdigest()}
