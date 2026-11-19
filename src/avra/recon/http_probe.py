"""Interpret ``http_probe`` evidence on the Windows side (ADR 0007, M8.1).

Input: the envelope the Runner child printed (stored as write-once
evidence). Two steps, both deterministic and offline:

1. ``parse_envelope`` — strict shape, base64 that decodes to bytes with the
   stated SHA-256 and length, and the request bytes must be EXACTLY the
   fixed request for this host and port (request/response pairing).
2. ``parse_http_response`` — reads the response bytes without repairing
   them. The only thing it establishes is ``protocol_observed`` (a valid
   HTTP status line). Server-supplied strings (``Server``,
   ``X-Powered-By``, ``<title>``) are bounded, escaped and reported only as
   TENTATIVE indications. Nothing here infers a product, a version or a
   vulnerability, and nothing here is ever treated as an instruction.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

from avra.runner.schemas import validate_http_path
from avra.runner.tools.http_probe import (
    ENVELOPE_FORMAT,
    GET_PATH_FORMAT,
    MAX_RESPONSE_BYTES,
    request_bytes,
)

MAX_HEADER_SECTION = 16_384
MAX_HEADERS = 100
MAX_HEADER_VALUE = 1_024
MAX_REASON = 100
MAX_TITLE = 200
TITLE_SCAN_BYTES = 65_536
INDICATION_NOTE = ("Tentative, server-controlled strings. They are claims made by the "
                   "server, not a confirmed product, version or vulnerability.")
_HEX64 = r"^[0-9a-f]{64}$"
_STATUS_LINE = re.compile(rb"^HTTP/([0-9])\.([0-9]) ([0-9]{3})(?: ([^\r\n]*))?$")
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_TEXTUAL = ("text/", "application/json", "application/xml", "application/javascript",
            "application/xhtml+xml")


class HttpProbeError(Exception):
    """The evidence envelope is malformed or does not match the request."""


# Outcomes decided before any byte was sent: they can never carry a response.
_NO_RESPONSE_OUTCOMES = ("connection_refused", "connect_timeout")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise HttpProbeError("envelope has duplicate keys")
    return dict(pairs)


class HttpProbeEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    format: Literal["avra-http-probe/1"]
    host: StrictStr
    port: StrictInt = Field(ge=1, le=65535)
    outcome: Literal["response_received", "connection_refused", "connect_timeout",
                     "read_timeout", "connection_reset", "network_error"]
    error: StrictStr = Field(max_length=100)
    request_b64: StrictStr
    request_sha256: StrictStr = Field(pattern=_HEX64)
    request_bytes: StrictInt = Field(ge=0)
    response_b64: StrictStr
    response_sha256: StrictStr = Field(pattern=_HEX64)
    response_bytes: StrictInt = Field(ge=0)
    truncated: StrictBool
    complete: StrictBool
    elapsed_ms: StrictInt = Field(ge=0)


class HttpGetPathEnvelope(HttpProbeEnvelope):
    """M10.5 (ADR 0018): the http_get_path envelope = the probe envelope + the path."""

    format: Literal["avra-http-get-path/1"]  # type: ignore[assignment]
    path: StrictStr


class Header(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str   # lower-case
    value: str  # latin-1 decoded, control chars escaped, bounded


class Indication(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: Literal["header:server", "header:x-powered-by", "html:title"]
    value: str
    tentative: bool = True


class HttpResponseFacts(BaseModel):
    """What the bytes show. ``protocol_observed`` is the only established fact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_observed: bool
    identity_level: Literal["none", "protocol_observed"]
    http_version: str | None = None
    status_code: int | None = None
    reason: str = ""
    headers: tuple[Header, ...] = ()
    header_lines_total: int = 0
    header_section_bytes: int | None = None
    body_bytes: int = 0
    body_sha256: str = hashlib.sha256(b"").hexdigest()
    content_type: str = ""
    declared_length: int | None = None
    is_redirect: bool = False
    location: str = ""      # recorded, never followed
    binary: bool = False
    title: str = ""
    indications: tuple[Indication, ...] = ()
    indication_note: str = INDICATION_NOTE
    malformed: tuple[str, ...] = ()
    complete: bool = False
    truncated: bool = False


def _b64(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise HttpProbeError(f"{what} is not valid base64") from None


def parse_envelope(text: str, *, host: str, port: int, path: str | None = None
                   ) -> tuple[HttpProbeEnvelope, bytes, bytes]:
    """Validate the envelope against the request it answers; return the
    envelope and the exact request/response bytes. ``path`` None = an http_probe
    envelope (``GET /``); a path = an http_get_path envelope for exactly that path."""
    if not isinstance(text, str) or not text.isascii():
        raise HttpProbeError("envelope must be pure ASCII")
    model, fmt = ((HttpProbeEnvelope, ENVELOPE_FORMAT) if path is None
                  else (HttpGetPathEnvelope, GET_PATH_FORMAT))
    try:
        env = model.model_validate(json.loads(text, object_pairs_hook=_no_duplicate_keys))
    except (ValueError, ValidationError, RecursionError):  # ValueError: JSON + int-digit cap
        raise HttpProbeError(f"envelope is not a valid {fmt} record") from None
    if env.format != fmt:
        raise HttpProbeError("unknown envelope format")
    if path is not None:
        try:
            validate_http_path(path)
        except ValueError:
            raise HttpProbeError("requested path is not a valid path") from None
        if env.path != path:
            raise HttpProbeError("envelope path does not match the request")
    if (env.host, env.port) != (host, port):
        raise HttpProbeError("envelope host/port does not match the request")
    req, resp = _b64(env.request_b64, "request"), _b64(env.response_b64, "response")
    if len(req) != env.request_bytes or hashlib.sha256(req).hexdigest() != env.request_sha256:
        raise HttpProbeError("request bytes do not match their recorded size/hash")
    if len(resp) != env.response_bytes or hashlib.sha256(resp).hexdigest() != \
            env.response_sha256:
        raise HttpProbeError("response bytes do not match their recorded size/hash")
    if req != request_bytes(host, port, path or "/"):
        raise HttpProbeError("request bytes are not the fixed probe request for this target")
    if env.outcome in _NO_RESPONSE_OUTCOMES and resp:
        raise HttpProbeError(f"outcome {env.outcome} must not carry response bytes")
    # Flags must agree with each other and with the child's fixed limits.
    if len(resp) > MAX_RESPONSE_BYTES:
        raise HttpProbeError("response exceeds the probe's byte limit")
    if (env.outcome == "response_received") != (env.error == ""):
        raise HttpProbeError("outcome and error are inconsistent")
    if env.truncated and (len(resp) != MAX_RESPONSE_BYTES
                          or env.outcome != "response_received"):
        raise HttpProbeError("truncated flag is inconsistent with the response")
    if env.complete and (env.truncated or env.outcome != "response_received" or not resp):
        raise HttpProbeError("complete flag is inconsistent with the outcome")
    return env, req, resp


def _safe(text: str, limit: int) -> str:
    """Escape control characters (incl. CR/LF/ESC) and bound the length."""
    out = "".join(c if (c.isprintable() or c == " ") else f"\\x{ord(c):02x}"
                  for c in text)
    return out[:limit]


def _title_tag_end(ch: str) -> bool:
    """``<title`` must be followed by ``>``, ``/`` or whitespace (not ``<titlex``)."""
    return bool(ch) and (ch in ">/" or ch.isspace())


def _find_title(text: str) -> str:
    """First ``<title ...>...</title>`` only, by linear ``find`` scans (no
    backtracking regex: hostile bodies with many unclosed tags stay O(n))."""
    low = text.translate(_ASCII_LOWER)  # same length as text, unlike str.lower()
    start = low.find("<title")
    while start != -1 and not _title_tag_end(low[start + 6:start + 7]):
        start = low.find("<title", start + 6)
    if start == -1:
        return ""
    gt = low.find(">", start)
    if gt == -1:
        return ""
    end = low.find("</title", gt + 1)
    return text[gt + 1:end] if end != -1 else ""


def parse_http_response(data: bytes, *, complete: bool = True, truncated: bool = False
                        ) -> HttpResponseFacts:
    """Read, never repair. Malformed input is recorded, not raised."""
    malformed: list[str] = []
    if not data:
        return HttpResponseFacts(protocol_observed=False, identity_level="none",
                                 malformed=("empty response",), complete=complete,
                                 truncated=truncated)
    end = data.find(b"\r\n\r\n", 0, MAX_HEADER_SECTION + 4)
    if end == -1:
        malformed.append("header section exceeds 16384 bytes" if len(data) > MAX_HEADER_SECTION
                         else "header section not terminated")
        head, body, header_bytes = data[:MAX_HEADER_SECTION], b"", None
    else:
        head, body, header_bytes = data[:end], data[end + 4:], end + 4
    lines = head.split(b"\r\n")
    m = _STATUS_LINE.fullmatch(lines[0])
    if not m:
        malformed.append("invalid HTTP status line")
        return HttpResponseFacts(protocol_observed=False, identity_level="none",
                                 header_section_bytes=header_bytes, body_bytes=len(body),
                                 body_sha256=hashlib.sha256(body).hexdigest(),
                                 malformed=tuple(malformed), complete=complete,
                                 truncated=truncated)
    version = f"{m.group(1).decode()}.{m.group(2).decode()}"
    status = int(m.group(3))
    reason = _safe((m.group(4) or b"").decode("latin-1"), MAX_REASON)
    headers: list[Header] = []
    bad = 0
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not _TOKEN.match(name):
            bad += 1
            continue
        if len(headers) < MAX_HEADERS:
            headers.append(Header(name=name.decode("ascii").lower(),
                                  value=_safe(value.strip().decode("latin-1"),
                                              MAX_HEADER_VALUE)))
    if bad:
        malformed.append(f"{bad} malformed header line(s) ignored")
    if len(lines) - 1 > MAX_HEADERS:
        malformed.append(f"more than {MAX_HEADERS} header lines; extra ones not kept")

    def first(name: str) -> str:
        return next((h.value for h in headers if h.name == name), "")

    def all_of(name: str) -> list[str]:
        return [h.value for h in headers if h.name == name]

    content_type = first("content-type").lower()
    declared = None
    cl = first("content-length")
    cls = all_of("content-length")
    if len(set(cls)) > 1:
        malformed.append("conflicting Content-Length headers")
    te = all_of("transfer-encoding")
    if te:
        # Forbidden in a reply to an HTTP/1.0 request (RFC 9112 6.1); the
        # body is kept as the raw, still-encoded bytes and never decoded.
        malformed.append("Transfer-Encoding in reply to HTTP/1.0; body not decoded")
        if cls:
            malformed.append("both Transfer-Encoding and Content-Length present")
    if cl:
        if cl.isascii() and cl.isdigit():
            declared = int(cl)
            if (complete and not truncated and header_bytes is not None and not te
                    and len(set(cls)) == 1 and declared != len(body)):
                malformed.append("body length differs from Content-Length")
        else:
            malformed.append("invalid Content-Length")
    binary = b"\x00" in body[:1024] or bool(content_type) and not content_type.startswith(
        _TEXTUAL)
    title = ""
    if "html" in content_type and not binary and body:
        charset = "utf-8"
        cm = re.search(r"charset=([A-Za-z0-9._-]+)", content_type)
        if cm:
            charset = cm.group(1)
        try:
            text = body[:TITLE_SCAN_BYTES].decode(charset, errors="replace")
        except LookupError:
            malformed.append("unknown charset; decoded as UTF-8 with replacement")
            text = body[:TITLE_SCAN_BYTES].decode("utf-8", errors="replace")
        title = _safe(" ".join(_find_title(text).split()), MAX_TITLE)
    is_redirect = 300 <= status < 400 and status != 304
    indications = tuple(Indication(source=src, value=val) for src, val in (
        ("header:server", first("server")), ("header:x-powered-by", first("x-powered-by")),
        ("html:title", title)) if val)
    if truncated:
        malformed.append("response truncated at the byte limit")
    return HttpResponseFacts(
        protocol_observed=True, identity_level="protocol_observed", http_version=version,
        status_code=status, reason=reason, headers=tuple(headers),
        header_lines_total=len(lines) - 1, header_section_bytes=header_bytes,
        body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
        content_type=content_type, declared_length=declared, is_redirect=is_redirect,
        location=first("location") if is_redirect else "", binary=binary, title=title,
        indications=indications, malformed=tuple(malformed), complete=complete,
        truncated=truncated)
