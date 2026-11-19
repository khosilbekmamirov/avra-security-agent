"""Bounded, read-only web surface extraction (M10.1, ADR 0017).

Input: RECORDED, hash-checked ``http_probe`` evidence only. Nothing here sends
a request, follows a link, submits a form or executes JavaScript. The output is
a structured inventory of what the recorded response *references*:

* same-origin links, scripts, stylesheets, other resources and form actions;
* form methods, actions and field names (never values, never submitted);
* API endpoint candidates quoted in inline scripts (``/api/...``, ``/rest/...``);
* client-side (SPA) routes such as ``/#/jobs``;
* useful response metadata (security headers present, CORS, cookie NAMES and
  flags - never cookie values, custom ``X-`` header names);
* external origins that were referenced and deliberately NOT followed;
* suspected prompt-injection text in server-controlled content (flag + location
  only; the text itself is never forwarded to a model).

Every item carries provenance: the evidence request id, the evidence file's
SHA-256 and the exact source (``html:script@src``, ``header:location``, ...)
with a character offset. A reference observed in a response is NOT proof that
the endpoint exists: every endpoint is ``referenced_not_fetched``.

Determinism: the same evidence bytes give the same surface and the same
``sha256()`` on every run and platform.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import SplitResult, urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from avra.recon.http_probe import HttpProbeError, parse_envelope

if TYPE_CHECKING:
    from avra.verification.evidence import SessionEvidence

SURFACE_FORMAT = "avra-web-surface/1"
MAX_SCAN_CHARS = 262_144       # the probe's own response limit (256 KiB)
MAX_ENDPOINTS = 200
MAX_FORMS = 20
MAX_FIELDS = 30
MAX_PATH = 300
MAX_PROVENANCE = 5
MAX_EXTERNAL = 30
MAX_FLAGS = 20
MAX_NAME = 80
STATUS = "referenced_not_fetched"
FETCHED = "fetched"  # M10.5: AVRA requested this exact path (http_get_path / http_probe)
NOTE = ("References observed in recorded, server-controlled responses. AVRA did not fetch "
        "them; their existence and behaviour are NOT verified.")

_PATH_OK = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*$")
_ROUTE_OK = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/?]*$")
_NAME_OK = re.compile(r"^[A-Za-z0-9_\-.\[\]:]{1,80}$")
_API_QUOTED = re.compile(r"""["'`](/(?:api|rest|graphql|v[0-9])(?:/[A-Za-z0-9\-._~%:@]*)*/?)["'`?]""")
_HEADER_PATH = re.compile(r"^/[A-Za-z0-9\-._~!$&'()*+,;=:@%/#?]{0,299}$")
# Instruction-like text in server-controlled content. A flag only: the matched
# text is never forwarded, and nothing is ever followed.
_INJECTION = re.compile(
    r"(ignore|disregard|forget)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\s+"
    r"(instructions|prompts?|rules)|\byou\s+are\s+now\b|\bsystem\s+prompt\b|"
    r"<\|im_start\|>|\bnew\s+instructions\s*:|\bassistant\s*:|\bcall\s+the\s+tool\b|"
    r"\bpropose_[a-z_]+\b|\bverify_hypothesis\b|\bfinish_session\b", re.IGNORECASE)
_SKIP_SCHEMES = ("javascript", "data", "mailto", "tel", "about", "blob", "file", "ftp", "ws",
                 "wss", "vbscript")
_STANDARD_HEADERS = frozenset({
    "location", "content-location", "link", "refresh"})  # headers whose value can be a path
_SECURITY_HEADERS = ("content-security-policy", "content-security-policy-report-only",
                     "strict-transport-security", "x-content-type-options", "x-frame-options",
                     "referrer-policy", "permissions-policy", "feature-policy",
                     "cross-origin-opener-policy", "cross-origin-resource-policy",
                     "cross-origin-embedder-policy")
_CORS_HEADERS = ("access-control-allow-origin", "access-control-allow-credentials",
                 "access-control-allow-methods", "access-control-allow-headers",
                 "access-control-expose-headers")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Provenance(_Frozen):
    request_id: str
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source: str          # e.g. "html:a@href", "header:location", "inline-script"
    offset: int = Field(ge=0)  # character offset in the decoded body (0 for headers)


class Endpoint(_Frozen):
    path: str            # normalized same-origin path ("/main.js", "/#/jobs" for routes)
    kinds: tuple[str, ...]  # link | script | stylesheet | resource | form_action |
    #                         api_candidate | client_route | redirect | header_hint
    query_keys: tuple[str, ...] = ()  # parameter NAMES only, never values
    status: str = STATUS
    provenance: tuple[Provenance, ...]
    # M10.5: (request_id, HTTP status) of every trusted fetch of exactly this path
    fetches: tuple[tuple[str, int | None], ...] = ()


class FormField(_Frozen):
    name: str
    type: str


class Form(_Frozen):
    action: str          # normalized same-origin path ("" = the page itself)
    method: str          # GET | POST | OTHER
    fields: tuple[FormField, ...]
    submitted: bool = False  # never: AVRA does not submit forms
    provenance: Provenance


class CookieInfo(_Frozen):
    name: str
    secure: bool
    httponly: bool
    samesite: str        # "" when absent


class ResponseMeta(_Frozen):
    request_id: str
    evidence_sha256: str
    path: str = "/"  # M10.5: the path AVRA requested
    status_code: int | None
    content_type: str
    security_headers: dict[str, bool]
    cors: dict[str, str]
    cookies: tuple[CookieInfo, ...]
    custom_header_names: tuple[str, ...]
    server_claims: dict[str, str]  # server / x-powered-by: tentative claims
    body_chars_scanned: int
    html: bool
    truncated: bool = False   # M12: the fetch hit the 256 KiB limit; later content unknown
    body_bytes: int = 0


class Flag(_Frozen):
    code: str            # injection_suspected | base_href_ignored | ...
    provenance: Provenance


class WebSurface(_Frozen):
    format: str = SURFACE_FORMAT
    host: str
    port: int
    origin: str
    note: str = NOTE
    responses: tuple[ResponseMeta, ...]
    endpoints: tuple[Endpoint, ...]
    forms: tuple[Form, ...]
    external_origins: tuple[str, ...]  # referenced, never followed
    skipped_references: int            # javascript:/data:/malformed/over-limit
    flags: tuple[Flag, ...]
    limits_hit: tuple[str, ...]

    def canonical(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical().encode("ascii")).hexdigest()

    def paths(self) -> frozenset[str]:
        return frozenset(e.path for e in self.endpoints) | frozenset(
            f.action for f in self.forms if f.action)


def _bounded(text: str, limit: int) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:limit]


# --- URL handling ----------------------------------------------------------------------

class _Resolver:
    def __init__(self, host: str, port: int) -> None:
        self.host, self.port = host, port
        self.base = f"http://{host}:{port}/"

    def same_origin(self, u: SplitResult) -> bool:
        try:
            port = u.port or (80 if u.scheme == "http" else 443 if u.scheme == "https" else None)
        except ValueError:
            return False
        return u.scheme == "http" and (u.hostname or "") == self.host and port == self.port

    def resolve(self, ref: str, base: str | None = None
                ) -> tuple[str, str, tuple[str, ...], str | None]:
        """-> (status, path, query_keys, external_origin). status: ok | route | external |
        skipped. ``route`` puts the SPA route in ``path`` ("/#/jobs")."""
        ref = ref.strip()
        if not ref or len(ref) > 2048:
            return "skipped", "", (), None
        scheme = ref.split(":", 1)[0].lower() if ":" in ref.split("/", 1)[0] else ""
        if scheme in _SKIP_SCHEMES:
            return "skipped", "", (), None
        try:
            u = urlsplit(urljoin(base or self.base, ref))
        except ValueError:
            return "skipped", "", (), None
        if u.scheme not in ("http", "https"):
            return "skipped", "", (), None
        if not self.same_origin(u):
            origin = f"{u.scheme}://{(u.hostname or '')[:100]}"
            if u.port:
                origin += f":{u.port}"
            return "external", "", (), origin
        path = u.path or "/"
        trailing = path.endswith("/")
        path = posixpath.normpath(path)
        path = "/" + path.lstrip("/") if path != "." else "/"
        if trailing and path != "/":
            path += "/"
        if len(path) > MAX_PATH or not _PATH_OK.fullmatch(path):
            return "skipped", "", (), None
        keys = tuple(sorted({k for k in (p.split("=", 1)[0] for p in u.query.split("&") if p)
                             if _NAME_OK.fullmatch(k)}))[:20]
        if u.fragment.startswith("/") and path == "/":
            route = "/#" + u.fragment
            if len(route) <= MAX_PATH and _ROUTE_OK.fullmatch(route[2:] or "/"):
                return "route", route, (), None
            return "skipped", "", (), None
        return "ok", path, keys, None


# --- HTML walk ---------------------------------------------------------------------------

_LINK_REL = {"stylesheet": "stylesheet", "icon": "resource", "shortcut": "resource",
             "manifest": "resource", "preload": "resource", "modulepreload": "script",
             "prefetch": "resource", "alternate": "link"}
_FIELD_TAGS = ("input", "select", "textarea", "button")


class _Walker(HTMLParser):
    """Collects attribute references; tracks inline script text and comments.
    ``convert_charrefs`` keeps entity handling in the stdlib; no script runs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refs: list[tuple[str, str, int, str]] = []  # (kind, ref, offset, source)
        self.base_href: tuple[str, int] | None = None
        self.forms: list[dict] = []
        self.scripts: list[tuple[str, int]] = []
        self.texts: list[tuple[str, int, str]] = []       # (text, offset, where)
        self._in_script = False
        self._form: dict | None = None
        self._offset = 0

    def _pos(self) -> int:
        line, col = self.getpos()
        return self._line_starts[line - 1] + col if line - 1 < len(self._line_starts) else 0

    def feed_text(self, text: str) -> None:
        starts, n = [0], 0
        for line in text.split("\n"):
            n += len(line) + 1
            starts.append(n)
        self._line_starts = starts
        self.feed(text)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        pos = self._pos()
        for v in a.values():  # attribute text is server-controlled too
            if v and _INJECTION.search(v):
                self.texts.append((v, pos, "html:attribute"))
        if tag == "base" and a.get("href") and self.base_href is None:
            self.base_href = (a["href"], pos)
        elif tag == "a" or tag == "area":
            if a.get("href"):
                self.refs.append(("link", a["href"], pos, f"html:{tag}@href"))
        elif tag == "link" and a.get("href"):
            rels = a.get("rel", "").lower().split()
            if "preconnect" in rels or "dns-prefetch" in rels:
                self.refs.append(("preconnect", a["href"], pos, "html:link@href"))
            else:
                kind = next((_LINK_REL[r] for r in rels if r in _LINK_REL), "resource")
                self.refs.append((kind, a["href"], pos, "html:link@href"))
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.refs.append(("script", a["src"], pos, "html:script@src"))
        elif tag in ("img", "iframe", "frame", "embed", "source", "audio", "video", "track"):
            if a.get("src"):
                self.refs.append(("resource", a["src"], pos, f"html:{tag}@src"))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "GET"),
                          "fields": [], "offset": pos}
            self.forms.append(self._form)
        if tag in _FIELD_TAGS and self._form is not None and a.get("name"):
            self._form["fields"].append((a["name"], a.get("type", tag)))
        if tag in ("button", "input") and a.get("formaction"):
            self.refs.append(("form_action", a["formaction"], pos, f"html:{tag}@formaction"))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag == "script":
            self._in_script = False

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.scripts.append((data, self._pos()))
        elif data.strip():
            self.texts.append((data, self._pos(), "html:text"))

    def handle_comment(self, data: str) -> None:
        self.texts.append((data, self._pos(), "html:comment"))


# --- extraction ---------------------------------------------------------------------------

def _split_body(response: bytes) -> tuple[bytes, bytes] | None:
    end = response.find(b"\r\n\r\n", 0, 16_388)
    return None if end == -1 else (response[:end], response[end + 4:])


def _cookie(value: str) -> CookieInfo | None:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and "=" in parts[0] else ""
    if not _NAME_OK.fullmatch(name or "!"):
        return None
    attrs = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "")
             for p in parts[1:] if p}
    return CookieInfo(name=name, secure="secure" in attrs, httponly="httponly" in attrs,
                      samesite=_bounded(attrs.get("samesite", ""), 20))


def _meta(request_id: str, sha: str, facts, chars: int, html: bool,
          path: str = "/") -> ResponseMeta:
    headers = [(h.name, h.value) for h in facts.headers]

    def first(n: str) -> str | None:
        return next((v for k, v in headers if k == n), None)

    cookies = tuple(c for c in (_cookie(v) for k, v in headers if k == "set-cookie")
                    if c is not None)[:20]
    return ResponseMeta(
        request_id=request_id, evidence_sha256=sha, path=path,
        status_code=facts.status_code,
        content_type=_bounded(facts.content_type, 100),
        security_headers={h: first(h) is not None for h in _SECURITY_HEADERS},
        cors={h: _bounded(first(h), 200) for h in _CORS_HEADERS if first(h) is not None},
        cookies=cookies,
        custom_header_names=tuple(sorted({k for k, _ in headers if k.startswith("x-")}))[:30],
        server_claims={k: _bounded(first(k), 100) for k in ("server", "x-powered-by")
                       if first(k)},
        body_chars_scanned=chars, html=html, truncated=bool(facts.truncated),
        body_bytes=facts.body_bytes)


class _Builder:
    def __init__(self, host: str, port: int) -> None:
        self.r = _Resolver(host, port)
        self.endpoints: dict[str, dict] = {}
        self.forms: list[Form] = []
        self.external: set[str] = set()
        self.skipped = 0
        self.flags: list[Flag] = []
        self.limits: set[str] = set()
        self.metas: list[ResponseMeta] = []
        self.fetched: dict[str, list[tuple[str, int | None]]] = {}

    def add(self, kind: str, ref: str, prov: Provenance, base: str | None = None) -> None:
        status, path, keys, ext = self.r.resolve(ref, base)
        if status == "external":
            if len(self.external) < MAX_EXTERNAL:
                self.external.add(ext)
            else:
                self.limits.add(f"external origins capped at {MAX_EXTERNAL}")
            return
        if status == "skipped":
            self.skipped += 1
            return
        if kind == "preconnect":
            return  # a same-origin preconnect says nothing about a path
        if status == "route":
            kind = "client_route"
        self._put(path, kind, keys, prov)

    def _put(self, path: str, kind: str, keys: tuple[str, ...], prov: Provenance) -> None:
        e = self.endpoints.get(path)
        if e is None:
            if len(self.endpoints) >= MAX_ENDPOINTS:
                self.limits.add(f"endpoints capped at {MAX_ENDPOINTS}")
                return
            e = self.endpoints[path] = {"kinds": set(), "keys": set(), "prov": []}
        e["kinds"].add(kind)
        e["keys"].update(keys)
        if len(e["prov"]) < MAX_PROVENANCE and prov not in e["prov"]:
            e["prov"].append(prov)

    def flag(self, code: str, prov: Provenance) -> None:
        if len(self.flags) < MAX_FLAGS:
            self.flags.append(Flag(code=code, provenance=prov))
        else:
            self.limits.add(f"flags capped at {MAX_FLAGS}")

    def response(self, request_id: str, sha: str, response: bytes, facts,
                 path: str = "/") -> None:
        def prov(source: str, offset: int = 0) -> Provenance:
            return Provenance(request_id=request_id, evidence_sha256=sha, source=source,
                              offset=offset)

        self.fetched.setdefault(path, []).append((request_id, facts.status_code))
        page = urljoin(self.r.base, path)  # relative references resolve against this page

        # Headers that can carry a same-origin path (Location, X-Recruiting: /#/jobs, ...).
        for h in facts.headers:
            if h.name in ("location", "content-location") or (
                    h.name not in _STANDARD_HEADERS and h.name.startswith("x-")
                    and _HEADER_PATH.fullmatch(h.value)):
                kind = "redirect" if h.name == "location" else "header_hint"
                self.add(kind, h.value, prov(f"header:{h.name}"), page)
            if _INJECTION.search(h.value):
                self.flag("injection_suspected", prov(f"header:{h.name}"))
        parts = _split_body(response)
        textual = bool(facts.content_type) and not facts.binary
        html = "html" in facts.content_type and textual
        chars = 0
        if parts is not None and textual and parts[1]:
            cm = re.search(r"charset=([A-Za-z0-9._-]+)", facts.content_type)
            try:
                text = parts[1].decode(cm.group(1) if cm else "utf-8", errors="replace")
            except LookupError:
                text = parts[1].decode("utf-8", errors="replace")
            if len(text) > MAX_SCAN_CHARS:
                self.limits.add(f"body scan capped at {MAX_SCAN_CHARS} characters")
                text = text[:MAX_SCAN_CHARS]
            chars = len(text)
            if html:
                self._html(text, prov, page)
            else:
                self._script_text(text, 0, prov, "body")
        self.metas.append(_meta(request_id, sha, facts, chars, html, path))

    def _script_text(self, text: str, base_offset: int, prov, where: str) -> None:
        for m in _API_QUOTED.finditer(text):
            self.add("api_candidate", m.group(1), prov(f"{where}:string",
                                                       base_offset + m.start(1)))
        if _INJECTION.search(text):
            self.flag("injection_suspected", prov(where, base_offset))

    def _html(self, text: str, prov, page: str | None = None) -> None:
        w = _Walker()
        try:
            w.feed_text(text)
        except (AssertionError, ValueError):  # malformed markup: keep what was read
            self.limits.add("HTML parse stopped early on malformed markup")
        base = page
        if w.base_href is not None:
            status, path, _k, _e = self.r.resolve(w.base_href[0], page)
            if status == "ok":
                base = urljoin(self.r.base, path)
            else:
                self.flag("base_href_ignored", prov("html:base@href", w.base_href[1]))
        for kind, ref, off, source in w.refs:
            self.add(kind, ref, prov(source, off), base)
        for f in w.forms[:MAX_FORMS]:
            p = prov("html:form", f["offset"])
            action = ""
            if f["action"].strip():
                status, path, _k, ext = self.r.resolve(f["action"], base)
                if status == "external":
                    self.external.add(ext)
                    self.flag("form_posts_off_origin", p)
                    continue
                if status != "ok":
                    self.skipped += 1
                    continue
                action = path
                self._put(path, "form_action", (), p)
            method = f["method"].strip().upper()
            fields = tuple(FormField(name=n, type=_bounded(t.lower(), 20))
                           for n, t in f["fields"] if _NAME_OK.fullmatch(n))[:MAX_FIELDS]
            self.forms.append(Form(action=action, method=method if method in ("GET", "POST")
                                   else "OTHER", fields=fields, provenance=p))
        if len(w.forms) > MAX_FORMS:
            self.limits.add(f"forms capped at {MAX_FORMS}")
        for data, off in w.scripts:
            self._script_text(data, off, prov, "inline-script")
        for data, off, where in w.texts:
            if _INJECTION.search(data):
                self.flag("injection_suspected", prov(where, off))

    def build(self) -> WebSurface:
        for p in self.fetched:  # a fetched path is part of the surface even if unreferenced
            if p not in self.endpoints and p != "/" and len(self.endpoints) < MAX_ENDPOINTS:
                self.endpoints[p] = {"kinds": {"fetched_only"}, "keys": set(), "prov": []}
        endpoints = tuple(Endpoint(path=p, kinds=tuple(sorted(e["kinds"])),
                                   query_keys=tuple(sorted(e["keys"]))[:20],
                                   provenance=tuple(e["prov"]),
                                   status=FETCHED if p in self.fetched else STATUS,
                                   fetches=tuple(sorted(self.fetched.get(p, ()),
                                                        key=lambda x: x[0]))[:5])
                          for p, e in sorted(self.endpoints.items()))
        return WebSurface(host=self.r.host, port=self.r.port, origin=self.r.base.rstrip("/"),
                          responses=tuple(self.metas), endpoints=endpoints,
                          forms=tuple(self.forms), external_origins=tuple(sorted(self.external)),
                          skipped_references=self.skipped, flags=tuple(self.flags),
                          limits_hit=tuple(sorted(self.limits)))


def extract_surface(host: str, port: int, responses: list[tuple]) -> WebSurface:
    """Pure: ``responses`` = [(request_id, evidence_sha256, response_bytes, HttpResponseFacts
    [, path])] already verified by the caller. Deterministic for the same input."""
    b = _Builder(host, port)
    for r in sorted(responses, key=lambda r: r[0]):
        request_id, sha, response, facts = r[:4]
        if facts is None or not facts.protocol_observed:
            continue
        b.response(request_id, sha, response, facts, r[4] if len(r) > 4 else "/")
    return b.build()


class SurfaceIssue(_Frozen):
    request_id: str
    code: str


def surfaces_from_evidence(evidence: SessionEvidence, evidence_root: Path
                           ) -> tuple[list[WebSurface], list[SurfaceIssue]]:
    """One surface per target with trusted http_probe responses. Each evidence file is
    re-read and re-checked against the SHA-256 the audit chain recorded (fail closed):
    a mismatch or an unparsable envelope excludes that response."""
    from avra.verification.evidence import HttpObservation, evidence_file

    if not evidence.trusted:
        return [], []
    groups: dict[tuple[str, int], list] = {}
    issues: list[SurfaceIssue] = []
    for o in evidence.observations:
        if not isinstance(o, HttpObservation) or o.facts is None:
            continue
        rid = o.ref.request_id
        req_path = getattr(o, "path", "/")
        tool = o.ref.tool
        try:
            path = evidence_file(Path(evidence_root), _uuid(evidence.session_id), _uuid(rid),
                                 tool)
            raw = path.read_bytes()
        except (OSError, ValueError):
            issues.append(SurfaceIssue(request_id=rid, code="evidence_unreadable"))
            continue
        if hashlib.sha256(raw).hexdigest() != o.ref.sha256:
            issues.append(SurfaceIssue(request_id=rid, code="hash_mismatch"))
            continue
        try:
            _env, _req, resp = parse_envelope(
                raw.decode("ascii"), host=o.target.host, port=o.target.port,
                path=req_path if tool == "http_get_path" else None)
        except (HttpProbeError, UnicodeDecodeError):
            issues.append(SurfaceIssue(request_id=rid, code="envelope_invalid"))
            continue
        groups.setdefault((o.target.host, o.target.port), []).append(
            (rid, o.ref.sha256, resp, o.facts, req_path))
    return [extract_surface(h, p, rs) for (h, p), rs in sorted(groups.items())], issues


def _uuid(value: str):
    import uuid

    return uuid.UUID(str(value))


def surface_digest(surface: WebSurface, limit: int = 25) -> dict:
    """Compact, bounded model view: paths, kinds, provenance POINTERS (no body text).
    Paths are server-controlled strings, restricted to a URL-safe character set."""
    priority = {"api_candidate": 0, "form_action": 1, "client_route": 2, "header_hint": 3,
                "redirect": 3, "link": 4, "script": 5, "stylesheet": 7, "resource": 8}
    ranked = sorted(surface.endpoints, key=lambda e: (min(priority.get(k, 9) for k in e.kinds),
                                                     e.path))
    return {
        "origin": surface.origin, "note": NOTE, "surface_sha256": surface.sha256(),
        "endpoint_count": len(surface.endpoints),
        "endpoints": [{"path": e.path, "kinds": list(e.kinds), "status": e.status,
                       **({"query_keys": list(e.query_keys)} if e.query_keys else {}),
                       **({"fetched_http_status": [s for _, s in e.fetches]}
                          if e.fetches else {}),
                       "evidence": sorted({p.request_id for p in e.provenance}
                                          | {r for r, _ in e.fetches}),
                       "source": e.provenance[0].source if e.provenance else "fetch"}
                      for e in ranked[:limit]],
        "forms": [{"action": f.action or "(same page)", "method": f.method,
                   "fields": [x.name for x in f.fields][:10]} for f in surface.forms[:5]],
        "external_origins_not_followed": len(surface.external_origins),
        "flags": sorted({f.code for f in surface.flags}),
        "responses": [{"request_id": m.request_id, "path": m.path,
                       "status_code": m.status_code,
                       **({"truncated_at_limit": True} if m.truncated else {}),
                       "security_headers_present": sorted(k for k, v in m.security_headers.items()
                                                          if v),
                       "cors": sorted(m.cors), "cookies": [c.name for c in m.cookies],
                       "custom_headers": list(m.custom_header_names)[:10]}
                      for m in surface.responses[:5]],
        **({"limits_hit": list(surface.limits_hit)} if surface.limits_hit else {}),
    }
