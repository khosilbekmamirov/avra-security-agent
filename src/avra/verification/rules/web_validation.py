"""Passive validation rules on recorded responses (M10.4, ADR 0017).

Same evidence discipline as the web-header pack (``_HeaderRule``): only a trusted,
complete, untruncated 2xx ``GET /`` response with a body and a cleanly parsed
header section is eligible. Nothing here sends traffic.

- ``http.cors_wildcard_with_credentials`` (low): ``Access-Control-Allow-Origin: *``
  together with ``Access-Control-Allow-Credentials: true``. Browsers refuse
  credentialed reads with ``*``, so this is a misconfigured CORS policy (often a
  sign that origins are reflected elsewhere), not a proven cross-origin data leak.
- ``http.cookie_missing_httponly`` (low): a cookie set by the response lacks the
  ``HttpOnly`` flag, so page scripts (e.g. an XSS payload) could read it. Cookie
  NAMES and flags only; values are never read or reported.
"""

from __future__ import annotations

from avra.verification.rules.web_headers import (
    _CONFIRMED_BASE,
    _criteria,
    _HeaderRule,
    _values,
)


class CorsWildcardWithCredentialsRule(_HeaderRule):
    id = "http.cors_wildcard_with_credentials"
    severity = "low"
    title = "CORS wildcard combined with Allow-Credentials"
    description = ("Access-Control-Allow-Origin: * is sent together with "
                   "Access-Control-Allow-Credentials: true. Browsers reject this combination for "
                   "credentialed requests, so it signals a misconfigured CORS policy.")
    references = ("CWE-942", "OWASP Testing Guide: Testing Cross Origin Resource Sharing")
    depends_on = ("access-control-allow-origin", "access-control-allow-credentials")
    finding_code, clean_code = "cors_wildcard_with_credentials", "cors_credentials_not_combined"
    criteria = _criteria("Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: "
                         "true are both sent.",
                         "The two headers are not sent in that combination.")
    confirmed_requires = _CONFIRMED_BASE + ("sends Access-Control-Allow-Origin: * together with "
                                            "Access-Control-Allow-Credentials: true; and none "
                                            "that does not.")
    limitations = (*_HeaderRule.base_limitations,
                   ("Origin reflection cannot be observed passively (it needs a request with an "
                   "Origin header); a credentialed cross-origin read was not attempted."))

    def weak(self, o):
        acao = [v.strip() for v in _values(o, "access-control-allow-origin")]
        acac = [v.strip().lower() for v in _values(o, "access-control-allow-credentials")]
        both = bool(acao) and acao[0] == "*" and bool(acac) and acac[0] == "true"
        if both:
            return True, "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
        return False, ("no Access-Control-Allow-Credentials: true" if not acac or acac[0] != "true"
                       else f"Access-Control-Allow-Origin: {acao[0] if acao else '(none)'}")


class CookieMissingHttpOnlyRule(_HeaderRule):
    id = "http.cookie_missing_httponly"
    severity = "low"
    title = "Cookie set without the HttpOnly flag"
    description = ("A cookie set by the response lacks HttpOnly, so scripts running in the page "
                   "can read it. Whether the cookie is sensitive is not judged.")
    references = ("CWE-1004", "OWASP Session Management Cheat Sheet")
    depends_on = ()  # Set-Cookie legitimately repeats
    finding_code, clean_code = "cookie_without_httponly", "cookies_httponly_or_none"
    criteria = _criteria("At least one Set-Cookie lacks the HttpOnly attribute.",
                         "Every Set-Cookie has HttpOnly, or the response sets no cookie.")
    confirmed_requires = _CONFIRMED_BASE + ("sets a cookie without the HttpOnly attribute; and "
                                            "none where every cookie has it.")
    limitations = (*_HeaderRule.base_limitations,
                   ("Only cookies set by this response were examined; cookie values are never "
                   "read, so the cookie's sensitivity is unknown."))

    def weak(self, o):
        names = []
        for v in _values(o, "set-cookie"):
            parts = [p.strip() for p in v.split(";")]
            name = parts[0].split("=", 1)[0].strip()[:60] if parts else ""
            if not any(p.lower() == "httponly" for p in parts[1:]):
                names.append(name or "(unnamed)")
        if names:
            return True, f"cookie(s) without HttpOnly: {', '.join(sorted(set(names)))[:120]}"
        return False, ("every cookie has HttpOnly" if _values(o, "set-cookie")
                       else "no Set-Cookie in this response")


WEB_VALIDATION_RULES = (CorsWildcardWithCredentialsRule, CookieMissingHttpOnlyRule)
