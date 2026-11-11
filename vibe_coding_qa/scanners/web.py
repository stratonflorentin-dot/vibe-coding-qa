"""Read-only security checks for a deployed website or application URL.

This is a *black-box* scanner. It never authenticates, never submits forms, and
never attempts exploitation. It performs a bounded number of plain HTTP(S)
requests and reports only what the responses actually disclosed:

* transport security - plain HTTP, TLS protocol version, certificate validity
  and expiry, and whether an HTTP request is upgraded to HTTPS;
* response-header hygiene - HSTS, CSP, clickjacking protection, MIME sniffing,
  referrer and feature policy;
* cookie flags - ``Secure``, ``HttpOnly``, ``SameSite``;
* cross-origin policy - wildcard or reflected ``Access-Control-Allow-Origin``;
* information disclosure - framework and server banners, directory listing,
  mixed content and insecure form actions;
* a small, fixed list of conventionally sensitive paths (``/.env``,
  ``/.git/config``, backups, actuator endpoints).

Two properties matter for trustworthiness:

* **Bounded** - every request is capped by count and timeout, so a scan cannot
  turn into a flood or hang forever.
* **No false positives from catch-all routing** - single-page apps answer ``200``
  for every path, so a "sensitive file" is only reported when its body differs
  from the site's own index page *and* matches the expected content shape.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from vibe_coding_qa import Finding, Severity


class _BudgetExceeded(Exception):
    """Raised internally when the bounded request budget is spent."""


class _NoRedirect(HTTPRedirectHandler):
    """Redirects are followed manually so each hop is counted and inspected."""

    def redirect_request(self, *args, **kwargs):  # noqa: D102 - see urllib
        return None


@dataclass(frozen=True)
class WebScanLimits:
    """Hard bounds. A web scan must never become a flood or an infinite wait."""

    timeout: float = 8.0
    max_requests: int = 60
    max_body_bytes: int = 400_000
    max_redirects: int = 5
    max_links: int = 40
    user_agent: str = "vibe-coding-qa-web-scan/0.5 (read-only authorised check)"


@dataclass
class WebResponse:
    """A single observed HTTP response."""

    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="ignore")

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";", 1)[0].strip().lower()

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class HttpFetcher:
    """Bounded HTTP client with manual redirects and TLS-error capture."""

    def __init__(self, limits: WebScanLimits):
        self.limits = limits
        self.requests = 0
        self.tls_error: str | None = None

    def get(self, url: str, *, follow: bool = True, headers: dict[str, str] | None = None) -> WebResponse:
        return self._follow(url, follow=follow, headers=headers, method="GET")

    def options(self, url: str) -> WebResponse:
        return self._once(url, headers=None, method="OPTIONS")

    def _follow(
        self, url: str, *, follow: bool, headers: dict[str, str] | None, method: str
    ) -> WebResponse:
        current = url
        for _ in range(self.limits.max_redirects + 1):
            response = self._once(current, headers=headers, method=method)
            location = response.header("location")
            if follow and response.status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            if follow and current != url:
                response.url = current
            return response
        return WebResponse(url=current, status=0, error="Too many redirects")

    # -------------------------------------------------------------- internals
    def _once(self, url: str, *, headers: dict[str, str] | None, method: str = "GET") -> WebResponse:
        if self.requests >= self.limits.max_requests:
            raise _BudgetExceeded
        self.requests += 1

        request = Request(
            url,
            method=method,
            headers={
                "User-Agent": self.limits.user_agent,
                "Accept": "*/*",
                **(headers or {}),
            },
        )
        # A certificate that fails verification is itself a finding, and the scan
        # must still be able to report the site's headers, so retry unverified.
        for verify in (True, False):
            try:
                with self._opener(verify).open(request, timeout=self.limits.timeout) as response:
                    return WebResponse(
                        url=str(response.geturl()),
                        status=int(response.status),
                        headers={k.lower(): v for k, v in response.headers.items()},
                        body=response.read(self.limits.max_body_bytes),
                    )
            except HTTPError as exc:
                raw = exc.read(self.limits.max_body_bytes) if exc.fp else b""
                return WebResponse(
                    url=str(exc.geturl() or url),
                    status=int(exc.code),
                    headers={k.lower(): v for k, v in (exc.headers or {}).items()},
                    body=raw,
                )
            except URLError as exc:
                reason = exc.reason
                if isinstance(reason, ssl.SSLCertVerificationError):
                    self.tls_error = _ssl_reason(reason)
                    if verify:
                        continue
                return WebResponse(url=url, status=0, error=_ssl_reason(reason))

        return WebResponse(url=url, status=0, error="The request could not be completed.")

    def _opener(self, verify: bool):
        context = ssl.create_default_context() if verify else ssl._create_unverified_context()
        return build_opener(_NoRedirect(), HTTPSHandler(context=context))


def _ssl_reason(reason: object) -> str:
    if isinstance(reason, ssl.SSLCertVerificationError):
        return getattr(reason, "verify_message", None) or str(reason)
    return str(reason)


# --------------------------------------------------------------------- checks
#: A deliberately small, fixed list. These are the paths an operator most often
#: leaves exposed; anything broader would be a crawler, not a check.
_SENSITIVE_PATHS: tuple[tuple[str, Severity, str, str, str | None], ...] = (
    ("/.env", Severity.CRITICAL, "exposed-env-file", "A .env file is downloadable.", r"(?m)^[A-Z0-9_]{2,}\s*="),
    ("/.git/config", Severity.CRITICAL, "exposed-git-metadata", "Git metadata is downloadable.", r"\[core\]"),
    ("/.git/HEAD", Severity.CRITICAL, "exposed-git-metadata", "Git metadata is downloadable.", r"^ref:\s"),
    ("/.svn/entries", Severity.HIGH, "exposed-svn-metadata", "Subversion metadata is downloadable.", r"\d+"),
    ("/.DS_Store", Severity.LOW, "exposed-ds-store", "A macOS metadata file is downloadable.", None),
    ("/phpinfo.php", Severity.HIGH, "exposed-phpinfo", "A phpinfo() page is publicly readable.", r"PHP Version|phpinfo\(\)"),
    ("/server-status", Severity.MEDIUM, "exposed-server-status", "Apache server-status is public.", r"Apache Server Status"),
    ("/actuator/env", Severity.HIGH, "exposed-actuator", "A Spring actuator env endpoint is public.", r"propertySources"),
    ("/backup.sql", Severity.HIGH, "exposed-backup", "A database dump is downloadable.", r"(?i)(CREATE TABLE|INSERT INTO)"),
    ("/backup.zip", Severity.HIGH, "exposed-backup", "A backup archive is downloadable.", None),
    ("/wp-config.php.bak", Severity.HIGH, "exposed-backup", "A WordPress config backup is downloadable.", r"DB_PASSWORD|DB_NAME"),
    ("/config.json", Severity.HIGH, "exposed-config", "A configuration file is publicly readable.", r"\{"),
)

#: Advisory headers. Only the ones with real impact are treated as actionable.
_HEADER_RULES: tuple[tuple[str, Severity, str, str], ...] = (
    ("x-content-type-options", Severity.LOW, "missing-nosniff", "X-Content-Type-Options is missing."),
    ("referrer-policy", Severity.LOW, "missing-referrer-policy", "Referrer-Policy is missing."),
    ("permissions-policy", Severity.INFO, "missing-permissions-policy", "Permissions-Policy is missing."),
)

_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via")

_ROOT_RE = re.compile(r"<title>\s*Index of", re.IGNORECASE)
_HTTP_URL_RE = re.compile(r"""(?:src|href)\s*=\s*["'](http://[^"'>\s]+)["']""", re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r"""<form[^>]*\baction\s*=\s*["'](http://[^"'>\s]+)["']""", re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r"""<input[^>]*\btype\s*=\s*["']password["']""", re.IGNORECASE)
_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'>\s]+)["']""", re.IGNORECASE)


class WebSecurityScanner:
    """Runs the read-only checks and returns findings in the engine's shape."""

    module = "web"

    def __init__(
        self,
        target: str,
        *,
        limits: WebScanLimits | None = None,
        fetcher: HttpFetcher | None = None,
    ) -> None:
        self.target = target
        self.limits = limits or WebScanLimits()
        self.fetcher = fetcher or HttpFetcher(self.limits)
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.requests_made = 0

    # ------------------------------------------------------------------ public
    def scan(self) -> list[Finding]:
        parsed = urlsplit(self.target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        secure = parsed.scheme == "https"

        self._check_transport(parsed, origin)

        try:
            base = self.fetcher.get(self.target, headers={"Origin": "https://vcqa-probe.invalid"})
        except _BudgetExceeded:
            self.notes.append("The request budget was exhausted before the target could be fetched.")
            return self.findings

        if base.status == 0:
            self._add(
                "unreachable", Severity.HIGH, "/", 
                f"The target could not be reached: {base.error or 'no response'}.",
                "Confirm the URL is correct and publicly reachable from this machine.",
            )
            return self.findings

        self.notes.append(f"{origin} answered with HTTP {base.status} ({base.content_type or 'no content type'}).")

        self._check_headers(base, secure)
        self._check_disclosure(base)
        self._check_cookies(base, secure)
        self._check_cors(base)
        self._check_content(base, secure)
        self._check_http_upgrade(parsed)
        self._check_methods(origin)
        self._check_sensitive_paths(origin, base)
        self._map_surface(origin)

        self.notes.append(f"{self.fetcher.requests} read-only request(s) made; no exploitation was attempted.")
        return self.findings

    # ------------------------------------------------------------ transport
    def _check_transport(self, parsed, origin: str) -> None:
        if parsed.scheme != "https":
            self._add(
                "insecure-transport", Severity.HIGH, "/",
                "The site is served over plain HTTP.",
                "Serve the application over HTTPS and redirect all HTTP traffic to it.",
            )
            return

        host, port = parsed.hostname or "", parsed.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.limits.timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    self._report_tls(tls.version(), tls.getpeercert())
        except ssl.SSLCertVerificationError as exc:
            self._add(
                "invalid-certificate", Severity.HIGH, "/",
                f"The TLS certificate is not trusted: {_ssl_reason(exc)}.",
                "Install a valid certificate for this hostname (for example via Let's Encrypt).",
            )
            self._probe_unverified(host, port)
        except (ssl.SSLError, OSError) as exc:
            self._add(
                "tls-handshake-failed", Severity.MEDIUM, "/",
                f"The TLS handshake failed: {_ssl_reason(exc)}.",
                "Check the TLS configuration and the certificate chain presented by the server.",
            )

    def _probe_unverified(self, host: str, port: int) -> None:
        """Still learn the negotiated protocol when the certificate is rejected."""
        try:
            with socket.create_connection((host, port), timeout=self.limits.timeout) as raw:
                with ssl._create_unverified_context().wrap_socket(raw, server_hostname=host) as tls:
                    self._report_tls(tls.version(), tls.getpeercert())
        except (ssl.SSLError, OSError):
            return

    def _report_tls(self, version: str | None, cert: dict | None) -> None:
        if version and version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
            self._add(
                "weak-tls-version", Severity.HIGH, "/",
                f"The server negotiated the obsolete protocol {version}.",
                "Require TLS 1.2 or newer and disable SSLv3/TLS 1.0/TLS 1.1.",
            )
        if not cert:
            return
        not_after = cert.get("notAfter")
        if not not_after:
            return
        try:
            expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
        except (ValueError, OSError):
            return
        days = (expiry - datetime.now(tz=timezone.utc)).days
        if days < 0:
            self._add(
                "expired-certificate", Severity.HIGH, "/",
                f"The TLS certificate expired on {not_after}.",
                "Renew the certificate and automate renewal.",
            )
        elif days <= 30:
            self._add(
                "expiring-certificate", Severity.MEDIUM, "/",
                f"The TLS certificate expires in {days} day(s) ({not_after}).",
                "Renew the certificate and confirm automated renewal is working.",
            )

    # -------------------------------------------------------------- headers
    def _check_headers(self, response: WebResponse, secure: bool) -> None:
        if secure:
            hsts = response.header("strict-transport-security")
            if not hsts:
                self._add(
                    "missing-hsts", Severity.MEDIUM, "/",
                    "Strict-Transport-Security is missing, so browsers may downgrade to HTTP.",
                    "Send Strict-Transport-Security with a long max-age once HTTPS is confirmed working.",
                )
            else:
                match = re.search(r"max-age\s*=\s*(\d+)", hsts)
                if match and int(match.group(1)) < 15552000:
                    self._add(
                        "weak-hsts", Severity.LOW, "/",
                        f"HSTS max-age is only {match.group(1)} seconds.",
                        "Raise max-age to at least 15552000 (180 days).",
                    )

        csp = response.header("content-security-policy")
        if not csp:
            self._add(
                "missing-csp", Severity.MEDIUM, "/",
                "Content-Security-Policy is missing, so injected scripts are unrestricted.",
                "Add a Content-Security-Policy and tighten it to the origins the app actually uses.",
            )
        elif re.search(r"unsafe-(inline|eval)", csp, re.IGNORECASE):
            token = "unsafe-inline" if re.search(r"unsafe-inline", csp, re.IGNORECASE) else "unsafe-eval"
            self._add(
                "weak-csp", Severity.LOW, "/",
                f"The Content-Security-Policy allows '{token}', which weakens its protection.",
                f"Remove '{token}' and load the affected scripts from files or nonces.",
            )

        if not response.header("x-frame-options") and "frame-ancestors" not in (csp or ""):
            self._add(
                "clickjacking", Severity.MEDIUM, "/",
                "The page can be framed by any origin (no X-Frame-Options or CSP frame-ancestors).",
                "Send X-Frame-Options: DENY or add frame-ancestors to the Content-Security-Policy.",
            )

        for name, severity, rule, message in _HEADER_RULES:
            if not response.header(name):
                self._add(rule, severity, "/", message, f"Add the {name} response header.")

    def _check_disclosure(self, response: WebResponse) -> None:
        for name in _DISCLOSURE_HEADERS:
            value = response.header(name)
            if value:
                self._add(
                    "information-disclosure", Severity.LOW, "/",
                    f"The {name} header discloses implementation detail: {value[:120]}.",
                    f"Remove or genericise the {name} header at the proxy.",
                )

    # -------------------------------------------------------------- cookies
    def _check_cookies(self, response: WebResponse, secure: bool) -> None:
        raw = response.headers.get("set-cookie", "")
        if not raw:
            return
        # ``Set-Cookie`` can repeat; urllib joins them, so split defensively.
        for cookie in re.split(r",\s*(?=[^;,=]+=)", raw):
            name = cookie.split("=", 1)[0].strip()
            if not name:
                continue
            lowered = cookie.lower()
            if secure and "secure" not in lowered:
                self._add(
                    "cookie-without-secure", Severity.MEDIUM, "/",
                    f"The cookie '{name}' is set without the Secure flag.",
                    "Add the Secure flag so the cookie is never sent over plain HTTP.",
                )
            if "httponly" not in lowered:
                self._add(
                    "cookie-without-httponly", Severity.LOW, "/",
                    f"The cookie '{name}' is set without HttpOnly, so scripts can read it.",
                    "Add HttpOnly unless JavaScript genuinely needs the value.",
                )
            if "samesite" not in lowered:
                self._add(
                    "cookie-without-samesite", Severity.LOW, "/",
                    f"The cookie '{name}' is set without SameSite.",
                    "Add SameSite=Lax (or Strict) to limit cross-site sending.",
                )

    # ----------------------------------------------------------------- CORS
    def _check_cors(self, response: WebResponse) -> None:
        allow_origin = response.header("access-control-allow-origin")
        allow_credentials = response.header("access-control-allow-credentials").lower() == "true"
        if not allow_origin:
            return
        wildcard = allow_origin.strip() == "*"
        reflected = "vcqa-probe.invalid" in allow_origin
        if (wildcard or reflected) and allow_credentials:
            self._add(
                "cors-credentials-exposed", Severity.HIGH, "/",
                f"CORS returns Access-Control-Allow-Origin: {allow_origin} together with credentials.",
                "Never combine a wildcard or attacker-reflected origin with credentials; allow-list exact origins.",
            )
        elif wildcard:
            self._add(
                "cors-wildcard", Severity.LOW, "/",
                "CORS allows any origin (Access-Control-Allow-Origin: *).",
                "Restrict the allowed origins to the ones that actually need access.",
            )

    # -------------------------------------------------------------- content
    def _check_content(self, response: WebResponse, secure: bool) -> None:
        if response.content_type != "text/html":
            return
        body = response.text
        if _ROOT_RE.search(body):
            self._add(
                "directory-listing", Severity.MEDIUM, response.url,
                "Directory listing is enabled, exposing the contents of a directory.",
                "Disable automatic directory indexes on the web server.",
            )
        if not secure:
            return
        insecure_assets = {match for match in _HTTP_URL_RE.findall(body) if "localhost" not in match}
        if insecure_assets:
            example = sorted(insecure_assets)[0]
            self._add(
                "mixed-content", Severity.MEDIUM, response.url,
                f"An HTTPS page loads {len(insecure_assets)} insecure http:// asset(s), e.g. {example[:120]}.",
                "Load every subresource over HTTPS (or protocol-relative URLs) to avoid mixed content.",
            )
        insecure_forms = _FORM_ACTION_RE.findall(body)
        if insecure_forms:
            self._add(
                "insecure-form-action", Severity.HIGH, response.url,
                f"A form submits to an insecure http:// endpoint ({insecure_forms[0][:120]}).",
                "Post credentials only to HTTPS endpoints.",
            )
        if _PASSWORD_INPUT_RE.search(body):
            self.notes.append("A password field was found; the login flow was not exercised.")

    def _check_http_upgrade(self, parsed) -> None:
        """An HTTPS site should also upgrade or redirect plain-HTTP requests."""
        if parsed.scheme != "https":
            return
        plain = f"http://{parsed.netloc}{parsed.path or '/'}"
        try:
            response = self.fetcher.get(plain, follow=True)
        except _BudgetExceeded:
            return
        if response.status == 0:
            return
        if urlsplit(response.url).scheme != "https" and response.ok:
            self._add(
                "no-http-upgrade", Severity.MEDIUM, "/",
                "The site answers plain HTTP without redirecting to HTTPS.",
                "Redirect all HTTP traffic to the HTTPS origin with a 301 or 308.",
            )

    def _check_methods(self, origin: str) -> None:
        try:
            response = self.fetcher.options(origin)
        except _BudgetExceeded:
            return
        allow = response.header("allow")
        if not allow:
            return
        risky = [method for method in ("TRACE", "PUT", "DELETE") if method in allow.upper()]
        if risky:
            self._add(
                "dangerous-http-methods", Severity.MEDIUM, "/",
                f"The server advertises risky HTTP methods: {', '.join(risky)}.",
                "Disable unused methods (especially TRACE) at the web server.",
            )

    # ------------------------------------------------------- sensitive paths
    def _check_sensitive_paths(self, origin: str, base: WebResponse) -> None:
        for path, severity, rule, message, marker in _SENSITIVE_PATHS:
            try:
                response = self.fetcher.get(f"{origin}{path}", follow=False)
            except _BudgetExceeded:
                self.notes.append("Sensitive-path probing stopped early: the request budget was spent.")
                return
            if not response.ok:
                continue
            if marker is None and response.content_type == "text/html":
                continue
            if self._is_catchall(response, base):
                continue
            text = response.text
            if marker and not re.search(marker, text):
                continue
            self._add(
                rule, severity, path,
                f"{message} ({path} returned HTTP {response.status}, {len(response.body)} bytes)",
                f"Block {path} at the web server and confirm it is not included in the deployment.",
            )

    def _is_catchall(self, response: WebResponse, base: WebResponse) -> bool:
        """Single-page apps answer 200 for every path; that is not an exposure."""
        if not base.body:
            return False
        head = response.body[:2000]
        return bool(head) and head == base.body[:2000]

    # ------------------------------------------------------------- surface
    def _map_surface(self, origin: str) -> None:
        discovered: list[str] = []
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            try:
                response = self.fetcher.get(f"{origin}{path}", follow=False)
            except _BudgetExceeded:
                break
            if response.ok:
                discovered.append(path)
            elif path.endswith("security.txt"):
                self._add(
                    "missing-security-txt", Severity.INFO, path,
                    "No /.well-known/security.txt was found, so researchers cannot report issues.",
                    "Publish a security.txt with a contact address and disclosure policy.",
                )
        if discovered:
            self.notes.append(f"Public surface files found: {', '.join(discovered)}.")

        try:
            home = self.fetcher.get(origin, follow=True)
        except _BudgetExceeded:
            home = None
        if home is not None and home.content_type == "text/html":
            links: set[str] = set()
            for raw in _LINK_RE.findall(home.text):
                absolute = urljoin(home.url, raw)
                if absolute.startswith(origin) and absolute not in links:
                    links.add(absolute.split("#", 1)[0])
                if len(links) >= self.limits.max_links:
                    break
            if links:
                self.notes.append(
                    f"{len(links)} same-origin link(s) were discovered during surface mapping."
                )

    # -------------------------------------------------------------- finding
    def _add(self, rule: str, severity: Severity, location: str, message: str, suggestion: str) -> None:
        path = urlsplit(location).path if "://" in location else location
        self.findings.append(
            Finding(
                rule=f"{self.module}:{rule}",
                module=self.module,
                severity=severity,
                # A URL path is the natural "location" for a web finding. A POSIX
                # path keeps it readable and stable on Windows too.
                file=PurePosixPath(path or "/"),
                line=0,
                message=message,
                suggestion=suggestion,
                confidence="high" if severity != Severity.INFO else "medium",
            )
        )


__all__ = ["HttpFetcher", "WebResponse", "WebScanLimits", "WebSecurityScanner"]
