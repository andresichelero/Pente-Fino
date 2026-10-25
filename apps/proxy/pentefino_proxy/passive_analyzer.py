from __future__ import annotations

import hashlib
import json
import logging
import posixpath
import re
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from pentefino_adapters.models import PassiveFindingRecord
from pentefino_domain.models import Observation

logger = logging.getLogger(__name__)

# Normalize alias
PassiveFinding = PassiveFindingRecord


def _normalize_url_path(raw_path: str) -> str:
    """Normalizes URL path for consistent deduplication."""
    unquoted = urllib.parse.unquote(raw_path or "/")
    unquoted = unquoted.replace("\\", "/")
    segments = [seg.split(";", 1)[0] for seg in unquoted.split("/")]
    collapsed = re.sub(r"/+", "/", "/".join(segments))
    norm = posixpath.normpath(collapsed)
    norm = re.sub(r"^/+", "/", norm)
    if not norm.startswith("/"):
        norm = f"/{norm}"
    return norm.lower()


class PassiveResponseAnalyzer:
    """
    Zero-outbound-request passive security inspection engine.
    Analyzes observed HTTP responses passing through ForwardProxyServer:
    1. Security Headers (HSTS, CSP, nosniff, X-Frame-Options, Referrer-Policy).
    2. Cookie security attributes (Secure, HttpOnly, SameSite).
    3. Information disclosure in headers (Server banners, X-Powered-By, debug headers).
    4. High-confidence secret leaks and stack traces in response bodies (with strict sanitization).
    """

    # High-confidence body leakage regex patterns
    AWS_KEY_PATTERN = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    )
    SLACK_TOKEN_PATTERN = re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")
    GITHUB_TOKEN_PATTERN = re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36})\b")
    JWT_PATTERN = re.compile(
        r"\b(eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})\b"
    )

    # Stack trace signatures
    STACK_TRACE_PATTERNS = [
        (
            "Python Traceback",
            re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
        ),
        (
            "Java Stack Trace",
            re.compile(
                r"(?:\bat [a-zA-Z0-9_.]+\([a-zA-Z0-9_]+\.java:\d+\)|Exception in thread \"[^\"]+\")"
            ),
        ),
        (
            "PHP Fatal Error",
            re.compile(
                r"(?:<b>Fatal error</b>|Fatal error: Uncaught \w+:|Parse error: syntax error)",
                re.IGNORECASE,
            ),
        ),
        (
            "Django Debug Page",
            re.compile(
                r"You're seeing this error because you have <code>DEBUG = True</code>",
                re.IGNORECASE,
            ),
        ),
        (
            "Spring Boot Whitelabel",
            re.compile(r"Whitelabel Error Page", re.IGNORECASE),
        ),
    ]

    # Sensitive cookie names that MUST have HttpOnly
    SENSITIVE_COOKIE_SUBSTRINGS = (
        "session",
        "sess",
        "token",
        "jwt",
        "sid",
        "auth",
        "phpsessid",
        "jsessionid",
        "connect.sid",
        "access_token",
        "id_token",
    )

    def __init__(self, max_body_scan_bytes: int = 524288):
        self.max_body_scan_bytes = max_body_scan_bytes

    def _get_header(self, headers: Dict[str, Any], name: str) -> Optional[str]:
        """Case-insensitive header retrieval."""
        target = name.lower()
        for k, v in headers.items():
            if k.lower() == target:
                return str(v)
        return None

    def _parse_cookies(self, headers: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parses Set-Cookie headers into structured cookie attributes."""
        cookies: List[Dict[str, Any]] = []

        # Headers can store multiple Set-Cookie as list or string
        raw_cookie_values: List[str] = []
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                if isinstance(v, list):
                    raw_cookie_values.extend(str(x) for x in v)
                elif isinstance(v, str):
                    raw_cookie_values.append(v)

        for raw in raw_cookie_values:
            # Cookies may contain multiple semicolon-delimited directives
            parts = [p.strip() for p in raw.split(";") if p.strip()]
            if not parts:
                continue

            first_part = parts[0]
            if "=" not in first_part:
                continue

            cookie_name, cookie_val = first_part.split("=", 1)
            cookie_dict: Dict[str, Any] = {
                "name": cookie_name.strip(),
                "value": cookie_val.strip(),
                "secure": False,
                "httponly": False,
                "samesite": None,
                "raw": raw,
            }

            for directive in parts[1:]:
                directive_lower = directive.lower()
                if directive_lower == "secure":
                    cookie_dict["secure"] = True
                elif directive_lower == "httponly":
                    cookie_dict["httponly"] = True
                elif directive_lower.startswith("samesite="):
                    cookie_dict["samesite"] = directive.split("=", 1)[1].strip().lower()

            cookies.append(cookie_dict)

        return cookies

    def _mask_secret(self, secret: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """Masks sensitive secret string preserving length indication."""
        if len(secret) <= prefix_len + suffix_len:
            return "[REDACTED_SECRET]"
        masked_middle = "*" * (len(secret) - prefix_len - suffix_len)
        return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"

    def analyze(
        self,
        url: str,
        status_code: int,
        headers: Dict[str, Any],
        body: Union[bytes, str],
        program_id: Optional[Union[str, uuid.UUID]] = "default",
    ) -> List[PassiveFinding]:
        """
        Executes zero-outbound-request passive inspection of HTTP response.
        Returns list of PassiveFinding records with granular deduplication keys.
        """
        findings: List[PassiveFinding] = []
        parsed = urllib.parse.urlsplit(url)
        canonical_asset = (parsed.hostname or "localhost").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        norm_path = _normalize_url_path(parsed.path)
        prog_id_str = str(program_id or "default")

        is_https = parsed.scheme.lower() == "https"
        content_type = (self._get_header(headers, "content-type") or "").lower()
        is_html = "text/html" in content_type or not content_type

        # -------------------------------------------------------------
        # 1. Security Headers Analysis
        # -------------------------------------------------------------

        # HSTS (Strict-Transport-Security)
        if is_https:
            hsts = self._get_header(headers, "strict-transport-security")
            if not hsts:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-SEC-HSTS-MISSING",
                        category="security_header",
                        title="Missing Strict-Transport-Security (HSTS) Header",
                        severity="low",
                        description="HTTPS response is missing the Strict-Transport-Security header, allowing potential SSL stripping.",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                    )
                )
            else:
                max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 15724800:  # Less than 180 days
                        findings.append(
                            self._create_finding(
                                rule_id="PASSIVE-SEC-HSTS-SHORT",
                                category="security_header",
                                title="Strict-Transport-Security max-age Too Short",
                                severity="low",
                                description=f"HSTS max-age is set to {max_age} seconds (recommended minimum: 15,724,800 seconds / 180 days).",
                                remediation="Increase HSTS max-age to at least 31536000 (1 year).",
                                url=url,
                                path=norm_path,
                                status_code=status_code,
                                prog_id=prog_id_str,
                                asset=canonical_asset,
                                port=port,
                                matched_text=hsts,
                            )
                        )

        # X-Content-Type-Options: nosniff
        nosniff = self._get_header(headers, "x-content-type-options")
        if not nosniff or "nosniff" not in nosniff.lower():
            findings.append(
                self._create_finding(
                    rule_id="PASSIVE-SEC-NOSNIFF",
                    category="security_header",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    severity="low",
                    description="Response is missing 'X-Content-Type-Options: nosniff', which permits MIME type sniffing by older browsers.",
                    remediation="Add 'X-Content-Type-Options: nosniff' header.",
                    url=url,
                    path=norm_path,
                    status_code=status_code,
                    prog_id=prog_id_str,
                    asset=canonical_asset,
                    port=port,
                )
            )

        # Content-Security-Policy (CSP)
        csp = self._get_header(headers, "content-security-policy")
        if is_html and status_code < 400:
            if not csp:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-SEC-CSP-MISSING",
                        category="security_header",
                        title="Missing Content-Security-Policy Header",
                        severity="low",
                        description="HTML response does not declare a Content-Security-Policy header, leaving users vulnerable to XSS and data injection.",
                        remediation="Implement a restrictive Content-Security-Policy with script-src, style-src, and default-src directives.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                    )
                )
            else:
                csp_lower = csp.lower()
                if "'unsafe-inline'" in csp_lower:
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-SEC-CSP-UNSAFE-INLINE",
                            category="security_header",
                            title="Content-Security-Policy Contains 'unsafe-inline'",
                            severity="low",
                            description="CSP allows 'unsafe-inline' script execution, significantly weakening XSS protections.",
                            remediation="Refactor inline scripts to external scripts and use nonces or hashes.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=csp[:200],
                        )
                    )
                if "'unsafe-eval'" in csp_lower:
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-SEC-CSP-UNSAFE-EVAL",
                            category="security_header",
                            title="Content-Security-Policy Contains 'unsafe-eval'",
                            severity="low",
                            description="CSP allows 'unsafe-eval', enabling string-to-code execution (eval(), setTimeout strings).",
                            remediation="Avoid eval() constructs and remove 'unsafe-eval' from script-src.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=csp[:200],
                        )
                    )

        # X-Frame-Options (Clickjacking)
        xfo = self._get_header(headers, "x-frame-options")
        has_frame_ancestors = csp and "frame-ancestors" in csp.lower()
        if is_html and status_code < 400 and not xfo and not has_frame_ancestors:
            findings.append(
                self._create_finding(
                    rule_id="PASSIVE-SEC-XFO-MISSING",
                    category="security_header",
                    title="Missing Clickjacking Protection (X-Frame-Options)",
                    severity="low",
                    description="HTML page does not set X-Frame-Options or CSP frame-ancestors, allowing potential clickjacking attacks via iframes.",
                    remediation="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
                    url=url,
                    path=norm_path,
                    status_code=status_code,
                    prog_id=prog_id_str,
                    asset=canonical_asset,
                    port=port,
                )
            )

        # Referrer-Policy
        referrer = self._get_header(headers, "referrer-policy")
        if referrer and referrer.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(
                self._create_finding(
                    rule_id="PASSIVE-SEC-REFERRER-INSECURE",
                    category="security_header",
                    title="Insecure Referrer-Policy Configuration",
                    severity="low",
                    description=f"Referrer-Policy is configured to '{referrer}', which may leak sensitive URL parameters to external origins.",
                    remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    url=url,
                    path=norm_path,
                    status_code=status_code,
                    prog_id=prog_id_str,
                    asset=canonical_asset,
                    port=port,
                    matched_text=referrer,
                )
            )

        # -------------------------------------------------------------
        # 2. Insecure Cookies Analysis
        # -------------------------------------------------------------
        cookies = self._parse_cookies(headers)
        for c in cookies:
            c_name = c["name"]
            c_lower = c_name.lower()
            is_sensitive_cookie = any(sub in c_lower for sub in self.SENSITIVE_COOKIE_SUBSTRINGS)

            # Missing Secure attribute on HTTPS
            if is_https and not c["secure"]:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-COOKIE-NO-SECURE",
                        category="cookie",
                        title=f"Cookie '{c_name}' Missing Secure Flag",
                        severity="low",
                        description=f"Cookie '{c_name}' was set over HTTPS without the 'Secure' attribute, risking transmission over unencrypted HTTP.",
                        remediation="Add '; Secure' to the Set-Cookie directive.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                        matched_text=f"Set-Cookie: {c_name}=...",
                    )
                )

            # Missing HttpOnly on sensitive session cookies
            if is_sensitive_cookie and not c["httponly"]:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-COOKIE-NO-HTTPONLY",
                        category="cookie",
                        title=f"Session Cookie '{c_name}' Missing HttpOnly Flag",
                        severity="medium",
                        description=f"Sensitive authentication/session cookie '{c_name}' does not set 'HttpOnly', making it readable by JavaScript via XSS.",
                        remediation="Add '; HttpOnly' to the Set-Cookie directive.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                        matched_text=f"Set-Cookie: {c_name}=...",
                    )
                )

            # Missing SameSite or SameSite=None without Secure
            if not c["samesite"]:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-COOKIE-NO-SAMESITE",
                        category="cookie",
                        title=f"Cookie '{c_name}' Missing SameSite Attribute",
                        severity="low",
                        description=f"Cookie '{c_name}' is missing the 'SameSite' attribute, relying on default browser CSRF behavior.",
                        remediation="Add '; SameSite=Lax' or '; SameSite=Strict' to the Set-Cookie directive.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                        matched_text=f"Set-Cookie: {c_name}=...",
                    )
                )
            elif c["samesite"] == "none" and not c["secure"]:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-COOKIE-SAMESITE-NONE-INSECURE",
                        category="cookie",
                        title=f"Cookie '{c_name}' SameSite=None Without Secure",
                        severity="medium",
                        description=f"Cookie '{c_name}' specifies 'SameSite=None' without the 'Secure' attribute, rejected by modern browsers.",
                        remediation="Ensure 'Secure' is set whenever 'SameSite=None' is used.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                        matched_text=f"Set-Cookie: {c_name}=...",
                    )
                )

        # -------------------------------------------------------------
        # 3. Information Leakage in Headers
        # -------------------------------------------------------------
        server_banner = self._get_header(headers, "server")
        if server_banner and re.search(r"[\w-]+/\d+(\.\d+)*", server_banner):
            findings.append(
                self._create_finding(
                    rule_id="PASSIVE-LEAK-SERVER-BANNER",
                    category="information_leakage",
                    title="Detailed Web Server Version Disclosure",
                    severity="info",
                    description=f"Server header exposes exact software version: '{server_banner}'.",
                    remediation="Configure the web server to suppress exact version banners.",
                    url=url,
                    path=norm_path,
                    status_code=status_code,
                    prog_id=prog_id_str,
                    asset=canonical_asset,
                    port=port,
                    matched_text=f"Server: {server_banner}",
                )
            )

        powered_by = self._get_header(headers, "x-powered-by")
        if powered_by:
            findings.append(
                self._create_finding(
                    rule_id="PASSIVE-LEAK-POWERED-BY",
                    category="information_leakage",
                    title="Technology Disclosure via X-Powered-By Header",
                    severity="info",
                    description=f"Response discloses backend framework/runtime: '{powered_by}'.",
                    remediation="Remove or disable the 'X-Powered-By' header in framework configuration.",
                    url=url,
                    path=norm_path,
                    status_code=status_code,
                    prog_id=prog_id_str,
                    asset=canonical_asset,
                    port=port,
                    matched_text=f"X-Powered-By: {powered_by}",
                )
            )

        for debug_header in ("x-aspnet-version", "x-debug-token", "x-sourcemap", "x-runtime"):
            dbg_val = self._get_header(headers, debug_header)
            if dbg_val:
                findings.append(
                    self._create_finding(
                        rule_id="PASSIVE-LEAK-DEBUG-HEADER",
                        category="information_leakage",
                        title=f"Diagnostic Header Exposure ({debug_header})",
                        severity="info",
                        description=f"Response exposes internal diagnostic header '{debug_header}: {dbg_val}'.",
                        remediation=f"Strip diagnostic header '{debug_header}' in production reverse proxy.",
                        url=url,
                        path=norm_path,
                        status_code=status_code,
                        prog_id=prog_id_str,
                        asset=canonical_asset,
                        port=port,
                        matched_text=f"{debug_header}: {dbg_val}",
                    )
                )

        # -------------------------------------------------------------
        # 4. Body Regex Leaks & Stack Traces (With Sanitization)
        # -------------------------------------------------------------
        if body:
            body_str: str = ""
            if isinstance(body, bytes):
                try:
                    body_str = body[: self.max_body_scan_bytes].decode("utf-8", errors="replace")
                except Exception:
                    body_str = ""
            elif isinstance(body, str):
                body_str = body[: self.max_body_scan_bytes]

            if body_str:
                # AWS Key Leak
                aws_match = self.AWS_KEY_PATTERN.search(body_str)
                if aws_match:
                    raw_key = aws_match.group(1)
                    masked = self._mask_secret(raw_key, prefix_len=4, suffix_len=4)
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-LEAK-AWS-KEY",
                            category="sensitive_data",
                            title="AWS Access Key ID Leaked in Response Body",
                            severity="high",
                            description="Response body contains an exposed AWS Access Key ID.",
                            remediation="Revoke the exposed AWS credential immediately in AWS IAM and remove hardcoded secrets.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=masked,
                        )
                    )

                # Private Key Leak
                priv_match = self.PRIVATE_KEY_PATTERN.search(body_str)
                if priv_match:
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-LEAK-PRIVATE-KEY",
                            category="sensitive_data",
                            title="Cryptographic Private Key Leaked in Response Body",
                            severity="critical",
                            description="Response body contains an unencrypted cryptographic private key header.",
                            remediation="Immediately revoke and rotate the private key and remove key files from web root.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text="-----BEGIN PRIVATE KEY... [REDACTED]-----",
                        )
                    )

                # Slack Token Leak
                slack_match = self.SLACK_TOKEN_PATTERN.search(body_str)
                if slack_match:
                    raw_token = slack_match.group(1)
                    masked = self._mask_secret(raw_token, prefix_len=5, suffix_len=4)
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-LEAK-SLACK-TOKEN",
                            category="sensitive_data",
                            title="Slack API Token Leaked in Response Body",
                            severity="high",
                            description="Response body contains an exposed Slack API token.",
                            remediation="Revoke and rotate the exposed Slack token immediately.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=masked,
                        )
                    )

                # GitHub Token Leak
                gh_match = self.GITHUB_TOKEN_PATTERN.search(body_str)
                if gh_match:
                    raw_token = gh_match.group(1)
                    masked = self._mask_secret(raw_token, prefix_len=4, suffix_len=4)
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-LEAK-GITHUB-TOKEN",
                            category="sensitive_data",
                            title="GitHub Token Leaked in Response Body",
                            severity="high",
                            description="Response body contains an exposed GitHub Personal Access Token.",
                            remediation="Revoke and reissue the exposed GitHub token.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=masked,
                        )
                    )

                # JWT Token in response body
                jwt_match = self.JWT_PATTERN.search(body_str)
                if jwt_match:
                    raw_jwt = jwt_match.group(1)
                    masked_jwt = self._mask_secret(raw_jwt, prefix_len=8, suffix_len=8)
                    findings.append(
                        self._create_finding(
                            rule_id="PASSIVE-LEAK-JWT-TOKEN",
                            category="sensitive_data",
                            title="JSON Web Token (JWT) Exposed in Response Body",
                            severity="medium",
                            description="Response body exposes a raw JSON Web Token (JWT).",
                            remediation="Verify whether token exposure in this endpoint is intended; use HttpOnly cookies for session storage.",
                            url=url,
                            path=norm_path,
                            status_code=status_code,
                            prog_id=prog_id_str,
                            asset=canonical_asset,
                            port=port,
                            matched_text=masked_jwt,
                        )
                    )

                # Stack traces
                for st_name, st_pattern in self.STACK_TRACE_PATTERNS:
                    match = st_pattern.search(body_str)
                    if match:
                        snippet = match.group(0)[:150].strip()
                        findings.append(
                            self._create_finding(
                                rule_id="PASSIVE-LEAK-STACK-TRACE",
                                category="sensitive_data",
                                title=f"Application Stack Trace Leaked ({st_name})",
                                severity="medium",
                                description=f"Response body discloses application stack trace or debug information ({st_name}).",
                                remediation="Disable debug mode and configure custom error handling pages in production.",
                                url=url,
                                path=norm_path,
                                status_code=status_code,
                                prog_id=prog_id_str,
                                asset=canonical_asset,
                                port=port,
                                matched_text=snippet,
                            )
                        )
                        break

        return findings

    def _create_finding(
        self,
        rule_id: str,
        category: str,
        title: str,
        severity: str,
        description: str,
        remediation: str,
        url: str,
        path: str,
        status_code: int,
        prog_id: str,
        asset: str,
        port: int,
        matched_text: Optional[str] = None,
    ) -> PassiveFinding:
        """Helper to construct PassiveFinding with standardized deduplication key."""
        dedup_raw = f"{prog_id}:{asset}:{port}:{path}:{rule_id}"
        dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()

        return PassiveFinding(
            rule_id=rule_id,
            category=category,
            title=title,
            severity=severity,
            description=description,
            matched_text=matched_text,
            url=url,
            path=path,
            status_code=status_code,
            dedup_key=dedup_key,
            remediation=remediation,
            confidence="high",
            evidence_level="E1",
            raw_details={
                "asset": asset,
                "port": port,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def to_observation(self, finding: PassiveFinding, asset_id: uuid.UUID) -> Observation:
        """Converts a PassiveFinding into an Observation database record."""
        return Observation(
            asset_id=asset_id,
            observation_type="passive_finding",
            raw_data=json.dumps(finding.model_dump()),
            metadata_json=finding.model_dump(),
        )
