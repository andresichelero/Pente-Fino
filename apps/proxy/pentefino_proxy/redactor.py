from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Dict, Optional, Union

# Regex patterns for sensitive tokens and credentials
RE_BEARER = re.compile(r"^(Bearer\s+)(\S+)", re.IGNORECASE)
RE_BASIC = re.compile(r"^(Basic\s+)(\S+)", re.IGNORECASE)
RE_TOKEN_AUTH = re.compile(r"^(Token\s+)(\S+)", re.IGNORECASE)

RE_JWT = re.compile(r"ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+PRIVATE KEY-----"
)
RE_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")

# Sensitive JSON keys
SENSITIVE_JSON_KEYS = {
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "token",
    "private_key",
    "session_id",
    "session",
    "credentials",
}

# Sensitive header names whose entire value should be masked
SENSITIVE_EXACT_HEADERS = {
    "x-api-key",
    "x-auth-token",
    "apikey",
    "api-key",
    "proxy-authorization",
    "x-amz-security-token",
}

# Max response/request body size in bytes before truncation (1 MB)
MAX_BODY_BYTES = 1024 * 1024


def redact_cookie_string(cookie_header: str) -> str:
    """
    Sanitizes Cookie header values to [REDACTED] while preserving cookie names.
    e.g. 'session=xyz123; user_id=42' -> 'session=[REDACTED]; user_id=[REDACTED]'
    """
    if not cookie_header or not cookie_header.strip():
        return "[REDACTED]"

    parts = cookie_header.split(";")
    redacted_parts = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _ = part.split("=", 1)
            redacted_parts.append(f"{name.strip()}=[REDACTED]")
        else:
            redacted_parts.append(f"{part}=[REDACTED]")

    return "; ".join(redacted_parts) if redacted_parts else "[REDACTED]"


def redact_set_cookie_string(set_cookie_header: str) -> str:
    """
    Sanitizes Set-Cookie header value while preserving security attributes (Path, Secure, HttpOnly, SameSite).
    e.g. 'PHPSESSID=abcdef; Path=/; Secure; HttpOnly' -> 'PHPSESSID=[REDACTED]; Path=/; Secure; HttpOnly'
    """
    if not set_cookie_header or not set_cookie_header.strip():
        return "[REDACTED]"

    parts = set_cookie_header.split(";")
    if not parts:
        return "[REDACTED]"

    # First part is the cookie assignment name=value
    first = parts[0].strip()
    if "=" in first:
        name, _ = first.split("=", 1)
        redacted_first = f"{name.strip()}=[REDACTED]"
    else:
        redacted_first = f"{first}=[REDACTED]"

    # Remaining parts are attributes
    attrs = [p.strip() for p in parts[1:] if p.strip()]
    if attrs:
        return f"{redacted_first}; {'; '.join(attrs)}"
    return redacted_first


class Redactor:
    """
    Data Sanitizer & Credentials Redactor.
    Enforces ADR-14 and acceptance criteria by replacing Bearer tokens, cookies,
    passwords, JWTs, and private keys with [REDACTED].
    """

    def __init__(self, max_body_size: int = MAX_BODY_BYTES):
        self.max_body_size = max_body_size

    def redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Sanitizes HTTP headers map."""
        sanitized: Dict[str, str] = {}
        for key, value in headers.items():
            key_lower = key.lower()

            # Authorization headers
            if key_lower == "authorization":
                if RE_BEARER.search(value):
                    sanitized[key] = "Bearer [REDACTED]"
                elif RE_BASIC.search(value):
                    sanitized[key] = "Basic [REDACTED]"
                elif RE_TOKEN_AUTH.search(value):
                    sanitized[key] = "Token [REDACTED]"
                else:
                    sanitized[key] = "[REDACTED]"

            # Cookie headers
            elif key_lower == "cookie":
                sanitized[key] = redact_cookie_string(value)

            # Set-Cookie headers
            elif key_lower == "set-cookie":
                sanitized[key] = redact_set_cookie_string(value)

            # Specific sensitive headers
            elif key_lower in SENSITIVE_EXACT_HEADERS:
                sanitized[key] = "[REDACTED]"

            else:
                sanitized[key] = value

        return sanitized

    def _redact_json_obj(self, obj: Any) -> Any:
        """Recursively sanitizes sensitive fields in parsed JSON data."""
        if isinstance(obj, dict):
            new_dict = {}
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() in SENSITIVE_JSON_KEYS:
                    new_dict[k] = "[REDACTED]"
                else:
                    new_dict[k] = self._redact_json_obj(v)
            return new_dict
        elif isinstance(obj, list):
            return [self._redact_json_obj(item) for item in obj]
        elif isinstance(obj, str):
            return self._redact_text_patterns(obj)
        return obj

    def _redact_text_patterns(self, text: str) -> str:
        """Applies regex pattern redaction for JWT, Private Keys, AWS Keys, etc."""
        redacted = RE_PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
        redacted = RE_JWT.sub("[REDACTED_JWT]", redacted)
        redacted = RE_AWS_KEY.sub("[REDACTED_AWS_KEY]", redacted)
        return redacted

    def redact_body(
        self,
        body: Union[str, bytes],
        content_type: Optional[str] = None,
    ) -> Union[str, bytes]:
        """
        Sanitizes request or response body content.
        Parses JSON if applicable and applies pattern scrubbing and length truncation.
        """
        if not body:
            return body

        is_bytes = isinstance(body, bytes)
        raw_bytes = body if is_bytes else body.encode("utf-8", errors="replace")

        # 1. Truncate if larger than max_body_size
        truncated = False
        if len(raw_bytes) > self.max_body_size:
            raw_bytes = raw_bytes[: self.max_body_size]
            truncated = True

        raw_str = raw_bytes.decode("utf-8", errors="replace")

        # 2. Try JSON, Form-URL-Encoded, or text pattern scrubbing
        c_type = (content_type or "").lower()
        if "application/json" in c_type or raw_str.strip().startswith(("{", "[")):
            try:
                parsed = json.loads(raw_str)
                redacted_json = self._redact_json_obj(parsed)
                raw_str = json.dumps(redacted_json, ensure_ascii=False)
            except Exception:
                raw_str = self._redact_text_patterns(raw_str)
        elif "application/x-www-form-urlencoded" in c_type or (
            not c_type and "=" in raw_str and not raw_str.strip().startswith(("<", "{", "["))
        ):
            try:
                pairs = urllib.parse.parse_qsl(raw_str, keep_blank_values=True)
                is_form = "application/x-www-form-urlencoded" in c_type or any(
                    k.lower() in SENSITIVE_JSON_KEYS for k, _ in pairs
                )
                if pairs and is_form:
                    redacted_pairs = []
                    for k, v in pairs:
                        if k.lower() in SENSITIVE_JSON_KEYS:
                            redacted_pairs.append((k, "[REDACTED]"))
                        else:
                            redacted_pairs.append((k, self._redact_text_patterns(v)))
                    raw_str = urllib.parse.urlencode(redacted_pairs, safe=":[]")
                else:
                    raw_str = self._redact_text_patterns(raw_str)
            except Exception:
                raw_str = self._redact_text_patterns(raw_str)
        else:
            raw_str = self._redact_text_patterns(raw_str)

        if truncated:
            raw_str += "\n[TRUNCATED_AT_1MB]"

        return raw_str.encode("utf-8") if is_bytes else raw_str

    def redact_interaction(self, interaction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes a full HTTP interaction dict and returns a sanitized copy.
        """
        sanitized = dict(interaction)

        # Sanitize request
        if "request" in sanitized and isinstance(sanitized["request"], dict):
            req = dict(sanitized["request"])
            if "headers" in req:
                req["headers"] = self.redact_headers(req["headers"])
            if "body" in req and req["body"]:
                content_type = req.get("headers", {}).get("Content-Type") or req.get("headers", {}).get("content-type")
                req["body"] = self.redact_body(req["body"], content_type=content_type)
            sanitized["request"] = req

        # Sanitize response
        if "response" in sanitized and isinstance(sanitized["response"], dict):
            resp = dict(sanitized["response"])
            if "headers" in resp:
                resp["headers"] = self.redact_headers(resp["headers"])
            if "body" in resp and resp["body"]:
                content_type = resp.get("headers", {}).get("Content-Type") or resp.get("headers", {}).get("content-type")
                resp["body"] = self.redact_body(resp["body"], content_type=content_type)
            sanitized["response"] = resp

        return sanitized
