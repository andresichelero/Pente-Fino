"""Sanitized Webhook Notification Dispatcher (ADR-10).

Enforces zero-secret leakage in outbound alerts: only metadata coordinates
(program_slug, canonical_key, detector_id, severity, evidence_level, dedup_key)
are transmitted. Supports HMAC-SHA256 request signing.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any
import httpx
from pydantic import BaseModel, Field

SECRET_PATTERNS = re.compile(
    r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*|Basic\s+[A-Za-z0-9+/=]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)",
    re.IGNORECASE,
)


class SanitizedFindingAlert(BaseModel):
    """Strict, credential-free alert model for outbound webhook notifications."""

    program_slug: str
    canonical_key: str
    detector_id: str
    severity: str = "info"
    evidence_level: str = "E2"
    dedup_key: str = Field(..., min_length=8, max_length=64)
    advisory_id: str | None = None
    summary: str = ""

    def scrubbed_summary(self) -> str:
        """Guarantees any accidental token in summary is redacted prior to serialization."""
        return SECRET_PATTERNS.sub("[REDACTED]", self.summary or "")


class NotificationDispatcher:
    """Dispatches sanitized finding alerts to Slack, Discord, or Generic HMAC webhooks."""

    def __init__(
        self,
        signing_secret: str | None = None,
        timeout_seconds: float = 5.0,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.signing_secret = signing_secret
        self.timeout_seconds = timeout_seconds
        self._http_client = http_client

    def compute_hmac_signature(self, payload_bytes: bytes) -> str:
        """Compute `sha256=<hex>` HMAC signature for webhook verification."""
        if not self.signing_secret:
            return ""
        digest = hmac.new(
            self.signing_secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256,
        ).hexdigest()
        return f"sha256={digest}"

    def format_payload(
        self, alert: SanitizedFindingAlert, provider: str = "generic"
    ) -> dict[str, Any]:
        """Format alert payload for Slack, Discord, or generic webhook consumers."""
        prov = provider.strip().lower()
        clean_summary = alert.scrubbed_summary()
        headline = (
            f"[{alert.severity.upper()}] [{alert.evidence_level}] "
            f"{alert.detector_id} on {alert.canonical_key} ({alert.program_slug})"
        )

        if prov == "slack":
            return {
                "text": headline,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*{headline}*\n"
                                f"• *Dedup SHA-256*: `{alert.dedup_key[:16]}...`\n"
                                f"• *Advisory*: `{alert.advisory_id or 'N/A'}`\n"
                                f"{clean_summary}"
                            ).strip(),
                        },
                    }
                ],
            }

        if prov == "discord":
            return {
                "content": headline,
                "embeds": [
                    {
                        "title": headline,
                        "description": clean_summary or "Forensic E2 evidence captured.",
                        "fields": [
                            {"name": "Program", "value": alert.program_slug, "inline": True},
                            {"name": "Asset", "value": alert.canonical_key, "inline": True},
                            {"name": "Evidence", "value": alert.evidence_level, "inline": True},
                            {"name": "Dedup Key", "value": alert.dedup_key[:16], "inline": False},
                        ],
                    }
                ],
            }

        return {
            "event": "finding.alert",
            "program_slug": alert.program_slug,
            "canonical_key": alert.canonical_key,
            "detector_id": alert.detector_id,
            "severity": alert.severity.lower(),
            "evidence_level": alert.evidence_level.upper(),
            "dedup_key": alert.dedup_key,
            "advisory_id": alert.advisory_id,
            "summary": clean_summary,
        }

    async def send_webhook(
        self,
        webhook_url: str,
        alert: SanitizedFindingAlert,
        provider: str = "generic",
    ) -> bool:
        """Serialize, sign, and POST a sanitized alert to the specified webhook URL."""
        body_dict = self.format_payload(alert, provider=provider)
        body_bytes = json.dumps(body_dict, sort_keys=True).encode("utf-8")

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "PenteFino-Webhook-Dispatcher/0.5",
        }
        sig = self.compute_hmac_signature(body_bytes)
        if sig:
            headers["X-PenteFino-Signature-256"] = sig

        try:
            if self._http_client is not None:
                resp = await self._http_client.post(
                    webhook_url, content=body_bytes, headers=headers
                )
            else:
                async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                    resp = await client.post(
                        webhook_url, content=body_bytes, headers=headers
                    )
            return 200 <= resp.status_code < 300
        except Exception:
            return False
