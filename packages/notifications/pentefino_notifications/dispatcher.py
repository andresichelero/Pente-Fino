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
        target_provider = provider
        if target_provider == "generic":
            if "hooks.slack.com" in webhook_url:
                target_provider = "slack"
            elif "discord.com" in webhook_url or "discordapp.com" in webhook_url:
                target_provider = "discord"

        body_dict = self.format_payload(alert, provider=target_provider)
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


async def dispatch_finding_alert(
    finding: Any,
    destination_urls: list[str],
    webhook_secret: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    provider: str = "generic",
) -> dict[str, bool]:
    """Dispatch sanitized webhook alerts for a Finding to multiple destinations.

    Args:
        finding: Finding model or object containing finding attributes.
        destination_urls: List of webhook endpoint URLs.
        webhook_secret: Optional HMAC signing secret.
        http_client: Optional async HTTP client for mocking or connection pooling.
        provider: Provider format ('generic', 'slack', 'discord', or 'auto').

    Returns:
        Dict mapping each destination URL to boolean success status.
    """
    if not destination_urls:
        return {}

    dispatcher = NotificationDispatcher(
        signing_secret=webhook_secret,
        http_client=http_client,
    )

    # Extract finding coordinates safely across dicts and domain objects
    program_slug = (
        getattr(finding, "program_slug", None)
        or str(getattr(finding, "program_id", "pentefino"))
    )
    canonical_key = (
        getattr(finding, "canonical_asset", None)
        or getattr(finding, "canonical_key", None)
        or str(getattr(finding, "asset_id", "target"))
    )
    detector_id = str(getattr(finding, "detector_id", "unknown"))
    evidence_level = str(getattr(finding, "evidence_level", "E2"))
    dedup_key = str(getattr(finding, "dedup_key", "0" * 64))
    advisory_id = getattr(finding, "advisory_id", None)
    severity = str(
        getattr(finding, "severity", None)
        or getattr(finding, "confidence", "high")
    )
    priority_tier = getattr(finding, "priority_tier", "standard")
    in_cisa_kev = getattr(finding, "in_cisa_kev", False)
    epss_score = getattr(finding, "epss_score", None)

    summary_parts = [
        f"Alert for {detector_id} on {canonical_key}",
        f"Tier: {priority_tier}",
    ]
    if in_cisa_kev:
        summary_parts.append("IN CISA KEV")
    if epss_score is not None:
        try:
            summary_parts.append(f"EPSS: {float(epss_score):.4f}")
        except (ValueError, TypeError):
            pass

    alert = SanitizedFindingAlert(
        program_slug=str(program_slug),
        canonical_key=str(canonical_key),
        detector_id=detector_id,
        severity=severity,
        evidence_level=evidence_level,
        dedup_key=dedup_key,
        advisory_id=str(advisory_id) if advisory_id else None,
        summary=" | ".join(summary_parts),
    )

    results: dict[str, bool] = {}
    for url in destination_urls:
        url_str = str(url).strip()
        if not url_str:
            continue
        ok = await dispatcher.send_webhook(url_str, alert, provider=provider)
        results[url_str] = ok

    return results

