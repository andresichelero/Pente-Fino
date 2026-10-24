"""PenteFino Notification Dispatcher Package (ADR-10).

Provides:
- NotificationDispatcher: Sends strictly sanitized finding alerts to Slack, Discord, or Generic HMAC webhooks.
- SanitizedFindingAlert: Validated, credential-free alert payload model.
"""
from pentefino_notifications.dispatcher import (
    NotificationDispatcher,
    SanitizedFindingAlert,
)

__all__ = [
    "NotificationDispatcher",
    "SanitizedFindingAlert",
]
