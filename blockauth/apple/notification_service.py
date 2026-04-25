"""Apple server-to-server notification dispatcher.

Apple posts {"payload": "<JWT>"} to the integrator's webhook. The JWT is signed
with the same keys used for id_tokens; the audience is the integrator's
Services ID.

The `events` claim is sometimes a JSON string (legacy) and sometimes a JSON
object (newer). We parse defensively.

Event handling:
  - consent-revoked -> drop the SocialIdentity for (apple, sub)
  - account-delete  -> if user has no other social identities, delete the User
  - email-disabled / email-enabled -> log only
"""

import json
import logging
from dataclasses import dataclass
from typing import Any

from django.db import transaction

from blockauth.apple._settings import apple_setting
from blockauth.apple.constants import AppleClaimKeys, AppleNotificationEvents
from blockauth.apple.id_token_verifier import AppleIdTokenVerifier
from blockauth.social.models import SocialIdentity
from blockauth.utils.generics import import_string_or_none

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AppleNotificationDispatchResult:
    event_type: str
    handled: bool


def _parse_events_claim(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        return json.loads(raw)
    raise TypeError(f"Unexpected events claim type: {type(raw)!r}")


class AppleNotificationService:
    def dispatch(self, payload_jwt: str) -> AppleNotificationDispatchResult:
        services_id = apple_setting("APPLE_SERVICES_ID")
        if not services_id:
            raise RuntimeError("APPLE_SERVICES_ID is not configured")

        claims = AppleIdTokenVerifier().verify_raw(payload_jwt, audiences=(services_id,))
        events = _parse_events_claim(claims.get(AppleClaimKeys.EVENTS))
        event_type = str(events.get("type") or "")
        sub = str(events.get("sub") or "")
        logger.info("apple.notification.received", extra={"event_type": event_type})

        handled = False
        if event_type == AppleNotificationEvents.CONSENT_REVOKED:
            handled = self._handle_consent_revoked(sub)
        elif event_type == AppleNotificationEvents.ACCOUNT_DELETE:
            handled = self._handle_account_delete(sub)
        elif event_type in (AppleNotificationEvents.EMAIL_DISABLED, AppleNotificationEvents.EMAIL_ENABLED):
            handled = True

        trigger_path = apple_setting("APPLE_NOTIFICATION_TRIGGER")
        trigger = import_string_or_none(trigger_path) if trigger_path else None
        if trigger:
            try:
                trigger().run({"event_type": event_type, "sub": sub, "claims": claims})
            except Exception as exc:  # never let an integrator hook bring down the webhook
                logger.error("apple.notification.trigger_failed", extra={"error_class": exc.__class__.__name__})

        return AppleNotificationDispatchResult(event_type=event_type, handled=handled)

    @staticmethod
    @transaction.atomic
    def _handle_consent_revoked(sub: str) -> bool:
        identity = SocialIdentity.objects.filter(provider="apple", subject=sub).first()
        if identity is None:
            return False
        identity.delete()
        return True

    @staticmethod
    @transaction.atomic
    def _handle_account_delete(sub: str) -> bool:
        identity = SocialIdentity.objects.select_related("user").filter(provider="apple", subject=sub).first()
        if identity is None:
            return False
        user = identity.user
        other_count = SocialIdentity.objects.filter(user=user).exclude(provider="apple", subject=sub).count()
        if other_count == 0:
            user.delete()  # CASCADE removes the apple identity row too
            logger.info("apple.notification.account_deleted", extra={"user_id": str(user.id)})
            return True
        identity.delete()
        return True
