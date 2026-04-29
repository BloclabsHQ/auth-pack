"""Apple server-to-server notification dispatcher.

Apple posts {"payload": "<JWT>"} to the integrator's webhook. The JWT is signed
with the same keys used for id_tokens; the audience is the integrator's
Services ID.

The `events` claim is sometimes a JSON string (legacy) and sometimes a JSON
object (newer). We parse defensively.

Event handling:
  - consent-revoked -> drop the SocialIdentity for (apple, sub)
  - account-delete  -> if user has no other social identities, delete the
    SocialIdentity and then delete the User
  - email-disabled / email-enabled -> log only

Trigger contract (APPLE_NOTIFICATION_TRIGGER):
  Integrators receive a trimmed dict containing `event_type`, `sub`,
  `event_time`, and `user_id` — NOT the full decoded JWT claims. The
  payload is intentionally minimal to reduce the surface for accidental
  PII leaks if the integrator logs it. `user_id` is the integrator's own
  user identifier (resolved from the SocialIdentity before the affected
  row is mutated), so a downstream handler can publish events or run
  side-effects that need the local id without doing a second lookup
  against state we just dropped. It is `None` when no SocialIdentity row
  matched the (apple, sub) pair.
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

        # Pre-resolve the affected user_id so the post-handler trigger can
        # still reference it after consent-revoked / account-delete have
        # mutated state. Returning the id alongside the boolean keeps the
        # handler API minimal and avoids a second lookup against rows the
        # handler may have just deleted.
        handled = False
        affected_user_id: str | None = None
        if event_type == AppleNotificationEvents.CONSENT_REVOKED:
            handled, affected_user_id = self._handle_consent_revoked(sub)
        elif event_type == AppleNotificationEvents.ACCOUNT_DELETE:
            handled, affected_user_id = self._handle_account_delete(sub)
        elif event_type in (AppleNotificationEvents.EMAIL_DISABLED, AppleNotificationEvents.EMAIL_ENABLED):
            handled = True
            affected_user_id = self._lookup_user_id_for_subject(sub)
        else:
            # Unknown / unsupported event type. Log so integrators see new
            # event types Apple may add in the future without crashing.
            logger.warning(
                "apple.notification.unknown_event_type",
                extra={"event_type": event_type or "<empty>"},
            )

        trigger_path = apple_setting("APPLE_NOTIFICATION_TRIGGER")
        trigger = import_string_or_none(trigger_path) if trigger_path else None
        if trigger:
            try:
                # Trim the trigger payload to event_type/sub/event_time/user_id.
                # The full JWT claims are NOT passed — see module docstring.
                trigger().run(
                    {
                        "event_type": event_type,
                        "sub": sub,
                        "event_time": events.get("event_time"),
                        "user_id": affected_user_id,
                    }
                )
            except Exception as exc:  # never let an integrator hook bring down the webhook
                logger.error("apple.notification.trigger_failed", extra={"error_class": exc.__class__.__name__})

        return AppleNotificationDispatchResult(event_type=event_type, handled=handled)

    @staticmethod
    @transaction.atomic
    def _handle_consent_revoked(sub: str) -> tuple[bool, str | None]:
        identity = SocialIdentity.objects.select_related("user").filter(provider="apple", subject=sub).first()
        if identity is None:
            return False, None
        user_id = str(identity.user.pk)
        identity.delete()
        return True, user_id

    @staticmethod
    @transaction.atomic
    def _handle_account_delete(sub: str) -> tuple[bool, str | None]:
        identity = SocialIdentity.objects.select_related("user").filter(provider="apple", subject=sub).first()
        if identity is None:
            return False, None
        user = identity.user
        user_id = str(user.pk)
        other_count = SocialIdentity.objects.filter(user=user).exclude(provider="apple", subject=sub).count()
        if other_count == 0:
            # Do not rely solely on FK CASCADE here. Reusable apps may use
            # soft-delete user models whose delete() implementation keeps the
            # row in place, so explicitly remove the Apple identity before
            # invoking the integrator's user-delete behavior.
            identity.delete()
            user.delete()
            logger.info("apple.notification.account_deleted", extra={"user_id": user_id})
            return True, user_id
        identity.delete()
        return True, user_id

    @staticmethod
    def _lookup_user_id_for_subject(sub: str) -> str | None:
        """Return the integrator's user_id for an (apple, sub) pair without
        mutating any row. Used for read-only events (email-disabled /
        email-enabled) so the trigger still receives a usable identifier."""
        identity = SocialIdentity.objects.select_related("user").filter(provider="apple", subject=sub).first()
        return str(identity.user.pk) if identity is not None else None
