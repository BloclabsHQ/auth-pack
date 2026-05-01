"""Apple server-to-server notification dispatcher.

Apple posts {"payload": "<JWT>"} to the integrator's webhook. The JWT is signed
with the same keys used for id_tokens; the audience is the integrator's
Services ID.

The `events` claim is sometimes a JSON string (legacy) and sometimes a JSON
object (newer). We parse defensively.

Event handling:
  - consent-revoked -> drop the SocialIdentity for (apple, sub)
  - account-deleted -> if user has no other social identities, delete the
    SocialIdentity and then delete the User
  - email-disabled / email-enabled -> log only

Trigger contract (APPLE_NOTIFICATION_TRIGGER):
  Integrators receive a trimmed dict containing `event_type`, `sub`,
  normalized `event_time`, and `user_id` — NOT the full decoded JWT claims. The
  payload is intentionally minimal to reduce the surface for accidental
  PII leaks if the integrator logs it. `user_id` is the integrator's own
  user identifier (resolved from the SocialIdentity before the affected
  row is mutated), so a downstream handler can publish events or run
  side-effects that need the local id without doing a second lookup
  against state we just dropped. It is `None` when no SocialIdentity row
  matched the (apple, sub) pair.
"""

import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass
from typing import Any

from django.core.cache import cache as default_cache
from django.db import transaction

from blockauth.apple._settings import apple_setting
from blockauth.apple.constants import AppleClaimKeys, AppleNotificationEvents
from blockauth.apple.exceptions import AppleNotificationVerificationFailed
from blockauth.apple.id_token_verifier import AppleIdTokenVerifier
from blockauth.social.models import SocialIdentity
from blockauth.utils.generics import import_string_or_none

logger = logging.getLogger(__name__)

_REPLAY_CACHE_KEY_PREFIX = "blockauth:apple_notification_replay:"


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


def _event_time_seconds(value: Any) -> float:
    try:
        event_time = float(value)
    except (TypeError, ValueError) as exc:
        raise AppleNotificationVerificationFailed("Apple notification event_time is missing or invalid") from exc
    # Apple's public examples use Unix seconds. Some older field reports used
    # milliseconds, so accept both and normalize before freshness checks.
    if event_time > 9_999_999_999:
        event_time = event_time / 1000
    if not math.isfinite(event_time):
        raise AppleNotificationVerificationFailed("Apple notification event_time is not finite")
    return event_time


def _int_setting(key: str, default: int, *, minimum: int) -> int:
    try:
        value = int(apple_setting(key, default))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{key} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{key} must be >= {minimum} (got {value})")
    return value


def _max_age_seconds() -> int:
    return _int_setting("APPLE_NOTIFICATION_MAX_AGE_SECONDS", 300, minimum=1)


def _future_leeway_seconds() -> int:
    return _int_setting("APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS", 60, minimum=0)


def _normalized_event_time_value(event_time: float) -> int | float:
    return int(event_time) if event_time.is_integer() else event_time


def _stable_event_time_identity(event_time: int | float) -> str:
    return f"{float(event_time):.6f}".rstrip("0").rstrip(".")


def _validate_event_time_fresh(events: dict[str, Any]) -> int | float:
    event_time = _event_time_seconds(events.get("event_time"))
    now = time.time()
    max_age = _max_age_seconds()
    leeway = _future_leeway_seconds()
    if event_time < now - max_age:
        raise AppleNotificationVerificationFailed("Apple notification event_time is stale")
    if event_time > now + leeway:
        raise AppleNotificationVerificationFailed("Apple notification event_time is in the future")
    return _normalized_event_time_value(event_time)


def _replay_cache_key(claims: dict[str, Any], events: dict[str, Any], event_time: int | float) -> str:
    jti = claims.get("jti")
    if jti:
        replay_identity = {"aud": claims.get("aud"), "jti": str(jti)}
    else:
        replay_identity = {
            "aud": claims.get("aud"),
            "event_time": _stable_event_time_identity(event_time),
            "event_type": events.get("type"),
            "sub": events.get("sub"),
        }
    digest = hashlib.sha256(
        json.dumps(replay_identity, default=str, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    return f"{_REPLAY_CACHE_KEY_PREFIX}{digest}"


def _reserve_replay(claims: dict[str, Any], events: dict[str, Any], event_time: int | float) -> tuple[str, bool]:
    ttl_seconds = _max_age_seconds() + _future_leeway_seconds()
    cache_key = _replay_cache_key(claims, events, event_time)
    already_seen = not default_cache.add(cache_key, True, timeout=ttl_seconds)
    return cache_key, already_seen


class AppleNotificationService:
    def dispatch(self, payload_jwt: str) -> AppleNotificationDispatchResult:
        services_id = apple_setting("APPLE_SERVICES_ID")
        if not services_id:
            raise RuntimeError("APPLE_SERVICES_ID is not configured")

        claims = AppleIdTokenVerifier().verify_raw(payload_jwt, audiences=(services_id,))
        events = _parse_events_claim(claims.get(AppleClaimKeys.EVENTS))
        event_time = _validate_event_time_fresh(events)
        event_type = str(events.get("type") or "")
        sub = str(events.get("sub") or "")
        replay_cache_key, replayed = _reserve_replay(claims, events, event_time)
        if replayed:
            logger.info("apple.notification.replay_suppressed", extra={"event_type": event_type or "<empty>"})
            return AppleNotificationDispatchResult(event_type=event_type, handled=False)
        try:
            logger.info("apple.notification.received", extra={"event_type": event_type})

            # Pre-resolve the affected user_id so the post-handler trigger can
            # still reference it after consent-revoked / account-deleted have
            # mutated state. Returning the id alongside the boolean keeps the
            # handler API minimal and avoids a second lookup against rows the
            # handler may have just deleted.
            handled = False
            affected_user_id: str | None = None
            if event_type == AppleNotificationEvents.CONSENT_REVOKED:
                handled, affected_user_id = self._handle_consent_revoked(sub)
            elif event_type == AppleNotificationEvents.ACCOUNT_DELETED:
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
                    payload = {
                        "event_type": event_type,
                        "sub": sub,
                        "event_time": event_time,
                        "user_id": affected_user_id,
                    }
                    trigger_instance = trigger()
                    trigger_method = getattr(trigger_instance, "trigger", None)
                    if callable(trigger_method) and not getattr(trigger_method, "__isabstractmethod__", False):
                        trigger_method(payload)
                    else:
                        run_method = getattr(trigger_instance, "run")
                        run_method(payload)
                except Exception as exc:  # never let an integrator hook bring down the webhook
                    logger.exception(
                        "apple.notification.trigger_failed",
                        extra={"error_class": exc.__class__.__name__},
                    )

            return AppleNotificationDispatchResult(event_type=event_type, handled=handled)
        except Exception:
            default_cache.delete(replay_cache_key)
            raise

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
