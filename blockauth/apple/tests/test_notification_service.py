"""AppleNotificationService tests.

Apple's S2S notification body is `{"payload": "<JWT>"}`. The JWT is signed with
the same Apple keys used for id_tokens. Inside, the `events` claim carries
either a JSON string (legacy) or a JSON object (newer).
"""

import json
import time
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings

from blockauth.apple.constants import AppleNotificationEvents
from blockauth.apple.exceptions import AppleNotificationVerificationFailed
from blockauth.apple.id_token_verifier import _reset_verifier_cache
from blockauth.apple.notification_service import AppleNotificationService
from blockauth.social.models import SocialIdentity

User = get_user_model()


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    cache.clear()
    _reset_verifier_cache()
    yield
    cache.clear()
    _reset_verifier_cache()


@pytest.fixture
def apple_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": (),
            # FEATURES.APPLE_LOGIN required by the Phase 16 feature-flag
            # dispatcher; without it, /apple/notifications/ doesn't route.
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


def _fresh_event_time() -> int:
    return int(time.time())


def test_account_delete_constant_is_deprecated_alias():
    assert AppleNotificationEvents.ACCOUNT_DELETE == AppleNotificationEvents.ACCOUNT_DELETED


@pytest.mark.django_db
def test_consent_revoked_deletes_social_identity_only(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="alice_user", email="alice@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.consent",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": json.dumps(
                {"type": "consent-revoked", "sub": "001234.consent", "event_time": _fresh_event_time()}
            ),
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.consent").exists()
    assert User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_account_deleted_with_only_apple_link_deletes_user(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="bob_user", email="bob@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.acct",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "account-deleted", "sub": "001234.acct", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.acct").exists()


@pytest.mark.django_db
def test_account_deleted_removes_identity_when_user_delete_does_not_cascade(
    apple_settings, build_id_token, jwks_response
):
    user = User.objects.create_user(username="soft_user", email="soft@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.soft",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "account-deleted", "sub": "001234.soft", "event_time": _fresh_event_time()},
        }
    )

    with (
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
        patch.object(User, "delete", return_value=None),
    ):
        AppleNotificationService().dispatch(payload_jwt)

    assert User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.soft").exists()


@pytest.mark.django_db
def test_account_deleted_with_other_links_keeps_user(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="carol_user", email="carol@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.dual",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    SocialIdentity.objects.create(
        provider="google",
        subject="g_dual",
        user=user,
        email_at_link="carol@example.com",
        email_verified_at_link=True,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "account-deleted", "sub": "001234.dual", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.dual").exists()
    assert SocialIdentity.objects.filter(provider="google", subject="g_dual").exists()


@pytest.mark.django_db
def test_account_deleted_event_type_deletes_user(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="official_delete_user", email="official-delete@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.official-delete",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {
                "type": "account-deleted",
                "sub": "001234.official-delete",
                "event_time": _fresh_event_time(),
            },
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        result = AppleNotificationService().dispatch(payload_jwt)

    assert result.handled is True
    assert not User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.official-delete").exists()


@pytest.mark.django_db
def test_email_disabled_is_logged_only(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="dave_user", email="dave@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.email",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "email-disabled", "sub": "001234.email", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert SocialIdentity.objects.filter(provider="apple", subject="001234.email").exists()
    assert User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_invalid_jwt_raises(apple_settings, jwks_response):
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(Exception):
            AppleNotificationService().dispatch("not-a-jwt")


@pytest.mark.django_db
def test_email_enabled_is_logged_only(apple_settings, build_id_token, jwks_response):
    """email-enabled is symmetric with email-disabled: log only, no state change."""
    user = User.objects.create_user(username="enabled_user", email="enabled@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.enabled",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "email-enabled", "sub": "001234.enabled", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        result = AppleNotificationService().dispatch(payload_jwt)

    assert result.handled is True
    assert SocialIdentity.objects.filter(provider="apple", subject="001234.enabled").exists()


@pytest.mark.django_db
def test_account_deleted_for_unknown_sub_returns_handled_false(apple_settings, build_id_token, jwks_response):
    """account-deleted for a sub with no matching SocialIdentity returns
    handled=False without raising. Apple may deliver a stale notification
    after the integrator already cleaned up; the handler must be idempotent."""
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "account-deleted", "sub": "001234.unknown.sub", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        result = AppleNotificationService().dispatch(payload_jwt)

    assert result.handled is False


@pytest.mark.django_db
def test_trigger_hook_called_with_trimmed_payload(apple_settings, build_id_token, jwks_response):
    """When APPLE_NOTIFICATION_TRIGGER is configured, the hook is called with
    {event_type, sub, event_time, user_id} only — NOT the full JWT claims.
    `user_id` is pre-resolved before the consent-revoked handler deletes
    the SocialIdentity, so the trigger can publish events / run side
    effects that reference the integrator's local id without doing a
    second lookup against the row that was just dropped."""
    user = User.objects.create_user(username="trigger_user", email="trigger@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.trigger",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    event_time = _fresh_event_time()

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "consent-revoked", "sub": "001234.trigger", "event_time": event_time},
        }
    )

    captured: dict = {}

    class _CaptureTrigger:
        def run(self, payload):
            captured.update(payload)

    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=_CaptureTrigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._CaptureTrigger",
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        AppleNotificationService().dispatch(payload_jwt)

    assert captured == {
        "event_type": "consent-revoked",
        "sub": "001234.trigger",
        "event_time": event_time,
        "user_id": str(user.pk),
    }
    # Critically: the full JWT claims (iss, aud, etc.) must NOT be in the
    # payload — that's the PII-leak defense the trigger trim implements.
    assert "claims" not in captured
    assert "iss" not in captured


@pytest.mark.django_db
def test_trigger_hook_uses_base_trigger_method(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="base_trigger_user", email="base-trigger@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.base-trigger",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {
                "type": "email-enabled",
                "sub": "001234.base-trigger",
                "event_time": _fresh_event_time(),
            },
        }
    )
    captured: dict = {}

    class _BaseStyleTrigger:
        def trigger(self, payload):
            captured.update(payload)

    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=_BaseStyleTrigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._BaseStyleTrigger",
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        AppleNotificationService().dispatch(payload_jwt)

    assert captured["event_type"] == "email-enabled"
    assert captured["user_id"] == str(user.pk)


@pytest.mark.django_db
def test_trigger_hook_exception_is_swallowed(apple_settings, build_id_token, jwks_response):
    """A trigger that raises must not crash the dispatch — the webhook MUST
    return 200 to Apple even when the integrator's hook is buggy."""
    user = User.objects.create_user(username="boom_user", email="boom@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.boom",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "consent-revoked", "sub": "001234.boom", "event_time": _fresh_event_time()},
        }
    )

    class _BoomTrigger:
        def run(self, payload):
            raise RuntimeError("trigger explodes")

    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=_BoomTrigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._BoomTrigger",
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        # Must NOT raise.
        result = AppleNotificationService().dispatch(payload_jwt)

    assert result.event_type == "consent-revoked"
    assert result.handled is True
    # The identity was still deleted before the trigger fired (state
    # changes happen first; trigger is informational).
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.boom").exists()


@pytest.mark.django_db
def test_stale_notification_is_rejected_before_mutation_or_trigger(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="stale_user", email="stale@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.stale",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "consent-revoked", "sub": "001234.stale", "event_time": 1},
        }
    )

    trigger = MagicMock()
    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=lambda: trigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._CaptureTrigger",
                "APPLE_NOTIFICATION_MAX_AGE_SECONDS": 300,
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        with pytest.raises(AppleNotificationVerificationFailed):
            AppleNotificationService().dispatch(payload_jwt)

    assert SocialIdentity.objects.filter(provider="apple", subject="001234.stale").exists()
    trigger.run.assert_not_called()
    trigger.trigger.assert_not_called()


@pytest.mark.django_db
def test_future_notification_uses_apple_notification_leeway(apple_settings, build_id_token, jwks_response):
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {
                "type": "email-enabled",
                "sub": "001234.future",
                "event_time": int(time.time()) + 30,
            },
        }
    )

    with (
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_MAX_AGE_SECONDS": 300,
                "APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS": 5,
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        with pytest.raises(AppleNotificationVerificationFailed):
            AppleNotificationService().dispatch(payload_jwt)


@pytest.mark.django_db
def test_invalid_notification_time_setting_is_runtime_error(apple_settings, build_id_token, jwks_response):
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "email-enabled", "sub": "001234.bad-config", "event_time": _fresh_event_time()},
        }
    )

    with (
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_MAX_AGE_SECONDS": "not-an-int",
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        with pytest.raises(RuntimeError, match="APPLE_NOTIFICATION_MAX_AGE_SECONDS must be an integer"):
            AppleNotificationService().dispatch(payload_jwt)


@pytest.mark.django_db
def test_replayed_notification_is_suppressed_before_second_trigger(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="replay_user", email="replay@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.replay",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    event_time = _fresh_event_time()
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "jti": "apple-s2s-event-replay-1",
            "events": {"type": "email-enabled", "sub": "001234.replay", "event_time": event_time},
        }
    )
    captured: list[dict] = []

    class _CaptureTrigger:
        def trigger(self, payload):
            captured.append(payload)

    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=_CaptureTrigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._CaptureTrigger",
                "APPLE_NOTIFICATION_MAX_AGE_SECONDS": 300,
                "APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS": 60,
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        first_result = AppleNotificationService().dispatch(payload_jwt)
        second_result = AppleNotificationService().dispatch(payload_jwt)

    assert first_result.handled is True
    assert second_result.event_type == "email-enabled"
    assert second_result.handled is False
    assert captured == [
        {
            "event_type": "email-enabled",
            "sub": "001234.replay",
            "event_time": event_time,
            "user_id": str(user.pk),
        }
    ]


@pytest.mark.django_db
def test_replay_key_normalizes_event_time_without_jti(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="normalized_replay_user", email="normalized-replay@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.normalized-replay",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    event_time = _fresh_event_time()
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {
                "type": "email-enabled",
                "sub": "001234.normalized-replay",
                "event_time": event_time * 1000,
            },
        }
    )
    equivalent_payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {
                "type": "email-enabled",
                "sub": "001234.normalized-replay",
                "event_time": event_time,
            },
        }
    )
    captured: list[dict] = []

    class _CaptureTrigger:
        def trigger(self, payload):
            captured.append(payload)

    with (
        patch(
            "blockauth.apple.notification_service.import_string_or_none",
            return_value=_CaptureTrigger,
        ),
        patch(
            "blockauth.apple.notification_service.apple_setting",
            side_effect=lambda key, default=None: {
                "APPLE_SERVICES_ID": "com.example.services",
                "APPLE_NOTIFICATION_TRIGGER": "_test._CaptureTrigger",
                "APPLE_NOTIFICATION_MAX_AGE_SECONDS": 300,
                "APPLE_NOTIFICATION_FUTURE_LEEWAY_SECONDS": 60,
            }.get(key, default),
        ),
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
    ):
        first_result = AppleNotificationService().dispatch(payload_jwt)
        second_result = AppleNotificationService().dispatch(equivalent_payload_jwt)

    assert first_result.handled is True
    assert second_result.event_type == "email-enabled"
    assert second_result.handled is False
    assert captured == [
        {
            "event_type": "email-enabled",
            "sub": "001234.normalized-replay",
            "event_time": event_time,
            "user_id": str(user.pk),
        }
    ]


@pytest.mark.django_db
def test_replay_marker_is_cleared_when_dispatch_side_effect_fails(apple_settings, build_id_token, jwks_response):
    user = User.objects.create_user(username="retry_user", email="retry@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.retry",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "jti": "apple-s2s-event-retry-1",
            "events": {
                "type": "consent-revoked",
                "sub": "001234.retry",
                "event_time": _fresh_event_time(),
            },
        }
    )
    service = AppleNotificationService()

    with (
        patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response),
        patch.object(service, "_handle_consent_revoked", side_effect=RuntimeError("database unavailable")),
    ):
        with pytest.raises(RuntimeError):
            service.dispatch(payload_jwt)

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        result = AppleNotificationService().dispatch(payload_jwt)

    assert result.handled is True
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.retry").exists()


@pytest.mark.django_db
def test_non_finite_event_time_is_rejected(apple_settings, build_id_token, jwks_response):
    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "email-enabled", "sub": "001234.nan", "event_time": "nan"},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        with pytest.raises(AppleNotificationVerificationFailed):
            AppleNotificationService().dispatch(payload_jwt)


@pytest.mark.django_db
def test_notification_endpoint_returns_200_on_valid_payload(apple_settings, build_id_token, jwks_response, client):
    user = User.objects.create_user(username="end_user", email="end@example.com", password="pw")
    SocialIdentity.objects.create(
        provider="apple",
        subject="001234.endpoint",
        user=user,
        email_at_link=None,
        email_verified_at_link=False,
    )

    payload_jwt = build_id_token(
        {
            "iss": "https://appleid.apple.com",
            "aud": "com.example.services",
            "sub": "apple-server",
            "events": {"type": "consent-revoked", "sub": "001234.endpoint", "event_time": _fresh_event_time()},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/apple/notifications/",
            data={"payload": payload_jwt},
            content_type="application/json",
        )

    assert response.status_code == 200, response.content


@pytest.mark.django_db
def test_notification_endpoint_returns_400_on_bad_payload(apple_settings, jwks_response, client):
    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        response = client.post(
            "/apple/notifications/",
            data={"payload": "not-a-real-jwt"},
            content_type="application/json",
        )

    assert response.status_code == 400
