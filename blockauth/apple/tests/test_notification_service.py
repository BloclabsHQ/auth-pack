"""AppleNotificationService tests.

Apple's S2S notification body is `{"payload": "<JWT>"}`. The JWT is signed with
the same Apple keys used for id_tokens. Inside, the `events` claim carries
either a JSON string (legacy) or a JSON object (newer).
"""

import json
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from blockauth.apple.id_token_verifier import _reset_verifier_cache
from blockauth.apple.notification_service import AppleNotificationService
from blockauth.social.models import SocialIdentity

User = get_user_model()


@pytest.fixture(autouse=True)
def _clear_verifier_cache():
    _reset_verifier_cache()
    yield
    _reset_verifier_cache()


@pytest.fixture
def apple_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": (),
        }
    ):
        yield


@pytest.fixture
def jwks_response(jwks_payload_bytes):
    response = MagicMock(status_code=200, content=jwks_payload_bytes)
    response.json.return_value = json.loads(jwks_payload_bytes.decode())
    return response


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
                {"type": "consent-revoked", "sub": "001234.consent", "event_time": 1700000000}
            ),
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.consent").exists()
    assert User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_account_delete_with_only_apple_link_deletes_user(apple_settings, build_id_token, jwks_response):
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
            "events": {"type": "account-delete", "sub": "001234.acct", "event_time": 1700000001},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert not User.objects.filter(id=user.id).exists()


@pytest.mark.django_db
def test_account_delete_with_other_links_keeps_user(apple_settings, build_id_token, jwks_response):
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
            "events": {"type": "account-delete", "sub": "001234.dual", "event_time": 1700000002},
        }
    )

    with patch("blockauth.utils.jwt.jwks_cache.requests.get", return_value=jwks_response):
        AppleNotificationService().dispatch(payload_jwt)

    assert User.objects.filter(id=user.id).exists()
    assert not SocialIdentity.objects.filter(provider="apple", subject="001234.dual").exists()
    assert SocialIdentity.objects.filter(provider="google", subject="g_dual").exists()


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
            "events": {"type": "email-disabled", "sub": "001234.email", "event_time": 1700000003},
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
            "events": {"type": "consent-revoked", "sub": "001234.endpoint", "event_time": 1700000004},
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
