"""Apple endpoint throttling tests."""

import pytest
from django.core.cache import cache
from django.test import override_settings


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def apple_throttle_settings():
    with override_settings(
        BLOCK_AUTH_SETTINGS={
            "APPLE_SERVICES_ID": "com.example.services",
            "APPLE_BUNDLE_IDS": ("com.example.app",),
            "FEATURES": {"APPLE_LOGIN": True, "SOCIAL_AUTH": True},
            "APPLE_NATIVE_VERIFY_RATE_LIMIT": (1, 60),
            "APPLE_WEB_CALLBACK_RATE_LIMIT": (1, 60),
            "APPLE_NOTIFICATION_RATE_LIMIT": (1, 60),
        }
    ):
        yield


@pytest.mark.django_db
def test_native_verify_is_throttled_by_ip_before_validation(apple_throttle_settings, client):
    first = client.post("/apple/verify/", data={"id_token": "invalid"}, content_type="application/json")
    second = client.post("/apple/verify/", data={"id_token": "invalid"}, content_type="application/json")

    assert first.status_code == 400
    assert second.status_code == 429


@pytest.mark.django_db
def test_web_callback_is_throttled_by_ip_before_validation(apple_throttle_settings, client):
    first = client.post("/apple/callback/", data={"state": "missing-code"})
    second = client.post("/apple/callback/", data={"state": "missing-code"})

    assert first.status_code == 400
    assert second.status_code == 429


@pytest.mark.django_db
def test_notifications_are_throttled_by_ip_before_validation(apple_throttle_settings, client):
    first = client.post("/apple/notifications/", data={}, content_type="application/json")
    second = client.post("/apple/notifications/", data={}, content_type="application/json")

    assert first.status_code == 400
    assert second.status_code == 429
