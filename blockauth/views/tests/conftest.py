"""
Shared fixtures for view-level tests.

Design principles:
- Use real DB (SQLite :memory:) for user and OTP models
- Use real token generation (HS256 with test key)
- Use real rate limiters (cache-based, cleared between tests)
- Only mock: external HTTP calls (OAuth), wallet signatures
"""

import pytest


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear Django cache before and after each test to isolate rate limiters."""
    from django.core.cache import cache

    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def api_client():
    """DRF APIClient for full HTTP request cycle testing."""
    from rest_framework.test import APIClient

    return APIClient()


@pytest.fixture
def create_user(db):
    """Factory fixture to create TestBlockUser instances."""
    from blockauth.utils.config import get_block_auth_user_model

    User = get_block_auth_user_model()

    def _create(
        email="user@test.com",
        password="TestP@ss123!",
        is_verified=True,
        **kwargs,
    ):
        user = User(email=email, is_verified=is_verified, **kwargs)
        if password:
            user.set_password(password)
        user.save()
        return user

    return _create


@pytest.fixture
def create_otp(db):
    """Factory fixture to create OTP records."""
    from blockauth.models.otp import OTP

    def _create(identifier, subject, code="ABC123", payload=None):
        return OTP.objects.create(
            identifier=identifier,
            code=code,
            subject=subject,
            payload=payload,
        )

    return _create


@pytest.fixture
def authenticated_client(api_client, create_user):
    """Returns an APIClient with real JWT auth and the associated user."""

    def _make(user=None, **user_kwargs):
        from blockauth.utils.token import Token, generate_auth_token

        if user is None:
            user = create_user(**user_kwargs)
        token = Token()
        access, _ = generate_auth_token(
            token_class=token,
            user_id=str(user.id),
        )
        api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        return api_client, user

    return _make
