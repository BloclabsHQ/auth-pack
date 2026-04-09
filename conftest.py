"""
Root conftest.py — bootstraps Django for the test suite.

BlockAuth is a Django package, so tests require Django to be configured.
This file sets up a minimal Django environment for pytest.
"""

import django
from django.conf import settings


def pytest_configure():
    if settings.configured:
        return
    settings.configure(
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "blockauth-test-cache",
            }
        },
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "blockauth",
            "tests",
        ],
        ROOT_URLCONF="blockauth.urls",
        SECRET_KEY="test-secret-key-not-for-production",
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        BLOCK_AUTH_SETTINGS={
            "SECRET_KEY": "test-secret-key-not-for-production",
            "ALGORITHM": "HS256",
            "BLOCK_AUTH_USER_MODEL": "tests.TestBlockUser",
            "KDF_ENABLED": True,
            "KDF_MASTER_SALT": "test-platform-master-salt-32-chars-min",
            "MASTER_ENCRYPTION_KEY": "0x" + "ab" * 32,
            "PLATFORM_MASTER_SALT": "test-platform-master-salt-32-chars-min",
            "FEATURES": {
                "SIGNUP": True,
                "BASIC_LOGIN": True,
                "PASSWORDLESS_LOGIN": True,
                "WALLET_LOGIN": True,
                "TOKEN_REFRESH": True,
                "PASSWORD_RESET": True,
                "PASSWORD_CHANGE": True,
                "EMAIL_CHANGE": True,
                "WALLET_EMAIL_ADD": True,
                "SOCIAL_AUTH": True,
                "PASSKEY_AUTH": True,
            },
            "GOOGLE_CLIENT_ID": "test-google-client-id",
            "GOOGLE_CLIENT_SECRET": "test-google-client-secret",
            "GOOGLE_REDIRECT_URI": "http://localhost/auth/google/callback/",
            "FACEBOOK_CLIENT_ID": "test-facebook-client-id",
            "FACEBOOK_CLIENT_SECRET": "test-facebook-client-secret",
            "FACEBOOK_REDIRECT_URI": "http://localhost/auth/facebook/callback/",
            "LINKEDIN_CLIENT_ID": "test-linkedin-client-id",
            "LINKEDIN_CLIENT_SECRET": "test-linkedin-client-secret",
            "LINKEDIN_REDIRECT_URI": "http://localhost/auth/linkedin/callback/",
            "AUTH_PROVIDERS": {
                "GOOGLE": {
                    "CLIENT_ID": "test-google-client-id",
                    "CLIENT_SECRET": "test-google-client-secret",
                    "REDIRECT_URI": "http://localhost/auth/google/callback/",
                },
                "FACEBOOK": {
                    "CLIENT_ID": "test-facebook-client-id",
                    "CLIENT_SECRET": "test-facebook-client-secret",
                    "REDIRECT_URI": "http://localhost/auth/facebook/callback/",
                },
                "LINKEDIN": {
                    "CLIENT_ID": "test-linkedin-client-id",
                    "CLIENT_SECRET": "test-linkedin-client-secret",
                    "REDIRECT_URI": "http://localhost/auth/linkedin/callback/",
                },
            },
        },
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "blockauth.authentication.JWTAuthentication",
            ],
        },
    )
    django.setup()
