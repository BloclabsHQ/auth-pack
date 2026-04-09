"""
Root conftest.py — bootstraps Django for the test suite.

BlockAuth is a Django package, so tests require Django to be configured.
This file sets up a minimal Django environment for pytest.
"""

import django
from django.conf import settings


def pytest_configure():
    settings.configure(
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "blockauth",
        ],
        ROOT_URLCONF="blockauth.urls",
        SECRET_KEY="test-secret-key-not-for-production",
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        BLOCK_AUTH_SETTINGS={
            "SECRET_KEY": "test-secret-key-not-for-production",
            "ALGORITHM": "HS256",
            "BLOCK_AUTH_USER_MODEL": "auth.User",
        },
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "blockauth.authentication.JWTAuthentication",
            ],
        },
    )
    django.setup()
