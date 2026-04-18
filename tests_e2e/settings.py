"""Django settings for the BlockAuth E2E test project.

This file spins up a real Django dev server you can hit with pytest +
``requests`` or with Insomnia.  It is the only configuration where the
``_test/`` helper endpoints are exposed — do not re-use it outside the
E2E suite.
"""

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "e2e-only-secret-not-for-production"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "blockauth",
    "tests_e2e",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "tests_e2e.urls"
WSGI_APPLICATION = None

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("E2E_DB_PATH", BASE_DIR / "tests_e2e" / "e2e.sqlite3"),
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "blockauth-e2e-cache",
    }
}

AUTH_USER_MODEL = "tests_e2e.E2EUser"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True
TIME_ZONE = "UTC"

# SIWE configuration for the E2E SIWE scripts.  ``localhost`` is what
# the scripted signer uses when it builds the challenge payload.
WALLET_LOGIN_EXPECTED_DOMAINS = ("localhost",)
WALLET_LOGIN_DEFAULT_CHAIN_ID = 1
WALLET_LOGIN_NONCE_TTL_SECONDS = 300

# Feature / provider block — mirrors ``BLOCK_AUTH_SETTINGS`` production
# shape so the test run exercises the same dispatch.
BLOCK_AUTH_SETTINGS = {
    "SECRET_KEY": SECRET_KEY,
    "ALGORITHM": "HS256",
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=1),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "OTP_VALIDITY": timedelta(minutes=5),
    "OTP_LENGTH": 6,
    "BLOCK_AUTH_USER_MODEL": "tests_e2e.E2EUser",
    "ROTATE_REFRESH_TOKENS": True,
    "FEATURES": {
        "SIGNUP": True,
        "BASIC_LOGIN": True,
        "PASSWORDLESS_LOGIN": True,
        "WALLET_LOGIN": True,
        "TOKEN_REFRESH": True,
        "PASSWORD_RESET": True,
        "PASSWORD_CHANGE": True,
        "EMAIL_CHANGE": True,
        "EMAIL_VERIFICATION": True,
        "WALLET_EMAIL_ADD": True,
        "WALLET_LINK": True,
        "SOCIAL_AUTH": False,  # deferred until sandbox OAuth apps exist
        "PASSKEY_AUTH": True,
        "TOTP_2FA": True,
    },
    "TOTP_CONFIG": {
        "ENCRYPTION_KEY": "e2e-totp-encryption-key-32-chars-min!!",
    },
    "PASSKEY_CONFIG": {
        "RP_ID": "localhost",
        "RP_NAME": "BlockAuth E2E",
        "ORIGIN": "http://localhost:8765",
    },
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "blockauth.authentication.JWTAuthentication",
    ],
}

# Step-up receipt secret used by tests_e2e.flows.test_stepup
STEPUP_RECEIPT_SECRET = "e2e-stepup-receipt-secret-32-chars-minimum"
