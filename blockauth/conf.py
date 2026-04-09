from datetime import timedelta

from django.conf import settings
from django.core.signals import setting_changed
from rest_framework.settings import APISettings

from blockauth.constants import ConfigKeys

USER_SETTINGS = getattr(settings, "BLOCK_AUTH_SETTINGS", dict())

DEFAULTS = {
    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ALGORITHM": "HS256",
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "SECRET_KEY": settings.SECRET_KEY,
    # Asymmetric JWT (RS256/ES256): set these instead of JWT_SECRET_KEY
    "JWT_PRIVATE_KEY": None,  # PEM-encoded private key for signing
    "JWT_PUBLIC_KEY": None,  # PEM-encoded public key for verification
    "OTP_VALIDITY": timedelta(minutes=1),
    "OTP_LENGTH": 6,
    "REQUEST_LIMIT": (
        3,
        30,
    ),  # (number of request, duration in second) rate limits based on per (email, subject, and IP address)
    # Email verification settings
    "EMAIL_VERIFICATION_REQUIRED": False,  # Whether users must verify email before accessing non-auth endpoints
    # Feature flags - Enable/disable specific authentication features
    ConfigKeys.FEATURES: {
        # Core authentication features
        "SIGNUP": True,  # Enable user registration
        "BASIC_LOGIN": True,  # Enable email/password login
        "PASSWORDLESS_LOGIN": True,  # Enable passwordless login with OTP
        "WALLET_LOGIN": True,  # Enable wallet-based authentication
        "TOKEN_REFRESH": True,  # Enable JWT token refresh
        # Password management
        "PASSWORD_RESET": True,  # Enable password reset functionality
        "PASSWORD_CHANGE": True,  # Enable password change for authenticated users
        # Email management
        "EMAIL_CHANGE": True,  # Enable email change functionality
        "EMAIL_VERIFICATION": True,  # Enable email verification requirement
        # Wallet features
        "WALLET_EMAIL_ADD": True,  # Enable adding email to wallet accounts
        # Social authentication (controlled by provider configuration)
        "SOCIAL_AUTH": True,  # Master switch for social authentication
        # Passkey/WebAuthn authentication
        "PASSKEY_AUTH": True,  # Enable passkey/WebAuthn authentication (Face ID, Touch ID, Windows Hello)
        # TOTP 2FA
        "TOTP_2FA": False,  # Enable TOTP 2FA (requires TOTP_CONFIG.ENCRYPTION_KEY)
    },
    # Trigger classes
    "POST_SIGNUP_TRIGGER": "blockauth.triggers.DummyPostSignupTrigger",
    "PRE_SIGNUP_TRIGGER": "blockauth.triggers.DummyPreSignupTrigger",
    "POST_LOGIN_TRIGGER": "blockauth.triggers.DummyPostLoginTrigger",
    # Password management triggers
    "POST_PASSWORD_CHANGE_TRIGGER": "blockauth.triggers.DummyPostPasswordChangeTrigger",
    "POST_PASSWORD_RESET_TRIGGER": "blockauth.triggers.DummyPostPasswordResetTrigger",
    # other util classes
    "DEFAULT_NOTIFICATION_CLASS": "blockauth.notification.DummyNotification",
    "BLOCK_AUTH_LOGGER_CLASS": "blockauth.utils.logger.DummyLogger",
    # Wallet replay protection
    "WALLET_MESSAGE_TTL": 300,  # Signed wallet messages expire after 5 minutes
    # Refresh token rotation
    "ROTATE_REFRESH_TOKENS": True,  # Blacklist old refresh token on rotation
}


# Update defaults with provider-specific settings
for provider, settings_dict in USER_SETTINGS.get("AUTH_PROVIDERS", dict()).items():
    for key, val in settings_dict.items():
        DEFAULTS[f"{provider}_{key}"] = val

for class_name, class_object in USER_SETTINGS.get("DEFAULT_TRIGGER_CLASSES", dict()).items():
    DEFAULTS[f"{class_name}_TRIGGER"] = class_object

for key, val in USER_SETTINGS.items():
    DEFAULTS[key] = val

IMPORT_STRINGS = (
    "DEFAULT_NOTIFICATION_CLASS",
    "POST_SIGNUP_TRIGGER",
    "PRE_SIGNUP_TRIGGER",
    "POST_LOGIN_TRIGGER",
    "POST_PASSWORD_CHANGE_TRIGGER",
    "POST_PASSWORD_RESET_TRIGGER",
    "BLOCK_AUTH_LOGGER_CLASS",
)

auth_settings = APISettings(user_settings=None, defaults=DEFAULTS, import_strings=IMPORT_STRINGS)


def reload_api_settings(**kwargs) -> None:
    setting = kwargs.get("setting")
    if setting == "BLOCK_AUTH_SETTINGS":
        auth_settings.reload()


setting_changed.connect(reload_api_settings)
