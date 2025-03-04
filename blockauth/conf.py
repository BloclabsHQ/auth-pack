from datetime import timedelta

from django.conf import settings
from django.core.signals import setting_changed
from rest_framework.settings import APISettings

USER_SETTINGS = getattr(settings, "BLOCK_AUTH_SETTINGS", dict())

DEFAULTS = {
    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ALGORITHM": "HS256",
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "SECRET_KEY": settings.SECRET_KEY,

    "OTP_VALIDITY": timedelta(minutes=1),
    "OTP_LENGTH": 6,
    "OTP_REQUEST_LIMIT": (3, 30),  # (number of request, duration in second) rate limits based on per (email, subject, and IP address)

    # Trigger classes
    "POST_SIGNUP_TRIGGER": 'blockauth.triggers.DummyPostSignupTrigger',
    "PRE_SIGNUP_TRIGGER": 'blockauth.triggers.DummyPreSignupTrigger',
    "POST_LOGIN_TRIGGER": 'blockauth.triggers.DummyPostLoginTrigger',

    # other util classes
    "DEFAULT_COMMUNICATION_CLASS": "blockauth.communication.DummyCommunication",
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
    "DEFAULT_COMMUNICATION_CLASS",
    "POST_SIGNUP_TRIGGER",
    "PRE_SIGNUP_TRIGGER",
    "POST_LOGIN_TRIGGER",
)

auth_settings = APISettings(user_settings=None, defaults=DEFAULTS, import_strings=IMPORT_STRINGS)

def reload_api_settings(**kwargs) -> None:
    setting = kwargs.get("setting")
    if setting == "BLOCK_AUTH_SETTINGS":
        auth_settings.reload()

setting_changed.connect(reload_api_settings)