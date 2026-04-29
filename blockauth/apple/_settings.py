"""Internal helper for reading BLOCK_AUTH_SETTINGS at runtime.

Used by all apple sub-modules. Reads through django.conf.settings (not the
APISettings cache in blockauth.conf) so override_settings in tests
propagates and runtime config changes are picked up on next request.
"""

from typing import Any

from django.conf import settings


def apple_setting(key: str, default: Any = None) -> Any:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    return block_settings.get(key, default)
