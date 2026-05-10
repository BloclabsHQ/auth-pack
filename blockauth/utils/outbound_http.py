"""Shared outbound HTTP settings."""

from typing import TypeAlias

from django.conf import settings

RequestsTimeout: TypeAlias = float | tuple[float, float]

DEFAULT_SOCIAL_OUTBOUND_TIMEOUT: tuple[float, float] = (3.05, 10)


def get_social_outbound_timeout() -> RequestsTimeout:
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    configured = block_settings.get(
        "SOCIAL_OUTBOUND_TIMEOUT",
        DEFAULT_SOCIAL_OUTBOUND_TIMEOUT,
    )
    if isinstance(configured, list):
        return tuple(configured)
    return configured
