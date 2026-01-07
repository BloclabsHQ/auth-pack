"""
BlockAuth Settings Module

Provides a dict-like wrapper around DRF APISettings for consistent
access across all BlockAuth sub-modules.
"""
from blockauth.conf import auth_settings, DEFAULTS


class BlockAuthSettings:
    """
    Wrapper around DRF APISettings that provides dict-like .get() access.

    This allows sub-modules like TOTP to use:
        blockauth_settings.get('TOTP_ENABLED', False)

    Instead of direct attribute access which would fail for missing keys.
    """

    def __init__(self, api_settings, defaults):
        self._settings = api_settings
        self._defaults = defaults

    def get(self, key, default=None):
        """Get a setting value with optional default."""
        try:
            return getattr(self._settings, key)
        except AttributeError:
            return self._defaults.get(key, default)

    def __getattr__(self, key):
        """Allow direct attribute access for backwards compatibility."""
        return getattr(self._settings, key)


# Create the settings wrapper
blockauth_settings = BlockAuthSettings(auth_settings, DEFAULTS)

__all__ = ['blockauth_settings', 'auth_settings']
