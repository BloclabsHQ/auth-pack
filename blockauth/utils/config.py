# blockauth/utils/config.py
from blockauth.conf import auth_settings

# if the following settings are not provided, the social auth provider is considered not configured
_OPTIONAL_SETTINGS = (
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'FACEBOOK_CLIENT_ID',
    'FACEBOOK_CLIENT_SECRET',
    'LINKEDIN_CLIENT_ID',
    'LINKEDIN_CLIENT_SECRET',
)

def get_config(key: str):
    try:
        return getattr(auth_settings, key)
    except AttributeError:
        if key in _OPTIONAL_SETTINGS:
            return None
        raise AttributeError(f"Configuration key '{key}' not found")

def is_social_auth_configured(provider: str) -> bool:
    provider = provider.upper()
    return bool(get_config(f'{provider}_CLIENT_ID') and get_config(f'{provider}_CLIENT_SECRET'))