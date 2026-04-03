# blockauth/utils/config.py
import importlib

from blockauth.conf import auth_settings

# if the following settings are not provided, the social auth provider is considered not configured
_OPTIONAL_SETTINGS = (
    "GOOGLE_CLIENT_ID",
    "GOOGLE_CLIENT_SECRET",
    "FACEBOOK_CLIENT_ID",
    "FACEBOOK_CLIENT_SECRET",
    "LINKEDIN_CLIENT_ID",
    "LINKEDIN_CLIENT_SECRET",
)


def get_config(key: str):
    try:
        return getattr(auth_settings, key)
    except AttributeError:
        if key in _OPTIONAL_SETTINGS:
            return None
        raise AttributeError(f"Configuration key '{key}' not found")


def get_block_auth_user_model():
    """
    Return the Blockauth user model that is active in this project.
    """
    try:
        path = auth_settings.BLOCK_AUTH_USER_MODEL
        module_path, class_name = path.rsplit(".", 1)
        module = importlib.import_module(f"{module_path}.models")
        return getattr(module, class_name)
    except ValueError:
        raise ImproperlyConfigured("BLOCK_AUTH_USER_MODEL must be of the form 'app_label.model_name'")


def is_social_auth_configured(provider: str) -> bool:
    provider = provider.upper()
    return bool(get_config(f"{provider}_CLIENT_ID") and get_config(f"{provider}_CLIENT_SECRET"))
