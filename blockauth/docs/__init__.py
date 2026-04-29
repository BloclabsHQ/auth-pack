"""
BlockAuth Documentation Package

This package contains all Swagger/OpenAPI documentation for BlockAuth endpoints,
separated from business logic for better maintainability and organization.
"""

from .apple_docs import (
    apple_authorize_schema,
    apple_callback_schema,
    apple_native_verify_schema,
    apple_notifications_schema,
)
from .auth_docs import (
    basic_login_docs,
    email_change_confirm_docs,
    email_change_docs,
    password_change_docs,
    password_reset_confirm_docs,
    password_reset_docs,
    passwordless_confirm_docs,
    passwordless_login_docs,
    refresh_token_docs,
    signup_confirm_docs,
    signup_docs,
    signup_resend_otp_docs,
)
from .social_auth_docs import (
    facebook_auth_callback_schema,
    facebook_auth_login_schema,
    google_auth_callback_schema,
    google_auth_login_schema,
    google_native_verify_schema,
    linkedin_auth_callback_schema,
    linkedin_auth_login_schema,
)
from .wallet_auth_docs import wallet_email_add_docs, wallet_login_docs

# Passkey docs are in blockauth/passkey/docs/ but can be imported here for convenience
try:
    from blockauth.passkey.docs import (
        passkey_authentication_options_docs,
        passkey_authentication_verify_docs,
        passkey_credential_delete_docs,
        passkey_credential_detail_docs,
        passkey_credential_update_docs,
        passkey_credentials_list_docs,
        passkey_registration_options_docs,
        passkey_registration_verify_docs,
    )

    _passkey_docs_available = True
except ImportError:
    _passkey_docs_available = False


__all__ = [
    # Authentication docs
    "signup_docs",
    "signup_resend_otp_docs",
    "signup_confirm_docs",
    "basic_login_docs",
    "passwordless_login_docs",
    "passwordless_confirm_docs",
    "refresh_token_docs",
    "password_reset_docs",
    "password_reset_confirm_docs",
    "password_change_docs",
    "email_change_docs",
    "email_change_confirm_docs",
    # Wallet docs
    "wallet_login_docs",
    "wallet_email_add_docs",
    # Social auth docs
    "google_auth_login_schema",
    "google_auth_callback_schema",
    "google_native_verify_schema",
    "facebook_auth_login_schema",
    "facebook_auth_callback_schema",
    "linkedin_auth_login_schema",
    "linkedin_auth_callback_schema",
    # Apple Sign-In docs
    "apple_authorize_schema",
    "apple_callback_schema",
    "apple_native_verify_schema",
    "apple_notifications_schema",
    # Passkey docs (if available)
    "passkey_registration_options_docs",
    "passkey_registration_verify_docs",
    "passkey_authentication_options_docs",
    "passkey_authentication_verify_docs",
    "passkey_credentials_list_docs",
    "passkey_credential_detail_docs",
    "passkey_credential_update_docs",
    "passkey_credential_delete_docs",
]
