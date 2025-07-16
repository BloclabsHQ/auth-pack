"""
BlockAuth Documentation Package

This package contains all Swagger/OpenAPI documentation for BlockAuth endpoints,
separated from business logic for better maintainability and organization.
"""

from .auth_docs import (
    signup_docs,
    signup_resend_otp_docs,
    signup_confirm_docs,
    basic_login_docs,
    passwordless_login_docs,
    passwordless_confirm_docs,
    refresh_token_docs,
    password_reset_docs,
    password_reset_confirm_docs,
    password_change_docs,
    email_change_docs,
    email_change_confirm_docs
)

from .wallet_auth_docs import (
    wallet_login_docs,
    wallet_email_add_docs
)

from .social_auth_docs import (
    google_auth_login_schema,
    google_auth_callback_schema,
    facebook_auth_login_schema,
    facebook_auth_callback_schema,
    linkedin_auth_login_schema,
    linkedin_auth_callback_schema
)


__all__ = [
    # Authentication docs
    'signup_docs',
    'signup_resend_otp_docs',
    'signup_confirm_docs',
    'basic_login_docs',
    'passwordless_login_docs',
    'passwordless_confirm_docs',
    'refresh_token_docs',
    'password_reset_docs',
    'password_reset_confirm_docs',
    'password_change_docs',
    'email_change_docs',
    'email_change_confirm_docs',
    
    # Wallet docs
    'wallet_login_docs',
    'wallet_email_add_docs',
    
    # Social auth docs
    'google_auth_login_schema',
    'google_auth_callback_schema',
    'facebook_auth_login_schema',
    'facebook_auth_callback_schema',
    'linkedin_auth_login_schema',
    'linkedin_auth_callback_schema',
] 