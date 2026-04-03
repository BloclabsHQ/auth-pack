"""
BlockAuth Passkey Documentation Package

This package contains all Swagger/OpenAPI documentation for Passkey/WebAuthn endpoints,
separated from business logic for better maintainability and organization.
"""

from .passkey_docs import (  # Registration; Authentication; Credential Management
    passkey_authentication_options_docs,
    passkey_authentication_verify_docs,
    passkey_credential_delete_docs,
    passkey_credential_detail_docs,
    passkey_credential_update_docs,
    passkey_credentials_list_docs,
    passkey_registration_options_docs,
    passkey_registration_verify_docs,
)

__all__ = [
    # Registration
    "passkey_registration_options_docs",
    "passkey_registration_verify_docs",
    # Authentication
    "passkey_authentication_options_docs",
    "passkey_authentication_verify_docs",
    # Credential Management
    "passkey_credentials_list_docs",
    "passkey_credential_detail_docs",
    "passkey_credential_update_docs",
    "passkey_credential_delete_docs",
]
