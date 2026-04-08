"""
BlockAuth TOTP 2FA Documentation Package

This package contains all Swagger/OpenAPI documentation for TOTP 2FA endpoints,
separated from business logic for better maintainability and organization.
"""

from .totp_docs import (  # Setup Flow; Verification; Status & Management
    totp_confirm_docs,
    totp_disable_docs,
    totp_regenerate_backup_codes_docs,
    totp_setup_docs,
    totp_status_docs,
    totp_verify_docs,
)

__all__ = [
    # Setup Flow
    "totp_setup_docs",
    "totp_confirm_docs",
    # Verification
    "totp_verify_docs",
    # Status & Management
    "totp_status_docs",
    "totp_disable_docs",
    "totp_regenerate_backup_codes_docs",
]
