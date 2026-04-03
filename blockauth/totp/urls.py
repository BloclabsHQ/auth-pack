"""
TOTP 2FA URL Configuration

URL patterns for TOTP 2FA API endpoints.
"""

from django.urls import path

from .views import (
    TOTPConfirmView,
    TOTPDisableView,
    TOTPRegenerateBackupCodesView,
    TOTPSetupView,
    TOTPStatusView,
    TOTPVerifyView,
)

app_name = "totp"

urlpatterns = [
    # Setup flow
    path("setup/", TOTPSetupView.as_view(), name="setup"),
    path("confirm/", TOTPConfirmView.as_view(), name="confirm"),
    # Verification
    path("verify/", TOTPVerifyView.as_view(), name="verify"),
    # Status and management
    path("status/", TOTPStatusView.as_view(), name="status"),
    path("disable/", TOTPDisableView.as_view(), name="disable"),
    # Backup codes
    path("backup-codes/regenerate/", TOTPRegenerateBackupCodesView.as_view(), name="regenerate-backup-codes"),
]
