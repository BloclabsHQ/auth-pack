"""
TOTP 2FA Serializers

DRF serializers for TOTP 2FA API endpoints.
"""

from rest_framework import serializers

from .constants import TOTPStatus


class TOTPSetupRequestSerializer(serializers.Serializer):
    """Request serializer for TOTP setup."""

    # Optional custom issuer name (uses config default if not provided)
    issuer = serializers.CharField(max_length=100, required=False, help_text="Custom issuer name for authenticator app")


class TOTPSetupResponseSerializer(serializers.Serializer):
    """Response serializer for TOTP setup."""

    secret = serializers.CharField(help_text="Base32-encoded TOTP secret (show to user for manual entry)")
    provisioning_uri = serializers.CharField(help_text="otpauth:// URI for QR code generation")
    backup_codes = serializers.ListField(
        child=serializers.CharField(), help_text="One-time backup codes (show once, then discard)"
    )
    qr_code_data = serializers.CharField(
        required=False, help_text="Base64-encoded QR code image (if generated server-side)"
    )


class TOTPConfirmRequestSerializer(serializers.Serializer):
    """Request serializer for TOTP setup confirmation."""

    code = serializers.CharField(min_length=6, max_length=8, help_text="6-digit TOTP code from authenticator app")

    def validate_code(self, value):
        """Validate TOTP code format."""
        code = value.strip()
        if not code.isdigit():
            raise serializers.ValidationError("TOTP code must be numeric")
        if len(code) not in (6, 8):
            raise serializers.ValidationError("TOTP code must be 6 or 8 digits")
        return code


class TOTPVerifyRequestSerializer(serializers.Serializer):
    """Request serializer for TOTP verification."""

    code = serializers.CharField(
        min_length=6, max_length=16, help_text="TOTP code or backup code"  # Allow for backup codes
    )

    def validate_code(self, value):
        """Normalize the code."""
        return value.strip().replace("-", "").replace(" ", "")


class TOTPVerifyResponseSerializer(serializers.Serializer):
    """Response serializer for TOTP verification."""

    success = serializers.BooleanField(help_text="Whether verification was successful")
    verification_type = serializers.ChoiceField(choices=["totp", "backup"], help_text="Type of code that was verified")
    backup_codes_remaining = serializers.IntegerField(
        required=False, help_text="Number of unused backup codes remaining"
    )


class TOTPStatusResponseSerializer(serializers.Serializer):
    """Response serializer for TOTP status."""

    enabled = serializers.BooleanField(help_text="Whether TOTP is enabled")
    status = serializers.ChoiceField(choices=[s.value for s in TOTPStatus], help_text="Current TOTP status")
    backup_codes_remaining = serializers.IntegerField(help_text="Number of unused backup codes remaining")
    enabled_at = serializers.DateTimeField(required=False, allow_null=True, help_text="When TOTP was enabled")


class TOTPDisableRequestSerializer(serializers.Serializer):
    """Request serializer for TOTP disable."""

    code = serializers.CharField(
        min_length=6, max_length=16, required=False, help_text="TOTP code or backup code for verification (recommended)"
    )
    password = serializers.CharField(required=False, help_text="User password as alternative verification")

    def validate(self, attrs):
        """Ensure at least one verification method is provided."""
        if not attrs.get("code") and not attrs.get("password"):
            raise serializers.ValidationError("Either 'code' or 'password' must be provided for verification")
        return attrs


class BackupCodesResponseSerializer(serializers.Serializer):
    """Response serializer for backup codes operations."""

    backup_codes = serializers.ListField(
        child=serializers.CharField(), help_text="New backup codes (show once, then discard)"
    )
    count = serializers.IntegerField(help_text="Number of backup codes generated")


class TOTPErrorSerializer(serializers.Serializer):
    """Serializer for TOTP error responses."""

    error = serializers.CharField(help_text="Error code")
    message = serializers.CharField(help_text="Human-readable error message")
    lockout_remaining_seconds = serializers.IntegerField(
        required=False, help_text="Seconds remaining on account lockout (if locked)"
    )
