"""
BlockAuth TOTP 2FA Documentation

This module contains comprehensive Swagger/OpenAPI documentation for TOTP 2FA endpoints.
Separated from business logic for better maintainability and organization.

TOTP (Time-based One-Time Password) provides two-factor authentication using:
- Authenticator Apps: Google Authenticator, Authy, Microsoft Authenticator, or another TOTP app
- Backup Codes: One-time recovery codes for emergency access
- RFC 6238 Compliance: Industry-standard time-based OTP algorithm
"""

from drf_spectacular.utils import OpenApiExample, OpenApiResponse

# =============================================================================
# SETUP DOCUMENTATION
# =============================================================================

totp_setup_docs = {
    "operation_id": "totp_setup",
    "summary": "Initialize TOTP 2FA Setup",
    "description": (
        "Initialize TOTP 2FA setup for the authenticated user's account.\n"
        "\n"
        "**Important**: This endpoint requires authentication. The user must already be logged in "
        "(via password, social login, passkey, etc.) before they can set up TOTP.\n"
        "\n"
        "**Flow**:\n"
        "1. Frontend calls this endpoint with JWT token\n"
        "2. Backend generates a cryptographic secret and backup codes\n"
        "3. Response includes secret (Base32) and provisioning URI for QR code\n"
        "4. User scans QR code with authenticator app (Google Authenticator, Authy, etc.)\n"
        "5. User enters generated code to `/confirm/` endpoint to complete setup\n"
        "\n"
        "**Note**: TOTP is NOT enabled until the user confirms with a valid code from their "
        "authenticator app. This ensures the user has properly configured their app.\n"
        "\n"
        "**Security**:\n"
        "- Requires valid JWT authentication\n"
        "- Secret is encrypted before storage (256-bit AES)\n"
        "- 10 single-use backup codes generated for account recovery\n"
        "- Rate limited to 3 attempts per hour\n"
        "\n"
        "**QR Code Generation**:\n"
        "Use the `provisioning_uri` to generate a QR code on the frontend:\n"
        "```javascript\n"
        "// Using qrcode.js or similar library\n"
        "QRCode.toDataURL(response.provisioning_uri)\n"
        "```\n"
        "\n"
        "**Use Cases**:\n"
        "- Adding 2FA to existing account\n"
        "- Enhancing account security\n"
        "- Compliance with security requirements\n"
        "- Enterprise security policies\n"
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "properties": {
                "issuer": {
                    "type": "string",
                    "description": (
                        "Optional custom issuer name shown in authenticator app. "
                        "Defaults to application name if not provided."
                    ),
                }
            },
        }
    },
    "examples": [
        OpenApiExample("Default Setup", value={}, request_only=True, description="Setup TOTP with default issuer name"),
        OpenApiExample(
            "Custom Issuer",
            value={"issuer": "MyApp Production"},
            request_only=True,
            description="Setup TOTP with custom issuer name shown in authenticator",
        ),
    ],
    "responses": {
        201: OpenApiResponse(
            description="TOTP setup initiated successfully. User must confirm with a valid code.",
            response={
                "type": "object",
                "properties": {
                    "secret": {
                        "type": "string",
                        "description": "Base32-encoded secret for manual entry in authenticator app",
                    },
                    "provisioning_uri": {
                        "type": "string",
                        "description": "otpauth:// URI for QR code generation (RFC 6238)",
                    },
                    "backup_codes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "One-time backup codes for account recovery (store securely!)",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "secret": "JBSWY3DPEHPK3PXP",
                        "provisioning_uri": "otpauth://totp/BlockAuth:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=BlockAuth&digits=6&period=30",
                        "backup_codes": [
                            "ABCD-EFGH",
                            "IJKL-MNOP",
                            "QRST-UVWX",
                            "YZAB-CDEF",
                            "GHIJ-KLMN",
                            "OPQR-STUV",
                            "WXYZ-1234",
                            "5678-9ABC",
                            "DEFG-HIJK",
                            "LMNO-PQRS",
                        ],
                    },
                    status_codes=[201],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Bad request - TOTP not enabled or configuration error",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string", "description": "Error code for programmatic handling"},
                    "message": {"type": "string", "description": "Human-readable error message"},
                },
            },
            examples=[
                OpenApiExample(
                    "Setup Failed",
                    value={"error": "totp_setup_failed", "message": "Failed to set up TOTP 2FA."},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Encryption Required",
                    value={
                        "error": "totp_encryption_required",
                        "message": "TOTP encryption service not configured. Secrets must be encrypted.",
                    },
                    status_codes=[400],
                ),
            ],
        ),
        409: OpenApiResponse(
            description="Conflict - TOTP already enabled for this account",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Already Enabled",
                    value={"error": "totp_already_enabled", "message": "TOTP 2FA is already enabled for this account."},
                    status_codes=[409],
                )
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required in Authorization header"),
        429: OpenApiResponse(
            description="Rate limit exceeded - too many setup attempts",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Rate Limited",
                    value={
                        "error": "rate_limit_exceeded",
                        "message": "Too many setup attempts. Please try again later.",
                    },
                    status_codes=[429],
                )
            ],
        ),
    },
}


# =============================================================================
# CONFIRM DOCUMENTATION
# =============================================================================

totp_confirm_docs = {
    "operation_id": "totp_confirm",
    "summary": "Confirm TOTP Setup",
    "description": (
        "Confirm TOTP setup by verifying a code from the user's authenticator app.\n"
        "\n"
        "**Flow**:\n"
        "1. User has already called `/setup/` and scanned QR code\n"
        "2. User opens their authenticator app to get the 6-digit code\n"
        "3. Frontend sends the code to this endpoint\n"
        "4. Backend verifies the code against the stored secret\n"
        "5. On success, TOTP is enabled for the account\n"
        "\n"
        "**Important**: This endpoint MUST be called after `/setup/` to actually enable TOTP. "
        "Without confirmation, TOTP remains in `pending_confirmation` status and cannot be "
        "used for authentication.\n"
        "\n"
        "**Security**:\n"
        "- Validates code using RFC 6238 TOTP algorithm\n"
        "- Allows ±1 time step window for clock skew tolerance\n"
        "- Rate limited to 5 attempts per minute\n"
        "- Failed attempts are logged for security auditing\n"
        "\n"
        '**Code Format**: 6-digit numeric code (e.g., "123456")\n'
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["code"],
            "properties": {
                "code": {
                    "type": "string",
                    "pattern": "^[0-9]{6}$",
                    "description": "6-digit TOTP code from authenticator app",
                }
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Confirm with Code",
            value={"code": "123456"},
            request_only=True,
            description="Confirm TOTP setup with authenticator code",
        )
    ],
    "responses": {
        200: OpenApiResponse(
            description="TOTP 2FA enabled successfully",
            response={
                "type": "object",
                "properties": {"message": {"type": "string", "description": "Success message"}},
            },
            examples=[
                OpenApiExample("Success", value={"message": "TOTP 2FA enabled successfully"}, status_codes=[200])
            ],
        ),
        400: OpenApiResponse(
            description="Invalid code or validation error",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={"error": "totp_invalid_code", "message": "Invalid TOTP code."},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Missing Code",
                    value={"error": "validation_error", "message": "Code field is required."},
                    status_codes=[400],
                ),
            ],
        ),
        404: OpenApiResponse(
            description="TOTP setup not found - user must call /setup/ first",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Not Found",
                    value={"error": "totp_not_enabled", "message": "TOTP 2FA is not enabled for this account."},
                    status_codes=[404],
                )
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Rate Limited",
                    value={
                        "error": "rate_limit_exceeded",
                        "message": "Too many confirmation attempts. Please try again later.",
                    },
                    status_codes=[429],
                )
            ],
        ),
    },
}


# =============================================================================
# VERIFY DOCUMENTATION
# =============================================================================

totp_verify_docs = {
    "operation_id": "totp_verify",
    "summary": "Verify TOTP Code",
    "description": (
        "Verify a TOTP code or backup code for two-factor authentication.\n"
        "\n"
        "**Primary Use Case**: Called during login after successful password authentication "
        "to complete 2FA verification.\n"
        "\n"
        "**Flow**:\n"
        "1. User logs in with email/password\n"
        "2. Backend checks if TOTP is enabled for the account\n"
        "3. If enabled, frontend prompts for TOTP code\n"
        "4. User enters code from authenticator app (or backup code)\n"
        "5. Frontend sends code to this endpoint\n"
        "6. On success, 2FA is complete\n"
        "\n"
        "**Accepts Two Code Types**:\n"
        '- **TOTP Code**: 6-digit code from authenticator app (e.g., "123456")\n'
        '- **Backup Code**: 8-character recovery code (e.g., "ABCD-EFGH")\n'
        "\n"
        "The endpoint automatically detects the code type based on format.\n"
        "\n"
        "**Security Features**:\n"
        "- Replay attack prevention (codes can only be used once per time window)\n"
        "- Clock skew tolerance (±1 time step)\n"
        "- Rate limiting (5 attempts per minute)\n"
        "- Account lockout after excessive failures\n"
        "- IP and user agent logging for audit trail\n"
        "\n"
        "**Backup Codes**:\n"
        "- Each backup code can only be used ONCE\n"
        "- Response includes remaining backup code count\n"
        "- Warn users when running low on backup codes\n"
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["code"],
            "properties": {"code": {"type": "string", "description": "6-digit TOTP code or 8-character backup code"}},
        }
    },
    "examples": [
        OpenApiExample(
            "TOTP Code",
            value={"code": "123456"},
            request_only=True,
            description="Verify with 6-digit TOTP code from authenticator",
        ),
        OpenApiExample(
            "Backup Code",
            value={"code": "ABCD-EFGH"},
            request_only=True,
            description="Verify with single-use backup code",
        ),
    ],
    "responses": {
        200: OpenApiResponse(
            description="Verification successful",
            response={
                "type": "object",
                "properties": {
                    "success": {"type": "boolean", "description": "Whether verification succeeded"},
                    "verification_type": {
                        "type": "string",
                        "enum": ["totp", "backup_code"],
                        "description": "Type of code that was verified",
                    },
                    "backup_codes_remaining": {
                        "type": "integer",
                        "description": "Number of unused backup codes remaining",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "TOTP Verified",
                    value={"success": True, "verification_type": "totp", "backup_codes_remaining": 10},
                    status_codes=[200],
                ),
                OpenApiExample(
                    "Backup Code Verified",
                    value={"success": True, "verification_type": "backup_code", "backup_codes_remaining": 9},
                    status_codes=[200],
                    description="Backup code used - one fewer remaining",
                ),
            ],
        ),
        400: OpenApiResponse(
            description="Validation error",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Missing Code",
                    value={"error": "validation_error", "message": "Code field is required."},
                    status_codes=[400],
                )
            ],
        ),
        401: OpenApiResponse(
            description="Invalid code or verification failed",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Invalid TOTP Code",
                    value={"error": "totp_invalid_code", "message": "Invalid TOTP code."},
                    status_codes=[401],
                ),
                OpenApiExample(
                    "Invalid Backup Code",
                    value={"error": "totp_invalid_backup_code", "message": "Invalid backup code."},
                    status_codes=[401],
                ),
                OpenApiExample(
                    "Code Already Used (Replay Attack)",
                    value={"error": "totp_code_reused", "message": "This TOTP code has already been used."},
                    status_codes=[401],
                ),
                OpenApiExample(
                    "Verification Failed",
                    value={"error": "totp_verification_failed", "message": "TOTP verification failed."},
                    status_codes=[401],
                ),
            ],
        ),
        404: OpenApiResponse(
            description="TOTP not enabled for this account",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Not Enabled",
                    value={"error": "totp_not_enabled", "message": "TOTP 2FA is not enabled for this account."},
                    status_codes=[404],
                )
            ],
        ),
        423: OpenApiResponse(
            description="Account locked due to too many failed attempts",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "lockout_remaining_seconds": {"type": "integer"},
                },
            },
            examples=[
                OpenApiExample(
                    "Account Locked",
                    value={
                        "error": "totp_account_locked",
                        "message": "Account is temporarily locked due to failed attempts.",
                        "lockout_remaining_seconds": 285,
                    },
                    status_codes=[423],
                )
            ],
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Too Many Attempts",
                    value={
                        "error": "totp_too_many_attempts",
                        "message": "Too many failed attempts. Please try again later.",
                    },
                    status_codes=[429],
                ),
                OpenApiExample(
                    "Rate Limited",
                    value={
                        "error": "rate_limit_exceeded",
                        "message": "Too many verification attempts. Please try again later.",
                    },
                    status_codes=[429],
                ),
            ],
        ),
    },
}


# =============================================================================
# STATUS DOCUMENTATION
# =============================================================================

totp_status_docs = {
    "operation_id": "totp_status",
    "summary": "Get TOTP Status",
    "description": (
        "Get the current TOTP 2FA status for the authenticated user.\n"
        "\n"
        "Returns information about whether TOTP is enabled, the current status, "
        "and the number of remaining backup codes.\n"
        "\n"
        "**Status Values**:\n"
        "- `disabled`: TOTP not set up for this account\n"
        "- `pending_confirmation`: Setup initiated but not confirmed with valid code\n"
        "- `enabled`: TOTP is fully enabled and active\n"
        "\n"
        "**Use Cases**:\n"
        "- Check if user needs to complete 2FA during login\n"
        "- Display 2FA status in account settings\n"
        '- Show backup code warnings (e.g., "Only 2 backup codes remaining")\n'
        "- Determine if setup wizard should be shown\n"
        "\n"
        "**Authentication Required**: Valid JWT access token in Authorization header\n"
        "\n"
        "**Rate Limit**: 30 requests per minute (read-only endpoint)\n"
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "responses": {
        200: OpenApiResponse(
            description="TOTP status retrieved successfully",
            response={
                "type": "object",
                "properties": {
                    "enabled": {
                        "type": "boolean",
                        "description": 'Whether TOTP is fully enabled (status == "enabled")',
                    },
                    "status": {
                        "type": "string",
                        "enum": ["disabled", "pending_confirmation", "enabled"],
                        "description": "Current TOTP status",
                    },
                    "backup_codes_remaining": {
                        "type": "integer",
                        "description": "Number of unused backup codes remaining",
                    },
                    "enabled_at": {
                        "type": "string",
                        "format": "date-time",
                        "nullable": True,
                        "description": "When TOTP was enabled (null if not enabled)",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "TOTP Enabled",
                    value={
                        "enabled": True,
                        "status": "enabled",
                        "backup_codes_remaining": 8,
                        "enabled_at": "2024-01-15T10:30:00Z",
                    },
                    status_codes=[200],
                ),
                OpenApiExample(
                    "TOTP Pending Confirmation",
                    value={
                        "enabled": False,
                        "status": "pending_confirmation",
                        "backup_codes_remaining": 10,
                        "enabled_at": None,
                    },
                    status_codes=[200],
                    description="User called /setup/ but hasn't confirmed yet",
                ),
                OpenApiExample(
                    "TOTP Disabled",
                    value={"enabled": False, "status": "disabled", "backup_codes_remaining": 0, "enabled_at": None},
                    status_codes=[200],
                    description="TOTP not set up for this account",
                ),
                OpenApiExample(
                    "Low Backup Codes Warning",
                    value={
                        "enabled": True,
                        "status": "enabled",
                        "backup_codes_remaining": 2,
                        "enabled_at": "2024-01-10T09:00:00Z",
                    },
                    status_codes=[200],
                    description="User should regenerate backup codes soon",
                ),
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Rate Limited",
                    value={"error": "rate_limit_exceeded", "message": "Too many requests. Please try again later."},
                    status_codes=[429],
                )
            ],
        ),
    },
}


# =============================================================================
# DISABLE DOCUMENTATION
# =============================================================================

totp_disable_docs = {
    "operation_id": "totp_disable",
    "summary": "Disable TOTP 2FA",
    "description": (
        "Disable TOTP 2FA for the authenticated user's account.\n"
        "\n"
        "**Warning**: This action reduces account security. The user will no longer be "
        "required to provide a TOTP code during login.\n"
        "\n"
        "**Verification Required**: For security, the user must verify their identity before "
        "disabling TOTP. Provide ONE of:\n"
        "- `code`: Valid 6-digit TOTP code from authenticator app\n"
        "- `password`: User's account password\n"
        "\n"
        "**Flow**:\n"
        "1. User requests to disable TOTP in settings\n"
        "2. Frontend prompts for TOTP code or password\n"
        "3. Send verification to this endpoint\n"
        "4. On success, TOTP is disabled immediately\n"
        "5. Backup codes are invalidated\n"
        "\n"
        "**Security**:\n"
        "- Requires re-authentication (TOTP code or password)\n"
        "- Rate limited to 3 attempts per hour\n"
        "- Action is logged in audit trail\n"
        "- User should receive email notification (handled by application)\n"
        "\n"
        "**Rate Limit**: 3 attempts per hour (sensitive security operation)\n"
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "pattern": "^[0-9]{6}$",
                    "description": "6-digit TOTP code from authenticator (alternative to password)",
                },
                "password": {"type": "string", "description": "User account password (alternative to TOTP code)"},
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Disable with TOTP Code",
            value={"code": "123456"},
            request_only=True,
            description="Verify with authenticator code before disabling",
        ),
        OpenApiExample(
            "Disable with Password",
            value={"password": "userPassword123"},
            request_only=True,
            description="Verify with account password before disabling",
        ),
    ],
    "responses": {
        200: OpenApiResponse(
            description="TOTP 2FA disabled successfully",
            response={
                "type": "object",
                "properties": {"message": {"type": "string", "description": "Success message"}},
            },
            examples=[
                OpenApiExample("Success", value={"message": "TOTP 2FA disabled successfully"}, status_codes=[200])
            ],
        ),
        401: OpenApiResponse(
            description="Verification failed - invalid code or password",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Invalid TOTP Code",
                    value={"error": "totp_invalid_code", "message": "Invalid TOTP code."},
                    status_codes=[401],
                ),
                OpenApiExample(
                    "Invalid Password",
                    value={"error": "invalid_password", "message": "Invalid password"},
                    status_codes=[401],
                ),
            ],
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Rate Limited",
                    value={
                        "error": "rate_limit_exceeded",
                        "message": "Too many disable attempts. Please try again later.",
                    },
                    status_codes=[429],
                )
            ],
        ),
    },
}


# =============================================================================
# REGENERATE BACKUP CODES DOCUMENTATION
# =============================================================================

totp_regenerate_backup_codes_docs = {
    "operation_id": "totp_regenerate_backup_codes",
    "summary": "Regenerate Backup Codes",
    "description": (
        "Generate new backup codes for TOTP recovery.\n"
        "\n"
        "**Important**: This action invalidates ALL existing backup codes. "
        "The user must store the new codes securely.\n"
        "\n"
        "**When to Regenerate**:\n"
        "- User has used most of their backup codes\n"
        "- Backup codes may have been compromised\n"
        "- User lost their stored backup codes\n"
        "- Periodic security refresh\n"
        "\n"
        "**Verification Required**: User must verify with a valid TOTP code from their "
        "authenticator app. Backup codes cannot be used for this operation.\n"
        "\n"
        "**Flow**:\n"
        "1. User requests to regenerate backup codes\n"
        "2. Frontend prompts for current TOTP code\n"
        "3. Send code to this endpoint\n"
        "4. On success, 10 new backup codes are generated\n"
        "5. Old backup codes are immediately invalidated\n"
        "6. Frontend displays new codes for user to save\n"
        "\n"
        "**Security**:\n"
        "- Requires valid TOTP code (not backup code)\n"
        "- Rate limited to 3 attempts per hour\n"
        "- Daily limit of 5 regenerations\n"
        "- Action is logged in audit trail\n"
        "\n"
        '**Backup Code Format**: 8 characters with hyphen (e.g., "ABCD-EFGH")\n'
    ),
    "tags": ["TOTP 2FA"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["code"],
            "properties": {
                "code": {
                    "type": "string",
                    "pattern": "^[0-9]{6}$",
                    "description": "6-digit TOTP code from authenticator app (backup codes not accepted)",
                }
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Regenerate with TOTP",
            value={"code": "123456"},
            request_only=True,
            description="Verify with authenticator code before regenerating",
        )
    ],
    "responses": {
        200: OpenApiResponse(
            description="Backup codes regenerated successfully",
            response={
                "type": "object",
                "properties": {
                    "backup_codes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "New one-time backup codes (store securely!)",
                    },
                    "count": {"type": "integer", "description": "Number of backup codes generated"},
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "backup_codes": [
                            "WXYZ-1234",
                            "ABCD-5678",
                            "EFGH-9012",
                            "IJKL-3456",
                            "MNOP-7890",
                            "QRST-1234",
                            "UVWX-5678",
                            "YZAB-9012",
                            "CDEF-3456",
                            "GHIJ-7890",
                        ],
                        "count": 10,
                    },
                    status_codes=[200],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Verification failed or validation error",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={"error": "totp_invalid_code", "message": "Invalid TOTP code."},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Backup Code Not Allowed",
                    value={"error": "totp_verification_failed", "message": "TOTP verification failed."},
                    status_codes=[400],
                    description="User tried to use backup code instead of TOTP",
                ),
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={"type": "object", "properties": {"error": {"type": "string"}, "message": {"type": "string"}}},
            examples=[
                OpenApiExample(
                    "Rate Limited",
                    value={
                        "error": "rate_limit_exceeded",
                        "message": "Too many regeneration attempts. Please try again later.",
                    },
                    status_codes=[429],
                )
            ],
        ),
    },
}
