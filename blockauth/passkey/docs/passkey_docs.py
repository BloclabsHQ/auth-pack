"""
BlockAuth Passkey/WebAuthn Documentation

This module contains comprehensive Swagger/OpenAPI documentation for Passkey endpoints.
Separated from business logic for better maintainability and organization.

Passkeys enable passwordless authentication using:
- Biometrics: Face ID, Touch ID, Windows Hello, Android fingerprint
- Hardware Keys: YubiKey, Titan Security Key
- Device PIN: Fallback when biometrics unavailable
"""

from drf_spectacular.utils import OpenApiExample, OpenApiResponse

# =============================================================================
# REGISTRATION DOCUMENTATION
# =============================================================================

passkey_registration_options_docs = {
    "operation_id": "passkey_registration_options",
    "summary": "Generate Passkey Registration Options",
    "description": (
        "Generate WebAuthn options for registering a new passkey to the authenticated user's account.\n"
        "\n"
        "**Important**: This endpoint requires authentication. The user must already be logged in "
        "(via password, social login, etc.) before they can register a passkey.\n"
        "\n"
        "**Flow**:\n"
        "1. Frontend calls this endpoint with JWT token\n"
        "2. Backend returns cryptographic challenge and options\n"
        "3. Frontend passes options to `navigator.credentials.create()`\n"
        "4. Browser triggers biometric/PIN prompt\n"
        "5. User verifies identity\n"
        "6. Frontend sends response to `/register/verify/`\n"
        "\n"
        "**Note**: Passkeys do NOT create users. They are additional authentication methods "
        "for existing accounts.\n"
        "\n"
        "**Security**:\n"
        "- Requires valid JWT authentication\n"
        "- Challenge is cryptographically random and time-limited\n"
        "- Existing credentials are excluded to prevent duplicates\n"
        "\n"
        "**Use Cases**:\n"
        "- Adding Face ID/Touch ID login to existing account\n"
        "- Registering hardware security key (YubiKey)\n"
        "- Setting up Windows Hello authentication\n"
        "- Enabling passwordless login for returning users\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "properties": {
                "display_name": {
                    "type": "string",
                    "description": (
                        "Optional display name shown on authenticator during registration. "
                        "Defaults to user email/username if not provided."
                    ),
                }
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Default Registration",
            value={},
            request_only=True,
            description="Register passkey with default display name (user's email)",
        ),
        OpenApiExample(
            "Custom Display Name",
            value={"display_name": "John Doe"},
            request_only=True,
            description="Register passkey with custom display name",
        ),
    ],
    "responses": {
        200: OpenApiResponse(
            description="Registration options generated successfully. Pass these to navigator.credentials.create().",
            response={
                "type": "object",
                "properties": {
                    "rp": {
                        "type": "object",
                        "description": "Relying Party information (your application)",
                        "properties": {
                            "name": {"type": "string", "description": "Application display name"},
                            "id": {"type": "string", "description": "Domain identifier (RP_ID)"},
                        },
                    },
                    "user": {
                        "type": "object",
                        "description": "User information for credential association",
                        "properties": {
                            "id": {"type": "string", "description": "Base64URL-encoded user handle"},
                            "name": {"type": "string", "description": "User identifier (email)"},
                            "displayName": {"type": "string", "description": "User display name"},
                        },
                    },
                    "challenge": {
                        "type": "string",
                        "description": "Base64URL-encoded cryptographic challenge (must be signed by authenticator)",
                    },
                    "pubKeyCredParams": {
                        "type": "array",
                        "description": "Supported public key algorithms (-7=ES256, -257=RS256)",
                        "items": {
                            "type": "object",
                            "properties": {"type": {"type": "string"}, "alg": {"type": "integer"}},
                        },
                    },
                    "timeout": {"type": "integer", "description": "Registration timeout in milliseconds"},
                    "excludeCredentials": {
                        "type": "array",
                        "description": "User's existing credentials (prevents duplicate registration)",
                        "items": {"type": "object"},
                    },
                    "authenticatorSelection": {
                        "type": "object",
                        "description": "Authenticator requirements",
                        "properties": {
                            "authenticatorAttachment": {"type": "string"},
                            "residentKey": {"type": "string"},
                            "userVerification": {"type": "string"},
                        },
                    },
                    "attestation": {
                        "type": "string",
                        "description": "Attestation conveyance preference (none, indirect, direct, enterprise)",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "rp": {"name": "My Application", "id": "example.com"},
                        "user": {"id": "dXNlci1oYW5kbGU", "name": "user@example.com", "displayName": "John Doe"},
                        "challenge": "randomBase64UrlChallenge",
                        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
                        "timeout": 60000,
                        "excludeCredentials": [],
                        "authenticatorSelection": {
                            "authenticatorAttachment": "platform",
                            "residentKey": "preferred",
                            "userVerification": "required",
                        },
                        "attestation": "none",
                    },
                    status_codes=[200],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Bad request - passkey not enabled or max credentials reached",
            response={
                "type": "object",
                "properties": {
                    "error_code": {"type": "string", "description": "Error code for programmatic handling"},
                    "message": {"type": "string", "description": "Human-readable error message"},
                },
            },
            examples=[
                OpenApiExample(
                    "Max Credentials Reached",
                    value={
                        "error_code": "MAX_CREDENTIALS_REACHED",
                        "message": "User has reached maximum of 10 credentials",
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Passkey Not Enabled",
                    value={"error_code": "PASSKEY_NOT_ENABLED", "message": "Passkey module is not enabled"},
                    status_codes=[400],
                ),
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required in Authorization header"),
    },
}


passkey_registration_verify_docs = {
    "operation_id": "passkey_registration_verify",
    "summary": "Verify Passkey Registration",
    "description": (
        "Verify the WebAuthn registration response from the browser and store the credential.\n"
        "\n"
        "**Flow**:\n"
        "1. After `navigator.credentials.create()` returns, encode the response\n"
        "2. Send the encoded credential to this endpoint\n"
        "3. Backend verifies the cryptographic signature\n"
        "4. Credential is stored and linked to the user's account\n"
        "\n"
        "**Request Body Fields**:\n"
        "- `id`: Base64URL credential ID from authenticator\n"
        "- `rawId`: Base64URL raw credential ID\n"
        '- `type`: Must be "public-key"\n'
        "- `response.clientDataJSON`: Base64URL client data from browser\n"
        "- `response.attestationObject`: Base64URL attestation from authenticator\n"
        "- `response.transports`: Array of supported transports (internal, usb, nfc, ble, hybrid)\n"
        '- `name`: Optional user-friendly name (e.g., "MacBook Pro Touch ID")\n'
        "\n"
        "**Security**:\n"
        "- Verifies cryptographic signature from authenticator\n"
        "- Validates challenge was issued by this server\n"
        "- Checks origin matches allowed origins\n"
        "- Stores public key for future authentication\n"
        "\n"
        "**Use Cases**:\n"
        "- Completing passkey registration after biometric verification\n"
        "- Storing Face ID, Touch ID, or Windows Hello credential\n"
        "- Registering hardware security key\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["id", "type", "response"],
            "properties": {
                "id": {"type": "string", "description": "Base64URL-encoded credential ID from authenticator"},
                "rawId": {"type": "string", "description": "Base64URL-encoded raw credential ID"},
                "type": {
                    "type": "string",
                    "description": 'Credential type, must be "public-key"',
                    "enum": ["public-key"],
                },
                "response": {
                    "type": "object",
                    "description": "Authenticator response data",
                    "properties": {
                        "clientDataJSON": {
                            "type": "string",
                            "description": "Base64URL-encoded client data from browser",
                        },
                        "attestationObject": {
                            "type": "string",
                            "description": "Base64URL-encoded attestation from authenticator",
                        },
                        "transports": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Supported transports: internal, usb, nfc, ble, hybrid",
                        },
                    },
                },
                "name": {
                    "type": "string",
                    "description": 'User-friendly name for this passkey (e.g., "MacBook Pro Touch ID")',
                },
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Platform Authenticator (Touch ID)",
            value={
                "id": "base64UrlCredentialId",
                "rawId": "base64UrlCredentialId",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "base64UrlEncodedClientData",
                    "attestationObject": "base64UrlEncodedAttestation",
                    "transports": ["internal", "hybrid"],
                },
                "name": "MacBook Pro Touch ID",
            },
            request_only=True,
            description="Register Touch ID credential",
        ),
        OpenApiExample(
            "Hardware Key (YubiKey)",
            value={
                "id": "base64UrlCredentialId",
                "rawId": "base64UrlCredentialId",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "base64UrlEncodedClientData",
                    "attestationObject": "base64UrlEncodedAttestation",
                    "transports": ["usb"],
                },
                "name": "YubiKey 5 NFC",
            },
            request_only=True,
            description="Register hardware security key",
        ),
    ],
    "responses": {
        201: OpenApiResponse(
            description="Credential registered successfully",
            response={
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "format": "uuid",
                        "description": "UUID for managing this credential via API",
                    },
                    "credential_id": {
                        "type": "string",
                        "description": "Base64URL WebAuthn credential ID (used by browser)",
                    },
                    "name": {"type": "string", "description": "User-assigned credential name"},
                    "created_at": {"type": "string", "format": "date-time", "description": "Registration timestamp"},
                    "authenticator_attachment": {
                        "type": "string",
                        "enum": ["platform", "cross-platform"],
                        "description": 'Authenticator type: "platform" (built-in) or "cross-platform" (hardware key)',
                    },
                    "transports": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "How authenticator communicates: internal, usb, nfc, ble, hybrid",
                    },
                    "backup_eligible": {
                        "type": "boolean",
                        "description": "Whether passkey can sync to other devices (iCloud Keychain, Google Password Manager)",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "credential_id": "base64UrlCredentialId",
                        "name": "MacBook Pro Touch ID",
                        "created_at": "2024-01-15T10:30:00Z",
                        "authenticator_attachment": "platform",
                        "transports": ["internal", "hybrid"],
                        "backup_eligible": True,
                    },
                    status_codes=[201],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Verification failed",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Invalid Credential Data",
                    value={"error_code": "INVALID_CREDENTIAL_DATA", "message": "Missing required credential fields"},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Invalid Origin",
                    value={
                        "error_code": "INVALID_ORIGIN",
                        "message": "Origin 'https://evil.com' not in allowed origins",
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Challenge Expired",
                    value={"error_code": "CHALLENGE_EXPIRED", "message": "Challenge has expired"},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Signature Verification Failed",
                    value={
                        "error_code": "SIGNATURE_VERIFICATION_FAILED",
                        "message": "Registration verification failed",
                    },
                    status_codes=[400],
                ),
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
    },
}


# =============================================================================
# AUTHENTICATION DOCUMENTATION
# =============================================================================

passkey_authentication_options_docs = {
    "operation_id": "passkey_authentication_options",
    "summary": "Generate Passkey Authentication Options",
    "description": (
        "Generate WebAuthn options for authenticating with a passkey. This is a **public endpoint**.\n"
        "\n"
        "**Two Authentication Modes**:\n"
        "\n"
        "**1. With `username` (Non-Discoverable Mode)**:\n"
        "- Pass the user's email in the request\n"
        "- Backend returns `allowCredentials` with that user's registered credential IDs\n"
        "- Browser only shows passkeys matching those specific IDs\n"
        "- Use when: Login form has email field, you want to filter passkeys\n"
        "\n"
        "**2. Without `username` (Discoverable Mode)**:\n"
        "- Omit `username` or pass null\n"
        "- Backend returns empty `allowCredentials`\n"
        "- Browser shows ALL available passkeys for this domain\n"
        "- User selects which passkey to use\n"
        "- The `userHandle` in the response identifies the user\n"
        '- Use when: "One-click" passkey login, better UX for returning users\n'
        "\n"
        "**Security Note**: When `username` is provided but user doesn't exist, the endpoint "
        "still returns valid options (empty `allowCredentials`). This prevents user enumeration.\n"
        "\n"
        "**Flow**:\n"
        "1. Frontend calls this endpoint (optionally with username)\n"
        "2. Backend returns challenge and options\n"
        "3. Frontend passes options to `navigator.credentials.get()`\n"
        "4. Browser triggers biometric/PIN prompt\n"
        "5. User verifies identity\n"
        "6. Frontend sends response to `/auth/verify/`\n"
        "\n"
        "**Use Cases**:\n"
        "- Passwordless login with Face ID/Touch ID\n"
        "- One-click authentication for returning users\n"
        "- Multi-factor authentication with hardware key\n"
        "- Enterprise SSO with security keys\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "properties": {
                "username": {
                    "type": "string",
                    "description": (
                        "Optional user email/username. If provided, returns only that user's credential IDs "
                        "(non-discoverable mode). If omitted, enables discoverable credential mode where "
                        "browser shows all available passkeys for this domain."
                    ),
                }
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Discoverable Mode (One-Click)",
            value={},
            request_only=True,
            description="No username - browser shows all available passkeys for this domain",
        ),
        OpenApiExample(
            "Non-Discoverable Mode (With Email)",
            value={"username": "user@example.com"},
            request_only=True,
            description="With username - browser shows only this user's passkeys",
        ),
    ],
    "responses": {
        200: OpenApiResponse(
            description="Authentication options generated successfully",
            response={
                "type": "object",
                "properties": {
                    "challenge": {"type": "string", "description": "Base64URL-encoded cryptographic challenge to sign"},
                    "timeout": {"type": "integer", "description": "Authentication timeout in milliseconds"},
                    "rpId": {
                        "type": "string",
                        "description": "Relying Party ID (your domain) - must match registration",
                    },
                    "allowCredentials": {
                        "type": "array",
                        "description": "Specific credentials to use. Empty array = show all available passkeys (discoverable mode)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string"},
                                "id": {"type": "string"},
                                "transports": {"type": "array", "items": {"type": "string"}},
                            },
                        },
                    },
                    "userVerification": {
                        "type": "string",
                        "description": "User verification requirement: required, preferred, or discouraged",
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "With Username (Non-Discoverable)",
                    value={
                        "challenge": "randomBase64UrlChallenge",
                        "timeout": 60000,
                        "rpId": "example.com",
                        "allowCredentials": [
                            {"type": "public-key", "id": "credId1", "transports": ["internal"]},
                            {"type": "public-key", "id": "credId2", "transports": ["usb"]},
                        ],
                        "userVerification": "required",
                    },
                    status_codes=[200],
                    description="Returns specific credential IDs for the user",
                ),
                OpenApiExample(
                    "Without Username (Discoverable)",
                    value={
                        "challenge": "randomBase64UrlChallenge",
                        "timeout": 60000,
                        "rpId": "example.com",
                        "allowCredentials": [],
                        "userVerification": "required",
                    },
                    status_codes=[200],
                    description="Empty allowCredentials - browser shows all available passkeys",
                ),
            ],
        ),
        400: OpenApiResponse(
            description="Bad request - passkey not enabled",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Passkey Not Enabled",
                    value={"error_code": "PASSKEY_NOT_ENABLED", "message": "Passkey module is not enabled"},
                    status_codes=[400],
                )
            ],
        ),
    },
}


passkey_authentication_verify_docs = {
    "operation_id": "passkey_authentication_verify",
    "summary": "Verify Passkey Authentication",
    "description": (
        "Verify the WebAuthn authentication response and issue JWT tokens. This is a **public endpoint**.\n"
        "\n"
        "**Important**: This endpoint only authenticates **existing users** with registered passkeys. "
        "It does NOT create new users. If the credential is not found, authentication fails.\n"
        "\n"
        "**Flow**:\n"
        "1. After `navigator.credentials.get()` returns, encode the response\n"
        "2. Send the encoded assertion to this endpoint\n"
        "3. Backend finds the credential by ID\n"
        "4. Backend verifies the cryptographic signature using stored public key\n"
        "5. On success, returns JWT access and refresh tokens\n"
        "\n"
        "**Request Body Fields**:\n"
        "- `id`: Base64URL credential ID\n"
        "- `rawId`: Base64URL raw credential ID\n"
        '- `type`: Must be "public-key"\n'
        "- `response.clientDataJSON`: Base64URL client data containing signed challenge\n"
        "- `response.authenticatorData`: Base64URL authenticator data\n"
        "- `response.signature`: Base64URL cryptographic signature\n"
        "- `response.userHandle`: Base64URL user handle (for discoverable credentials)\n"
        "\n"
        "**Security Features**:\n"
        "- Counter validation detects cloned authenticators\n"
        "- Challenge expiry prevents replay attacks\n"
        "- Origin validation prevents phishing\n"
        "- Signature verification ensures authenticator possession\n"
        "\n"
        "**Use Cases**:\n"
        "- Completing passwordless login\n"
        "- Authenticating with Face ID/Touch ID\n"
        "- Hardware key authentication\n"
        "- Multi-factor authentication verification\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["id", "type", "response"],
            "properties": {
                "id": {"type": "string", "description": "Base64URL-encoded credential ID used for authentication"},
                "rawId": {"type": "string", "description": "Base64URL-encoded raw credential ID"},
                "type": {
                    "type": "string",
                    "description": 'Credential type, must be "public-key"',
                    "enum": ["public-key"],
                },
                "response": {
                    "type": "object",
                    "description": "Authenticator assertion response",
                    "properties": {
                        "clientDataJSON": {
                            "type": "string",
                            "description": "Base64URL-encoded client data containing signed challenge",
                        },
                        "authenticatorData": {"type": "string", "description": "Base64URL-encoded authenticator data"},
                        "signature": {"type": "string", "description": "Base64URL-encoded cryptographic signature"},
                        "userHandle": {
                            "type": "string",
                            "description": "Base64URL-encoded user handle (for discoverable credentials)",
                        },
                    },
                },
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Authentication Assertion",
            value={
                "id": "base64UrlCredentialId",
                "rawId": "base64UrlCredentialId",
                "type": "public-key",
                "response": {
                    "clientDataJSON": "base64UrlEncodedClientData",
                    "authenticatorData": "base64UrlEncodedAuthData",
                    "signature": "base64UrlEncodedSignature",
                    "userHandle": "base64UrlEncodedUserHandle",
                },
            },
            request_only=True,
            description="WebAuthn assertion from navigator.credentials.get()",
        )
    ],
    "responses": {
        200: OpenApiResponse(
            description="Authentication successful - JWT tokens returned",
            response={
                "type": "object",
                "properties": {
                    "access": {
                        "type": "string",
                        "description": "JWT access token for API authentication",
                        "format": "jwt",
                    },
                    "refresh": {
                        "type": "string",
                        "description": "JWT refresh token for token renewal",
                        "format": "jwt",
                    },
                    "user": {
                        "type": "object",
                        "description": "Authenticated user information",
                        "properties": {
                            "id": {"type": "string", "format": "uuid", "description": "User's UUID"},
                            "email": {"type": "string", "format": "email", "description": "User's email address"},
                        },
                    },
                    "credential": {
                        "type": "object",
                        "description": "Credential used for authentication",
                        "properties": {
                            "id": {"type": "string", "format": "uuid", "description": "UUID of credential used"},
                            "name": {"type": "string", "description": "User-assigned credential name"},
                            "last_used_at": {
                                "type": "string",
                                "format": "date-time",
                                "description": "Timestamp of this authentication",
                            },
                        },
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {"id": "550e8400-e29b-41d4-a716-446655440000", "email": "user@example.com"},
                        "credential": {
                            "id": "660e8400-e29b-41d4-a716-446655440001",
                            "name": "MacBook Pro Touch ID",
                            "last_used_at": "2024-01-15T14:30:00Z",
                        },
                    },
                    status_codes=[200],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Verification failed",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Invalid Credential Data",
                    value={
                        "error_code": "INVALID_CREDENTIAL_DATA",
                        "message": "Missing required authentication fields",
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Invalid Origin",
                    value={"error_code": "INVALID_ORIGIN", "message": "Origin not in allowed origins"},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Signature Verification Failed",
                    value={
                        "error_code": "SIGNATURE_VERIFICATION_FAILED",
                        "message": "Authentication verification failed",
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Counter Regression (Possible Clone)",
                    value={
                        "error_code": "COUNTER_REGRESSION",
                        "message": "Signature counter regression detected - possible cloned authenticator",
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Credential Revoked",
                    value={"error_code": "CREDENTIAL_REVOKED", "message": "Credential has been revoked"},
                    status_codes=[400],
                ),
            ],
        ),
        404: OpenApiResponse(
            description="Credential not found",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Not Found",
                    value={"error_code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found"},
                    status_codes=[404],
                )
            ],
        ),
    },
}


# =============================================================================
# CREDENTIAL MANAGEMENT DOCUMENTATION
# =============================================================================

passkey_credentials_list_docs = {
    "operation_id": "passkey_credentials_list",
    "summary": "List Passkey Credentials",
    "description": (
        "List all passkey credentials registered by the authenticated user.\n"
        "\n"
        "Returns an array of credentials with details about each passkey including:\n"
        "- Device/authenticator information\n"
        "- Usage statistics (created, last used)\n"
        "- Backup/sync status\n"
        "- Active status\n"
        "\n"
        "Use this endpoint to build a passkey management UI where users can view "
        "and manage their registered passkeys.\n"
        "\n"
        "**Authentication Required**: Valid JWT access token in Authorization header\n"
        "\n"
        "**Use Cases**:\n"
        "- Displaying user's registered passkeys in settings\n"
        "- Building passkey management interface\n"
        "- Showing device/authenticator information\n"
        "- Identifying unused or outdated passkeys\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "responses": {
        200: OpenApiResponse(
            description="List of user credentials",
            response={
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Total number of credentials"},
                    "credentials": {
                        "type": "array",
                        "description": "List of credential objects",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string", "format": "uuid"},
                                "credential_id": {"type": "string"},
                                "name": {"type": "string"},
                                "created_at": {"type": "string", "format": "date-time"},
                                "last_used_at": {"type": "string", "format": "date-time", "nullable": True},
                                "authenticator_attachment": {"type": "string"},
                                "transports": {"type": "array", "items": {"type": "string"}},
                                "backup_eligible": {"type": "boolean"},
                                "backup_state": {"type": "boolean"},
                                "is_active": {"type": "boolean"},
                            },
                        },
                    },
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "count": 2,
                        "credentials": [
                            {
                                "id": "550e8400-e29b-41d4-a716-446655440000",
                                "credential_id": "base64UrlCredentialId1",
                                "name": "MacBook Pro Touch ID",
                                "created_at": "2024-01-10T09:00:00Z",
                                "last_used_at": "2024-01-15T14:30:00Z",
                                "authenticator_attachment": "platform",
                                "transports": ["internal", "hybrid"],
                                "backup_eligible": True,
                                "backup_state": True,
                                "is_active": True,
                            },
                            {
                                "id": "660e8400-e29b-41d4-a716-446655440001",
                                "credential_id": "base64UrlCredentialId2",
                                "name": "YubiKey 5",
                                "created_at": "2024-01-12T11:00:00Z",
                                "last_used_at": None,
                                "authenticator_attachment": "cross-platform",
                                "transports": ["usb"],
                                "backup_eligible": False,
                                "backup_state": False,
                                "is_active": True,
                            },
                        ],
                    },
                    status_codes=[200],
                )
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
    },
}


passkey_credential_detail_docs = {
    "operation_id": "passkey_credential_detail",
    "summary": "Get Passkey Credential Details",
    "description": (
        "Get detailed information about a specific passkey credential.\n"
        "\n"
        "The credential must belong to the authenticated user. Returns full credential "
        "details including usage statistics and sync status.\n"
        "\n"
        "**Authentication Required**: Valid JWT access token in Authorization header\n"
        "\n"
        "**URL Parameters**:\n"
        "- `credential_id`: UUID of the credential (from list endpoint)\n"
        "\n"
        "**Use Cases**:\n"
        "- Viewing detailed passkey information\n"
        "- Checking last usage time\n"
        "- Verifying backup/sync status\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "responses": {
        200: OpenApiResponse(
            description="Credential details",
            response={
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid", "description": "UUID for API operations"},
                    "credential_id": {"type": "string", "description": "Base64URL WebAuthn credential identifier"},
                    "name": {"type": "string", "description": "User-friendly credential name"},
                    "created_at": {
                        "type": "string",
                        "format": "date-time",
                        "description": "When passkey was registered",
                    },
                    "last_used_at": {
                        "type": "string",
                        "format": "date-time",
                        "nullable": True,
                        "description": "Last successful authentication",
                    },
                    "authenticator_attachment": {"type": "string", "description": "Type: platform or cross-platform"},
                    "transports": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Communication methods",
                    },
                    "backup_eligible": {"type": "boolean", "description": "Can sync to cloud"},
                    "backup_state": {"type": "boolean", "description": "Currently synced"},
                    "is_active": {"type": "boolean", "description": "Whether credential is enabled"},
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "credential_id": "base64UrlCredentialId",
                        "name": "MacBook Pro Touch ID",
                        "created_at": "2024-01-10T09:00:00Z",
                        "last_used_at": "2024-01-15T14:30:00Z",
                        "authenticator_attachment": "platform",
                        "transports": ["internal", "hybrid"],
                        "backup_eligible": True,
                        "backup_state": True,
                        "is_active": True,
                    },
                    status_codes=[200],
                )
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        404: OpenApiResponse(
            description="Credential not found or belongs to another user",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Not Found",
                    value={"error_code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found"},
                    status_codes=[404],
                )
            ],
        ),
    },
}


passkey_credential_update_docs = {
    "operation_id": "passkey_credential_update",
    "summary": "Update Passkey Credential Name",
    "description": (
        "Update the user-friendly name of a passkey credential.\n"
        "\n"
        'Use this to help users identify their passkeys, e.g., "MacBook Pro Touch ID", '
        '"iPhone Face ID", "YubiKey 5 NFC".\n'
        "\n"
        "The credential must belong to the authenticated user.\n"
        "\n"
        "**Authentication Required**: Valid JWT access token in Authorization header\n"
        "\n"
        "**URL Parameters**:\n"
        "- `credential_id`: UUID of the credential to update\n"
        "\n"
        "**Use Cases**:\n"
        "- Renaming passkey after device change\n"
        "- Adding descriptive names for easy identification\n"
        "- Organizing multiple passkeys\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "request": {
        "application/json": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "New user-friendly name for the credential",
                    "example": "iPhone Face ID",
                }
            },
        }
    },
    "examples": [
        OpenApiExample(
            "Update Name", value={"name": "iPhone Face ID"}, request_only=True, description="Update credential name"
        )
    ],
    "responses": {
        200: OpenApiResponse(
            description="Credential updated successfully",
            response={
                "type": "object",
                "properties": {
                    "id": {"type": "string", "format": "uuid"},
                    "credential_id": {"type": "string"},
                    "name": {"type": "string"},
                    "created_at": {"type": "string", "format": "date-time"},
                    "last_used_at": {"type": "string", "format": "date-time", "nullable": True},
                    "authenticator_attachment": {"type": "string"},
                    "transports": {"type": "array", "items": {"type": "string"}},
                    "backup_eligible": {"type": "boolean"},
                    "backup_state": {"type": "boolean"},
                    "is_active": {"type": "boolean"},
                },
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "credential_id": "base64UrlCredentialId",
                        "name": "iPhone Face ID",
                        "created_at": "2024-01-10T09:00:00Z",
                        "last_used_at": "2024-01-15T14:30:00Z",
                        "authenticator_attachment": "platform",
                        "transports": ["internal", "hybrid"],
                        "backup_eligible": True,
                        "backup_state": True,
                        "is_active": True,
                    },
                    status_codes=[200],
                )
            ],
        ),
        400: OpenApiResponse(
            description="Validation error",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Missing Name",
                    value={"error_code": "VALIDATION_ERROR", "message": "Name is required"},
                    status_codes=[400],
                )
            ],
        ),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        404: OpenApiResponse(
            description="Credential not found",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Not Found",
                    value={"error_code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found"},
                    status_codes=[404],
                )
            ],
        ),
    },
}


passkey_credential_delete_docs = {
    "operation_id": "passkey_credential_delete",
    "summary": "Delete Passkey Credential",
    "description": (
        "Permanently delete a passkey credential.\n"
        "\n"
        "**Warning**: This action cannot be undone. The passkey will be removed from the "
        "user's account and can no longer be used for authentication.\n"
        "\n"
        "**Important**: Ensure the user has other authentication methods available before "
        "deleting their last passkey, or they may be locked out of their account.\n"
        "\n"
        "The credential must belong to the authenticated user.\n"
        "\n"
        "**Authentication Required**: Valid JWT access token in Authorization header\n"
        "\n"
        "**URL Parameters**:\n"
        "- `credential_id`: UUID of the credential to delete\n"
        "\n"
        "**Use Cases**:\n"
        "- Removing passkey from lost/sold device\n"
        "- Cleaning up unused passkeys\n"
        "- Security cleanup after device compromise\n"
    ),
    "tags": ["Passkey"],
    "deprecated": False,
    "responses": {
        204: OpenApiResponse(description="Credential deleted successfully (no content)"),
        401: OpenApiResponse(description="Not authenticated - JWT token required"),
        404: OpenApiResponse(
            description="Credential not found",
            response={
                "type": "object",
                "properties": {"error_code": {"type": "string"}, "message": {"type": "string"}},
            },
            examples=[
                OpenApiExample(
                    "Not Found",
                    value={"error_code": "CREDENTIAL_NOT_FOUND", "message": "Credential not found"},
                    status_codes=[404],
                )
            ],
        ),
    },
}
