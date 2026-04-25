from drf_spectacular.utils import OpenApiExample

from blockauth.schemas.factory import CustomOpenApiResponse

"""Apple Sign-In — Web Authorize"""

apple_authorize_schema = {
    "operation_id": "apple_web_authorize",
    "summary": "Initiate Apple Sign-In (web)",
    "description": (
        "Initiates the Apple Sign-In web flow by redirecting the user to Apple's authorize endpoint\n"
        "\n"
        "**Flow:**\n"
        '1. User clicks "Sign in with Apple"\n'
        "2. Server generates `state`, raw `nonce`, and PKCE verifier; stores them in HttpOnly cookies\n"
        "3. Server returns 302 → `https://appleid.apple.com/auth/authorize?...`\n"
        "4. User completes Apple authentication\n"
        "5. Apple POSTs the authorization code back to `apple/callback/` (`form_post`)\n"
        "\n"
        "**Prerequisites:**\n"
        "- `APPLE_SERVICES_ID` and `APPLE_REDIRECT_URI` configured in `BLOCK_AUTH_SETTINGS`\n"
        "- Services ID, return URL, and domain registered in the Apple Developer console\n"
        "- HTTPS-fronted callback URL (Apple `form_post` requires `SameSite=None; Secure` cookies)\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (public endpoint)\n"
        "- CSRF protection via `state` cookie + form parameter comparison on callback\n"
        "- PKCE (S256) prevents authorization code interception\n"
        "- Hashed nonce binds the id_token to this authorization request\n"
        "- Cookies are HttpOnly, Secure, SameSite=None\n"
        "\n"
        "**Use Cases:**\n"
        "- Web sign-in with Apple ID (Apple Services ID flow)\n"
        "- Account linking via Apple identity\n"
    ),
    "tags": ["Apple Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Sign in with Apple REST API",
        "url": "https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api",
    },
    "examples": [
        OpenApiExample(
            "Successful Redirect",
            value={
                "location": "https://appleid.apple.com/auth/authorize?response_mode=form_post&client_id=...&redirect_uri=...&state=...&nonce=...&code_challenge=..."
            },
            response_only=True,
            status_codes=["302"],
        ),
        OpenApiExample(
            "Configuration Error",
            value={"detail": "Apple Sign-In is not configured"},
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        302: CustomOpenApiResponse(
            status=302,
            description="Redirect to Apple authorize endpoint with PKCE + nonce + state cookies set",
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Apple Sign-In is not configured (missing APPLE_SERVICES_ID or APPLE_REDIRECT_URI)",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "integer", "example": 4020},
                },
                "required": ["detail"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during authorization initialization",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "request_id": {"type": "string"},
                },
                "required": ["error", "message"],
            },
        ),
    },
}


"""Apple Sign-In — Web Callback (form_post)"""

apple_callback_schema = {
    "operation_id": "apple_web_callback",
    "summary": "Handle Apple Sign-In callback (web, form_post)",
    "description": (
        "Processes Apple's `form_post` callback, exchanges the authorization code for tokens, "
        "verifies the id_token, upserts the social identity, and issues blockauth JWTs\n"
        "\n"
        "**Process:**\n"
        "1. Read `state` and `code` from POST body; compare `state` against the cookie\n"
        "2. Read PKCE verifier and raw nonce from cookies\n"
        "3. Build Apple `client_secret` (ES256 JWT signed with the .p8 private key)\n"
        "4. Exchange code for tokens at `https://appleid.apple.com/auth/token`\n"
        "5. Verify id_token signature, issuer, audience, expiry, and nonce\n"
        "6. Upsert `SocialIdentity(provider=apple, subject=sub)` and link to user\n"
        "7. Issue blockauth access + refresh tokens\n"
        "8. Clear state, PKCE, and nonce cookies on the response\n"
        "\n"
        "**Error Handling:**\n"
        "- 400 (4051): missing PKCE verifier cookie\n"
        "- 400 (4053): Apple token endpoint unreachable or token exchange failed\n"
        "- 400 (4054): missing/invalid authorization code or id_token verification failed\n"
        "- 400 (4055): missing nonce cookie or id_token nonce mismatch\n"
        "- 400 (4020): Apple client_secret build failed (missing keys/team/services config)\n"
        "- 409: SocialIdentity conflict — Apple subject already linked to a different user\n"
        "\n"
        "**Security:**\n"
        "- State cookie/parameter comparison defends against CSRF\n"
        "- PKCE verifier defends against authorization code interception\n"
        "- Nonce binding prevents id_token replay\n"
        "- Signed-in cookies are cleared on every response (success or error) to prevent replay\n"
        "\n"
        "**Use Cases:**\n"
        "- Completing Apple Sign-In on web\n"
        "- Linking an Apple identity to a new or existing account\n"
    ),
    "tags": ["Apple Authentication"],
    "deprecated": False,
    "examples": [
        OpenApiExample(
            "Successful Authentication",
            value={
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@privaterelay.appleid.com",
                    "is_verified": True,
                    "wallet_address": None,
                    "first_name": None,
                    "last_name": None,
                },
            },
            response_only=True,
            status_codes=["200"],
        ),
        OpenApiExample(
            "Missing Authorization Code",
            value={"detail": "Missing authorization code", "error_code": 4054},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "PKCE Verifier Missing",
            value={"detail": "PKCE verifier missing", "error_code": 4051},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Nonce Mismatch",
            value={"detail": "Apple id_token nonce mismatch", "error_code": 4055},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Token Exchange Failed",
            value={"detail": "Apple token exchange failed", "error_code": 4053},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Identity Conflict",
            value={
                "detail": "social identity conflict for provider=apple",
                "code": "SOCIAL_IDENTITY_CONFLICT",
            },
            response_only=True,
            status_codes=["409"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully authenticated with Apple",
            response={
                "type": "object",
                "properties": {
                    "access": {"type": "string", "description": "JWT access token", "format": "jwt"},
                    "refresh": {"type": "string", "description": "JWT refresh token", "format": "jwt"},
                    "user": {
                        "type": "object",
                        "description": "Authenticated user profile (same shape as /login/basic/)",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "email": {"type": "string", "nullable": True},
                            "is_verified": {"type": "boolean"},
                            "wallet_address": {"type": "string", "nullable": True},
                            "first_name": {"type": "string", "nullable": True},
                            "last_name": {"type": "string", "nullable": True},
                        },
                        "required": ["id", "is_verified"],
                    },
                },
                "required": ["access", "refresh", "user"],
            },
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Callback validation, token exchange, or id_token verification failed",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {
                        "type": "integer",
                        "enum": [4020, 4051, 4053, 4054, 4055],
                        "description": (
                            "4020=client_secret config; 4051=PKCE missing; 4053=token exchange; "
                            "4054=missing/invalid code or id_token; 4055=nonce mismatch"
                        ),
                    },
                },
                "required": ["detail"],
            },
        ),
        409: CustomOpenApiResponse(
            status=409,
            description="Apple subject is already linked to a different user account",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "code": {"type": "string", "example": "SOCIAL_IDENTITY_CONFLICT"},
                },
                "required": ["detail"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during Apple callback processing",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "request_id": {"type": "string"},
                },
                "required": ["error", "message"],
            },
        ),
    },
}


"""Apple Sign-In — Native id_token Verify"""

apple_native_verify_schema = {
    "operation_id": "apple_native_verify",
    "summary": "Verify Apple id_token from native client",
    "description": (
        "Verifies an Apple-issued id_token obtained by a native iOS client (`ASAuthorizationAppleIDProvider`) "
        "or any other platform that performs the Apple authentication UI itself, then issues blockauth JWTs\n"
        "\n"
        "**Process:**\n"
        "1. Validate request body (id_token + raw_nonce required; auth code + name optional)\n"
        "2. Hash `raw_nonce` (SHA-256 hex) and verify the id_token's `nonce` claim matches\n"
        "3. Verify id_token signature against Apple JWKS, plus issuer / audience / expiry\n"
        "4. (optional) Redeem `authorization_code` for a refresh token; store AES-GCM-encrypted\n"
        "5. Upsert `SocialIdentity(provider=apple, subject=sub)` and link to user\n"
        "6. Issue blockauth access + refresh tokens\n"
        "\n"
        "**Request Body:**\n"
        "- `id_token` (required): Apple-issued id_token JWT from the native client\n"
        "- `raw_nonce` (required): the un-hashed nonce the client passed when starting the request\n"
        "- `authorization_code` (optional): Apple authorization code for refresh-token redemption\n"
        "- `first_name`, `last_name` (optional): provided by Apple **only on first sign-in**\n"
        "\n"
        "**Audience:**\n"
        "Native id_tokens have `aud=<bundle_id>`, not the Services ID. Configure `APPLE_BUNDLE_IDS` "
        "to allowlist the iOS app's bundle identifier(s).\n"
        "\n"
        "**Error Handling:**\n"
        "- 400 (4054): id_token signature, issuer, audience, or expiry verification failed\n"
        "- 400 (4055): nonce mismatch between hashed `raw_nonce` and id_token claim\n"
        "- 400 (4020): Apple client_secret build failed (only when authorization_code present)\n"
        "- 409: SocialIdentity conflict — Apple subject already linked to a different user\n"
        "\n"
        "**Use Cases:**\n"
        "- Sign in with Apple from native iOS apps\n"
        "- Sign in with Apple from web clients using JS SDK in pop-up mode\n"
    ),
    "tags": ["Apple Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Authenticating users with Sign in with Apple",
        "url": "https://developer.apple.com/documentation/authenticationservices/authenticating_users_with_sign_in_with_apple",
    },
    "examples": [
        OpenApiExample(
            "Native Verify Request",
            value={
                "id_token": "eyJhbGciOiJSUzI1NiIs...",
                "raw_nonce": "k0FfV0eW...",
                "authorization_code": "c4a8...",
                "first_name": "Ada",
                "last_name": "Lovelace",
            },
            request_only=True,
        ),
        OpenApiExample(
            "Successful Authentication",
            value={
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "ada@example.com",
                    "is_verified": True,
                    "wallet_address": None,
                    "first_name": "Ada",
                    "last_name": "Lovelace",
                },
            },
            response_only=True,
            status_codes=["200"],
        ),
        OpenApiExample(
            "id_token Verification Failed",
            value={"detail": "id_token signature verification failed", "error_code": 4054},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Nonce Mismatch",
            value={"detail": "Apple id_token nonce mismatch", "error_code": 4055},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Identity Conflict",
            value={
                "detail": "social identity conflict for provider=apple",
                "code": "SOCIAL_IDENTITY_CONFLICT",
            },
            response_only=True,
            status_codes=["409"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully verified Apple id_token and authenticated the user",
            response={
                "type": "object",
                "properties": {
                    "access": {"type": "string", "description": "JWT access token", "format": "jwt"},
                    "refresh": {"type": "string", "description": "JWT refresh token", "format": "jwt"},
                    "user": {
                        "type": "object",
                        "description": "Authenticated user profile (same shape as /login/basic/)",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "email": {"type": "string", "nullable": True},
                            "is_verified": {"type": "boolean"},
                            "wallet_address": {"type": "string", "nullable": True},
                            "first_name": {"type": "string", "nullable": True},
                            "last_name": {"type": "string", "nullable": True},
                        },
                        "required": ["id", "is_verified"],
                    },
                },
                "required": ["access", "refresh", "user"],
            },
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Request validation, id_token verification, or nonce check failed",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {
                        "type": "integer",
                        "enum": [4020, 4054, 4055],
                        "description": (
                            "4020=Apple client_secret config; 4054=id_token verification; " "4055=nonce mismatch"
                        ),
                    },
                },
                "required": ["detail"],
            },
        ),
        409: CustomOpenApiResponse(
            status=409,
            description="Apple subject is already linked to a different user account",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "code": {"type": "string", "example": "SOCIAL_IDENTITY_CONFLICT"},
                },
                "required": ["detail"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during native id_token verification",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "request_id": {"type": "string"},
                },
                "required": ["error", "message"],
            },
        ),
    },
}


"""Apple Sign-In — Server-to-Server Notifications Webhook"""

apple_notifications_schema = {
    "operation_id": "apple_server_to_server_notifications",
    "summary": "Apple server-to-server notifications webhook",
    "description": (
        "Webhook endpoint that receives Apple's server-to-server notifications for the configured Services ID\n"
        "\n"
        "**Process:**\n"
        '1. Apple POSTs `{"payload": "<JWT>"}` to this endpoint\n'
        "2. Server verifies the JWT against Apple JWKS (issuer/audience pinned)\n"
        "3. The decoded `events` claim is dispatched by event `type`\n"
        "4. Server applies state changes to the matching `SocialIdentity` (revoke, delete, email toggles)\n"
        "5. Server returns 200 to acknowledge receipt; Apple retries on non-200 responses\n"
        "\n"
        "**Supported Event Types:**\n"
        "- `consent-revoked`: user revoked Sign in with Apple for the integrator's app\n"
        "- `account-delete`: user deleted their Apple ID — wipe linked SocialIdentity\n"
        "- `email-disabled`: private-relay email forwarding stopped for this user\n"
        "- `email-enabled`: private-relay email forwarding resumed\n"
        "\n"
        "**Configuration:**\n"
        "Set the **Server-to-Server Notification Endpoint** to this URL in the Apple Developer "
        "console for your Services ID. Apple delivers events with `aud=<APPLE_SERVICES_ID>`.\n"
        "\n"
        "**Error Handling:**\n"
        "- 400 (4056): payload missing, JWT signature/issuer/audience verification failed, or "
        "events claim malformed. Apple's retry logic will re-deliver.\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (Apple-signed JWT *is* the auth)\n"
        "- JWT signature, issuer, audience, and expiry are verified before any side effects\n"
        "- Trigger callbacks (`APPLE_NOTIFICATION_TRIGGER`) receive event metadata only, "
        "never the raw JWT or PII\n"
        "\n"
        "**Use Cases:**\n"
        "- Honor Apple-initiated consent revocations and account deletions\n"
        "- Track private-relay email enable/disable state per user\n"
    ),
    "tags": ["Apple Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Processing changes for Sign in with Apple accounts",
        "url": "https://developer.apple.com/documentation/sign_in_with_apple/processing_changes_for_sign_in_with_apple_accounts",
    },
    "examples": [
        OpenApiExample(
            "Notification Envelope",
            value={"payload": "eyJhbGciOiJSUzI1NiIs..."},
            request_only=True,
        ),
        OpenApiExample(
            "Acknowledged",
            value={},
            response_only=True,
            status_codes=["200"],
        ),
        OpenApiExample(
            "Invalid Payload",
            value={"detail": "Invalid Apple notification payload", "error_code": 4056},
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Notification accepted and dispatched",
            response={"type": "object"},
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Notification JWT verification or dispatch failed",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "integer", "example": 4056},
                },
                "required": ["detail"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error while handling the notification",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string"},
                    "message": {"type": "string"},
                    "request_id": {"type": "string"},
                },
                "required": ["error", "message"],
            },
        ),
    },
}
