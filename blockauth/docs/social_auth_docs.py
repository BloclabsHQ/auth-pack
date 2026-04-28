from drf_spectacular.utils import OpenApiExample, OpenApiParameter

from blockauth.schemas.factory import CustomOpenApiResponse
from blockauth.views.google_native_serializers import (
    GoogleNativeIdTokenVerifyRequestSerializer,
)

"""Google OAuth Authentication"""

google_auth_login_schema = {
    "operation_id": "google_oauth_login",
    "summary": "Initiate Google OAuth Login",
    "description": (
        "Initiates the Google OAuth authentication flow by redirecting users to Google's authorization server\n"
        "\n"
        "**Flow:**\n"
        '1. User clicks "Login with Google"\n'
        "2. Redirected to Google OAuth consent screen\n"
        "3. User authorizes the application\n"
        "4. Google redirects back to callback URL with authorization code\n"
        "\n"
        "**Prerequisites:**\n"
        "- Google OAuth credentials configured in settings\n"
        "- Valid redirect URI configured in Google Console\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (public endpoint)\n"
        "- CSRF protection via state parameter\n"
        "\n"
        "**Use Cases:**\n"
        "- Quick user registration and login\n"
        "- Single sign-on (SSO) integration\n"
        "- Reduced friction user onboarding\n"
        "- Mobile app social login\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Google OAuth 2.0 Documentation",
        "url": "https://developers.google.com/identity/protocols/oauth2",
    },
    "examples": [
        OpenApiExample(
            "Successful Redirect",
            value={
                "redirect_url": "https://accounts.google.com/oauth/authorize?client_id=...&redirect_uri=...&scope=...&response_type=code&state=..."
            },
            response_only=True,
            status_codes=["301"],
        ),
        OpenApiExample(
            "Configuration Error",
            value={"error": "oauth_config_error", "message": "Google OAuth credentials not configured"},
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        301: CustomOpenApiResponse(
            status=301,
            description="Redirect to Google OAuth authorization URL",
            response={
                "type": "object",
                "properties": {
                    "redirect_url": {"type": "string", "description": "Google OAuth authorization URL", "format": "uri"}
                },
                "required": ["redirect_url"],
            },
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Invalid OAuth configuration or missing credentials",
            response={
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "enum": ["oauth_config_error", "invalid_redirect_uri", "missing_credentials"],
                    },
                    "message": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during OAuth initialization",
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

google_auth_callback_schema = {
    "operation_id": "google_oauth_callback",
    "summary": "Handle Google OAuth Callback",
    "description": (
        "Processes the authorization code returned by Google OAuth and authenticates the user\n"
        "\n"
        "**Process:**\n"
        "1. Receives authorization code from Google\n"
        "2. Exchanges code for access token\n"
        "3. Retrieves user profile from Google\n"
        "4. Creates or updates user account\n"
        "5. Returns JWT tokens for authenticated session\n"
        "\n"
        "**Error Handling:**\n"
        "- Invalid authorization code\n"
        "- Expired authorization code\n"
        "- Network errors during token exchange\n"
        "- Profile retrieval failures\n"
        "\n"
        "**Security:**\n"
        "- Validates OAuth state parameter for CSRF protection\n"
        "- Verifies authorization code authenticity\n"
        "\n"
        "**Use Cases:**\n"
        "- Completing social authentication flow\n"
        "- User profile creation from social data\n"
        "- Account linking with social profiles\n"
        "- Social login completion\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "parameters": [
        OpenApiParameter(
            name="code",
            description="Authorization code received from Google OAuth",
            required=True,
            type=str,
            location="query",
            examples=[
                OpenApiExample("Valid Code", value="4/0AfJohXn...", description="Google OAuth authorization code")
            ],
        ),
        OpenApiParameter(
            name="state",
            description="OAuth state parameter for CSRF protection",
            required=False,
            type=str,
            location="query",
            examples=[
                OpenApiExample(
                    "State Parameter", value="abc123def456", description="Random state string for CSRF protection"
                )
            ],
        ),
    ],
    "examples": [
        OpenApiExample(
            "Successful Authentication",
            value={
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@example.com",
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
            "Invalid Code",
            value={
                "error": "invalid_grant",
                "message": "Authorization code is invalid or expired",
                "oauth_error": "invalid_grant",
            },
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully authenticated with Google",
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
            description="Invalid authorization code or OAuth error",
            response={
                "type": "object",
                "properties": {
                    "error": {"type": "string", "enum": ["invalid_grant", "invalid_request", "unauthorized_client"]},
                    "message": {"type": "string"},
                    "oauth_error": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during authentication",
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


"""Facebook OAuth Authentication"""

facebook_auth_login_schema = {
    "operation_id": "facebook_oauth_login",
    "summary": "Initiate Facebook OAuth Login",
    "description": (
        "Initiates the Facebook OAuth authentication flow by redirecting users to Facebook's authorization server\n"
        "\n"
        "**Flow:**\n"
        '1. User clicks "Login with Facebook"\n'
        "2. Redirected to Facebook OAuth consent screen\n"
        "3. User authorizes the application\n"
        "4. Facebook redirects back to callback URL with authorization code\n"
        "\n"
        "**Prerequisites:**\n"
        "- Facebook OAuth credentials configured in settings\n"
        "- Valid redirect URI configured in Facebook Developer Console\n"
        "- Required permissions configured (email, public_profile)\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (public endpoint)\n"
        "- CSRF protection via state parameter\n"
        "\n"
        "**Use Cases:**\n"
        "- Social media platform integration\n"
        "- Mobile app Facebook login\n"
        "- E-commerce social authentication\n"
        "- Gaming platform social login\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Facebook Login Documentation",
        "url": "https://developers.facebook.com/docs/facebook-login/",
    },
    "examples": [
        OpenApiExample(
            "Successful Redirect",
            value={
                "redirect_url": "https://www.facebook.com/v12.0/dialog/oauth?client_id=...&redirect_uri=...&scope=...&response_type=code&state=..."
            },
            response_only=True,
            status_codes=["301"],
        ),
        OpenApiExample(
            "Configuration Error",
            value={"error": "oauth_config_error", "message": "Facebook OAuth credentials not configured"},
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        301: CustomOpenApiResponse(
            status=301,
            description="Redirect to Facebook OAuth authorization URL",
            response={
                "type": "object",
                "properties": {
                    "redirect_url": {
                        "type": "string",
                        "description": "Facebook OAuth authorization URL",
                        "format": "uri",
                    }
                },
                "required": ["redirect_url"],
            },
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Invalid OAuth configuration or missing credentials",
            response={
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "enum": ["oauth_config_error", "invalid_redirect_uri", "missing_credentials"],
                    },
                    "message": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during OAuth initialization",
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

facebook_auth_callback_schema = {
    "operation_id": "facebook_oauth_callback",
    "summary": "Handle Facebook OAuth Callback",
    "description": (
        "Processes the authorization code returned by Facebook OAuth and authenticates the user\n"
        "\n"
        "**Process:**\n"
        "1. Receives authorization code from Facebook\n"
        "2. Exchanges code for access token\n"
        "3. Retrieves user profile from Facebook Graph API\n"
        "4. Creates or updates user account\n"
        "5. Returns JWT tokens for authenticated session\n"
        "\n"
        "**Error Handling:**\n"
        "- Invalid authorization code\n"
        "- Expired authorization code\n"
        "- Network errors during token exchange\n"
        "- Profile retrieval failures\n"
        "- Permission denied by user\n"
        "\n"
        "**Security:**\n"
        "- Validates OAuth state parameter for CSRF protection\n"
        "- Verifies authorization code authenticity\n"
        "\n"
        "**Use Cases:**\n"
        "- Completing Facebook authentication flow\n"
        "- Social profile data import\n"
        "- Social login completion\n"
        "- Account linking with Facebook profile\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "parameters": [
        OpenApiParameter(
            name="code",
            description="Authorization code received from Facebook OAuth",
            required=True,
            type=str,
            location="query",
            examples=[OpenApiExample("Valid Code", value="AQD...", description="Facebook OAuth authorization code")],
        ),
        OpenApiParameter(
            name="state",
            description="OAuth state parameter for CSRF protection",
            required=False,
            type=str,
            location="query",
            examples=[
                OpenApiExample(
                    "State Parameter", value="abc123def456", description="Random state string for CSRF protection"
                )
            ],
        ),
    ],
    "examples": [
        OpenApiExample(
            "Successful Authentication",
            value={
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@example.com",
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
            "Permission Denied",
            value={
                "error": "permission_denied",
                "message": "User denied permission to access profile information",
                "oauth_error": "access_denied",
            },
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully authenticated with Facebook",
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
            description="Invalid authorization code or OAuth error",
            response={
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "enum": ["invalid_grant", "invalid_request", "unauthorized_client", "permission_denied"],
                    },
                    "message": {"type": "string"},
                    "oauth_error": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during authentication",
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


"""LinkedIn OAuth Authentication"""

linkedin_auth_login_schema = {
    "operation_id": "linkedin_oauth_login",
    "summary": "Initiate LinkedIn OAuth Login",
    "description": (
        "Initiates the LinkedIn OAuth authentication flow by redirecting users to LinkedIn's authorization server\n"
        "\n"
        "**Flow:**\n"
        '1. User clicks "Login with LinkedIn"\n'
        "2. Redirected to LinkedIn OAuth consent screen\n"
        "3. User authorizes the application\n"
        "4. LinkedIn redirects back to callback URL with authorization code\n"
        "\n"
        "**Prerequisites:**\n"
        "- LinkedIn OAuth credentials configured in settings\n"
        "- Valid redirect URI configured in LinkedIn Developer Console\n"
        "- Required permissions configured (r_liteprofile, r_emailaddress)\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (public endpoint)\n"
        "- CSRF protection via state parameter\n"
        "\n"
        "**Use Cases:**\n"
        "- Professional networking platform integration\n"
        "- B2B application authentication\n"
        "- Enterprise social login\n"
        "- Professional profile import\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "LinkedIn OAuth 2.0 Documentation",
        "url": "https://docs.microsoft.com/en-us/linkedin/shared/authentication/authentication",
    },
    "examples": [
        OpenApiExample(
            "Successful Redirect",
            value={
                "redirect_url": "https://www.linkedin.com/oauth/v2/authorization?client_id=...&redirect_uri=...&scope=...&response_type=code&state=..."
            },
            response_only=True,
            status_codes=["301"],
        ),
        OpenApiExample(
            "Configuration Error",
            value={"error": "oauth_config_error", "message": "LinkedIn OAuth credentials not configured"},
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        301: CustomOpenApiResponse(
            status=301,
            description="Redirect to LinkedIn OAuth authorization URL",
            response={
                "type": "object",
                "properties": {
                    "redirect_url": {
                        "type": "string",
                        "description": "LinkedIn OAuth authorization URL",
                        "format": "uri",
                    }
                },
                "required": ["redirect_url"],
            },
        ),
        400: CustomOpenApiResponse(
            status=400,
            description="Invalid OAuth configuration or missing credentials",
            response={
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "enum": ["oauth_config_error", "invalid_redirect_uri", "missing_credentials"],
                    },
                    "message": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during OAuth initialization",
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

linkedin_auth_callback_schema = {
    "operation_id": "linkedin_oauth_callback",
    "summary": "Handle LinkedIn OAuth Callback",
    "description": (
        "Processes the authorization code returned by LinkedIn OAuth and authenticates the user\n"
        "\n"
        "**Process:**\n"
        "1. Receives authorization code from LinkedIn\n"
        "2. Exchanges code for access token\n"
        "3. Retrieves user profile from LinkedIn API\n"
        "4. Creates or updates user account\n"
        "5. Returns JWT tokens for authenticated session\n"
        "\n"
        "**Error Handling:**\n"
        "- Invalid authorization code\n"
        "- Expired authorization code\n"
        "- Network errors during token exchange\n"
        "- Profile retrieval failures\n"
        "- Permission denied by user\n"
        "\n"
        "**Security:**\n"
        "- Validates OAuth state parameter for CSRF protection\n"
        "- Verifies authorization code authenticity\n"
        "\n"
        "**Use Cases:**\n"
        "- Completing LinkedIn authentication flow\n"
        "- Professional profile data import\n"
        "- Business networking integration\n"
        "- Professional identity verification\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "parameters": [
        OpenApiParameter(
            name="code",
            description="Authorization code received from LinkedIn OAuth",
            required=True,
            type=str,
            location="query",
            examples=[OpenApiExample("Valid Code", value="AQT...", description="LinkedIn OAuth authorization code")],
        ),
        OpenApiParameter(
            name="state",
            description="OAuth state parameter for CSRF protection",
            required=False,
            type=str,
            location="query",
            examples=[
                OpenApiExample(
                    "State Parameter", value="abc123def456", description="Random state string for CSRF protection"
                )
            ],
        ),
    ],
    "examples": [
        OpenApiExample(
            "Successful Authentication",
            value={
                "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "user": {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "email": "user@example.com",
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
            "Permission Denied",
            value={
                "error": "permission_denied",
                "message": "User denied permission to access profile information",
                "oauth_error": "access_denied",
            },
            response_only=True,
            status_codes=["400"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully authenticated with LinkedIn",
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
            description="Invalid authorization code or OAuth error",
            response={
                "type": "object",
                "properties": {
                    "error": {
                        "type": "string",
                        "enum": ["invalid_grant", "invalid_request", "unauthorized_client", "permission_denied"],
                    },
                    "message": {"type": "string"},
                    "oauth_error": {"type": "string"},
                    "details": {"type": "object"},
                },
                "required": ["error", "message"],
            },
        ),
        500: CustomOpenApiResponse(
            status=500,
            description="Internal server error during authentication",
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


"""Google Native id_token Verify (Credential Manager / iOS / Web One Tap)"""

google_native_verify_schema = {
    "operation_id": "google_native_verify",
    "request": GoogleNativeIdTokenVerifyRequestSerializer,
    "summary": "Verify Google id_token from native client",
    "description": (
        "Verifies a Google-issued id_token obtained by a native client (Android Credential Manager, "
        "iOS Google Sign-In SDK, or Web One Tap) and issues blockauth JWTs without a redirect round-trip\n"
        "\n"
        "**Process:**\n"
        "1. Validate request body (`id_token` + `raw_nonce` required)\n"
        "2. Hash `raw_nonce` (SHA-256 hex) and verify the id_token's `nonce` claim matches\n"
        "3. Verify id_token signature against Google JWKS (`https://www.googleapis.com/oauth2/v3/certs`), "
        "plus issuer (`https://accounts.google.com`), audience (allowlisted), and expiry\n"
        "4. Upsert `SocialIdentity(provider=google, subject=sub)` and link to user\n"
        "5. Issue blockauth access + refresh tokens\n"
        "\n"
        "**Request Body:**\n"
        "- `id_token` (required): Google-issued id_token JWT\n"
        "- `raw_nonce` (required): the un-hashed nonce the client passed when requesting the id_token\n"
        "\n"
        "**Audience Allowlist:**\n"
        "Configure `GOOGLE_NATIVE_AUDIENCES` with the Web (server) OAuth client IDs the integrator "
        "registered. The `azp` claim (platform client ID) is captured but not enforced; integrators "
        "can validate it via a post-login trigger if they need stricter platform binding.\n"
        "\n"
        "**Error Handling:**\n"
        "- 400 (4020): `GOOGLE_NATIVE_AUDIENCES` is not configured\n"
        "- 400 (4061): id_token signature, issuer, audience, expiry, or nonce verification failed\n"
        "- 409: SocialIdentity conflict — Google subject already linked to a different user\n"
        "\n"
        "**Security:**\n"
        "- No authentication required (public endpoint)\n"
        "- id_token signature verification gates everything; no claim is trusted before verification\n"
        "- Nonce binding prevents id_token replay across requests\n"
        "- JWKS responses are cached (`OIDC_JWKS_CACHE_TTL_SECONDS`, default 3600s) to avoid\n"
        "  rate-limiting Google's certs endpoint\n"
        "\n"
        "**Use Cases:**\n"
        "- Sign in with Google from Android (Credential Manager)\n"
        "- Sign in with Google from iOS (Google Sign-In SDK)\n"
        "- Sign in with Google from web via One Tap\n"
    ),
    "tags": ["Social Authentication"],
    "deprecated": False,
    "external_docs": {
        "description": "Sign In With Google — verifying the id_token",
        "url": "https://developers.google.com/identity/sign-in/web/backend-auth",
    },
    "examples": [
        OpenApiExample(
            "Native Verify Request",
            value={
                "id_token": "eyJhbGciOiJSUzI1NiIs...",
                "raw_nonce": "f3K0...",
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
                    "email": "user@example.com",
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
            "Audiences Not Configured",
            value={"detail": "Google native audiences are not configured", "error_code": 4020},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "id_token Verification Failed",
            value={"detail": "id_token signature verification failed", "error_code": 4061},
            response_only=True,
            status_codes=["400"],
        ),
        OpenApiExample(
            "Identity Conflict",
            value={
                "detail": "social identity conflict for provider=google",
                "code": "SOCIAL_IDENTITY_CONFLICT",
            },
            response_only=True,
            status_codes=["409"],
        ),
    ],
    "responses": {
        200: CustomOpenApiResponse(
            status=200,
            description="Successfully verified Google id_token and authenticated the user",
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
            description="Configuration missing or id_token verification failed",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {
                        "type": "integer",
                        "enum": [4020, 4061],
                        "description": "4020=audiences not configured; 4061=id_token verification failed",
                    },
                },
                "required": ["detail"],
            },
        ),
        409: CustomOpenApiResponse(
            status=409,
            description="Google subject is already linked to a different user account",
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
