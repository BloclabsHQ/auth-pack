from drf_spectacular.utils import OpenApiParameter, OpenApiExample
from blockauth.schemas.factory import CustomOpenApiResponse

"""Google OAuth Authentication"""

google_auth_login_schema = {
    'operation_id': 'google_oauth_login',
    'summary': 'Initiate Google OAuth Login',
    'description': (
        "Initiates the Google OAuth authentication flow by redirecting users to Google's authorization server\n"
        "\n"
        "**Flow:**\n"
        "1. User clicks \"Login with Google\"\n"
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'external_docs': {
        'description': 'Google OAuth 2.0 Documentation',
        'url': 'https://developers.google.com/identity/protocols/oauth2'
    },
    'examples': [
        OpenApiExample(
            'Successful Redirect',
            value={
                'redirect_url': 'https://accounts.google.com/oauth/authorize?client_id=...&redirect_uri=...&scope=...&response_type=code&state=...'
            },
            response_only=True,
            status_codes=['301']
        ),
        OpenApiExample(
            'Configuration Error',
            value={
                'error': 'oauth_config_error',
                'message': 'Google OAuth credentials not configured'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        301: CustomOpenApiResponse(
            status=301,
            description='Redirect to Google OAuth authorization URL',
            response={
                'type': 'object',
                'properties': {
                    'redirect_url': {
                        'type': 'string',
                        'description': 'Google OAuth authorization URL',
                        'format': 'uri'
                    }
                },
                'required': ['redirect_url']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid OAuth configuration or missing credentials',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['oauth_config_error', 'invalid_redirect_uri', 'missing_credentials']
                    },
                    'message': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during OAuth initialization',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}

google_auth_callback_schema = {
    'operation_id': 'google_oauth_callback',
    'summary': 'Handle Google OAuth Callback',
    'description': (
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code received from Google OAuth',
            required=True,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'Valid Code',
                    value='4/0AfJohXn...',
                    description='Google OAuth authorization code'
                )
            ]
        ),
        OpenApiParameter(
            name='state',
            description='OAuth state parameter for CSRF protection',
            required=False,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'State Parameter',
                    value='abc123def456',
                    description='Random state string for CSRF protection'
                )
            ]
        )
    ],
    'examples': [
        OpenApiExample(
            'Successful Authentication',
            value={
                'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            response_only=True,
            status_codes=['200']
        ),
        OpenApiExample(
            'Invalid Code',
            value={
                'error': 'invalid_grant',
                'message': 'Authorization code is invalid or expired',
                'oauth_error': 'invalid_grant'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            description='Successfully authenticated with Google',
            response={
                'type': 'object',
                'properties': {
                    'access': {
                        'type': 'string',
                        'description': 'JWT access token for API authentication',
                        'format': 'jwt'
                    },
                    'refresh': {
                        'type': 'string',
                        'description': 'JWT refresh token for token renewal',
                        'format': 'jwt'
                    }
                },
                'required': ['access', 'refresh']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid authorization code or OAuth error',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['invalid_grant', 'invalid_request', 'unauthorized_client']
                    },
                    'message': {'type': 'string'},
                    'oauth_error': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during authentication',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}


"""Facebook OAuth Authentication"""

facebook_auth_login_schema = {
    'operation_id': 'facebook_oauth_login',
    'summary': 'Initiate Facebook OAuth Login',
    'description': (
        "Initiates the Facebook OAuth authentication flow by redirecting users to Facebook's authorization server\n"
        "\n"
        "**Flow:**\n"
        "1. User clicks \"Login with Facebook\"\n"
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'external_docs': {
        'description': 'Facebook Login Documentation',
        'url': 'https://developers.facebook.com/docs/facebook-login/'
    },
    'examples': [
        OpenApiExample(
            'Successful Redirect',
            value={
                'redirect_url': 'https://www.facebook.com/v12.0/dialog/oauth?client_id=...&redirect_uri=...&scope=...&response_type=code&state=...'
            },
            response_only=True,
            status_codes=['301']
        ),
        OpenApiExample(
            'Configuration Error',
            value={
                'error': 'oauth_config_error',
                'message': 'Facebook OAuth credentials not configured'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        301: CustomOpenApiResponse(
            status=301,
            description='Redirect to Facebook OAuth authorization URL',
            response={
                'type': 'object',
                'properties': {
                    'redirect_url': {
                        'type': 'string',
                        'description': 'Facebook OAuth authorization URL',
                        'format': 'uri'
                    }
                },
                'required': ['redirect_url']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid OAuth configuration or missing credentials',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['oauth_config_error', 'invalid_redirect_uri', 'missing_credentials']
                    },
                    'message': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during OAuth initialization',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}

facebook_auth_callback_schema = {
    'operation_id': 'facebook_oauth_callback',
    'summary': 'Handle Facebook OAuth Callback',
    'description': (
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code received from Facebook OAuth',
            required=True,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'Valid Code',
                    value='AQD...',
                    description='Facebook OAuth authorization code'
                )
            ]
        ),
        OpenApiParameter(
            name='state',
            description='OAuth state parameter for CSRF protection',
            required=False,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'State Parameter',
                    value='abc123def456',
                    description='Random state string for CSRF protection'
                )
            ]
        )
    ],
    'examples': [
        OpenApiExample(
            'Successful Authentication',
            value={
                'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            response_only=True,
            status_codes=['200']
        ),
        OpenApiExample(
            'Permission Denied',
            value={
                'error': 'permission_denied',
                'message': 'User denied permission to access profile information',
                'oauth_error': 'access_denied'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            description='Successfully authenticated with Facebook',
            response={
                'type': 'object',
                'properties': {
                    'access': {
                        'type': 'string',
                        'description': 'JWT access token for API authentication',
                        'format': 'jwt'
                    },
                    'refresh': {
                        'type': 'string',
                        'description': 'JWT refresh token for token renewal',
                        'format': 'jwt'
                    }
                },
                'required': ['access', 'refresh']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid authorization code or OAuth error',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['invalid_grant', 'invalid_request', 'unauthorized_client', 'permission_denied']
                    },
                    'message': {'type': 'string'},
                    'oauth_error': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during authentication',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}


"""LinkedIn OAuth Authentication"""

linkedin_auth_login_schema = {
    'operation_id': 'linkedin_oauth_login',
    'summary': 'Initiate LinkedIn OAuth Login',
    'description': (
        "Initiates the LinkedIn OAuth authentication flow by redirecting users to LinkedIn's authorization server\n"
        "\n"
        "**Flow:**\n"
        "1. User clicks \"Login with LinkedIn\"\n"
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'external_docs': {
        'description': 'LinkedIn OAuth 2.0 Documentation',
        'url': 'https://docs.microsoft.com/en-us/linkedin/shared/authentication/authentication'
    },
    'examples': [
        OpenApiExample(
            'Successful Redirect',
            value={
                'redirect_url': 'https://www.linkedin.com/oauth/v2/authorization?client_id=...&redirect_uri=...&scope=...&response_type=code&state=...'
            },
            response_only=True,
            status_codes=['301']
        ),
        OpenApiExample(
            'Configuration Error',
            value={
                'error': 'oauth_config_error',
                'message': 'LinkedIn OAuth credentials not configured'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        301: CustomOpenApiResponse(
            status=301,
            description='Redirect to LinkedIn OAuth authorization URL',
            response={
                'type': 'object',
                'properties': {
                    'redirect_url': {
                        'type': 'string',
                        'description': 'LinkedIn OAuth authorization URL',
                        'format': 'uri'
                    }
                },
                'required': ['redirect_url']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid OAuth configuration or missing credentials',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['oauth_config_error', 'invalid_redirect_uri', 'missing_credentials']
                    },
                    'message': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during OAuth initialization',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}

linkedin_auth_callback_schema = {
    'operation_id': 'linkedin_oauth_callback',
    'summary': 'Handle LinkedIn OAuth Callback',
    'description': (
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
    'tags': ['Social Authentication'],
    'deprecated': False,
    'parameters': [
        OpenApiParameter(
            name='code',
            description='Authorization code received from LinkedIn OAuth',
            required=True,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'Valid Code',
                    value='AQT...',
                    description='LinkedIn OAuth authorization code'
                )
            ]
        ),
        OpenApiParameter(
            name='state',
            description='OAuth state parameter for CSRF protection',
            required=False,
            type=str,
            location='query',
            examples=[
                OpenApiExample(
                    'State Parameter',
                    value='abc123def456',
                    description='Random state string for CSRF protection'
                )
            ]
        )
    ],
    'examples': [
        OpenApiExample(
            'Successful Authentication',
            value={
                'access': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
            },
            response_only=True,
            status_codes=['200']
        ),
        OpenApiExample(
            'Permission Denied',
            value={
                'error': 'permission_denied',
                'message': 'User denied permission to access profile information',
                'oauth_error': 'access_denied'
            },
            response_only=True,
            status_codes=['400']
        )
    ],
    'responses': {
        200: CustomOpenApiResponse(
            status=200,
            description='Successfully authenticated with LinkedIn',
            response={
                'type': 'object',
                'properties': {
                    'access': {
                        'type': 'string',
                        'description': 'JWT access token for API authentication',
                        'format': 'jwt'
                    },
                    'refresh': {
                        'type': 'string',
                        'description': 'JWT refresh token for token renewal',
                        'format': 'jwt'
                    }
                },
                'required': ['access', 'refresh']
            }
        ),
        400: CustomOpenApiResponse(
            status=400,
            description='Invalid authorization code or OAuth error',
            response={
                'type': 'object',
                'properties': {
                    'error': {
                        'type': 'string',
                        'enum': ['invalid_grant', 'invalid_request', 'unauthorized_client', 'permission_denied']
                    },
                    'message': {'type': 'string'},
                    'oauth_error': {'type': 'string'},
                    'details': {'type': 'object'}
                },
                'required': ['error', 'message']
            }
        ),
        500: CustomOpenApiResponse(
            status=500,
            description='Internal server error during authentication',
            response={
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'},
                    'message': {'type': 'string'},
                    'request_id': {'type': 'string'}
                },
                'required': ['error', 'message']
            }
        )
    }
}