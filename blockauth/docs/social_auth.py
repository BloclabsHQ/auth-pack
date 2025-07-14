from drf_spectacular.utils import OpenApiParameter, OpenApiExample
from blockauth.schemas.factory import CustomOpenApiResponse

"""Google OAuth Authentication"""

google_auth_login_schema = {
    'operation_id': 'google_oauth_login',
    'summary': 'Initiate Google OAuth Login',
    'description': '''
    Initiates the Google OAuth authentication flow by redirecting users to Google's authorization server.
    
    **Flow:**
    1. User clicks "Login with Google"
    2. Redirected to Google OAuth consent screen
    3. User authorizes the application
    4. Google redirects back to callback URL with authorization code
    
    **Prerequisites:**
    - Google OAuth credentials configured in settings
    - Valid redirect URI configured in Google Console
    
    **Security:**
    - No authentication required (public endpoint)
    - CSRF protection via state parameter
    
    **Use Cases:**
    - Quick user registration and login
    - Single sign-on (SSO) integration
    - Reduced friction user onboarding
    - Mobile app social login
    ''',
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
    'description': '''
    Processes the authorization code returned by Google OAuth and authenticates the user.
    
    **Process:**
    1. Receives authorization code from Google
    2. Exchanges code for access token
    3. Retrieves user profile from Google
    4. Creates or updates user account
    5. Returns JWT tokens for authenticated session
    
    **Error Handling:**
    - Invalid authorization code
    - Expired authorization code
    - Network errors during token exchange
    - Profile retrieval failures
    
    **Security:**
    - Validates OAuth state parameter for CSRF protection
    - Verifies authorization code authenticity
    
    **Use Cases:**
    - Completing social authentication flow
    - User profile creation from social data
    - Account linking with social profiles
    - Social login completion
    ''',
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
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'user': {
                    'id': 123,
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'is_verified': True
                }
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
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {
                                'type': 'integer',
                                'description': 'User ID in the system'
                            },
                            'email': {
                                'type': 'string',
                                'format': 'email',
                                'description': 'User email address'
                            },
                            'first_name': {
                                'type': 'string',
                                'description': 'User first name'
                            },
                            'last_name': {
                                'type': 'string',
                                'description': 'User last name'
                            },
                            'is_verified': {
                                'type': 'boolean',
                                'description': 'Whether user email is verified'
                            }
                        },
                        'required': ['id', 'email', 'is_verified']
                    }
                },
                'required': ['access', 'refresh', 'user']
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
    'description': '''
    Initiates the Facebook OAuth authentication flow by redirecting users to Facebook's authorization server.
    
    **Flow:**
    1. User clicks "Login with Facebook"
    2. Redirected to Facebook OAuth consent screen
    3. User authorizes the application
    4. Facebook redirects back to callback URL with authorization code
    
    **Prerequisites:**
    - Facebook OAuth credentials configured in settings
    - Valid redirect URI configured in Facebook Developer Console
    - Required permissions configured (email, public_profile)
    
    **Security:**
    - No authentication required (public endpoint)
    - CSRF protection via state parameter
    
    **Use Cases:**
    - Social media platform integration
    - Mobile app Facebook login
    - E-commerce social authentication
    - Gaming platform social login
    ''',
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
    'description': '''
    Processes the authorization code returned by Facebook OAuth and authenticates the user.
    
    **Process:**
    1. Receives authorization code from Facebook
    2. Exchanges code for access token
    3. Retrieves user profile from Facebook Graph API
    4. Creates or updates user account
    5. Returns JWT tokens for authenticated session
    
    **Error Handling:**
    - Invalid authorization code
    - Expired authorization code
    - Network errors during token exchange
    - Profile retrieval failures
    - Permission denied by user
    
    **Security:**
    - Validates OAuth state parameter for CSRF protection
    - Verifies authorization code authenticity
    
    **Use Cases:**
    - Completing Facebook authentication flow
    - Social profile data import
    - Social login completion
    - Account linking with Facebook profile
    ''',
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
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'user': {
                    'id': 123,
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'is_verified': True
                }
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
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {
                                'type': 'integer',
                                'description': 'User ID in the system'
                            },
                            'email': {
                                'type': 'string',
                                'format': 'email',
                                'description': 'User email address'
                            },
                            'first_name': {
                                'type': 'string',
                                'description': 'User first name'
                            },
                            'last_name': {
                                'type': 'string',
                                'description': 'User last name'
                            },
                            'is_verified': {
                                'type': 'boolean',
                                'description': 'Whether user email is verified'
                            }
                        },
                        'required': ['id', 'email', 'is_verified']
                    }
                },
                'required': ['access', 'refresh', 'user']
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
    'description': '''
    Initiates the LinkedIn OAuth authentication flow by redirecting users to LinkedIn's authorization server.
    
    **Flow:**
    1. User clicks "Login with LinkedIn"
    2. Redirected to LinkedIn OAuth consent screen
    3. User authorizes the application
    4. LinkedIn redirects back to callback URL with authorization code
    
    **Prerequisites:**
    - LinkedIn OAuth credentials configured in settings
    - Valid redirect URI configured in LinkedIn Developer Console
    - Required permissions configured (r_liteprofile, r_emailaddress)
    
    **Security:**
    - No authentication required (public endpoint)
    - CSRF protection via state parameter
    
    **Use Cases:**
    - Professional networking platform integration
    - B2B application authentication
    - Enterprise social login
    - Professional profile import
    ''',
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
    'description': '''
    Processes the authorization code returned by LinkedIn OAuth and authenticates the user.
    
    **Process:**
    1. Receives authorization code from LinkedIn
    2. Exchanges code for access token
    3. Retrieves user profile from LinkedIn API
    4. Creates or updates user account
    5. Returns JWT tokens for authenticated session
    
    **Error Handling:**
    - Invalid authorization code
    - Expired authorization code
    - Network errors during token exchange
    - Profile retrieval failures
    - Permission denied by user
    
    **Security:**
    - Validates OAuth state parameter for CSRF protection
    - Verifies authorization code authenticity
    
    **Use Cases:**
    - Completing LinkedIn authentication flow
    - Professional profile data import
    - Business networking integration
    - Professional identity verification
    ''',
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
                'refresh': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                'user': {
                    'id': 123,
                    'email': 'user@example.com',
                    'first_name': 'John',
                    'last_name': 'Doe',
                    'is_verified': True
                }
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
                    },
                    'user': {
                        'type': 'object',
                        'properties': {
                            'id': {
                                'type': 'integer',
                                'description': 'User ID in the system'
                            },
                            'email': {
                                'type': 'string',
                                'format': 'email',
                                'description': 'User email address'
                            },
                            'first_name': {
                                'type': 'string',
                                'description': 'User first name'
                            },
                            'last_name': {
                                'type': 'string',
                                'description': 'User last name'
                            },
                            'is_verified': {
                                'type': 'boolean',
                                'description': 'Whether user email is verified'
                            }
                        },
                        'required': ['id', 'email', 'is_verified']
                    }
                },
                'required': ['access', 'refresh', 'user']
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