"""
BlockAuth Authentication Documentation

This module contains comprehensive Swagger/OpenAPI documentation for authentication endpoints.
Separated from business logic for better maintainability and organization.
"""

from drf_spectacular.utils import OpenApiResponse, OpenApiExample, OpenApiParameter
from rest_framework import status

from blockauth.serializers.user_account_serializers import (
    SignUpRequestSerializer, SignUpResendOTPSerializer, SignUpConfirmationSerializer,
    BasicLoginSerializer, PasswordlessLoginSerializer, PasswordlessLoginConfirmationSerializer,
    RefreshTokenSerializer, PasswordResetRequestSerializer, PasswordResetConfirmationEmailSerializer,
    PasswordChangeSerializer, EmailChangeRequestSerializer, EmailChangeConfirmationSerializer
)


# =============================================================================
# SIGNUP DOCUMENTATION
# =============================================================================

signup_docs = {
    'operation_id': 'user_signup',
    'summary': 'User Registration',
    'description': '''
    Create a new user account with email/phone verification.
    
    **Process:**
    1. User provides email/phone and password
    2. System validates input data
    3. Creates user account (unverified)
    4. Sends OTP or verification link
    5. User completes verification via separate endpoint
    
    **Verification Methods:**
    - **OTP**: Time-based one-time password sent via email/SMS
    - **Link**: Verification link sent via email
    
    **Security:**
    - Password is hashed using Django's secure hashing
    - Rate limiting applied to prevent abuse
    - Email/phone validation before account creation
    
    **Prerequisites:**
    - Valid email address or phone number
    - Strong password (minimum 8 characters)
    - Unique identifier (email/phone not already registered)
    
    **Use Cases:**
    - New user registration for web/mobile applications
    - Account creation for e-commerce platforms
    - User onboarding for SaaS applications
    - Community platform member registration
    ''',
    'tags': ['Signup'],
    'deprecated': False,
    'request': SignUpRequestSerializer,
    'examples': [
        OpenApiExample(
            "Email Registration (OTP)",
            value={
                "identifier": "user@example.com",
                "password": "MySecretPassword123",
                "method": "email",
                "verification_type": "otp"
            },
            request_only=True,
            description="Register with email using OTP verification"
        ),
        OpenApiExample(
            "Email Registration (Link)",
            value={
                "identifier": "user@example.com",
                "password": "MySecretPassword123",
                "method": "email",
                "verification_type": "link"
            },
            request_only=True,
            description="Register with email using verification link"
        ),
        OpenApiExample(
            "Phone Registration (SMS)",
            value={
                "identifier": "+1234567890",
                "password": "MySecretPassword123",
                "method": "sms",
                "verification_type": "otp"
            },
            request_only=True,
            description="Register with phone number using SMS OTP"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Registration initiated successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Confirmation message with verification method",
                        "enum": [
                            "otp sent via email.",
                            "link sent via email.",
                            "otp sent via sms."
                        ]
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "OTP Sent",
                    value={"message": "otp sent via email."},
                    status_codes=[200],
                ),
                OpenApiExample(
                    "Link Sent",
                    value={"message": "link sent via email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Validation error - Invalid input data",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "Field-specific validation errors"
                    },
                    "error_code": {
                        "type": "string",
                        "description": "Application-specific error code"
                    }
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Invalid Email",
                    value={
                        "detail": {"identifier": ["Enter a valid email address."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Weak Password",
                    value={
                        "detail": {"password": ["This password is too short. It must contain at least 8 characters."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "User Already Exists",
                    value={
                        "detail": "User with this email already exists.",
                        "error_code": "4002"
                    },
                    status_codes=[400],
                )
            ]
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "string",
                        "description": "Rate limit error message"
                    }
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Rate Limit",
                    value={"detail": "Request limit exceeded. Please try again after 30 seconds."},
                    status_codes=[429],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


signup_resend_otp_docs = {
    'operation_id': 'resend_verification',
    'summary': 'Resend Verification OTP/Link',
    'description': '''
    Resend OTP or verification link for signup confirmation or wallet email verification.
    
    **Use Cases:**
    - User didn't receive initial verification
    - OTP expired and needs renewal
    - Wallet user adding email verification
    
    **Rate Limiting:**
    - Prevents abuse and spam
    - Configurable wait time between requests
    - Different limits for signup vs wallet verification
    
    **Security:**
    - Rate limiting prevents brute force attacks
    - Validates identifier format before sending
    - Logs all attempts for monitoring
    
    **Use Cases:**
    - User didn't receive initial verification email/SMS
    - OTP expired and needs renewal
    - Wallet user adding email verification
    - Account recovery for unverified users
    ''',
    'tags': ['Verification'],
    'deprecated': False,
    'request': SignUpResendOTPSerializer,
    'examples': [
        OpenApiExample(
            "Signup Verification (OTP)",
            value={
                "identifier": "user@example.com",
                "method": "email",
                "verification_type": "otp"
            },
            request_only=True,
            description="Resend OTP for signup verification"
        ),
        OpenApiExample(
            "Wallet Email Verification",
            value={
                "identifier": "user@example.com",
                "method": "email",
                "verification_type": "otp"
            },
            request_only=True,
            description="Resend OTP for wallet email verification"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Verification OTP/link sent successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Confirmation message with verification method"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "OTP Success",
                    value={"message": "otp sent via email."},
                    status_codes=[200],
                ),
                OpenApiExample(
                    "Link Success",
                    value={"message": "link sent via email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Validation error",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid identifier",
                    value={"detail": "Invalid email or phone number."},
                    status_codes=[400],
                )
            ]
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Rate limit",
                    value={"detail": "Request limit exceeded. Please try again after 30 seconds."},
                    status_codes=[429],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


signup_confirm_docs = {
    'operation_id': 'confirm_signup',
    'summary': 'Confirm User Registration',
    'description': '''
    Verify OTP or click verification link to complete user registration.
    
    **Process:**
    1. User provides identifier and verification code
    2. System validates OTP/link
    3. Marks user as verified
    4. User can now login to the system
    
    **Verification Types:**
    - **OTP**: Numeric code sent via email/SMS
    - **Link**: URL-based verification (handled separately)
    
    **Security:**
    - OTP has expiration time
    - One-time use only
    - Rate limiting on attempts
    - CSRF protection for link verification
    
    **Use Cases:**
    - Completing email verification after signup
    - Phone number verification for SMS-based auth
    - Account activation after registration
    - Two-factor authentication setup
    ''',
    'tags': ['Verification'],
    'deprecated': False,
    'request': SignUpConfirmationSerializer,
    'examples': [
        OpenApiExample(
            "Email OTP Confirmation",
            value={
                "identifier": "user@example.com",
                "code": "123456"
            },
            request_only=True,
            description="Confirm registration with email OTP"
        ),
        OpenApiExample(
            "Phone OTP Confirmation",
            value={
                "identifier": "+1234567890",
                "code": "123456"
            },
            request_only=True,
            description="Confirm registration with phone OTP"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Registration confirmed successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Success confirmation message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Email verified successfully."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid verification code",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={"detail": "Invalid verification code."},
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Expired Code",
                    value={"detail": "Verification code has expired."},
                    status_codes=[400],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


# =============================================================================
# LOGIN DOCUMENTATION
# =============================================================================

basic_login_docs = {
    'operation_id': 'basic_login',
    'summary': 'Basic Authentication Login',
    'description': '''
    Authenticate user with email/phone and password to obtain access tokens.
    
    **Authentication Flow:**
    1. User provides identifier (email/phone) and password
    2. System validates credentials
    3. Returns JWT access and refresh tokens
    4. User can use access token for authenticated requests
    
    **Security Features:**
    - Password hashing and validation
    - Account lockout after failed attempts
    - JWT token expiration
    - Refresh token for token renewal
    
    **Token Usage:**
    - **Access Token**: Include in Authorization header for API calls
    - **Refresh Token**: Use to get new access token when expired
    
    **Prerequisites:**
    - User account must be verified
    - Valid email/phone and password combination
    
    **Use Cases:**
    - Web application user login
    - Mobile app authentication
    - API access for authenticated users
    - E-commerce platform customer login
    ''',
    'tags': ['Login'],
    'deprecated': False,
    'request': BasicLoginSerializer,
    'examples': [
        OpenApiExample(
            "Email Login",
            value={
                "identifier": "user@example.com",
                "password": "MySecretPassword123"
            },
            request_only=True,
            description="Login with email and password"
        ),
        OpenApiExample(
            "Phone Login",
            value={
                "identifier": "+1234567890",
                "password": "MySecretPassword123"
            },
            request_only=True,
            description="Login with phone number and password"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Login successful",
            response={
                "type": "object",
                "properties": {
                    "access": {
                        "type": "string",
                        "description": "JWT access token for API authentication",
                        "format": "jwt"
                    },
                    "refresh": {
                        "type": "string",
                        "description": "JWT refresh token for token renewal",
                        "format": "jwt"
                    },
                    "user": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "integer",
                                "description": "User ID"
                            },
                            "email": {
                                "type": "string",
                                "format": "email",
                                "description": "User email address"
                            },
                            "phone_number": {
                                "type": "string",
                                "description": "User phone number"
                            },
                            "is_verified": {
                                "type": "boolean",
                                "description": "Email verification status"
                            }
                        },
                        "required": ["id", "is_verified"]
                    }
                },
                "required": ["access", "refresh"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {
                            "id": 123,
                            "email": "user@example.com",
                            "is_verified": True
                        }
                    },
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid credentials",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Credentials",
                    value={
                        "detail": "Invalid email or password.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Account Not Verified",
                    value={
                        "detail": "Please verify your email before logging in.",
                        "error_code": "4003"
                    },
                    status_codes=[400],
                )
            ]
        ),
        401: OpenApiResponse(
            description="Authentication failed",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        ),
        429: OpenApiResponse(
            description="Too many login attempts",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Rate Limit",
                    value={"detail": "Too many login attempts. Please try again later."},
                    status_codes=[429],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


passwordless_login_docs = {
    'operation_id': 'passwordless_login',
    'summary': 'Passwordless Login',
    'description': '''
    Initiate passwordless login by sending OTP or verification link.
    
    **Process:**
    1. User provides email/phone number
    2. System sends OTP or verification link
    3. User enters OTP or clicks link
    4. System authenticates user and returns tokens
    
    **Benefits:**
    - No password required
    - Enhanced security through time-based codes
    - Reduced password management overhead
    
    **Security:**
    - Rate limiting prevents abuse
    - OTP expiration for security
    - One-time use codes
    
    **Use Cases:**
    - Password-free authentication for mobile apps
    - Quick login for returning users
    - Enhanced security for sensitive applications
    - Corporate SSO integration
    ''',
    'tags': ['Login'],
    'deprecated': False,
    'request': PasswordlessLoginSerializer,
    'examples': [
        OpenApiExample(
            "Email OTP Login",
            value={
                "identifier": "user@example.com",
                "method": "email",
                "verification_type": "otp"
            },
            request_only=True,
            description="Login with email OTP"
        ),
        OpenApiExample(
            "Phone SMS Login",
            value={
                "identifier": "+1234567890",
                "method": "sms",
                "verification_type": "otp"
            },
            request_only=True,
            description="Login with SMS OTP"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Login OTP/link sent successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Confirmation message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "OTP Sent",
                    value={"message": "otp sent via email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid identifier or user not found",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "User Not Found",
                    value={
                        "detail": "User not found with this email.",
                        "error_code": "4004"
                    },
                    status_codes=[400],
                )
            ]
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Rate Limit",
                    value={"detail": "Request limit exceeded. Please try again after 30 seconds."},
                    status_codes=[429],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


passwordless_confirm_docs = {
    'operation_id': 'confirm_passwordless_login',
    'summary': 'Confirm Passwordless Login',
    'description': '''
    Complete passwordless login by verifying OTP or link.
    
    **Process:**
    1. User provides identifier and verification code
    2. System validates OTP/link
    3. Authenticates user and returns JWT tokens
    4. User can now access protected resources
    
    **Security:**
    - OTP validation with expiration check
    - One-time use verification codes
    - Rate limiting on verification attempts
    
    **Use Cases:**
    - Completing passwordless login flow
    - Two-factor authentication verification
    - Temporary access code validation
    - Guest user authentication
    ''',
    'tags': ['Verification'],
    'deprecated': False,
    'request': PasswordlessLoginConfirmationSerializer,
    'examples': [
        OpenApiExample(
            "Email OTP Confirmation",
            value={
                "identifier": "user@example.com",
                "code": "123456"
            },
            request_only=True,
            description="Confirm login with email OTP"
        ),
        OpenApiExample(
            "Phone OTP Confirmation",
            value={
                "identifier": "+1234567890",
                "code": "123456"
            },
            request_only=True,
            description="Confirm login with phone OTP"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Login successful",
            response={
                "type": "object",
                "properties": {
                    "access": {
                        "type": "string",
                        "description": "JWT access token for API authentication",
                        "format": "jwt"
                    },
                    "refresh": {
                        "type": "string",
                        "description": "JWT refresh token for token renewal",
                        "format": "jwt"
                    },
                    "user": {
                        "type": "object",
                        "properties": {
                            "id": {
                                "type": "integer",
                                "description": "User ID"
                            },
                            "email": {
                                "type": "string",
                                "format": "email",
                                "description": "User email address"
                            },
                            "phone_number": {
                                "type": "string",
                                "description": "User phone number"
                            },
                            "is_verified": {
                                "type": "boolean",
                                "description": "Email verification status"
                            }
                        },
                        "required": ["id", "is_verified"]
                    }
                },
                "required": ["access", "refresh"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {
                            "id": 123,
                            "email": "user@example.com",
                            "is_verified": True
                        }
                    },
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid verification code",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={
                        "detail": "Invalid verification code.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Expired Code",
                    value={
                        "detail": "Verification code has expired.",
                        "error_code": "4005"
                    },
                    status_codes=[400],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


# =============================================================================
# TOKEN MANAGEMENT DOCUMENTATION
# =============================================================================

refresh_token_docs = {
    'operation_id': 'refresh_token',
    'summary': 'Refresh Access Token',
    'description': '''
    Get a new access token using a valid refresh token.
    
    **Process:**
    1. User provides valid refresh token
    2. System validates refresh token
    3. Returns new access and refresh tokens
    4. Old refresh token becomes invalid
    
    **Security:**
    - Refresh tokens have longer expiration
    - Token rotation for enhanced security
    - Automatic invalidation of old tokens
    
    **Use Cases:**
    - Access token expired during active session
    - Regular token rotation for security
    - Session renewal for long-running applications
    - Mobile app background token refresh
    ''',
    'tags': ['Token Management'],
    'deprecated': False,
    'request': RefreshTokenSerializer,
    'examples': [
        OpenApiExample(
            "Token Refresh",
            value={
                "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            },
            request_only=True,
            description="Refresh access token with refresh token"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Token refreshed successfully",
            response={
                "type": "object",
                "properties": {
                    "access": {
                        "type": "string",
                        "description": "New JWT access token",
                        "format": "jwt"
                    },
                    "refresh": {
                        "type": "string",
                        "description": "New JWT refresh token",
                        "format": "jwt"
                    }
                },
                "required": ["access", "refresh"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    },
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid refresh token",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Token",
                    value={
                        "detail": "Invalid refresh token.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                )
            ]
        ),
        401: OpenApiResponse(
            description="Token expired or invalid",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


# =============================================================================
# PASSWORD MANAGEMENT DOCUMENTATION
# =============================================================================

password_reset_docs = {
    'operation_id': 'request_password_reset',
    'summary': 'Request Password Reset',
    'description': '''
    Initiate password reset process by sending OTP or reset link.
    
    **Process:**
    1. User provides email/phone number
    2. System validates user exists
    3. Sends OTP or reset link
    4. User completes reset via separate endpoint
    
    **Security:**
    - Rate limiting prevents abuse
    - No indication if user exists (security through obscurity)
    - Time-limited reset tokens
    
    **Use Cases:**
    - User forgot password
    - Account compromise recovery
    - Password expiration notification
    - Security policy enforcement
    ''',
    'tags': ['Password Management'],
    'deprecated': False,
    'request': PasswordResetRequestSerializer,
    'examples': [
        OpenApiExample(
            "Email Password Reset",
            value={
                "identifier": "user@example.com",
                "method": "email",
                "verification_type": "otp"
            },
            request_only=True,
            description="Request password reset via email OTP"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Password reset initiated successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Confirmation message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Password reset OTP sent via email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid identifier",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            }
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            },
            examples=[
                OpenApiExample(
                    "Rate Limit",
                    value={"detail": "Request limit exceeded. Please try again after 30 seconds."},
                    status_codes=[429],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


password_reset_confirm_docs = {
    'operation_id': 'confirm_password_reset',
    'summary': 'Confirm Password Reset',
    'description': '''
    Complete password reset by providing verification code and new password.
    
    **Process:**
    1. User provides identifier, verification code, and new password
    2. System validates code and password
    3. Updates user password
    4. Invalidates all existing sessions
    
    **Security:**
    - Password strength validation
    - Code expiration check
    - Session invalidation for security
    
    **Use Cases:**
    - Completing forgotten password recovery
    - Account security restoration
    - Compromised account recovery
    - Password policy compliance
    ''',
    'tags': ['Password Management'],
    'deprecated': False,
    'request': PasswordResetConfirmationEmailSerializer,
    'examples': [
        OpenApiExample(
            "Password Reset Confirmation",
            value={
                "identifier": "user@example.com",
                "code": "123456",
                "new_password": "NewSecurePassword123"
            },
            request_only=True,
            description="Confirm password reset with OTP and new password"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Password reset successful",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Success message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Password reset successful."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid code or weak password",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={
                        "detail": "Invalid verification code.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Weak Password",
                    value={
                        "detail": {"new_password": ["This password is too short."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                )
            ]
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


password_change_docs = {
    'operation_id': 'change_password',
    'summary': 'Change Password',
    'description': '''
    Change password for authenticated user.
    
    **Process:**
    1. User provides current password and new password
    2. System validates current password
    3. Updates to new password
    4. Invalidates all existing sessions
    
    **Security:**
    - Requires current password verification
    - Password strength validation
    - Session invalidation for security
    - Rate limiting on attempts
    
    **Authentication Required:**
    - Valid JWT access token in Authorization header
    
    **Use Cases:**
    - Proactive password security updates
    - Regular password rotation compliance
    - Account security enhancement
    - Password policy enforcement
    ''',
    'tags': ['Password Management'],
    'deprecated': False,
    'request': PasswordChangeSerializer,
    'examples': [
        OpenApiExample(
            "Password Change",
            value={
                "current_password": "OldPassword123",
                "new_password": "NewSecurePassword123"
            },
            request_only=True,
            description="Change password with current and new password"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Password changed successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Success message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Password changed successfully."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid current password or weak new password",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Current Password",
                    value={
                        "detail": "Current password is incorrect.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Weak New Password",
                    value={
                        "detail": {"new_password": ["This password is too short."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                )
            ]
        ),
        401: OpenApiResponse(
            description="Authentication required",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            }
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


# =============================================================================
# EMAIL MANAGEMENT DOCUMENTATION
# =============================================================================

email_change_docs = {
    'operation_id': 'request_email_change',
    'summary': 'Request Email Change',
    'description': '''
    Initiate email change process for authenticated user.
    
    **Process:**
    1. User provides new email and current password
    2. System validates current password
    3. Sends verification OTP to new email
    4. User confirms via separate endpoint
    
    **Security:**
    - Requires current password verification
    - Rate limiting on requests
    - Verification required for new email
    
    **Authentication Required:**
    - Valid JWT access token in Authorization header
    
    **Use Cases:**
    - Personal email address updates
    - Corporate email migration
    - Account ownership transfer
    - Email provider changes
    ''',
    'tags': ['Account Management'],
    'deprecated': False,
    'request': EmailChangeRequestSerializer,
    'examples': [
        OpenApiExample(
            "Email Change Request",
            value={
                "new_email": "newemail@example.com",
                "current_password": "CurrentPassword123"
            },
            request_only=True,
            description="Request email change with new email and current password"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Email change initiated successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Confirmation message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Email change OTP sent to new email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid current password or email",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Password",
                    value={
                        "detail": "Current password is incorrect.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Email Already Exists",
                    value={
                        "detail": "Email already exists.",
                        "error_code": "4002"
                    },
                    status_codes=[400],
                )
            ]
        ),
        401: OpenApiResponse(
            description="Authentication required",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        ),
        429: OpenApiResponse(
            description="Rate limit exceeded",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"}
                },
                "required": ["detail"]
            }
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
}


email_change_confirm_docs = {
    'operation_id': 'confirm_email_change',
    'summary': 'Confirm Email Change',
    'description': '''
    Complete email change by providing verification code.
    
    **Process:**
    1. User provides verification code from new email
    2. System validates code
    3. Updates user email address
    4. Sends notification to old email
    
    **Security:**
    - Code expiration check
    - Notification to old email for security
    - Session invalidation
    
    **Authentication Required:**
    - Valid JWT access token in Authorization header
    
    **Use Cases:**
    - Completing email address updates
    - Account ownership verification
    - Email change confirmation
    - Account security verification
    ''',
    'tags': ['Account Management'],
    'deprecated': False,
    'request': EmailChangeConfirmationSerializer,
    'examples': [
        OpenApiExample(
            "Email Change Confirmation",
            value={
                "code": "123456"
            },
            request_only=True,
            description="Confirm email change with verification code"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Email changed successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Success message"
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "Success",
                    value={"message": "Email changed successfully."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid verification code",
            response={
                "type": "object",
                "properties": {
                    "detail": {
                        "type": "object",
                        "additionalProperties": {"type": "string"}
                    },
                    "error_code": {"type": "string"}
                }
            },
            examples=[
                OpenApiExample(
                    "Invalid Code",
                    value={
                        "detail": "Invalid verification code.",
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Expired Code",
                    value={
                        "detail": "Verification code has expired.",
                        "error_code": "4005"
                    },
                    status_codes=[400],
                )
            ]
        ),
        401: OpenApiResponse(
            description="Authentication required",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        ),
        500: OpenApiResponse(
            description="Internal server error",
            response={
                "type": "object",
                "properties": {
                    "detail": {"type": "string"},
                    "error_code": {"type": "string"}
                }
            }
        )
    }
} 