"""
BlockAuth Wallet Authentication Documentation

This module contains comprehensive Swagger/OpenAPI documentation for wallet authentication endpoints.
Separated from business logic for better maintainability and organization.
"""

from drf_spectacular.utils import OpenApiResponse, OpenApiExample, OpenApiParameter
from rest_framework import status

from blockauth.serializers.wallet_serializers import WalletLoginSerializer, WalletEmailAddSerializer


# =============================================================================
# WALLET AUTHENTICATION DOCUMENTATION
# =============================================================================

wallet_login_docs = {
    'operation_id': 'wallet_login',
    'summary': 'Ethereum Wallet Authentication',
    'description': '''
    Authenticate user using Ethereum wallet signature verification.
    
    **Process:**
    1. User provides wallet address, message, and signature
    2. System verifies signature using Ethereum cryptography
    3. Creates or retrieves user account
    4. Returns JWT access and refresh tokens
    
    **Security Features:**
    - Cryptographic signature verification
    - Nonce-based replay protection
    - Wallet address validation
    - Automatic user creation for new wallets
    
    **Message Format:**
    The message to sign follows this format:
    ```
    Welcome to BlockAuth!
    
    Please sign this message to authenticate with your wallet.
    
    Wallet Address: {wallet_address}
    Nonce: {nonce}
    Timestamp: {timestamp}
    
    This signature will be used to authenticate your account.
    ```
    
    **Prerequisites:**
    - Valid Ethereum wallet address
    - Properly signed message with correct format
    - Valid signature that matches the wallet address
    
    **Use Cases:**
    - DeFi application user authentication
    - NFT marketplace user access
    - Web3 gaming platform login
    - Decentralized application (dApp) login
    ''',
    'tags': ['Wallet'],
    'deprecated': False,
    'request': WalletLoginSerializer,
    'examples': [
        OpenApiExample(
            "New Wallet User",
            value={
                "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                "message": "Welcome to BlockAuth!\n\nPlease sign this message to authenticate with your wallet.\n\nWallet Address: 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6\nNonce: 1234567890\nTimestamp: 1640995200\n\nThis signature will be used to authenticate your account.",
                "signature": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b"
            },
            request_only=True,
            description="Login with new wallet address"
        ),
        OpenApiExample(
            "Existing Wallet User",
            value={
                "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                "message": "Welcome to BlockAuth!\n\nPlease sign this message to authenticate with your wallet.\n\nWallet Address: 0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6\nNonce: 1234567891\nTimestamp: 1640995201\n\nThis signature will be used to authenticate your account.",
                "signature": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1c"
            },
            request_only=True,
            description="Login with existing wallet address"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Wallet authentication successful",
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
                                "description": "User ID in the system"
                            },
                            "wallet_address": {
                                "type": "string",
                                "description": "Ethereum wallet address",
                                "pattern": "^0x[a-fA-F0-9]{40}$"
                            },
                            "email": {
                                "type": "string",
                                "format": "email",
                                "description": "User email address (if added)"
                            },
                            "is_verified": {
                                "type": "boolean",
                                "description": "Email verification status"
                            },
                            "created": {
                                "type": "boolean",
                                "description": "Whether this is a new user account"
                            }
                        },
                        "required": ["id", "wallet_address", "is_verified", "created"]
                    }
                },
                "required": ["access", "refresh"]
            },
            examples=[
                OpenApiExample(
                    "New User Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {
                            "id": 123,
                            "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                            "is_verified": False,
                            "created": True
                        }
                    },
                    status_codes=[200],
                    description="New wallet user created and authenticated"
                ),
                OpenApiExample(
                    "Existing User Success",
                    value={
                        "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "user": {
                            "id": 123,
                            "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
                            "email": "user@example.com",
                            "is_verified": True,
                            "created": False
                        }
                    },
                    status_codes=[200],
                    description="Existing wallet user authenticated"
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid wallet data or signature",
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
                    "Invalid Wallet Address",
                    value={
                        "detail": {"wallet_address": ["Enter a valid Ethereum address."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Invalid Signature",
                    value={
                        "detail": "Invalid signature for the provided wallet address.",
                        "error_code": "4002"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Invalid Message Format",
                    value={
                        "detail": "Message format is invalid or missing required fields.",
                        "error_code": "4003"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Expired Nonce",
                    value={
                        "detail": "Message nonce has expired. Please request a new one.",
                        "error_code": "4004"
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
            },
            examples=[
                OpenApiExample(
                    "Signature Verification Failed",
                    value={
                        "detail": "Signature verification failed.",
                        "error_code": "4001"
                    },
                    status_codes=[401],
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


wallet_email_add_docs = {
    'operation_id': 'add_wallet_email',
    'summary': 'Add Email to Wallet Account',
    'description': '''
    Add an email address to a wallet-based user account and send verification.
    
    **Process:**
    1. User provides email address
    2. System validates email format
    3. Updates user account with email
    4. Sends verification OTP/link to email
    5. User completes verification via separate endpoint
    
    **Benefits:**
    - Enhanced account recovery options
    - Email notifications and updates
    - Additional verification layer
    - Better user experience
    
    **Security:**
    - Email format validation
    - Rate limiting on requests
    - Verification required before email is active
    - Authentication required
    
    **Authentication Required:**
    - Valid JWT access token in Authorization header
    
    **Use Cases:**
    - Wallet user account enhancement
    - Account recovery setup for wallet users
    - Email notification preferences
    - Multi-factor authentication setup
    ''',
    'tags': ['Account Management'],
    'deprecated': False,
    'request': WalletEmailAddSerializer,
    'examples': [
        OpenApiExample(
            "Add Email with OTP",
            value={
                "email": "user@example.com",
                "verification_type": "otp"
            },
            request_only=True,
            description="Add email with OTP verification"
        ),
        OpenApiExample(
            "Add Email with Link",
            value={
                "email": "user@example.com",
                "verification_type": "link"
            },
            request_only=True,
            description="Add email with verification link"
        )
    ],
    'responses': {
        200: OpenApiResponse(
            description="Email added and verification sent successfully",
            response={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Success message with verification method",
                        "enum": [
                            "Email added successfully. otp sent via email.",
                            "Email added successfully. link sent via email."
                        ]
                    }
                },
                "required": ["message"]
            },
            examples=[
                OpenApiExample(
                    "OTP Sent",
                    value={"message": "Email added successfully. otp sent via email."},
                    status_codes=[200],
                ),
                OpenApiExample(
                    "Link Sent",
                    value={"message": "Email added successfully. link sent via email."},
                    status_codes=[200],
                )
            ]
        ),
        400: OpenApiResponse(
            description="Invalid email or validation error",
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
                        "detail": {"email": ["Enter a valid email address."]},
                        "error_code": "4001"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Email Already Exists",
                    value={
                        "detail": "Email address is already associated with another account.",
                        "error_code": "4002"
                    },
                    status_codes=[400],
                ),
                OpenApiExample(
                    "Email Already Added",
                    value={
                        "detail": "Email address is already associated with this wallet.",
                        "error_code": "4003"
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
            },
            examples=[
                OpenApiExample(
                    "Unauthorized",
                    value={
                        "detail": "Authentication credentials were not provided.",
                        "error_code": "4001"
                    },
                    status_codes=[401],
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