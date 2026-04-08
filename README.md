# BlockAuth

Comprehensive Python authentication package bridging Web2 and Web3. Provides JWT authentication, OAuth integration, passwordless login, Web3 wallet authentication, TOTP/2FA, WebAuthn passkeys, and a KDF system that enables blockchain access without crypto knowledge.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration Setup](#configuration-Setup)
  - [Django Configs](#django-configs)
  - [BlockAuth Configs](#blockauth-configs)
  - [Spectacular(API documentation) Configs](#spectacularapi-documentation-configs)
  - [Inherit Blockauth User Model](#inherit-blockauth-user-model)
  - [Add URLs](#add-urls)
- [User journey of some functionalities](#user-journey-of-some-functionalities)
  - [Sign up](#sign-up)
  - [Basic Login](#basic-login)
  - [Passwordless Login](#passwordless-login)
  - [Token Refresh](#token-refresh)
  - [Password Reset](#password-reset)
  - [Change Email](#change-email)
  - [Passkey/WebAuthn Authentication](#passkeywebauthn-authentication)
  - [Web3 Wallet Authentication](#web3-wallet-authentication)
- [Social Providers Login Mechanism (Google, LinkedIn, Facebook, etc.)](#social-providers-login-mechanism-google-linkedin-facebook-etc)
- [Utility Classes](#utility-classes)
  - [Communication Class](#communication-class)
  - [Trigger Classes](#trigger-classes)
- [Custom JWT Claims](#custom-jwt-claims)
- [Logging in BlocAuth](#logging-in-blocauth)
  - [Supported Log Levels and Icons](#supported-log-levels-and-icons)
  - [Custom Logger Integration](#custom-logger-integration)
  - [Example: Custom Logger Class](#example-custom-logger-class)
  - [Django Settings Configuration](#django-settings-configuration)
- [Rate Limiting](#rate-limiting)
- [Step-Up Authentication (TOTP Receipt)](#step-up-authentication-totp-receipt)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- JWT Authentication (HS256, RS256, ES256 — symmetric and asymmetric)
- Token refresh functionality
- SignUp with email and password
- Login with email and password (Basic Auth)
- Login via OTP (Passwordless login)
- Web3 Wallet Authentication (Ethereum/MetaMask)
- **🔐 Passkey/WebAuthn Authentication** - Face ID, Touch ID, Windows Hello, hardware keys
- Reset password
- Change password
- Change email
- Google, Facebook, LinkedIn login (OAuth2)
- **🔐 KDF (Key Derivation Function) System** - Complete Web2→Web3 bridge
- **🚀 Smart Contract Account Integration** - ERC-4337 account abstraction
- **🔑 Dual Encryption** - User password + platform key security
- **📱 Passwordless Authentication** - Email-only blockchain wallet generation
- **🔄 Password Management Triggers** - Automatic wallet re-encryption
- **🎯 Custom JWT Claims** - Extensible claims provider system for adding custom data to tokens
- **🛡️ Step-Up Authentication** - RFC 9470 receipt-based step-up auth for sensitive operations

---

## Step-Up Authentication (TOTP Receipt)

### Overview

The **Step-Up Authentication** module (`blockauth.stepup`) implements the industry-standard step-up authentication pattern (RFC 9470, PSD2/SCA, Auth0 Step-Up, Fireblocks TAP, AWS IAM MFA session tokens).

After a user completes an additional authentication factor (e.g., TOTP verification), the issuing service creates a short-lived signed **receipt** (HS256 JWT). The consuming service validates this receipt before allowing sensitive operations. This moves enforcement from the client (SDK) to the backend.

### Key Properties

- **Short-lived**: 120-second TTL by default (configurable)
- **Scoped**: `aud` claim prevents cross-service replay, `scope` restricts to operation classes
- **Anti-IDOR**: `sub` must match the authenticated user
- **Django-independent**: Pure Python + PyJWT, usable in any service
- **Generic**: Not tied to TOTP specifically -- works with any step-up factor

### Quick Start

#### Issuing Service (e.g., auth service)

```python
from blockauth.stepup import ReceiptIssuer

issuer = ReceiptIssuer(
    secret="your-shared-secret-min-32-chars",
    issuer="my-auth-service",
    default_audience="my-wallet-service",
    default_scope="mpc",
    default_ttl_seconds=120,
)

# After user passes TOTP verification:
receipt_token = issuer.issue(subject=str(user.id))
# Return receipt_token in the API response
```

#### Consuming Service (e.g., wallet service)

```python
from blockauth.stepup import ReceiptValidator, ReceiptValidationError

validator = ReceiptValidator(
    secret="your-shared-secret-min-32-chars",
    expected_audience="my-wallet-service",
    expected_scope="mpc",
)

try:
    claims = validator.validate(
        token=receipt_from_header,
        expected_subject=authenticated_user_id,  # anti-IDOR check
    )
    # claims.subject, claims.scope, claims.jti, etc.
except ReceiptValidationError as e:
    # e.reason — human-readable message
    # e.code — machine-readable code (e.g., "receipt_expired", "receipt_subject_mismatch")
    return 403, {"error": e.reason}
```

### Receipt JWT Claims

```json
{
  "sub": "user-uuid",
  "type": "stepup_receipt",
  "aud": "my-wallet-service",
  "scope": "mpc",
  "iat": 1740000000,
  "exp": 1740000120,
  "jti": "random-hex-16-bytes",
  "iss": "my-auth-service"
}
```

### Middleware Pattern (Header-Based)

The receipt is typically passed as an HTTP header (`X-TOTP-Receipt`). The consuming service applies middleware to protected endpoints:

- **Header present**: Must be valid or request is rejected (403)
- **Header absent**: Pass through (users who didn't do TOTP, e.g., passkey/EOA users)
- **Enforce mode**: Reject ALL requests without a valid receipt (opt-in, for strict environments)

### Validation Checks

| Check | Error Code |
|---|---|
| HS256 signature valid | `receipt_signature_invalid` |
| Not expired (`exp > now`) | `receipt_expired` |
| `type == "stepup_receipt"` | `receipt_wrong_type` |
| `aud` matches expected | `receipt_audience_mismatch` |
| `scope` matches expected | `receipt_scope_mismatch` |
| `sub` matches authenticated user | `receipt_subject_mismatch` |

### API Reference

#### `ReceiptIssuer(secret, *, issuer, default_audience, default_scope, default_ttl_seconds)`

Create an issuer. `secret` must be >= 32 characters.

- `issue(subject, *, audience=None, scope=None, ttl_seconds=None)` -> `str` (JWT)

#### `ReceiptValidator(secret, *, expected_audience, expected_scope)`

Create a validator.

- `validate(token, *, expected_subject=None)` -> `ReceiptClaims`

#### `ReceiptClaims` (frozen dataclass)

- `subject`, `audience`, `scope`, `issued_at`, `expires_at`, `jti`, `issuer`

#### `ReceiptValidationError`

- `reason` (str) — human-readable
- `code` (str) — machine-readable

---

## 🔐 KDF (Key Derivation Function) System

### Overview

The **KDF System** is a revolutionary feature that bridges Web2 and Web3 by enabling email/password users to have blockchain accounts without ever seeing or managing crypto keys. This makes blockchain accessible to billions of Web2 users.

### How It Works

```
Email + Password → KDF → Private Key → EOA → Smart Contract Account
     ↓              ↓         ↓         ↓           ↓
  Web2 Auth    Key Derivation  Hidden   Internal   User's Wallet
```

### Key Features

- **🔐 Deterministic Generation**: Same email/password always generates same private key
- **🚀 Smart Contract Accounts**: ERC-4337 accounts with programmable logic
- **🔑 Dual Encryption**: Private keys encrypted with both user password and platform key
- **📱 Passwordless Support**: Email-only authentication for blockchain wallets
- **🔄 Automatic Recovery**: Platform can recover any user wallet when needed
- **🛡️ Enterprise Security**: PBKDF2/Argon2 with configurable iterations

### Security Architecture

```
Layer 1: User Credentials (Email + Password)
Layer 2: Key Derivation (PBKDF2/Argon2 with 100k+ iterations)
Layer 3: Private Key Generation (32-byte deterministic)
Layer 4: Dual Encryption (AES-256-GCM)
Layer 5: Secure Storage (Database + Platform key backup)
```

### Use Cases

- **E-commerce**: Users can own NFTs without crypto knowledge
- **Gaming**: True ownership of in-game items on blockchain
- **Social Media**: Content creators can monetize with minimal fees
- **DeFi**: Access to decentralized finance with familiar authentication
- **Governance**: Participate in DAOs without MetaMask

### Configuration

```python
BLOCK_AUTH_SETTINGS = {
    "KDF_ENABLED": True,
    "KDF_ALGORITHM": "pbkdf2_sha256",  # or "argon2id"
    "KDF_ITERATIONS": 100000,           # Production: 100k+, Dev: 1k
    "KDF_SECURITY_LEVEL": "HIGH",       # LOW, MEDIUM, HIGH, CRITICAL
    "KDF_MASTER_SALT": "your-32-char-minimum-salt",
    "MASTER_ENCRYPTION_KEY": "0x" + "64-char-hex-key",
    "PLATFORM_MASTER_SALT": "your-platform-salt-32-chars-minimum",
}
```

---

## Requirements

- python = ^3.12
- django = 5.1.4
- pyjwt = 2.9.0
- requests = 2.32.3
- djangorestframework = 3.15.2
- setuptools = ^75.6.0
- drf-spectacular = 0.28.0
- drf-spectacular-sidecar = 2025.7.1

### KDF System Requirements

- **cryptography** = ^41.0.0 (for AES-256-GCM encryption)
- **web3** = ^6.0.0 (for Ethereum integration)
- **eth-account** = ^0.9.0 (for wallet management)
- **argon2-cffi** = ^21.3.0 (for Argon2 KDF algorithm)

## Installation

#### From GitHub Releases (recommended)

```bash
uv add "blockauth @ https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl"
```

Or with pip:
```bash
pip install https://github.com/BloclabsHQ/auth-pack/releases/download/v0.3.0/blockauth-0.3.0-py3-none-any.whl
```

#### From Git (development)

```bash
uv add "blockauth @ git+https://github.com/BloclabsHQ/auth-pack.git@dev"
```

#### Editable Mode (local development)

```bash
git clone https://github.com/BloclabsHQ/auth-pack.git
uv pip install -e ./auth-pack
```


## Configuration Setup

### Django Configs
Add the package to your Django project's `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    'rest_framework',
    'blockauth',
    ...
]
```

Add the Blockauth authentication classe to your Django project's `REST_FRAMEWORK` settings.
By this way, the package's authentication classes will be used for the APIs.:

```python
REST_FRAMEWORK = {
    ...
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'blockauth.authentication.JWTAuthentication',
    ),
    ...
}
```


### BlockAuth Configs
Configs which can be added to the Django project's `settings.py`. 
If you don't add these configs, the default values will be used which are shown here:

- _**AUTH_PROVIDERS** has no default values, you need to add the values for the providers you want to use. 
If you do not add them then the social auth URLs related to the providers won't be available.
See the following [Video tutorials](#social-providers-login-mechanism-google-linkedin-facebook-etc) to create OAuth client id & client secret._
- _**DEFAULT_TRIGGER_CLASSES** has default classes implemented within blockauth package. It's recommended to implement
own class and add the class path in the settings. Details disccussed in the [Utility Classes](#utility-classes) section._ 
- _**DEFAULT_NOTIFICATION_CLASS** has default class implemented within blockauth package. It's recommended to implement
own class and add the class path in the settings. Details disccussed in the [Utility Classes](#utility-classes) section._

```python
BLOCK_AUTH_SETTINGS = {
    "BLOCK_AUTH_USER_MODEL": "{{app_name.model_class_name}}",  # replace it with your custom user model class name for Blockauth users
    "CLIENT_APP_URL": "http://localhost:3000", # this is the URL of the client app which will communicate with the backend API

    "ACCESS_TOKEN_LIFETIME": timedelta(seconds=3600),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ALGORITHM": "HS256",           # Supports: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",   # Field name in the user model which will be used as user id in the JWT token
    "JWT_SECRET_KEY": "your-jwt-secret-key-here",  # For HS256: shared secret (optional, falls back to Django SECRET_KEY)
    # "JWT_PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----\n...",  # For RS256/ES256: PEM private key (signing)
    # "JWT_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\n...",        # For RS256/ES256: PEM public key (verification)
    # NOTE: For RS256/ES256, never expose private keys in logs, version control, or client-side code.
    # Use environment variables or a secrets manager (1Password, AWS Secrets Manager) in production.

    "OTP_VALIDITY": timedelta(minutes=3),
    "OTP_LENGTH": 6,
    "REQUEST_LIMIT": (3, 30),  # (number of request, duration in second) rate limits based on per (identifier, subject, and IP address)
    
    # Email verification settings
    "EMAIL_VERIFICATION_REQUIRED": False,  # Whether users must verify email before accessing non-auth endpoints
    
    # Feature flags - Enable/disable specific authentication features
    "FEATURES": {
        # Core authentication features
        "SIGNUP": True,                    # Enable user registration with email/password
        "BASIC_LOGIN": True,               # Enable email/password login authentication
        "PASSWORDLESS_LOGIN": True,        # Enable passwordless login with OTP
        "WALLET_LOGIN": True,              # Enable wallet-based authentication
        "TOKEN_REFRESH": True,             # Enable JWT token refresh functionality
        
        # Password management
        "PASSWORD_RESET": True,            # Enable password reset functionality
        "PASSWORD_CHANGE": True,           # Enable password change for authenticated users
        
        # Email management
        "EMAIL_CHANGE": True,              # Enable email change functionality
        "EMAIL_VERIFICATION": True,        # Enable email verification requirement
        
        # Wallet features
        "WALLET_EMAIL_ADD": True,          # Enable adding email to wallet accounts
        
        # Social authentication (controlled by provider configuration)
        "SOCIAL_AUTH": True,               # Master switch for social authentication

        # Passkey/WebAuthn authentication
        "PASSKEY_AUTH": True,              # Enable passkey authentication (Face ID, Touch ID, Windows Hello)
    },
        
    "AUTH_PROVIDERS": {
        "GOOGLE": {
            "CLIENT_ID": os.getenv('GOOGLE_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('GOOGLE_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('GOOGLE_REDIRECT_URI'),
        },
        "LINKEDIN": {
            "CLIENT_ID": os.getenv('LINKEDIN_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('LINKEDIN_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('LINKEDIN_REDIRECT_URI'),
        },
        "FACEBOOK": {
            "CLIENT_ID": os.getenv('FACEBOOK_CLIENT_ID'),
            "CLIENT_SECRET": os.getenv('FACEBOOK_CLIENT_SECRET'),
            "REDIRECT_URI": os.getenv('FACEBOOK_REDIRECT_URI'),
        }
    },
    
    # don't need to add DEFAULT_TRIGGER_CLASSES & DEFAULT_NOTIFICATION_CLASS object if you want to use default classes
    "DEFAULT_TRIGGER_CLASSES": {
        "POST_SIGNUP_TRIGGER": '{{path.to.your.Class}}',  # replace it with your own class path
        "PRE_SIGNUP_TRIGGER": '{{path.to.your.Class}}',   # replace it with your own class path
        "POST_LOGIN_TRIGGER": '{{path.to.your.Class}}',   # replace it with your own class path
    },
    
    "DEFAULT_NOTIFICATION_CLASS": "{{path.to.your.Class}}",   # replace it with your own class path
    "BLOCK_AUTH_LOGGER_CLASS": '{{path.to.your.Class}}',   # replace it with your own class path
}
```

### Spectacular(API documentation) Configs

BlockAuth provides comprehensive Swagger/OpenAPI documentation with detailed descriptions, examples, and security information for all endpoints.

Add the following related things to the Django project's `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'drf_spectacular',
    'drf_spectacular_sidecar',
    ...
]

REST_FRAMEWORK = {
    ...
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema', 
    ...
}

# read more about the settings here: https://drf-spectacular.readthedocs.io/en/latest/readme.html#installation
SPECTACULAR_SETTINGS = {
    'TITLE': 'Your API Title',
    'DESCRIPTION': 'Your API description here',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
    },
}
```

Add the following URL pattern to the Django project's `urls.py`:

```python
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

urlpatterns += [
    # Schema generation endpoint
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    # Optional UI endpoints
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
```

After adding the above URL pattern, you can access the swagger documentation by going to the URL `http://localhost:8000/api/swagger/` or
the redoc documentation by going to the URL `http://localhost:8000/api/redoc/`.

### Feature Flags

BlockAuth supports feature flags to enable/disable specific authentication features. This allows you to customize which endpoints are available in your application.

#### Available Features

- **SIGNUP**: Enable user registration with email and password
- **BASIC_LOGIN**: Enable email/password login authentication  
- **PASSWORDLESS_LOGIN**: Enable passwordless login with OTP
- **WALLET_LOGIN**: Enable wallet-based authentication
- **TOKEN_REFRESH**: Enable JWT token refresh functionality
- **PASSWORD_RESET**: Enable password reset functionality
- **PASSWORD_CHANGE**: Enable password change for authenticated users
- **EMAIL_CHANGE**: Enable email change functionality
- **EMAIL_VERIFICATION**: Enable email verification requirement
- **WALLET_EMAIL_ADD**: Enable adding email to wallet accounts
- **SOCIAL_AUTH**: Master switch for social authentication
- **PASSKEY_AUTH**: Enable passkey/WebAuthn authentication (Face ID, Touch ID, Windows Hello, hardware keys)

#### Example Configuration

To disable email change functionality:

```python
from blockauth.constants import Features

BLOCK_AUTH_SETTINGS = {
    # ... other settings ...
    "FEATURES": {
        Features.SIGNUP: True,
        Features.BASIC_LOGIN: True,
        Features.PASSWORDLESS_LOGIN: True,
        Features.WALLET_LOGIN: True,
        Features.TOKEN_REFRESH: True,
        Features.PASSWORD_RESET: True,
        Features.PASSWORD_CHANGE: True,
        Features.EMAIL_CHANGE: False,  # Disable email change
        Features.EMAIL_VERIFICATION: True,
        Features.WALLET_EMAIL_ADD: True,
        Features.SOCIAL_AUTH: True,
        Features.PASSKEY_AUTH: True,  # Passkey/WebAuthn authentication
    },
}
```

#### Using Constants

BlockAuth provides constants for better type safety and IDE support:

```python
from blockauth.constants import Features, SocialProviders, URLNames
from blockauth.utils.feature_flags import is_feature_enabled
from blockauth.utils.config import is_social_auth_configured

# Check if a feature is enabled
if is_feature_enabled(Features.EMAIL_CHANGE):
    # Show email change form
    pass

# Use social provider constants
if is_social_auth_configured(SocialProviders.GOOGLE):
    # Configure Google auth
    pass

# Use URL name constants
from django.urls import reverse
signup_url = reverse(URLNames.SIGNUP)  # Get signup URL
```

#### Advanced Usage

You can also use constants in your configuration for better maintainability:

```python
from blockauth.constants import Features, ConfigKeys

BLOCK_AUTH_SETTINGS = {
    ConfigKeys.FEATURES: {
        Features.SIGNUP: True,
        Features.EMAIL_CHANGE: False,
    },
    ConfigKeys.ACCESS_TOKEN_LIFETIME: timedelta(hours=1),
    ConfigKeys.OTP_VALIDITY: timedelta(minutes=5),
}
```





#### Feature Dependencies

Some features have logical dependencies:
- `EMAIL_CHANGE` requires `EMAIL_VERIFICATION` to be enabled
- `PASSWORDLESS_LOGIN` requires `SIGNUP` to be enabled

The system will automatically validate these dependencies and warn about any configuration issues.

#### Benefits

✅ **Type Safety** - Use constants instead of string literals  
✅ **IDE Support** - Autocomplete and error detection  
✅ **Maintainable** - Centralized constants in one place  
✅ **Consistent** - Uniform naming across the codebase  
✅ **Scalable** - Easy to add new features and constants  
✅ **Documented** - Comprehensive documentation and examples


### Inherit Blockauth User Model

Inherit the `blockauth.models.BlockUser` model in your custom User model in django project. An example is shown below:

```python
from django.db import models
from blockauth.models.user import BlockUser

class CustomUser(BlockUser):
    first_name = models.CharField("First name", max_length=50, null=True, blank=True)
    last_name = models.CharField("Last name", max_length=50, null=True, blank=True)
    date_joined = models.DateTimeField("date of joining", auto_now_add=True)
    is_online = models.BooleanField(default=False)

    # Profile Fields
    date_of_birth = models.DateField("date of birth", blank=True, null=True)
    bio = models.TextField("bio", blank=True, null=True, max_length=500)


    class Meta:
        db_table = "user"
```

Set this customer user model as the default user model in the Django project's `settings.py`:
```python
AUTH_USER_MODEL = 'app_name.CustomUser'
```

Make migration related commands in console to reflect database tables related to the app.
```shell
python manage.py makemigrations
python manage.py migrate
```

### Add URLs

Add the package's URLs to your Django project's `urls.py`:

```python
from django.urls import path, include

urlpatterns = [
    ...
    path('api/auth/', include('blockauth.urls')),
    ...
]
```
The available URLs will be shown in swagger after adding the above URL pattern:

Basic Auth:
- `auth/signup`: Request an OTP for signup with email & password.
- `auth/signup/otp/resend`: Resend OTP for signup with email.
- `auth/signup/confirm`:  Confirm sign up with email and otp.


- `auth/login/basic`: Login with **email** and **password** and get access token, refresh token.
- `auth/login/passwordless`: Request OTP for passwordless login with email.
- `auth/login/passwordless/confirm`: Confirm login with email and otp.
- `auth/token/refresh`: Refresh access token.


- `auth/password/reset`: Request OTP for password reset with email.
- `auth/password/reset/confirm`: Confirm password reset with email, otp and new password.
- `auth/password/change`: Change password with old password and new password while being an authenticated user


- `auth/email/change`: Request OTP for email change with current email and current password.
- `auth/email/change/confirm`: Confirm email change with current email, new email and otp.

**Web3 Wallet Authentication:**
- `auth/login/wallet`: Login with Ethereum wallet signature verification.
- `auth/wallet/email/add/`: Add email address for wallet user and automatically send verification.
- `auth/signup/confirm/`: Verify email using OTP (works for both signup and wallet email verification).

**Passkey/WebAuthn Authentication:**
- `auth/passkey/register/options/`: Get registration options for new passkey (requires auth)
- `auth/passkey/register/verify/`: Verify passkey registration (requires auth)
- `auth/passkey/auth/options/`: Get authentication options (public)
- `auth/passkey/auth/verify/`: Verify passkey authentication and get JWT tokens (public)
- `auth/passkey/credentials/`: List user's registered passkeys (requires auth)
- `auth/passkey/credentials/<uuid>/`: Get, update, or delete a specific passkey (requires auth)

Providers:
- `auth/google`: Redirect URL to Google login page.
- `auth/google/callback`: Callback URL after succesfull Google login. **This URL should be added to the Google OAuth2 client configuration**.


- `auth/linkedin`: Redirect URL to LinkedIn login page.
- `auth/linkedin/callback`: Callback URL to LinkedIn login page. **This URL should be added to the LinkedIn OAuth2 client configuration**.


- `auth/facebook`: Redirect URL to Facebook login page.
- `auth/facebook/callback`: Callback URL to Facebook login page. **This URL should be added to the Facebook OAuth2 client configuration**.

## User journey of some functionalities

### Sign up
1. The user requests to `auth/signup` with email and password. It will do the following:
   - Validate the email and password. Also checks whether the email is already registered or not.
   - Calls the `PRE_SIGNUP_TRIGGER` class with validated data to perform any pre-signup actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - User created with email & password and `is_verified=False` by default.
2. The user confirms the signup by calling `auth/signup/confirm` with email and OTP. It will do the following:
   - Validate the OTP and email.
   - Updates the user attribute `is_verified=True`.
   - Calls the `POST_SIGNUP_TRIGGER` class with user information to perform any post-signup actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
3. In case if the user wants to resend the OTP, the user can call `auth/signup/otp/resend` with email.

### Basic Login
The user can log in with email and password. After successful login, the user will get an `access token` and a `refresh token`.
Token validity can be configured in the settings.

### Passwordless Login
1. The user requests to `auth/login/passwordless` with email. It will do the following:
   - Validate the email.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the login by calling `auth/login/passwordless/confirm` with email and OTP. It will do the following:
   - Validate the OTP and email.
   - If the user is not found in the database, a new user is created with the email only and `is_verified=True`. Then calls the `POST_SIGNUP_TRIGGER` class with user information to perform any post-signup actions.
   - Calls the `POST_LOGIN_TRIGGER` class with user information to perform any post-login actions. _(This class should be implemented in the project. Currently, a dummy class is used by default.)_
   - Returns an `access token` and a `refresh token`.

### Token Refresh
The user can refresh the access token with the refresh token. The refresh token is used to generate a new access token.
Token validity can be configured in the settings.

### Password Reset
1. The user requests to `auth/password/reset` with email. It will do the following:
   - Validate the email.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the password reset by calling `auth/password/reset/confirm` with email, OTP, and new password. It will do the following:
   - Validate the OTP, email and new password.
   - Update the user password with the new password.


### Change Email
1. The user requests to `auth/email/change` with current email and password. It will do the following:
   - Validate the current email and password.
   - Generates an OTP.
   - Calls the `DEFAULT_NOTIFICATION_CLASS` class with OTP information to send the OTP to the user.
2. The user confirms the email change by calling `auth/email/change/confirm` with current email, new email, and OTP. It will do the following:
   - Validate the current email, new email, and OTP.
   - Update the user email with the new email.

### Passkey/WebAuthn Authentication
BlockAuth supports passwordless authentication using WebAuthn/FIDO2 standard. Users can authenticate using biometrics (Face ID, Touch ID, Windows Hello) or hardware security keys.

#### Registration Flow (Authenticated User)
1. User calls `auth/passkey/register/options/` with optional display name
2. Backend generates registration options (challenge, RP info, user info)
3. Frontend calls `navigator.credentials.create()` with options (triggers biometric prompt)
4. User verifies identity with biometric/PIN
5. Frontend sends credential response to `auth/passkey/register/verify/`
6. Backend verifies and stores the credential

#### Authentication Flow (Public)
1. User calls `auth/passkey/auth/options/` with optional username
2. Backend generates authentication options (challenge, allowed credentials)
3. Frontend calls `navigator.credentials.get()` with options (triggers biometric prompt)
4. User verifies identity with biometric/PIN
5. Frontend sends assertion to `auth/passkey/auth/verify/`
6. Backend verifies signature and returns JWT tokens

#### Configuration
```python
BLOCK_AUTH_SETTINGS = {
    "FEATURES": {
        "PASSKEY_AUTH": True,  # Enable passkey authentication
    },
    "PASSKEY_RP_ID": "example.com",  # Your domain (no protocol)
    "PASSKEY_RP_NAME": "My Application",
    "PASSKEY_ALLOWED_ORIGINS": ["https://example.com"],
}
```

For detailed documentation, see: **[Passkey Developer Guide](blockauth/passkey/README.md)**

### Web3 Wallet Authentication
BlockAuth supports Ethereum wallet-based authentication using cryptographic signature verification. This allows users to authenticate using their Web3 wallets (like MetaMask) without requiring email or password.

#### Authentication Flow
1. **Frontend**: User connects their wallet and signs a message (e.g., "ABC")
2. **Request**: Frontend sends wallet address, message, and signature to `auth/login/wallet`
3. **Verification**: Backend verifies the signature matches the wallet address
4. **User Creation**: If no user exists with this wallet address, a new user is created automatically
5. **Response**: Access token and refresh token are returned

#### Request Format
```json
POST /api/v1/auth/login/wallet/
{
  "wallet_address": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",
  "message": "ABC",
  "signature": "0x1234567890abcdef1234567890abcdef1234567890abcd..."
}
```

#### Response Format
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Features
- **Automatic User Creation**: New users are created automatically when first authenticating with a wallet
- **Signature Verification**: Uses Ethereum's cryptographic signature verification
- **No Email Required**: Users can authenticate using only their wallet address
- **Standard JWT Tokens**: Returns the same access/refresh token format as other authentication methods
- **Trigger Support**: Integrates with existing POST_SIGNUP_TRIGGER and POST_LOGIN_TRIGGER classes
- **Optional Email Verification**: Users can optionally add and verify email addresses after wallet login
- **Configurable Email Requirements**: Developers can enforce email verification for wallet users via settings

#### Dependencies
The Web3 wallet authentication requires the following dependencies (already included in pyproject.toml):
- `web3`: Ethereum Web3 library
- `eth-account`: Ethereum account utilities for signature verification

#### Email Verification for Wallet Users
Wallet users can optionally add and verify email addresses after authentication. This feature is controlled by the `EMAIL_VERIFICATION_REQUIRED` setting.

**Configuration**
```python
# settings.py
BLOCK_AUTH_SETTINGS = {
    "EMAIL_VERIFICATION_REQUIRED": True,  # Enforce email verification for all users
}
```

**Email Management Endpoints**
- `auth/wallet/email/add/`: Add an email address to wallet user and automatically send verification
- `auth/signup/confirm/`: Verify email using OTP (works for both signup and wallet email verification)

**Request Examples**

Add Email (automatically sends verification):
```json
POST /api/v1/auth/wallet/email/add/
{
  "email": "user@example.com",
  "verification_type": "otp"
}
```

Add Email with Link Verification:
```json
POST /api/v1/auth/wallet/email/add/
{
  "email": "user@example.com",
  "verification_type": "link"
}
```

Verify Email:
```json
POST /api/v1/auth/signup/confirm/
{
  "identifier": "user@example.com",
  "code": "123456"
}
```

**Access Control**
When `EMAIL_VERIFICATION_REQUIRED` is enabled, users without verified email addresses will be restricted from accessing protected endpoints. Use the `EmailVerificationPermission` class to enforce this restriction on your application endpoints:

```python
from blockauth.utils.permissions import EmailVerificationPermission

class MyProtectedView(APIView):
    permission_classes = [IsAuthenticated, EmailVerificationPermission]
```

**Protected Endpoints**
When `EMAIL_VERIFICATION_REQUIRED` is enabled, you should use the `EmailVerificationPermission` class on your application endpoints to restrict access for users without verified email. This includes endpoints like:

- User profile management
- Sensitive operations
- Payment processing
- Data access endpoints
- Any endpoint that requires verified user identity

**Note:** The `auth/wallet/email/add/` endpoint is specifically designed for adding email after wallet signup and will always allow users to add their email address, regardless of the `EMAIL_VERIFICATION_REQUIRED` setting.

**Note**: Wallet users authenticate solely via wallet signature verification. Email addresses are optional and can be added after login for additional functionality or compliance requirements. Verification is automatically sent when email is added or during signup. The system reuses existing signup endpoints for email verification to maintain API consistency.

**Example: Using Email Verification Permission**
```python
# views.py
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from blockauth.utils.permissions import EmailVerificationPermission

class NFTMintingView(APIView):
    permission_classes = [IsAuthenticated, EmailVerificationPermission]
    
    def post(self, request):
        # This endpoint will only be accessible to users with verified email
        # when EMAIL_VERIFICATION_REQUIRED is True
        return Response({"message": "NFT minted successfully"})
```

## Social Providers Login Mechanism (Google, LinkedIn, Facebook, etc.)

First, create OAuth client configurations for the social providers (Google, LinkedIn, Facebook, etc.) and add the **client id** 
and **client secret** to the **settings**. Also set the **redirect URL** to the callback URL of the respective provider.
Use the same **redirect URL** in the **auth providers** configuration.

#### Video tutorial for creating OAuth client
- [How to create Google OAuth client](https://www.youtube.com/watch?v=OKMgyF5ezFs&ab_channel=LearnWithDexter)
- [How to create Facebook OAuth client](https://youtu.be/LLlpH3vZVkg?t=133)
- [How to create LinkedIn OAuth client](https://www.youtube.com/watch?v=aV8d09e8nnA&ab_channel=LearnwithNAK)

#### Login Flow
1. Call the URL `auth/{provider_name}` to redirect to the respective provider login page.
2. The user will provide the credentials on the provider's login page & authorize the app.
3. Upon successful login, the user will be redirected to the `REDIRECT_URI` with the code. 
Here, `REDIRECT_URI` should redirect to the developer's frontend app.
4. The frontend app will call the backend API `auth/{provider_name}/callback?code={code}` with the code in query params.

#### What happens inside `auth/{provider_name}/callback` API?
1. By following the Oauth2 flow, user data (email, name, etc.) is fetched from the provider.
2. The user is then searched in the database via **email** field provided by the social provider. 
If the user is not found in the db, a new user is created with the `email`, `first_name` and `is_verified=True`.
Then calls the `POST_SIGNUP_TRIGGER` class with **provider name, user data from backend & provider** to perform any post-signup actions.
3. Calls the `POST_LOGIN_TRIGGER` class with **provider name, user data from backend & provider** to perform any post-login actions.
4. Finally, **access token and refresh token** generated with **user id** is returned.

## Utility Classes
### Communication Class
This class is used to send messages to the user. The default class is `blockauth.notification.DummyNotification`, 
which is a dummy class that prints the message to the console. 

Developers should implement their own class by inheriting `blockauth.notification.BaseNotification` and set the path in settings via `DEFAULT_NOTIFICATION_CLASS`.
Otherwise, the default class will be used.

Currently, the communication class is integrated in the following APIs:
- `auth/signup`: To send OTP/link for signup (automatic).
- `auth/wallet/email/add/`: To send OTP/link for wallet email verification (automatic).
- `auth/signup/otp/resend`: To resend OTP for signup (legacy endpoint).
- `auth/login/passwordless`: To send OTP for passwordless login.
- `auth/password/reset`: To send OTP for password reset.
- `auth/password/change`: To send password change notification.
- `auth/email/change`: To send OTP for email change.

**Usage example**

```python
from blockauth.notification import BaseNotification


class CustomNotification(BaseNotification):
    def notify(self, method: str, event: str, context: dict) -> None:
        """
       :param method: delivery method ('email', 'sms')
       :param event: notification event (see NotificationEvent constants)
       :param context: contains identifier and any extra data
       """
        if event == 'otp_request':
            self.send_otp(context)
        elif event == 'password_change':
            self.send_password_change_email(context)

    def send_otp(self, context: dict) -> None:
        email = context.get('email')
        otp = context.get('otp')
        print(f"Sending OTP {otp} to email {email}")

    def send_password_change_email(self, context: dict) -> None:
        email = context.get('email')
        print(f"Sending password change notification to email {email}")
```

The following notification events are available (see `blockauth.notification.NotificationEvent`):
```python
class NotificationEvent:
    OTP_REQUEST = "otp_request"
    SUCCESS_PASSWORD_RESET = "success_password_reset"
    SUCCESS_PASSWORD_CHANGE = "success_password_change"
    SUCCESS_EMAIL_CHANGE = "success_email_change"
```

### Trigger Classes
These classes are used to perform some actions before and after the signup and login process.
- `PRE_SIGNUP_TRIGGER`: Called before signup. Default: `blockauth.triggers.DummyPreSignupTrigger`
- `POST_SIGNUP_TRIGGER`: Called after signup. Default: `blockauth.triggers.DummyPostSignupTrigger`
- `POST_LOGIN_TRIGGER`: Called after login. Default: `blockauth.triggers.DummyPostLoginTrigger`
- `POST_PASSWORD_CHANGE_TRIGGER`: Called after password change. Default: `blockauth.triggers.DummyPostPasswordChangeTrigger`
- `POST_PASSWORD_RESET_TRIGGER`: Called after password reset. Default: `blockauth.triggers.DummyPostPasswordResetTrigger`

Developers have to implement their own classes by inheriting the respective base classes and set the path in the settings.

**Usage example**
```python
from blockauth.triggers import BaseTrigger

class CustomPreSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic before signup
        print(f"Custom pre-signup logic with context: {context}")

class CustomPostSignupTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic after signup
        print(f"Custom post-signup logic with context: {context}")

class CustomPostLoginTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # Custom logic after login
        print(f"Custom post-login logic with context: {context}")
```

## Logging in BlocAuth

BlocAuth provides a unified logging interface for all authentication-related events. This logger supports multiple log levels, each with a unique icon for easy identification.

### Supported Log Levels and Icons

| Level      | Icon  | Description                                                        |
|------------|-------|--------------------------------------------------------------------|
| debug      | 🐞    | Detailed information for debugging                                 |
| info       | ℹ️    | General information about application events                       |
| warning    | ⚠️    | Unusual or unexpected events, not necessarily errors               |
| error      | ❌    | Errors that prevent normal execution                               |
| critical   | 🔥    | Very serious errors requiring immediate attention                  |
| exception  | 💥    | Exceptions, typically with stack traces                            |
| trace      | 🔍    | Fine-grained tracing information                                   |
| notice     | 📢    | Important but normal events requiring special attention            |
| alert      | 🚨    | Events requiring immediate action, not yet critical                |
| fatal      | ☠️    | Fatal errors leading to shutdown or unrecoverable failure          |
| success    | ✅    | Successful completion of an operation                              |
| pending    | ⏳    | Operations in progress or waiting for completion                   |
| failure    | 💔    | Failed operations or processes                                     |

### Custom Logger Integration

To use your own logging backend, implement a callback class and set it in your Django settings inside the `BLOCK_AUTH_SETTINGS` dictionary as `BLOCK_AUTH_LOGGER_CLASS`.

#### Example: Custom Logger Class

```python
# myapp/logging.py
class MyBlockAuthLogger:
    def log(self, message, data=None, level="info", icon=None):
        # You can integrate with Python's logging, send to a service, or print
        print(f"{icon} [{level.upper()}] {message} | {data}")
```

#### Django Settings Configuration

```python
# settings.py
BLOCK_AUTH_SETTINGS = {
    "BLOCK_AUTH_LOGGER_CLASS": "myapp.logging.MyBlockAuthLogger",
    # ... other BlocAuth settings ...
}
```

- The logger class must implement a `log(message, data, level, icon)` method.
- The `icon` argument is a unicode symbol representing the log level.
- If `BLOCK_AUTH_LOGGER_CLASS` is not set in `BLOCK_AUTH_SETTINGS`, logging calls will be no-ops.


### Log Context Sanitization

To protect sensitive user data, BlocAuth automatically removes sensitive fields (such as passwords, tokens, codes, etc.) from all log data before writing to logs.

By default, the following fields are removed: `password`, `new_password`, `refresh`, `access`, `token`, `code`. This list can be extended by maintainers if needed.

All BlocAuth logging calls use this utility to ensure no sensitive information is ever logged.

## Permission Classes

BlockAuth provides permission classes to control access to endpoints based on email verification status.

### EmailVerificationPermission

A generic permission class that checks if users have verified their email address. This permission can be used on any endpoint to restrict access for users who haven't verified their email.

**Configuration:**
```python
# settings.py
BLOCK_AUTH_SETTINGS = {
    "EMAIL_VERIFICATION_REQUIRED": True,  # Enable email verification requirement
    # ... other settings
}
```

**Usage:**
```python
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from blockauth.utils.permissions import EmailVerificationPermission

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated, EmailVerificationPermission]
    
    def get(self, request):
        # This endpoint will only be accessible to users with verified email
        # when EMAIL_VERIFICATION_REQUIRED is True
        return Response({"message": "Access granted"})
```

**What it checks:**
1. If email verification is required (configurable via `EMAIL_VERIFICATION_REQUIRED`)
2. If the user has an email address
3. If the user's email is verified (`is_verified=True`)

**Note:** This permission is designed to be used on protected endpoints that require email verification. It should NOT be used on endpoints that are specifically for adding email addresses (like `auth/wallet/email/add/`) since users calling those endpoints are expected to be unverified.

**Error Messages:**
- "Email address required. Please add an email address to access this endpoint." - When user has no email
- "Email verification required. Please verify your email address to access this endpoint." - When email is not verified

---

## 🔐 KDF Usage Examples

### Basic KDF Wallet Creation

```python
from blockauth.kdf import get_kdf_manager

# Get KDF manager
kdf_manager = get_kdf_manager()

# Create wallet for email user
wallet_data = kdf_manager.create_wallet(
    email="user@example.com",
    password="SecurePassword123",
    wallet_name="primary"
)

print(f"Wallet Address: {wallet_data['wallet_address']}")
print(f"Wallet ID: {wallet_data['wallet_id']}")
```

### Passwordless Wallet Creation

```python
# Create wallet for passwordless user
wallet_data = kdf_manager.create_wallet(
    email="user@example.com",
    wallet_name="primary",
    auth_method='passwordless'  # No password required
)

print(f"Passwordless Wallet: {wallet_data['wallet_address']}")
```

### Multiple Wallets per User

```python
# Create multiple wallets with different names
wallets = kdf_manager.create_multiple_wallets(
    email="user@example.com",
    password="SecurePassword123",
    wallet_names=["primary", "trading", "savings"]
)

for wallet in wallets:
    print(f"{wallet['wallet_name']}: {wallet['wallet_address']}")
```

### Password Change Integration

Password change triggers fire automatically from the `PasswordChangeView`. To handle password changes in your app, implement a custom trigger:

```python
from blockauth.triggers import BaseTrigger

class MyPasswordChangeTrigger(BaseTrigger):
    def trigger(self, context: dict) -> None:
        # context contains: user_id, username, email, trigger_type, timestamp
        # NOTE: plaintext passwords are never included in the context
        user_id = context['user_id']
        # Perform post-password-change actions (e.g., invalidate sessions)
```

### KDF Configuration

```python
# In your Django settings
BLOCK_AUTH_SETTINGS = {
    "KDF_ENABLED": True,
    "KDF_ALGORITHM": "pbkdf2_sha256",  # or "argon2id"
    "KDF_ITERATIONS": 100000,           # Production: 100k+, Dev: 1k
    "KDF_SECURITY_LEVEL": "HIGH",       # LOW, MEDIUM, HIGH, CRITICAL
    "KDF_MASTER_SALT": "your-32-char-minimum-salt",
    "MASTER_ENCRYPTION_KEY": "0x" + "64-char-hex-key",
    "PLATFORM_MASTER_SALT": "your-platform-salt-32-chars-minimum",
}
```

---

## Custom JWT Claims

BlockAuth provides a flexible JWT claims provider system that allows you to add custom data to JWT tokens. This enables you to include application-specific information (like user roles, permissions, organization IDs, etc.) directly in the authentication token.

### Quick Start

1. **Create a claims provider class** with a `get_custom_claims` method
2. **Register the provider** with the JWT manager
3. **Custom claims are automatically included** in all generated tokens

### Example

```python
# myapp/jwt_claims.py
class MyClaimsProvider:
    def get_custom_claims(self, user):
        return {
            "role": user.role,
            "organization_id": str(user.organization_id),
            "permissions": list(user.permissions.all())
        }

# Register in Django app's ready() method
from blockauth.jwt.token_manager import jwt_manager
jwt_manager.register_claims_provider(MyClaimsProvider())
```

### Documentation

For detailed documentation on creating and managing custom JWT claims providers, including best practices, advanced usage, and troubleshooting, see:

📚 **[Custom JWT Claims Guide](docs/CUSTOM_JWT_CLAIMS.md)**

---

## Rate Limiting
Rate limiting is implemented for requests currently. The rate limit is based on the number of requests and the duration.
The rate limit can be configured in the settings.

---

## 🧪 KDF Development & Testing

### Development Setup

1. **Install KDF Dependencies**
```bash
uv add cryptography web3 eth-account argon2-cffi
```

2. **Configure KDF Settings**
```python
# In your Django settings
BLOCK_AUTH_SETTINGS = {
    "KDF_ENABLED": True,
    "KDF_ALGORITHM": "pbkdf2_sha256",
    "KDF_ITERATIONS": 1000,  # Lower for development
    "KDF_SECURITY_LEVEL": "LOW",
    "KDF_MASTER_SALT": "dev-salt-32-chars-minimum-for-development",
    "MASTER_ENCRYPTION_KEY": "0x" + "a" * 64,  # Development key
    "PLATFORM_MASTER_SALT": "dev-platform-salt-32-chars-minimum",
}
```

### Testing KDF Functionality

```python
# Test KDF wallet creation
from blockauth.kdf import get_kdf_manager

kdf_manager = get_kdf_manager()

# Test with email/password
wallet = kdf_manager.create_wallet(
    email="test@example.com",
    password="TestPassword123"
)

assert wallet['wallet_address'].startswith('0x')
assert len(wallet['wallet_address']) == 42
```

### Production Deployment

1. **Generate Secure Keys**
```bash
# Generate master encryption key
openssl rand -hex 32

# Generate platform master salt (minimum 32 characters)
openssl rand -base64 32
```

2. **Update Production Settings**
```python
BLOCK_AUTH_SETTINGS = {
    "KDF_ENABLED": True,
    "KDF_ALGORITHM": "pbkdf2_sha256",
    "KDF_ITERATIONS": 100000,  # Production iterations
    "KDF_SECURITY_LEVEL": "HIGH",
    "KDF_MASTER_SALT": "your-production-salt-32-chars-minimum",
    "MASTER_ENCRYPTION_KEY": "0x" + "your-64-char-hex-key",
    "PLATFORM_MASTER_SALT": "your-platform-salt-32-chars-minimum",
}
```

3. **Monitor Performance**
- Wallet creation success rate
- Average creation time (< 3 seconds)
- Memory usage per operation (< 100MB)
- Database query performance

---

## Folder Structure

```
blockauth/
├── __init__.py
├── apps.py
├── authentication.py
├── conf.py
├── migrations/
│   ├── __init__.py
│   └── 0001_initial.py
├── models/
│   ├── __init__.py
│   ├── otp.py
│   └── user.py
├── notification.py
├── docs/
│   ├── __init__.py
│   ├── auth_docs.py
│   ├── wallet_docs.py
│   └── social_auth.py
├── schemas/
│   ├── __init__.py
│   ├── account_settings.py
│   ├── examples/
│   │   ├── __init__.py
│   │   ├── account_settings.py
│   │   ├── common.py
│   │   ├── login.py
│   │   ├── password_reset.py
│   │   ├── signup.py
│   │   └── social_auth.py
│   ├── factory.py
│   ├── login.py
│   ├── password_reset.py
│   ├── signup.py
│   └── social_auth.py
├── serializers/
│   ├── __init__.py
│   ├── otp_serializers.py
│   ├── user_account_serializers.py
│   └── wallet_serializers.py
├── triggers.py
├── urls.py
├── utils/
│   ├── __init__.py
│   ├── config.py
│   ├── custom_exception.py
│   ├── generics.py
│   ├── logger.py
│   ├── permissions.py
│   ├── rate_limiter.py
│   ├── social.py
│   ├── token.py
│   ├── validators.py
│   └── web3/
│       └── wallet.py
├── kdf/                           # 🔐 KDF System Module
│   ├── __init__.py
│   ├── services.py                # Core KDF services
│   ├── encryption.py              # AES-256-GCM encryption
│   ├── algorithms/                # KDF algorithms
│   │   ├── __init__.py
│   │   ├── pbkdf2.py             # PBKDF2 implementation
│   │   └── argon2.py              # Argon2 implementation
│   └── utils.py                   # KDF utilities
├── passkey/                       # 🔐 Passkey/WebAuthn Module
│   ├── __init__.py
│   ├── views.py                   # API views
│   ├── models.py                  # PasskeyCredential, PasskeyChallenge
│   ├── config.py                  # Configuration manager
│   ├── constants.py               # Constants and defaults
│   ├── exceptions.py              # Custom exceptions
│   ├── services/                  # Business logic
│   │   ├── passkey_service.py    # WebAuthn operations
│   │   └── challenge_service.py  # Challenge management
│   ├── storage/                   # Credential storage
│   │   ├── base.py               # Abstract interface
│   │   └── django_storage.py     # Django ORM implementation
│   └── README.md                  # Developer guide
├── triggers/                      # 🔄 Password Management Triggers
│   ├── __init__.py
│   ├── password_triggers.py       # Password change/reset triggers
│   └── dummy_triggers.py          # Placeholder triggers
└── views/
    ├── __init__.py
    ├── basic_auth_views.py
    ├── facebook_auth_views.py
    ├── google_auth_views.py
    ├── linkedin_auth_views.py
    └── wallet_auth_views.py
```

## License
All rights reserved. 

## Acknowledgments
- [Django](https://www.djangoproject.com/)
- [Django REST framework](https://www.django-rest-framework.org/)
- [PyJWT](https://pyjwt.readthedocs.io/en/stable/)
- [drf-yasg](https://drf-yasg.readthedocs.io/en/stable/)
- [Google OAuth2](https://developers.google.com/identity/protocols/oauth2)
- [LinkedIn OAuth2](https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow?context=linkedin/context)
- [Facebook OAuth2](https://developers.facebook.com/docs/facebook-login/)
- [Cryptography](https://cryptography.io/) - For AES-256-GCM encryption
- [Web3.py](https://web3py.readthedocs.io/) - For Ethereum integration
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - For advanced KDF algorithms

