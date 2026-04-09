# API Endpoints

All endpoints are feature-flag controlled via `BLOCK_AUTH_SETTINGS['FEATURES']`. Disabling a feature removes its URL patterns entirely.

## Authentication

| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `signup/` | `SIGNUP` | Register with email/phone + password |
| POST | `signup/otp/resend/` | `SIGNUP` | Resend signup OTP |
| POST | `signup/confirm/` | `SIGNUP` | Confirm signup with OTP |
| POST | `login/basic/` | `BASIC_LOGIN` | Email/password login |
| POST | `login/passwordless/` | `PASSWORDLESS_LOGIN` | Request passwordless OTP |
| POST | `login/passwordless/confirm/` | `PASSWORDLESS_LOGIN` | Confirm passwordless login |
| POST | `login/wallet/` | `WALLET_LOGIN` | Web3 wallet signature auth |
| POST | `token/refresh/` | `TOKEN_REFRESH` | Refresh JWT tokens |

## Password Management

| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `password/reset/` | `PASSWORD_RESET` | Request password reset OTP |
| POST | `password/reset/confirm/` | `PASSWORD_RESET` | Confirm password reset with new password |
| POST | `password/change/` | `PASSWORD_CHANGE` | Change password (authenticated) |

## Email & Wallet

| Method | Path | Feature Flag | Description |
|--------|------|-------------|-------------|
| POST | `email/change/` | `EMAIL_CHANGE` | Request email change OTP |
| POST | `email/change/confirm/` | `EMAIL_CHANGE` | Confirm email change |
| POST | `wallet/email/add/` | `WALLET_EMAIL_ADD` | Add email to wallet account |

## OAuth Providers

Requires `SOCIAL_AUTH` feature flag and provider configuration in `AUTH_PROVIDERS`.

| Method | Path | Provider | Description |
|--------|------|----------|-------------|
| GET | `google/` | Google | Initiate Google OAuth |
| GET | `google/callback/` | Google | Google OAuth callback |
| GET | `facebook/` | Facebook | Initiate Facebook OAuth |
| GET | `facebook/callback/` | Facebook | Facebook OAuth callback |
| GET | `linkedin/` | LinkedIn | Initiate LinkedIn OAuth |
| GET | `linkedin/callback/` | LinkedIn | LinkedIn OAuth callback |

## Passkey / WebAuthn

Requires `PASSKEY_AUTH` feature flag.

| Method | Path | Description |
|--------|------|-------------|
| POST | `passkey/register/options/` | Get registration options |
| POST | `passkey/register/verify/` | Verify registration |
| POST | `passkey/auth/options/` | Get authentication options |
| POST | `passkey/auth/verify/` | Verify authentication |
| GET | `passkey/credentials/` | List credentials |
| DELETE | `passkey/credentials/<uuid>/` | Delete credential |

## Rate Limiting

All endpoints are rate-limited. The default limit is 3 requests per 30 seconds per (identifier, subject, IP address). Configure with:

```python
BLOCK_AUTH_SETTINGS = {
    'REQUEST_LIMIT': (3, 30),  # (max_requests, window_seconds)
}
```

OTP endpoints have additional OTP-specific throttling.

## Authentication Header

Protected endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

The header name is configurable via `AUTH_HEADER_NAME` (default: `HTTP_AUTHORIZATION`).

## Response Format

Successful authentication endpoints return:

```json
{
  "access": "<jwt_access_token>",
  "refresh": "<jwt_refresh_token>"
}
```

Errors return standard DRF error responses with appropriate HTTP status codes.
