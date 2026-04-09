# Signup & Login

BlockAuth provides three authentication methods: email/password, passwordless OTP, and Web3 wallet. All are controlled by [feature flags](../getting-started/configuration.md#feature-flags).

## Signup Flow

The signup flow uses a two-step OTP verification:

1. User submits email and password
2. BlockAuth sends an OTP via the configured notification class
3. User confirms with the OTP

### Step 1: Register

```bash
POST /auth/signup/

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

The password is validated against Django's password validators. BlockAuth includes `BlockAuthPasswordValidator` for additional strength checks.

### Step 2: Confirm OTP

```bash
POST /auth/signup/confirm/

{
  "email": "user@example.com",
  "otp": "123456"
}
```

Returns JWT tokens on success:

```json
{
  "access": "eyJ...",
  "refresh": "eyJ..."
}
```

### Resend OTP

If the OTP expires (default: 1 minute), request a new one:

```bash
POST /auth/signup/otp/resend/

{
  "email": "user@example.com"
}
```

!!! note
    OTP resend is rate-limited. See [Settings](../reference/settings.md) for `REQUEST_LIMIT` configuration.

## Basic Login

Email and password authentication:

```bash
POST /auth/login/basic/

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

Returns:

```json
{
  "access": "eyJ...",
  "refresh": "eyJ..."
}
```

## Passwordless Login

OTP-based login without a password. Requires the `PASSWORDLESS_LOGIN` feature flag.

### Step 1: Request OTP

```bash
POST /auth/login/passwordless/

{
  "email": "user@example.com"
}
```

### Step 2: Confirm

```bash
POST /auth/login/passwordless/confirm/

{
  "email": "user@example.com",
  "otp": "123456"
}
```

## Password Management

### Reset Password

For users who forgot their password:

```bash
# Step 1: Request reset OTP
POST /auth/password/reset/

{
  "email": "user@example.com"
}

# Step 2: Set new password
POST /auth/password/reset/confirm/

{
  "email": "user@example.com",
  "otp": "123456",
  "new_password": "NewSecurePass456!"
}
```

### Change Password

For authenticated users:

```bash
POST /auth/password/change/
Authorization: Bearer <access_token>

{
  "old_password": "SecurePass123!",
  "new_password": "NewSecurePass456!"
}
```

## Email Change

Two-step OTP verification for email changes:

```bash
# Step 1: Request change
POST /auth/email/change/
Authorization: Bearer <access_token>

{
  "new_email": "newemail@example.com"
}

# Step 2: Confirm
POST /auth/email/change/confirm/

{
  "email": "newemail@example.com",
  "otp": "123456"
}
```

## Token Refresh

Exchange a refresh token for new access and refresh tokens:

```bash
POST /auth/token/refresh/

{
  "refresh": "eyJ..."
}
```

When `ROTATE_REFRESH_TOKENS` is enabled (default), the old refresh token is blacklisted and a new pair is issued.

See [JWT Tokens](jwt-tokens.md) for token structure and custom claims.
