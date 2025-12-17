# Passkey/WebAuthn Developer Guide

This module provides WebAuthn/FIDO2 passwordless authentication for BlockAuth.

## Overview

Passkeys enable passwordless authentication using:
- **Biometrics**: Face ID, Touch ID, Windows Hello, Android fingerprint
- **Hardware Keys**: YubiKey, Titan Security Key
- **Device PIN**: Fallback when biometrics unavailable

**Key Benefits:**
- No passwords to remember or steal
- Phishing-resistant (bound to origin)
- Cross-platform support
- Same code works on all devices

## Quick Start

### 1. Enable Passkey Feature

```python
# settings.py
from blockauth.constants import Features

BLOCK_AUTH_SETTINGS = {
    # Enable passkey URLs
    "FEATURES": {
        Features.PASSKEY_AUTH: True,
    },

    # Enable passkey module
    "PASSKEY_ENABLED": True,

    # REQUIRED: Your domain (no protocol, no port)
    "PASSKEY_RP_ID": "localhost",  # Production: "example.com"

    # REQUIRED: Display name shown to users
    "PASSKEY_RP_NAME": "My Application",

    # REQUIRED: Allowed origins (must include protocol)
    "PASSKEY_ALLOWED_ORIGINS": [
        "http://localhost:3000",      # Dev frontend
        # "https://example.com",      # Production
    ],
}
```

### 2. Run Migrations

```bash
python manage.py makemigrations blockauth
python manage.py migrate
```

### 3. URLs Are Automatically Available

Passkey URLs are included in `blockauth.urls` - no separate URL include needed:

```python
# urls.py
urlpatterns = [
    path('auth/', include('blockauth.urls')),  # Passkey URLs included
]
```

## API Endpoints Overview

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/auth/passkey/register/options/` | POST | Required | Get registration options |
| `/auth/passkey/register/verify/` | POST | Required | Verify and store credential |
| `/auth/passkey/auth/options/` | POST | Public | Get authentication options |
| `/auth/passkey/auth/verify/` | POST | Public | Verify and return JWT tokens |
| `/auth/passkey/credentials/` | GET | Required | List user's passkeys |
| `/auth/passkey/credentials/<uuid>/` | GET/PATCH/DELETE | Required | Manage specific passkey |

---

## Detailed API Documentation

### Important: Passkeys Do NOT Create Users

Passkey authentication **only works with existing users**:
- **Registration** requires the user to be already logged in (JWT authentication)
- **Authentication** only succeeds if the credential belongs to an existing user
- To create a new user, use email/password signup, social login, or passwordless OTP first

---

### 1. POST `/auth/passkey/register/options/`

**Generate WebAuthn registration options for adding a new passkey.**

The authenticated user receives cryptographic options that the browser uses to create a new credential.

#### Authentication
`Required` - Bearer JWT token

#### Request Body
```json
{
  "display_name": "John Doe"  // Optional: shown on authenticator
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `display_name` | string | No | User-friendly name shown during registration. Defaults to user's email/username |

#### Response `200 OK`
```json
{
  "rp": {
    "name": "My Application",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-encoded-user-handle",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "challenge": "base64url-encoded-random-challenge",
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "timeout": 60000,
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url-existing-credential-id",
      "transports": ["internal"]
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "preferred",
    "userVerification": "required"
  },
  "attestation": "none",
  "_challenge": "stored-challenge-reference",
  "_user_id": "user-uuid",
  "_user_handle": "base64url-user-handle"
}
```

| Field | Description |
|-------|-------------|
| `rp` | Relying Party info (your app) |
| `user` | User info for credential association |
| `challenge` | Cryptographic challenge (must be signed) |
| `pubKeyCredParams` | Supported algorithms (-7=ES256, -257=RS256) |
| `timeout` | Registration timeout in milliseconds |
| `excludeCredentials` | User's existing credentials (prevents duplicates) |
| `authenticatorSelection` | Authenticator requirements |
| `attestation` | Attestation preference |

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `MAX_CREDENTIALS_REACHED` | User has reached maximum passkey limit (default: 10) |
| 400 | `PASSKEY_NOT_ENABLED` | Passkey module not enabled in settings |
| 401 | - | Not authenticated |

---

### 2. POST `/auth/passkey/register/verify/`

**Verify the registration response and store the new credential.**

After the browser creates a credential, send the response here to complete registration.

#### Authentication
`Required` - Bearer JWT token

#### Request Body
```json
{
  "id": "base64url-credential-id",
  "rawId": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-encoded-client-data",
    "attestationObject": "base64url-encoded-attestation",
    "transports": ["internal", "hybrid"]
  },
  "name": "MacBook Pro Touch ID"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Base64URL credential ID |
| `rawId` | string | Yes | Base64URL raw credential ID |
| `type` | string | Yes | Must be `"public-key"` |
| `response.clientDataJSON` | string | Yes | Browser-generated client data |
| `response.attestationObject` | string | Yes | Authenticator-generated attestation |
| `response.transports` | array | No | Supported transports (`internal`, `usb`, `nfc`, `ble`, `hybrid`) |
| `name` | string | No | User-friendly name for this passkey |

#### Response `201 Created`
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "credential_id": "base64url-credential-id",
  "name": "MacBook Pro Touch ID",
  "created_at": "2024-01-15T10:30:00Z",
  "authenticator_attachment": "platform",
  "transports": ["internal", "hybrid"],
  "backup_eligible": true
}
```

| Field | Description |
|-------|-------------|
| `id` | UUID for managing this credential via API |
| `credential_id` | WebAuthn credential ID (used by browser) |
| `name` | User-assigned name |
| `created_at` | Registration timestamp |
| `authenticator_attachment` | `platform` (built-in) or `cross-platform` (hardware key) |
| `transports` | How authenticator communicates |
| `backup_eligible` | Whether passkey can sync to other devices |

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `INVALID_CREDENTIAL_DATA` | Missing or malformed credential data |
| 400 | `INVALID_ORIGIN` | Origin not in `PASSKEY_ALLOWED_ORIGINS` |
| 400 | `SIGNATURE_VERIFICATION_FAILED` | Cryptographic verification failed |
| 400 | `CHALLENGE_EXPIRED` | Challenge timed out (default: 5 min) |
| 400 | `CHALLENGE_ALREADY_USED` | Challenge was already consumed |
| 401 | - | Not authenticated |

---

### 3. POST `/auth/passkey/auth/options/`

**Generate WebAuthn authentication options for logging in with a passkey.**

This is a **public endpoint** - no authentication required.

#### Authentication
`None` - Public endpoint

#### Request Body
```json
{
  "username": "user@example.com"  // Optional
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `username` | string | No | User's email to filter credentials |

#### Understanding the `username` Parameter

The `username` parameter changes how the browser presents passkeys:

**With `username` (Non-Discoverable Mode)**
```
User enters email → Backend returns that user's credential IDs →
Browser only shows passkeys matching those IDs
```

Use when:
- Login form has email field
- You want to filter passkeys to specific user
- User knows their email

**Without `username` (Discoverable Mode)**
```
User clicks "Login with Passkey" → Backend returns empty allowCredentials →
Browser shows ALL available passkeys for this domain →
User selects one → userHandle identifies the user
```

Use when:
- "One-click" passkey login
- No email entry required
- Better UX for returning users

#### Response `200 OK`

**With username (user found with credentials):**
```json
{
  "challenge": "base64url-random-challenge",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id-1",
      "transports": ["internal"]
    },
    {
      "type": "public-key",
      "id": "base64url-credential-id-2",
      "transports": ["usb"]
    }
  ],
  "userVerification": "required",
  "_challenge": "stored-challenge-reference"
}
```

**Without username (discoverable mode):**
```json
{
  "challenge": "base64url-random-challenge",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [],
  "userVerification": "required",
  "_challenge": "stored-challenge-reference"
}
```

| Field | Description |
|-------|-------------|
| `challenge` | Cryptographic challenge to sign |
| `timeout` | Authentication timeout in milliseconds |
| `rpId` | Your domain (must match registration) |
| `allowCredentials` | Specific credentials to use (empty = show all) |
| `userVerification` | Whether biometric/PIN is required |

#### Security Note
When `username` is provided but user doesn't exist, the endpoint still returns valid options (with empty `allowCredentials`). This prevents user enumeration attacks.

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `PASSKEY_NOT_ENABLED` | Passkey module not enabled |

---

### 4. POST `/auth/passkey/auth/verify/`

**Verify the authentication response and issue JWT tokens.**

This is a **public endpoint** - no authentication required.

#### Authentication
`None` - Public endpoint

#### Request Body
```json
{
  "id": "base64url-credential-id",
  "rawId": "base64url-credential-id",
  "type": "public-key",
  "response": {
    "clientDataJSON": "base64url-client-data",
    "authenticatorData": "base64url-authenticator-data",
    "signature": "base64url-signature",
    "userHandle": "base64url-user-handle"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Credential ID used for authentication |
| `rawId` | string | Yes | Raw credential ID |
| `type` | string | Yes | Must be `"public-key"` |
| `response.clientDataJSON` | string | Yes | Browser-generated client data with challenge |
| `response.authenticatorData` | string | Yes | Authenticator-generated data |
| `response.signature` | string | Yes | Cryptographic signature |
| `response.userHandle` | string | No | User handle (for discoverable credentials) |

#### Response `200 OK`
```json
{
  "access": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com"
  },
  "credential": {
    "id": "credential-uuid",
    "name": "MacBook Pro Touch ID",
    "last_used_at": "2024-01-15T14:30:00Z"
  }
}
```

| Field | Description |
|-------|-------------|
| `access` | JWT access token |
| `refresh` | JWT refresh token |
| `user.id` | User's UUID |
| `user.email` | User's email |
| `credential.id` | UUID of credential used |
| `credential.name` | User-assigned credential name |
| `credential.last_used_at` | Timestamp of this authentication |

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `INVALID_CREDENTIAL_DATA` | Missing or malformed data |
| 400 | `INVALID_ORIGIN` | Origin not allowed |
| 400 | `SIGNATURE_VERIFICATION_FAILED` | Invalid signature |
| 400 | `CHALLENGE_EXPIRED` | Challenge timed out |
| 400 | `COUNTER_REGRESSION` | Possible cloned authenticator detected |
| 404 | `CREDENTIAL_NOT_FOUND` | No credential with this ID |
| 400 | `CREDENTIAL_REVOKED` | Credential has been disabled |

---

### 5. GET `/auth/passkey/credentials/`

**List all passkeys registered by the authenticated user.**

#### Authentication
`Required` - Bearer JWT token

#### Response `200 OK`
```json
{
  "count": 2,
  "credentials": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "credential_id": "base64url-credential-id",
      "name": "MacBook Pro Touch ID",
      "created_at": "2024-01-10T09:00:00Z",
      "last_used_at": "2024-01-15T14:30:00Z",
      "authenticator_attachment": "platform",
      "transports": ["internal", "hybrid"],
      "backup_eligible": true,
      "backup_state": true,
      "is_active": true
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "credential_id": "base64url-credential-id-2",
      "name": "YubiKey 5",
      "created_at": "2024-01-12T11:00:00Z",
      "last_used_at": null,
      "authenticator_attachment": "cross-platform",
      "transports": ["usb"],
      "backup_eligible": false,
      "backup_state": false,
      "is_active": true
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `count` | Total number of credentials |
| `id` | UUID for API operations |
| `credential_id` | WebAuthn credential identifier |
| `name` | User-friendly name |
| `created_at` | When passkey was registered |
| `last_used_at` | Last successful authentication (null if never used) |
| `authenticator_attachment` | `platform` or `cross-platform` |
| `transports` | Communication methods |
| `backup_eligible` | Can sync to cloud |
| `backup_state` | Currently synced |
| `is_active` | Whether credential is enabled |

---

### 6. GET `/auth/passkey/credentials/<uuid>/`

**Get details of a specific passkey.**

#### Authentication
`Required` - Bearer JWT token

#### URL Parameters
| Parameter | Type | Description |
|-----------|------|-------------|
| `uuid` | UUID | Credential ID from list endpoint |

#### Response `200 OK`
Same format as individual credential in list response.

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 401 | - | Not authenticated |
| 404 | `CREDENTIAL_NOT_FOUND` | Credential doesn't exist or belongs to another user |

---

### 7. PATCH `/auth/passkey/credentials/<uuid>/`

**Update a passkey's name.**

#### Authentication
`Required` - Bearer JWT token

#### Request Body
```json
{
  "name": "iPhone Face ID"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | New name for the credential |

#### Response `200 OK`
Updated credential object (same format as GET).

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 400 | `VALIDATION_ERROR` | Name is required |
| 401 | - | Not authenticated |
| 404 | `CREDENTIAL_NOT_FOUND` | Credential not found |

---

### 8. DELETE `/auth/passkey/credentials/<uuid>/`

**Permanently delete a passkey.**

#### Authentication
`Required` - Bearer JWT token

#### Response `204 No Content`
Empty response on success.

#### Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 401 | - | Not authenticated |
| 404 | `CREDENTIAL_NOT_FOUND` | Credential not found |

#### Warning
Deleting a passkey is permanent. If the user has no other authentication methods, they may be locked out of their account.

---

## Error Response Format

All error responses follow this format:

```json
{
  "error_code": "CREDENTIAL_NOT_FOUND",
  "message": "Credential not found"
}
```

### Error Codes Reference

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `PASSKEY_NOT_ENABLED` | 400 | Passkey feature not enabled in settings |
| `MAX_CREDENTIALS_REACHED` | 400 | User has maximum allowed passkeys |
| `INVALID_CREDENTIAL_DATA` | 400 | Malformed or missing credential fields |
| `INVALID_ORIGIN` | 400 | Request origin not in allowed list |
| `SIGNATURE_VERIFICATION_FAILED` | 400 | Cryptographic verification failed |
| `CHALLENGE_EXPIRED` | 400 | Challenge timed out |
| `CHALLENGE_ALREADY_USED` | 400 | Challenge was already consumed |
| `COUNTER_REGRESSION` | 400 | Sign counter went backwards (possible clone) |
| `CREDENTIAL_NOT_FOUND` | 404 | Credential doesn't exist |
| `CREDENTIAL_REVOKED` | 400 | Credential has been disabled |
| `VALIDATION_ERROR` | 400 | General validation error |
| `PASSKEY_ERROR` | 400 | Generic passkey error |

## Configuration Reference

### Required Settings

| Setting | Description | Example |
|---------|-------------|---------|
| `PASSKEY_ENABLED` | Master switch | `True` |
| `PASSKEY_RP_ID` | Your domain (no protocol) | `"example.com"` |
| `PASSKEY_RP_NAME` | Display name for users | `"My App"` |
| `PASSKEY_ALLOWED_ORIGINS` | Frontend origins with protocol | `["https://example.com"]` |

### Optional Settings (with defaults)

| Setting | Default | Description |
|---------|---------|-------------|
| `PASSKEY_ATTESTATION` | `"none"` | `none`, `indirect`, `direct`, `enterprise` |
| `PASSKEY_AUTHENTICATOR_ATTACHMENT` | `None` | `None` (any), `"platform"`, `"cross-platform"` |
| `PASSKEY_RESIDENT_KEY` | `"preferred"` | `"required"`, `"preferred"`, `"discouraged"` |
| `PASSKEY_USER_VERIFICATION` | `"required"` | `"required"`, `"preferred"`, `"discouraged"` |
| `PASSKEY_REGISTRATION_TIMEOUT` | `60000` | Milliseconds |
| `PASSKEY_AUTHENTICATION_TIMEOUT` | `60000` | Milliseconds |
| `PASSKEY_CHALLENGE_LENGTH` | `32` | Bytes (minimum 16) |
| `PASSKEY_CHALLENGE_EXPIRY` | `300` | Seconds |
| `PASSKEY_MAX_CREDENTIALS_PER_USER` | `10` | Max passkeys per user |

## Understanding RP_ID

**RP_ID (Relying Party ID)** is your domain that identifies your app to authenticators.

### Rules:
- Domain only - no `https://`, no port, no path
- Must match or be parent of frontend origin
- **Cannot change** after users register (passkeys won't work)

### Examples:

| Frontend URL | RP_ID | Works? |
|--------------|-------|--------|
| `https://app.example.com` | `example.com` | Yes (parent domain) |
| `https://app.example.com` | `app.example.com` | Yes (exact match) |
| `https://other.example.com` | `app.example.com` | No (different subdomain) |
| `http://localhost:3000` | `localhost` | Yes (localhost special case) |

### Recommendation:
- Use **parent domain** (`example.com`) for flexibility across subdomains
- Use **exact subdomain** (`app.example.com`) for stricter security

## Frontend Integration

### Check Browser Support

```javascript
// Check WebAuthn support
const webauthnSupported = window.PublicKeyCredential !== undefined;

// Check platform authenticator (Face ID, Windows Hello, etc.)
const platformSupported = await PublicKeyCredential
    .isUserVerifyingPlatformAuthenticatorAvailable();

// Check conditional UI support (autofill)
const conditionalSupported = await PublicKeyCredential
    .isConditionalMediationAvailable?.() ?? false;
```

### Base64URL Utilities

```javascript
function base64urlDecode(str) {
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    const binary = atob(base64 + padding);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function base64urlEncode(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

### Register Passkey (Authenticated User)

```javascript
async function registerPasskey(accessToken, displayName = null) {
    // 1. Get registration options from server
    const optionsRes = await fetch('/auth/passkey/register/options/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ display_name: displayName }),
    });
    const options = await optionsRes.json();

    // 2. Decode base64url fields for WebAuthn API
    options.challenge = base64urlDecode(options.challenge);
    options.user.id = base64urlDecode(options.user.id);
    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(cred => ({
            ...cred,
            id: base64urlDecode(cred.id),
        }));
    }

    // 3. Create credential (triggers biometric prompt)
    const credential = await navigator.credentials.create({ publicKey: options });

    // 4. Send to server for verification
    const verifyRes = await fetch('/auth/passkey/register/verify/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: base64urlEncode(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
                attestationObject: base64urlEncode(credential.response.attestationObject),
                transports: credential.response.getTransports?.() || [],
            },
            name: 'My Device',  // Optional user-friendly name
        }),
    });

    return await verifyRes.json();
}
```

### Authenticate with Passkey (Public)

```javascript
async function authenticateWithPasskey(username = null) {
    // 1. Get authentication options
    const optionsRes = await fetch('/auth/passkey/auth/options/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),  // Optional for discoverable credentials
    });
    const options = await optionsRes.json();

    // 2. Decode base64url fields
    options.challenge = base64urlDecode(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(cred => ({
            ...cred,
            id: base64urlDecode(cred.id),
        }));
    }

    // 3. Get assertion (triggers biometric prompt)
    const assertion = await navigator.credentials.get({ publicKey: options });

    // 4. Verify and get JWT tokens
    const verifyRes = await fetch('/auth/passkey/auth/verify/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            id: assertion.id,
            rawId: base64urlEncode(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: base64urlEncode(assertion.response.clientDataJSON),
                authenticatorData: base64urlEncode(assertion.response.authenticatorData),
                signature: base64urlEncode(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? base64urlEncode(assertion.response.userHandle)
                    : null,
            },
        }),
    });

    const result = await verifyRes.json();
    // result = { access, refresh, user: { id, email }, credential: { id, name, last_used_at } }
    return result;
}
```

### Manage Passkeys

```javascript
// List user's passkeys
async function listPasskeys(accessToken) {
    const res = await fetch('/auth/passkey/credentials/', {
        headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    return await res.json();  // { count, credentials: [...] }
}

// Rename a passkey
async function renamePasskey(accessToken, credentialId, newName) {
    const res = await fetch(`/auth/passkey/credentials/${credentialId}/`, {
        method: 'PATCH',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: newName }),
    });
    return await res.json();
}

// Delete a passkey
async function deletePasskey(accessToken, credentialId) {
    await fetch(`/auth/passkey/credentials/${credentialId}/`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${accessToken}` },
    });
}
```

## Security Considerations

### HTTPS Required
WebAuthn only works on secure origins:
- `https://` in production
- `http://localhost` for development

### Origin Validation
Configure `PASSKEY_ALLOWED_ORIGINS` to match your frontend URLs exactly (with protocol).

### User Verification
Keep `PASSKEY_USER_VERIFICATION: "required"` for sensitive operations. This ensures biometric/PIN verification.

### Counter Validation
Enabled by default. Detects cloned authenticators by tracking signature counters.

### Challenge Expiry
Challenges expire after `PASSKEY_CHALLENGE_EXPIRY` seconds (default 5 minutes) to prevent replay attacks.

## Troubleshooting

### "Passkey module is not enabled"
```python
BLOCK_AUTH_SETTINGS = {
    "PASSKEY_ENABLED": True,  # Add this
}
```

### "RP ID mismatch" / "Origin not allowed"
- `PASSKEY_RP_ID` must match your domain exactly (no `https://`, no port)
- `PASSKEY_ALLOWED_ORIGINS` must include your frontend URL with protocol

### Browser doesn't show passkey prompt
1. Check HTTPS is enabled (or using localhost)
2. Check browser supports WebAuthn
3. Check user has platform authenticator or hardware key
4. Check console for JavaScript errors

### "No credentials available"
- User hasn't registered any passkeys yet
- User's passkeys were registered on a different RP_ID
- All user's passkeys were deleted

## Database Models

### PasskeyCredential
Stores registered passkey credentials.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `user` | FK | User who owns this credential |
| `credential_id` | Text | Base64URL credential ID from authenticator |
| `public_key` | Text | Base64URL COSE public key |
| `algorithm` | Int | COSE algorithm (-7 for ES256) |
| `sign_count` | BigInt | Signature counter for clone detection |
| `name` | Char | User-friendly name |
| `transports` | JSON | Supported transports (internal, usb, nfc, ble, hybrid) |
| `authenticator_attachment` | Char | platform or cross-platform |
| `backup_eligible` | Bool | Can be synced across devices |
| `is_discoverable` | Bool | Supports passwordless login |
| `created_at` | DateTime | Registration timestamp |
| `last_used_at` | DateTime | Last authentication timestamp |
| `is_active` | Bool | Soft delete flag |

### PasskeyChallenge
Temporary storage for WebAuthn challenges.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `challenge` | Char | Base64URL challenge |
| `user` | FK | Associated user (optional for auth) |
| `challenge_type` | Char | registration or authentication |
| `expires_at` | DateTime | Expiration timestamp |
| `is_used` | Bool | Whether challenge was consumed |

## Architecture

```
User Device                    Frontend                      Backend
     │                            │                             │
     │  1. Click "Add Passkey"    │                             │
     │ ◄──────────────────────────┤                             │
     │                            │  2. POST /register/options/ │
     │                            ├────────────────────────────►│
     │                            │  3. Challenge + Options     │
     │                            │◄────────────────────────────┤
     │  4. Biometric Prompt       │                             │
     │ ◄──────────────────────────┤                             │
     │  5. Verify (Face/Touch/PIN)│                             │
     ├──────────────────────────►│                             │
     │                            │  6. POST /register/verify/  │
     │                            ├────────────────────────────►│
     │                            │                             │ 7. Verify & Store
     │                            │  8. Success + Credential ID │
     │                            │◄────────────────────────────┤
```

## License

This module is part of BlockAuth and follows the same license terms.
