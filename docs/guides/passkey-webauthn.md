# Passkeys (WebAuthn)

BlockAuth supports FIDO2/WebAuthn passkey authentication -- Face ID, Touch ID, Windows Hello, and hardware security keys. Requires the `PASSKEY_AUTH` feature flag.

## How It Works

WebAuthn uses public-key cryptography. The private key never leaves the user's device. The server only stores a public key and credential ID.

**No biometric data is processed server-side.** Biometric matching happens entirely within the device's secure enclave.

## Registration Flow

### Step 1: Get Registration Options

```bash
POST /auth/passkey/register/options/
Authorization: Bearer <access_token>

{}
```

Returns WebAuthn registration options (challenge, relying party info, user info, supported algorithms).

### Step 2: Create Credential

Client-side: pass the options to `navigator.credentials.create()` to trigger the browser's passkey UI.

### Step 3: Verify Registration

```bash
POST /auth/passkey/register/verify/
Authorization: Bearer <access_token>

{
  "credential": { ... }  // Response from navigator.credentials.create()
}
```

## Authentication Flow

### Step 1: Get Authentication Options

```bash
POST /auth/passkey/auth/options/

{
  "email": "user@example.com"
}
```

### Step 2: Sign Challenge

Client-side: pass the options to `navigator.credentials.get()`.

### Step 3: Verify Authentication

```bash
POST /auth/passkey/auth/verify/

{
  "credential": { ... }  // Response from navigator.credentials.get()
}
```

Returns JWT tokens on success.

## Credential Management

### List Credentials

```bash
GET /auth/passkey/credentials/
Authorization: Bearer <access_token>
```

### Delete a Credential

```bash
DELETE /auth/passkey/credentials/<credential-uuid>/
Authorization: Bearer <access_token>
```

## Storage Backend

BlockAuth provides two storage backends for passkey credentials:

- **DjangoStorage** (default) -- stores credentials in the database via Django ORM
- **MemoryStorage** -- in-memory storage for testing

Implement `ICredentialStore` for custom storage:

```python
from blockauth.passkey.storage.base import ICredentialStore, CredentialData

class MyCredentialStore(ICredentialStore):
    def save_credential(self, credential: CredentialData) -> None:
        ...

    def get_credential(self, credential_id: bytes) -> CredentialData | None:
        ...

    def get_credentials_for_user(self, user_id: str) -> list[CredentialData]:
        ...

    def delete_credential(self, credential_id: bytes) -> None:
        ...
```

## Data Stored Server-Side

| Data | Classification |
|------|---------------|
| Public keys | Personal data |
| Credential IDs | Personal data |
| Sign counters | Technical metadata |
| AAGUID | Device type identifier |
| Fingerprints, face scans | **Never stored** -- device only |
| Private keys | **Never stored** -- device only |

This implementation is GDPR compliant with low privacy risk. See the [Data Protection Impact Assessment](https://github.com/BloclabsHQ/auth-pack/blob/dev/docs/WEBAUTHN_PASSKEY_DPIA.md) for details.

## Cleanup

Stale challenges and expired credentials can be cleaned up with:

```bash
python manage.py blockauth_cleanup
```
