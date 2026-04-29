# TOTP 2FA

BlockAuth includes a TOTP (Time-based One-Time Password) module for two-factor authentication. Compatible with Google Authenticator, Authy, and other TOTP apps.

## Architecture

The TOTP module uses a pluggable storage backend and encryption service:

- **TOTPService** -- generates secrets, creates QR codes, verifies codes
- **Storage** -- `ITOTP2FAStore` interface with Django and in-memory implementations
- **Encryption** -- secrets are encrypted at rest

## Setup Flow

### 1. Enable TOTP for a User

Generate a TOTP secret and provisioning URI:

```python
from blockauth.totp.services.totp_service import TOTPService

totp_service = TOTPService(storage=my_storage, encryption=my_encryption)

# Generate setup data (secret + QR code URI)
setup_data = totp_service.setup(user_id=str(user.id), issuer="MyApp")
# setup_data.provisioning_uri -- for QR code generation
# setup_data.secret -- backup codes (show once, then discard)
```

### 2. User Scans QR Code

Display the provisioning URI as a QR code in your frontend. The user scans it with their authenticator app.

### 3. Verify Setup

Have the user enter a code from their app to confirm setup:

```python
is_valid = totp_service.verify(user_id=str(user.id), code="123456")
```

## Verification

On login or sensitive operations, verify the TOTP code:

```python
is_valid = totp_service.verify(user_id=str(user.id), code="123456")
if not is_valid:
    raise AuthenticationError("Invalid 2FA code")
```

## Storage Backends

### Django Storage (production)

Uses Django ORM to store encrypted TOTP secrets:

```python
from blockauth.totp.storage.django_storage import DjangoTOTPStorage

storage = DjangoTOTPStorage()
```

### Memory Storage (testing)

```python
from blockauth.totp.storage.memory_storage import MemoryTOTPStorage

storage = MemoryTOTPStorage()
```

### Custom Storage

Implement `ITOTP2FAStore`:

```python
from blockauth.totp.storage.base import ITOTP2FAStore, TOTP2FAData

class MyTOTPStorage(ITOTP2FAStore):
    def save(self, data: TOTP2FAData) -> None:
        ...

    def get(self, user_id: str) -> TOTP2FAData | None:
        ...

    def delete(self, user_id: str) -> None:
        ...
```

## Encryption

TOTP secrets are encrypted before storage. Implement `ISecretEncryption` for custom encryption:

```python
from blockauth.totp.services.encryption import ISecretEncryption

class MyEncryption(ISecretEncryption):
    def encrypt(self, plaintext: str) -> str:
        ...

    def decrypt(self, ciphertext: str) -> str:
        ...
```

## Integration with Step-Up Auth

TOTP verification can issue a [step-up receipt](step-up-auth.md) for sensitive operations:

1. User verifies TOTP code
2. Auth service issues a short-lived receipt
3. Other services validate the receipt before allowing sensitive operations

See [Step-Up Auth](step-up-auth.md) for details.
