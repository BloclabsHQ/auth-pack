# Models

## BlockUser

`blockauth.models.BlockUser` is the abstract base model for user accounts. Your user model must inherit from it.

```python
from blockauth.models import BlockUser

class User(BlockUser):
    # Add custom fields
    organization = models.ForeignKey('Organization', null=True, on_delete=models.SET_NULL)
    role = models.CharField(max_length=50, default='user')
```

BlockUser extends Django's `AbstractBaseUser` and provides fields required by BlockAuth's authentication flows (email, wallet address, verification status, etc.).

Set your model in settings:

```python
BLOCK_AUTH_SETTINGS = {
    'BLOCK_AUTH_USER_MODEL': 'myapp.User',
}
```

## OTP

`blockauth.models.OTP` stores one-time passwords for signup confirmation, passwordless login, password reset, and email change.

Key fields:

- `email` -- recipient email
- `otp` -- the code (generated with `secrets.choice()`)
- `subject` -- OTP purpose (`OTPSubject` enum: SIGNUP, LOGIN, PASSWORD_RESET, EMAIL_CHANGE)
- `created_at` -- timestamp for expiry calculation
- `is_used` -- prevents reuse

OTPs expire based on the `OTP_VALIDITY` setting (default: 1 minute).

## TOTP2FA

`blockauth.totp.models.TOTP2FA` stores encrypted TOTP secrets for two-factor authentication.

Key fields:

- `user` -- foreign key to user
- `encrypted_secret` -- TOTP secret (encrypted at rest)
- `is_active` -- whether 2FA is enabled
- `created_at` -- setup timestamp

## PasskeyCredential

`blockauth.passkey.models.Credential` stores WebAuthn credentials.

Key fields:

- `id` -- UUID primary key
- `user` -- foreign key to user
- `credential_id` -- WebAuthn credential identifier (binary)
- `public_key` -- credential public key (binary)
- `sign_count` -- signature counter (clone detection)
- `aaguid` -- authenticator attestation GUID
- `name` -- user-provided credential name
- `created_at` -- registration timestamp
- `last_used_at` -- last authentication timestamp

## Migrations

Run migrations after installing BlockAuth:

```bash
python manage.py migrate
```

BlockAuth's migrations create the OTP, TOTP2FA, and Credential tables. Your user model migration is managed by your app.
