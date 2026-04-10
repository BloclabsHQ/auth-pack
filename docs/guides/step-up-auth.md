# Step-Up Authentication

The step-up authentication module (`blockauth.stepup`) implements RFC 9470-style receipt-based step-up auth. After a user completes an additional factor (e.g., TOTP), a short-lived signed receipt is issued. Other services validate this receipt before allowing sensitive operations.

This module is Django-independent -- it uses only PyJWT and the Python standard library.

## Concepts

- **Receipt**: A short-lived HS256 JWT proving the user completed a step-up challenge
- **Issuer**: The service that verifies the additional factor and creates the receipt
- **Validator**: The service that checks the receipt before allowing a sensitive operation
- **Scope**: Restricts the receipt to a class of operations (e.g., `mpc`, `withdrawal`)
- **Audience**: Prevents cross-service replay (`aud` claim)

## Issuing a Receipt

After the user passes TOTP (or any step-up factor):

```python
from blockauth.stepup import ReceiptIssuer

issuer = ReceiptIssuer(
    secret=RECEIPT_SHARED_SECRET,       # min 32 characters
    issuer="my-auth-service",
    default_audience="my-wallet-service",
    default_scope="mpc",
    default_ttl_seconds=120,            # 2 minutes
)

receipt_token = issuer.issue(subject=str(user.id))
# Return receipt_token in the API response
```

## Validating a Receipt

In the consuming service:

```python
from blockauth.stepup import ReceiptValidator, ReceiptValidationError

validator = ReceiptValidator(
    secret=RECEIPT_SHARED_SECRET,
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
    # e.reason -- human-readable message
    # e.code -- machine-readable code
    return 403, {"error": e.reason}
```

## Receipt JWT Claims

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

## Validation Checks

| Check | Error Code |
|-------|------------|
| HS256 signature valid | `receipt_signature_invalid` |
| Not expired (`exp > now`) | `receipt_expired` |
| `type == "stepup_receipt"` | `receipt_wrong_type` |
| `aud` matches expected | `receipt_audience_mismatch` |
| `scope` matches expected | `receipt_scope_mismatch` |
| `sub` matches authenticated user | `receipt_subject_mismatch` |

## Middleware Pattern

The receipt is typically passed as an HTTP header (`X-TOTP-Receipt`). Apply middleware to protected endpoints:

- **Header present**: must be valid or request is rejected (403)
- **Header absent**: pass through (for users who didn't do TOTP)
- **Enforce mode**: reject all requests without a valid receipt (opt-in for strict environments)

## API Reference

### `ReceiptIssuer(secret, *, issuer, default_audience, default_scope, default_ttl_seconds)`

Create an issuer. `secret` must be >= 32 characters.

- `issue(subject, *, audience=None, scope=None, ttl_seconds=None)` returns `str` (JWT)

### `ReceiptValidator(secret, *, expected_audience, expected_scope)`

Create a validator.

- `validate(token, *, expected_subject=None)` returns `ReceiptClaims`

### `ReceiptClaims` (frozen dataclass)

Fields: `subject`, `audience`, `scope`, `issued_at`, `expires_at`, `jti`, `issuer`

### `ReceiptValidationError`

Fields: `reason` (str, human-readable), `code` (str, machine-readable)
