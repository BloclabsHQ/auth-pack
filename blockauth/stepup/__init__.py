"""
Step-Up Authentication Receipt Module.

Implements short-lived signed JWT receipts for step-up authentication (RFC 9470).
After a user completes an additional authentication factor (e.g., TOTP, biometric),
the issuing service creates a receipt. The consuming service validates the receipt
before allowing sensitive operations.

Industry references:
- RFC 9470 (Step-Up Authentication Challenge Protocol)
- PSD2/SCA (EU Strong Customer Authentication)
- Auth0 Step-Up Authentication
- Fireblocks Transaction Authorization Policy (TAP)
- AWS IAM MFA Session Tokens

Usage (issuer side — e.g., auth service):
    from blockauth.stepup import ReceiptIssuer

    issuer = ReceiptIssuer(
        secret="shared-secret-with-consumer",
        issuer="my-auth-service",
        default_audience="my-wallet-service",
        default_scope="mpc",
    )
    token = issuer.issue(subject="user-uuid")

Usage (consumer side — e.g., wallet service, any language):
    # Python:
    from blockauth.stepup import ReceiptValidator

    validator = ReceiptValidator(
        secret="shared-secret-with-issuer",
        expected_audience="my-wallet-service",
        expected_scope="mpc",
    )
    claims = validator.validate(token, expected_subject="user-uuid")

    # Go / other languages: standard HS256 JWT validation with claims check.
"""

from .receipt import ReceiptIssuer, ReceiptValidator, ReceiptClaims, ReceiptValidationError

__all__ = [
    "ReceiptIssuer",
    "ReceiptValidator",
    "ReceiptClaims",
    "ReceiptValidationError",
]
