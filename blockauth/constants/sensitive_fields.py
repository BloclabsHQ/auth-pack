"""
Sensitive fields constants for auth-pack

This module defines common constants for fields that should be redacted
in logs to prevent sensitive data exposure.
"""

# Fields that contain sensitive data and should be redacted in logs
SENSITIVE_FIELDS = {
    # Authentication related
    "password",
    "old_password",
    "new_password",
    "confirm_password",
    "current_password",
    "hashed_password",
    "token",
    "access",
    "refresh",
    "signature",
    "code",
    "otp",
    "verification_code",
    "auth_code",
    "authorization_code",
    # Cryptographic keys and secrets
    "private_key",
    "public_key",
    "secret_key",
    "api_key",
    "encryption_key",
    "master_key",
    "session_key",
    "wallet_key",
    "user_key",
    "derived_key",
    "key_material",
    # Personal information
    "ssn",
    "social_security_number",
    "credit_card",
    "card_number",
    "cvv",
    "cvc",
    "pin",
    "pincode",
    # Account related
    "account_number",
    "routing_number",
    "iban",
    "swift_code",
    # Blockchain related
    "seed_phrase",
    "mnemonic",
    "wallet_seed",
    "recovery_phrase",
    "private_key_hex",
    "wallet_private_key",
    "transaction_hash",
    "block_hash",
    # JWT and tokens
    "jwt",
    "jwt_token",
    "bearer_token",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "csrf_token",
    # Other sensitive data
    "salt",
    "nonce",
    "iv",
    "ciphertext",
    "encrypted_data",
    "hash",
    "checksum",
    "fingerprint",
    "biometric_data",
    # OAuth / OIDC / Apple Sign-In
    "client_secret",
    "code_verifier",
    "raw_nonce",
    "apple_private_key_pem",
    "payload",
}

# Additional patterns that might contain sensitive data
SENSITIVE_PATTERNS = [
    r".*password.*",
    r".*secret.*",
    r".*key.*",
    r".*token.*",
    r".*auth.*",
    r".*credential.*",
    r".*private.*",
    r".*sensitive.*",
]

# Keys that are matched by SENSITIVE_PATTERNS but are provably non-secret and
# must pass through unredacted. These are legitimate log fields used by callers
# (e.g. credential_id is a WebAuthn credential identifier in passkey/views.py;
# authentication_type / authentication_types are enum display values like
# "email" or "wallet"). None of these appear in SENSITIVE_FIELDS, so the
# allowlist only counteracts the broad regex net — exact-field redaction remains
# authoritative and is unaffected.
NON_SENSITIVE_KEYS = {
    "credential_id",
    "authentication_type",
    "authentication_types",
}

# Redaction string used for sensitive fields
REDACTION_STRING = "***REDACTED***"
