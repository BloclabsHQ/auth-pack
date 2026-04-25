"""Apple-flow specific errors. Each subclass maps to one error code in the spec."""


class AppleAuthError(Exception):
    """Base for Apple auth failures."""


class AppleStateMismatch(AppleAuthError):
    """OAuth state cookie did not match the form-post state."""


class ApplePKCEMissing(AppleAuthError):
    """PKCE verifier cookie was absent on callback."""


class AppleTokenExchangeFailed(AppleAuthError):
    """Apple's /auth/token endpoint returned non-200."""

    def __init__(self, status_code: int, body: str):
        super().__init__(f"Apple token exchange failed: HTTP {status_code}")
        self.status_code = status_code
        self.body = body


class AppleIdTokenVerificationFailed(AppleAuthError):
    """The id_token returned by Apple failed signature/iss/aud/exp checks."""


class AppleNonceMismatch(AppleAuthError):
    """Apple id_token's `nonce` claim did not match the expected hash."""


class AppleNotificationVerificationFailed(AppleAuthError):
    """Server-to-server notification's inner JWT failed verification."""


class AppleClientSecretConfigError(AppleAuthError):
    """Required Apple settings missing for client_secret JWT construction."""
