"""Apple-flow specific errors. Each subclass maps to one error code in the spec."""


class AppleAuthError(Exception):
    """Base for Apple auth failures."""


class AppleStateMismatch(AppleAuthError):
    """OAuth state cookie did not match the form-post state."""


class ApplePKCEMissing(AppleAuthError):
    """PKCE verifier cookie was absent on callback."""


class AppleTokenExchangeFailed(AppleAuthError):
    """Apple's /auth/token endpoint returned non-200.

    Intentionally does NOT carry the response body: Apple error payloads can
    echo `client_secret` or `code` depending on the failure mode, and a
    future log/sentry breadcrumb capturing `exc.body` would leak those
    secrets. The status_code is sufficient for diagnosis.
    """

    def __init__(self, status_code: int):
        super().__init__(f"Apple token exchange failed: HTTP {status_code}")
        self.status_code = status_code


class AppleIdTokenVerificationFailed(AppleAuthError):
    """The id_token returned by Apple failed signature/iss/aud/exp checks."""


class AppleNonceMismatch(AppleAuthError):
    """Apple id_token's `nonce` claim did not match the expected hash."""


class AppleNotificationVerificationFailed(AppleAuthError):
    """Server-to-server notification's inner JWT failed verification."""


class AppleClientSecretConfigError(AppleAuthError):
    """Required Apple settings missing for client_secret JWT construction."""
