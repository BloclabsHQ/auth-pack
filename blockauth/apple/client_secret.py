"""Apple client_secret builder.

Apple's token endpoint requires a `client_secret` that is itself a JWT signed
with an ES256 .p8 key the integrator downloads from the Apple developer
console. This module builds and caches that JWT.

The cache holds a single secret for the process lifetime, rebuilding when the
remaining lifetime drops below 5 minutes. A `threading.Lock` serializes the
rebuild so concurrent requests never produce two different in-flight secrets.
"""

import logging
import threading
import time
from pathlib import Path

import jwt as pyjwt
from django.conf import settings

from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.exceptions import AppleClientSecretConfigError

logger = logging.getLogger(__name__)

CLIENT_SECRET_LIFETIME_SECONDS = 5 * 60 * 60  # 5 hours, well within Apple's 6-month max
CLIENT_SECRET_REBUILD_MARGIN_SECONDS = 5 * 60  # rebuild when < 5 min remain


class AppleClientSecretBuilder:
    def __init__(self):
        self._lock = threading.Lock()
        self._cached_secret: str | None = None
        self._cached_secret_expires_at: float = 0.0

    def build(self) -> str:
        now = time.time()
        if self._cached_secret is not None and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS:
            return self._cached_secret

        with self._lock:
            now = time.time()
            if self._cached_secret is not None and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS:
                return self._cached_secret

            team_id, key_id, private_pem, services_id = self._read_settings()
            issued_at = int(now)
            expires_at = issued_at + CLIENT_SECRET_LIFETIME_SECONDS
            secret = pyjwt.encode(
                {
                    "iss": team_id,
                    "iat": issued_at,
                    "exp": expires_at,
                    "aud": AppleEndpoints.AUDIENCE,
                    "sub": services_id,
                },
                private_pem,
                algorithm="ES256",
                headers={"kid": key_id, "alg": "ES256"},
            )
            self._cached_secret = secret
            self._cached_secret_expires_at = float(expires_at)
            logger.info("apple.client_secret.built", extra={"team_id_suffix": team_id[-4:]})
            return secret

    @staticmethod
    def _read_settings() -> tuple[str, str, str, str]:
        block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
        team_id = block_settings.get("APPLE_TEAM_ID")
        key_id = block_settings.get("APPLE_KEY_ID")
        services_id = block_settings.get("APPLE_SERVICES_ID")
        private_pem = block_settings.get("APPLE_PRIVATE_KEY_PEM")
        if not private_pem:
            path = block_settings.get("APPLE_PRIVATE_KEY_PATH")
            if path:
                private_pem = Path(path).read_text()
        if not all([team_id, key_id, services_id, private_pem]):
            raise AppleClientSecretConfigError(
                "APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_SERVICES_ID, and APPLE_PRIVATE_KEY_PEM (or APPLE_PRIVATE_KEY_PATH) must all be set"
            )
        return team_id, key_id, private_pem, services_id
