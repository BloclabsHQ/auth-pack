"""Apple client_secret builder.

Apple's token endpoint requires a `client_secret` that is itself a JWT signed
with an ES256 .p8 key the integrator downloads from the Apple developer
console. This module builds and caches that JWT.

The cache holds a single secret for the process lifetime, rebuilding when the
remaining lifetime drops below 5 minutes. A `threading.Lock` serializes the
rebuild so concurrent requests never produce two different in-flight secrets.

The module-level singleton `apple_client_secret_builder` is the canonical
instance to use from views/services so the cache survives across requests.
Per-instance caches don't help if every view instantiates its own builder —
import the singleton instead.
"""

import logging
import threading
import time
from pathlib import Path

import jwt as pyjwt

from blockauth.apple._settings import apple_setting
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
        if (
            self._cached_secret is not None
            and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS
        ):
            return self._cached_secret

        with self._lock:
            now = time.time()
            if (
                self._cached_secret is not None
                and (self._cached_secret_expires_at - now) > CLIENT_SECRET_REBUILD_MARGIN_SECONDS
            ):
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
                # alg is also set by the algorithm= kwarg above; explicit kid
                # is the only header field Apple requires beyond the default.
                headers={"kid": key_id},
            )
            self._cached_secret = secret
            self._cached_secret_expires_at = float(expires_at)
            logger.info("apple.client_secret.built", extra={"team_id_suffix": team_id[-4:]})
            return secret

    @staticmethod
    def _read_settings() -> tuple[str, str, str, str]:
        team_id = apple_setting("APPLE_TEAM_ID")
        key_id = apple_setting("APPLE_KEY_ID")
        services_id = apple_setting("APPLE_SERVICES_ID")
        private_pem = apple_setting("APPLE_PRIVATE_KEY_PEM")
        if not private_pem:
            path = apple_setting("APPLE_PRIVATE_KEY_PATH")
            if path:
                try:
                    private_pem = Path(path).read_text(encoding="utf-8")
                except FileNotFoundError as exc:
                    logger.warning(
                        "apple.client_secret.config_missing",
                        extra={"reason": "private_key_path_not_found", "path_suffix": str(path)[-12:]},
                    )
                    raise AppleClientSecretConfigError(
                        f"APPLE_PRIVATE_KEY_PATH is set but file does not exist: {path}"
                    ) from exc
        if not all([team_id, key_id, services_id, private_pem]):
            logger.warning(
                "apple.client_secret.config_missing",
                extra={
                    "reason": "required_setting_absent",
                    "missing": [
                        name
                        for name, value in [
                            ("APPLE_TEAM_ID", team_id),
                            ("APPLE_KEY_ID", key_id),
                            ("APPLE_SERVICES_ID", services_id),
                            ("APPLE_PRIVATE_KEY_PEM_or_PATH", private_pem),
                        ]
                        if not value
                    ],
                },
            )
            raise AppleClientSecretConfigError(
                "APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_SERVICES_ID, and "
                "APPLE_PRIVATE_KEY_PEM (or APPLE_PRIVATE_KEY_PATH) must all be set"
            )
        return team_id, key_id, private_pem, services_id


# Module-level singleton — import this from views/services so the
# in-process cache survives across requests instead of re-signing on
# every call.
apple_client_secret_builder = AppleClientSecretBuilder()
