"""Apple Sign-In revocation client.

Posts to https://appleid.apple.com/auth/revoke with the user's refresh token.
Failures (non-200, network errors) are logged but do not raise — account
deletion in the calling system must complete even if Apple's endpoint is
temporarily unreachable. Apple does not redeliver missed revocations
automatically.
"""

import logging

import requests

from blockauth.apple._settings import apple_setting
from blockauth.apple.client_secret import apple_client_secret_builder
from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.exceptions import AppleClientSecretConfigError

logger = logging.getLogger(__name__)


class AppleRevocationClient:
    def revoke(self, refresh_token: str) -> None:
        try:
            client_secret = apple_client_secret_builder.build()
        except AppleClientSecretConfigError as exc:
            logger.error(
                "apple.revocation.config_missing",
                extra={"error_class": exc.__class__.__name__},
            )
            return

        try:
            response = requests.post(
                AppleEndpoints.REVOKE,
                data={
                    "client_id": apple_setting("APPLE_SERVICES_ID"),
                    "client_secret": client_secret,
                    "token": refresh_token,
                    "token_type_hint": "refresh_token",
                },
                timeout=10,
            )
        except requests.RequestException as exc:
            logger.error(
                "apple.revocation.network_error",
                extra={"error_class": exc.__class__.__name__},
            )
            return

        if response.status_code != 200:
            logger.error(
                "apple.revocation.failed",
                extra={"status_code": response.status_code},
            )
        else:
            logger.info("apple.revocation.requested")
