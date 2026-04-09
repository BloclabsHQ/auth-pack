"""
Web3 Wallet Authentication Utilities

This module provides utilities for Ethereum wallet signature verification
with replay attack protection via nonce tracking and timestamp validation.

Dependencies:
    - web3: Ethereum Web3 library for blockchain interactions
    - eth_account: Ethereum account utilities for signature verification
"""

import hmac
import json
import logging
import time

from django.core.cache import cache as default_cache
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

from blockauth.utils.config import get_config

logger = logging.getLogger(__name__)

# Default: signed messages are valid for 5 minutes
DEFAULT_MESSAGE_TTL_SECONDS = 300

# Nonce cache prefix and retention (keep nonces for 2x TTL to cover clock skew)
_NONCE_CACHE_PREFIX = "wallet_nonce_"
_NONCE_RETENTION_FACTOR = 2


class WalletAuthenticator:
    """
    Ethereum Wallet Signature Authenticator with replay protection.

    Signature verification now requires a structured JSON message containing:
      - ``nonce``: a unique, single-use value (UUIDv4 recommended)
      - ``timestamp``: Unix epoch seconds when the message was created
      - ``body``: the human-readable sign-in text shown to the user

    A previously-used nonce is rejected. Messages older than
    ``WALLET_MESSAGE_TTL`` seconds (default 300) are rejected.

    Example (client-side message construction)::

        {
          "body": "Sign in to MyApp",
          "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
          "timestamp": 1712345678
        }
    """

    def __init__(self, cache=None):
        self.w3 = Web3()
        self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        self._cache = cache or default_cache

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify_signature(self, address: str, message: str, signature: str) -> bool:
        """
        Verify signature **and** enforce replay protection.

        The ``message`` parameter must be a JSON string with ``nonce`` and
        ``timestamp`` keys.  Plain-text messages are rejected.

        Args:
            address: Ethereum wallet address (0x...)
            message: JSON-encoded message with nonce + timestamp
            signature: Hex-encoded signature (with or without 0x prefix)

        Returns:
            True when the signature is valid, the nonce is fresh, and the
            timestamp is within the allowed TTL window.

        Raises:
            ValueError: For any validation failure (replay, expired, bad format).
        """
        # --- 1. Parse & validate the structured message -----------------
        nonce, timestamp = self._parse_message(message)
        self._validate_timestamp(timestamp)
        self._validate_nonce(nonce, address)

        # --- 2. Cryptographic signature check ---------------------------
        signature_bytes = self._decode_signature(signature)
        message_encoded = encode_defunct(text=message)
        recovered_address = self.w3.eth.account.recover_message(message_encoded, signature=signature_bytes)

        if not hmac.compare_digest(recovered_address.lower(), address.lower()):
            return False

        # --- 3. Mark nonce as consumed (only after sig is valid) --------
        self._consume_nonce(nonce, address)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_signature(signature: str) -> bytes:
        if signature.startswith("0x"):
            signature = signature[2:]
        signature = signature.strip().lower()
        if len(signature) != 130:
            raise ValueError("Invalid signature length")
        try:
            return bytes.fromhex(signature)
        except ValueError:
            raise ValueError("Invalid hex in signature")

    @staticmethod
    def _parse_message(message: str):
        """Return (nonce, timestamp) from a JSON message string."""
        try:
            parsed = json.loads(message)
        except (json.JSONDecodeError, TypeError):
            raise ValueError("Wallet message must be JSON with 'nonce' and 'timestamp' fields.")

        nonce = parsed.get("nonce")
        timestamp = parsed.get("timestamp")

        if not nonce or not isinstance(nonce, str) or len(nonce) < 16:
            raise ValueError("Message must contain a 'nonce' string (min 16 chars).")
        if timestamp is None:
            raise ValueError("Message must contain a 'timestamp' field.")
        try:
            timestamp = int(timestamp)
        except (TypeError, ValueError):
            raise ValueError("Timestamp must be a numeric Unix epoch value.")

        return nonce, timestamp

    def _validate_timestamp(self, timestamp: int) -> None:
        ttl = self._get_ttl()
        now = int(time.time())
        age = now - timestamp
        if age < 0:
            raise ValueError("Message timestamp is in the future.")
        if age > ttl:
            raise ValueError("Message has expired. Please sign a new message.")

    def _validate_nonce(self, nonce: str, address: str) -> None:
        """Reject a nonce that has already been consumed."""
        cache_key = self._nonce_key(nonce, address)
        if self._cache.get(cache_key):
            raise ValueError("Nonce has already been used. Please sign a new message.")

    def _consume_nonce(self, nonce: str, address: str) -> None:
        """Mark a nonce as consumed so it cannot be replayed."""
        ttl = self._get_ttl() * _NONCE_RETENTION_FACTOR
        cache_key = self._nonce_key(nonce, address)
        self._cache.set(cache_key, True, ttl)

    @staticmethod
    def _nonce_key(nonce: str, address: str) -> str:
        return f"{_NONCE_CACHE_PREFIX}{address.lower()}_{nonce}"

    @staticmethod
    def _get_ttl() -> int:
        try:
            return int(get_config("WALLET_MESSAGE_TTL"))
        except Exception:
            return DEFAULT_MESSAGE_TTL_SECONDS
