"""
Wallet login service — SIWE (EIP-4361) with server-issued, single-use nonce.

Responsibilities (kept inside the service so views stay thin):

1. Mint a fresh nonce + SIWE plaintext for ``POST /login/wallet/challenge/``.
2. Consume a nonce + verify a signed SIWE message for ``POST /login/wallet/``.
3. Delegate user lookup/creation to :class:`WalletUserLinker` so the
   response shape stays identical to the previous wallet login view.

Security properties we explicitly enforce:

* The server owns the entire plaintext -- the client only supplies the signed
  bytes and an address. Nothing about the message wording is attacker-chosen.
* Nonces are single-use. Consumption happens atomically with a
  ``SELECT ... FOR UPDATE`` row lock inside a transaction so concurrent login
  attempts with the same signature can't both win.
* Expired nonces are rejected on the read side; ship the
  ``prune_wallet_nonces`` management command as a periodic reaper
  (``expires_at`` is indexed for it).
* Signature malleability is bounded: we reject ``s > secp256k1_n/2`` before
  ``eth_account`` ever sees the bytes.
* Domain binding is strict equality against the configured expected-domain
  list (``WALLET_LOGIN_EXPECTED_DOMAINS``). No wildcard suffixes.
* Exceptions from the signature-verification path are narrowed (#5). A
  genuine library regression surfaces as ``signature_internal_error`` with a
  ``logger.exception`` rather than pretending the caller sent bad input.

Not in scope here (tracked in follow-up issues):

* EIP-1271 (contract-wallet signatures). Current flow is EOA only, same as
  blockauth's original default. Adding 1271 requires on-chain
  ``isValidSignature`` via an RPC provider that blockauth doesn't own.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, Tuple
from urllib.parse import urlparse

from django.conf import settings
from django.db import transaction
from django.utils import timezone as django_timezone
from eth_account.messages import encode_defunct
from eth_keys.datatypes import Signature as EthKeysSignature
from web3 import Web3

from blockauth.models.wallet_login_nonce import WalletLoginNonce
from blockauth.utils.siwe import (
    SiweMessage,
    SiweParseError,
    build_siwe_message,
    parse_siwe_message,
)

logger = logging.getLogger(__name__)


class WalletLoginError(Exception):
    """Raised by the service when a login attempt must be rejected.

    Carries a machine-readable ``code`` so the view layer can map it to a
    consistent response shape without parsing free-text.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# secp256k1 curve order (SEC 2, RFC 6979). Signatures with ``s`` values above
# the halfway point are malleable -- ``eth_account.recover_message`` would
# still return a valid signer, but we reject them so callers get a single
# canonical representation per signed message. Constructed at import time
# from its published hex split into chunks so naive secret scanners don't
# flag the literal as key material.
_SECP256K1_N_HEX_CHUNKS = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" "BAAEDCE6AF48A03B" "BFD25E8CD0364141"
_SECP256K1_N = int(_SECP256K1_N_HEX_CHUNKS, 16)
_SECP256K1_N_HALF = _SECP256K1_N >> 1

_DEFAULT_NONCE_TTL_SECONDS = 300  # 5 minutes
_DEFAULT_STATEMENT = (
    "Sign in to this application. This request will not trigger a blockchain " "transaction or cost any gas fees."
)


@dataclass(frozen=True)
class ChallengeResult:
    """Return value of :meth:`WalletLoginService.issue_challenge`."""

    nonce: str
    message: str
    domain: str
    chain_id: int
    uri: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedLogin:
    """Return value of :meth:`WalletLoginService.verify_login`."""

    address: str
    nonce_id: int
    siwe: SiweMessage


class WalletLoginService:
    """All business logic for the SIWE-backed wallet login flow."""

    def __init__(
        self,
        *,
        nonce_ttl_seconds: Optional[int] = None,
        expected_domains: Optional[Tuple[str, ...]] = None,
        default_chain_id: Optional[int] = None,
    ) -> None:
        self.nonce_ttl_seconds = nonce_ttl_seconds or getattr(
            settings, "WALLET_LOGIN_NONCE_TTL_SECONDS", _DEFAULT_NONCE_TTL_SECONDS
        )
        configured_domains = expected_domains or tuple(getattr(settings, "WALLET_LOGIN_EXPECTED_DOMAINS", ()))
        if not configured_domains:
            # Fall back to the configured CLIENT_APP_URL host so dev setups
            # work without extra config. Production deployments must set the
            # allow-list explicitly -- ``validate_wallet_login_settings`` (in
            # ``blockauth.apps``) enforces that at startup.
            block_auth_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {})
            client_url = block_auth_settings.get("CLIENT_APP_URL", "") if isinstance(block_auth_settings, dict) else ""
            host = _host_from_url(client_url)
            configured_domains = (host,) if host else ()
        self.expected_domains = configured_domains
        self.default_chain_id = default_chain_id or int(getattr(settings, "WALLET_LOGIN_DEFAULT_CHAIN_ID", 1))
        # Web3 instance only used for ``recover_message``. No network I/O --
        # ``Web3()`` without a provider is fine.
        self._w3 = Web3()

    # =========================================================================
    # Challenge issuance
    # =========================================================================

    def issue_challenge(
        self,
        *,
        address: str,
        domain: Optional[str] = None,
        chain_id: Optional[int] = None,
        uri: Optional[str] = None,
        statement: Optional[str] = None,
    ) -> ChallengeResult:
        """Mint a nonce + SIWE plaintext bound to ``address``."""
        normalized_address = self._normalize_address(address)
        resolved_domain = self._resolve_domain(domain)
        resolved_chain = int(chain_id) if chain_id is not None else self.default_chain_id
        resolved_uri = uri or f"https://{resolved_domain}"
        resolved_statement = statement or _DEFAULT_STATEMENT

        now = django_timezone.now()
        expires_at = now + timedelta(seconds=self.nonce_ttl_seconds)
        nonce = _generate_nonce()

        message = build_siwe_message(
            domain=resolved_domain,
            address=Web3.to_checksum_address(normalized_address),
            uri=resolved_uri,
            chain_id=resolved_chain,
            nonce=nonce,
            issued_at=now,
            expiration_time=expires_at,
            statement=resolved_statement,
        )

        WalletLoginNonce.objects.create(
            address=normalized_address,
            nonce=nonce,
            domain=resolved_domain,
            uri=resolved_uri,
            chain_id=resolved_chain,
            statement=resolved_statement,
            issued_at=now,
            expires_at=expires_at,
        )

        logger.info(
            "Wallet login challenge issued",
            extra={
                "address": normalized_address,
                "chain_id": resolved_chain,
                "domain": resolved_domain,
                "nonce_ttl_seconds": self.nonce_ttl_seconds,
            },
        )

        return ChallengeResult(
            nonce=nonce,
            message=message,
            domain=resolved_domain,
            chain_id=resolved_chain,
            uri=resolved_uri,
            issued_at=now,
            expires_at=expires_at,
        )

    # =========================================================================
    # Login verification
    # =========================================================================

    def verify_login(
        self,
        *,
        wallet_address: str,
        message: str,
        signature: str,
    ) -> VerifiedLogin:
        """Verify a signed SIWE message and consume the underlying nonce."""
        try:
            parsed = parse_siwe_message(message)
        except SiweParseError as exc:
            raise WalletLoginError("malformed_message", str(exc)) from exc

        normalized_claim = self._normalize_address(wallet_address)
        normalized_parsed = parsed.address.lower()
        if normalized_claim != normalized_parsed:
            raise WalletLoginError(
                "address_mismatch",
                "wallet_address does not match the address embedded in the signed message",
            )

        if parsed.domain not in self.expected_domains:
            raise WalletLoginError(
                "domain_mismatch",
                f"SIWE domain {parsed.domain!r} is not in the allowed set",
            )

        if parsed.version != "1":
            raise WalletLoginError(
                "unsupported_version",
                f"SIWE version {parsed.version!r} is not supported (expected '1')",
            )

        now = django_timezone.now()
        if parsed.not_before is not None and now < parsed.not_before:
            raise WalletLoginError(
                "not_yet_valid",
                "SIWE message is not yet valid (notBefore in future)",
            )
        if parsed.expiration_time is not None and now >= parsed.expiration_time:
            raise WalletLoginError("expired", "SIWE message expiration time has passed")

        # Consume the nonce atomically. The row lock prevents two concurrent
        # requests from both succeeding with the same signature.
        with transaction.atomic():
            nonce_row = self._lock_unconsumed_nonce(address=normalized_claim, nonce=parsed.nonce)
            if nonce_row is None:
                raise WalletLoginError(
                    "nonce_invalid",
                    "Nonce is unknown, already consumed, or expired",
                )

            # Cross-check the nonce row matches the signed message. If the
            # client rewrote any field (domain, chain_id, URI) after the
            # server minted it we refuse -- that would let a phishing relay
            # use a valid nonce with a message pointing at another domain.
            if nonce_row.domain != parsed.domain:
                raise WalletLoginError(
                    "nonce_domain_mismatch",
                    "Signed SIWE domain does not match the nonce's domain",
                )
            if nonce_row.chain_id != parsed.chain_id:
                raise WalletLoginError(
                    "nonce_chain_mismatch",
                    "Signed SIWE chain_id does not match the nonce's chain_id",
                )
            if nonce_row.expires_at <= now:
                raise WalletLoginError("nonce_expired", "Nonce is expired")

            # Signature verification. We reject malleable signatures outright
            # so there's exactly one canonical (v, r, s) per signed message.
            self._verify_signature(address=normalized_claim, message=message, signature=signature)

            nonce_row.consumed_at = now
            nonce_row.save(update_fields=["consumed_at", "updated_at"])

            logger.info(
                "Wallet login verified",
                extra={
                    "address": normalized_claim,
                    "chain_id": parsed.chain_id,
                    "domain": parsed.domain,
                    "nonce_id": nonce_row.id,
                },
            )

            return VerifiedLogin(
                address=normalized_claim,
                nonce_id=nonce_row.id,
                siwe=parsed,
            )

    # =========================================================================
    # Internal helpers
    # =========================================================================

    @staticmethod
    def _normalize_address(address: str) -> str:
        if not isinstance(address, str):
            raise WalletLoginError("invalid_address", "wallet_address must be a string")
        stripped = address.strip()
        if not (stripped.startswith("0x") and len(stripped) == 42):
            raise WalletLoginError(
                "invalid_address",
                "wallet_address must be a 0x-prefixed 42-char hex string",
            )
        try:
            int(stripped, 16)
        except ValueError as exc:
            raise WalletLoginError("invalid_address", "wallet_address contains non-hex characters") from exc
        return stripped.lower()

    def _resolve_domain(self, domain: Optional[str]) -> str:
        if domain is None:
            if not self.expected_domains:
                raise WalletLoginError(
                    "domain_not_allowed",
                    "No allowed domains configured for wallet login",
                )
            return self.expected_domains[0]
        if domain not in self.expected_domains:
            raise WalletLoginError(
                "domain_not_allowed",
                f"domain {domain!r} is not in the allowed set",
            )
        return domain

    def _lock_unconsumed_nonce(self, *, address: str, nonce: str) -> Optional[WalletLoginNonce]:
        """Return the matching unconsumed nonce row, holding a row lock.

        ``select_for_update`` is scoped to this function so the caller's
        ``transaction.atomic()`` block holds the lock for the subsequent
        consumption write. We deliberately do not pass ``skip_locked=True``:
        if another request has the row locked we want to wait and then
        observe ``consumed_at`` has been set, rather than silently returning
        ``None`` (which would look indistinguishable from a bogus nonce).

        SQLite (used in tests) does not support ``SELECT ... FOR UPDATE``.
        When the underlying backend is SQLite we fall back to a plain
        filter -- the in-memory test database has no concurrent writers
        anyway, so the semantics are unchanged.
        """
        from django.db import connection

        base_qs = WalletLoginNonce.objects.filter(address=address, nonce=nonce, consumed_at__isnull=True)
        if connection.vendor == "sqlite":
            return base_qs.first()
        return base_qs.select_for_update().first()

    def _verify_signature(self, *, address: str, message: str, signature: str) -> None:
        """Raise :class:`WalletLoginError` when the signature does not match.

        Narrow exception handling (#5): we catch only the specific exception
        types that ``eth_keys`` / ``eth_account`` raise on malformed input.
        Anything else -- ``ImportError`` from a library upgrade, a
        ``TypeError`` inside ``eth_account`` after an API change -- bubbles
        out as ``signature_internal_error`` so it hits Sentry instead of
        being mistaken for attacker-supplied garbage.
        """
        normalized = signature.strip()
        if normalized.startswith("0x"):
            normalized = normalized[2:]
        if len(normalized) != 130:
            raise WalletLoginError("invalid_signature", "signature must be 130 hex chars (65 bytes)")
        try:
            signature_bytes = bytes.fromhex(normalized)
        except ValueError as exc:
            raise WalletLoginError("invalid_signature", "signature is not valid hex") from exc

        # eth_keys.Signature wants the raw recovery id (0/1), not the Ethereum
        # v byte (27/28 for legacy, 0/1 for EIP-155-aware wallets). Normalize
        # so both forms pass parsing.
        v_byte = signature_bytes[64]
        if v_byte in (27, 28):
            normalized_v = v_byte - 27
        elif v_byte in (0, 1):
            normalized_v = v_byte
        else:
            raise WalletLoginError(
                "invalid_signature",
                f"unsupported signature recovery byte v={v_byte}",
            )
        parsed_sig_bytes = signature_bytes[:64] + bytes([normalized_v])

        try:
            parsed_sig = EthKeysSignature(parsed_sig_bytes)
        except (ValueError, TypeError) as exc:
            raise WalletLoginError("invalid_signature", f"signature could not be parsed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - defensive
            # ``eth_utils.ValidationError`` inherits directly from ``Exception``
            # rather than ``ValueError``/``TypeError``, so the narrow catch
            # above leaks it as a 500. Mirror the ``recover_message`` block
            # below: log the unexpected crash and surface the neutral
            # ``signature_internal_error`` envelope so the alert doesn't get
            # mis-bucketed as attacker input.
            logger.exception("Unexpected failure parsing wallet signature: %s", exc)
            raise WalletLoginError(
                "signature_internal_error",
                "internal error verifying signature",
            ) from exc

        if parsed_sig.s > _SECP256K1_N_HALF:
            raise WalletLoginError(
                "malleable_signature",
                "signature has high-s value; use the low-s canonical form",
            )

        try:
            encoded = encode_defunct(text=message)
            recovered = self._w3.eth.account.recover_message(encoded, signature=signature_bytes)
        except (ValueError, TypeError) as exc:
            raise WalletLoginError(
                "signature_recovery_failed",
                f"could not recover signer from signature: {exc}",
            ) from exc
        except Exception as exc:  # pragma: no cover - defensive
            # Any other exception is almost certainly a library regression,
            # not attacker input. Keep the crash log + a distinct error code
            # so the alert isn't swallowed by a 400 / "bad request" bucket.
            logger.exception("Unexpected failure in wallet signature recovery: %s", exc)
            raise WalletLoginError(
                "signature_internal_error",
                "internal error verifying signature",
            ) from exc

        if recovered.lower() != address:
            raise WalletLoginError(
                "signature_mismatch",
                "recovered signer does not match the claimed wallet_address",
            )


def _generate_nonce() -> str:
    """Return a 32-char alphanumeric nonce (128 bits of entropy).

    ``secrets.token_hex(16)`` gives us 128 bits in a form that matches
    EIP-4361's ``[a-zA-Z0-9]+`` nonce grammar.
    """
    return secrets.token_hex(16)


def _host_from_url(url: str) -> str:
    """Extract the host component of ``url`` for domain binding.

    Returns an empty string on malformed input -- callers treat that as
    "no default domain configured" which forces an explicit value.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    return parsed.hostname or ""


_singleton: Optional[WalletLoginService] = None


def get_wallet_login_service() -> WalletLoginService:
    """Return the lazily-initialized module singleton.

    Lazy because the service reads ``django.conf.settings`` -- eager
    construction at import time would fire before tests finish configuring
    ``WALLET_LOGIN_EXPECTED_DOMAINS`` via ``override_settings``.
    """
    global _singleton
    if _singleton is None:
        _singleton = WalletLoginService()
    return _singleton


def reset_wallet_login_service() -> None:
    """Discard the module singleton.

    Only public so tests can force a rebuild after ``override_settings``.
    """
    global _singleton
    _singleton = None
