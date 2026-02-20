"""
Step-Up Authentication Receipt — Issue and Validate.

A receipt is a short-lived HS256 JWT that proves a user completed an additional
authentication factor. The issuing service (e.g., auth) creates the receipt after
factor verification. The consuming service (e.g., wallet) validates it before
allowing sensitive operations.

Security properties:
- HS256 signature binds receipt to shared secret (not forgeable without key)
- ``type`` claim prevents confusion with session/access JWTs
- ``aud`` claim prevents cross-service replay
- ``scope`` claim restricts to specific operation classes
- ``sub`` must match the authenticated user (anti-IDOR)
- ``exp`` enforces short TTL (default 120s)
- ``jti`` provides unique identifier for audit logging

This module depends only on PyJWT (already a blockauth dependency) and the
Python stdlib. No Django dependency — usable in any Python service.
"""

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional

import jwt

logger = logging.getLogger(__name__)

# Receipt type constant — prevents confusion with access/refresh JWTs
RECEIPT_TYPE = "stepup_receipt"


class ReceiptValidationError(Exception):
    """Raised when a step-up receipt fails validation."""

    def __init__(self, reason: str, *, code: str = "invalid_receipt"):
        self.reason = reason
        self.code = code
        super().__init__(reason)


@dataclass(frozen=True)
class ReceiptClaims:
    """Decoded and validated receipt claims."""

    subject: str       # sub — user/consumer ID
    audience: str      # aud — intended consuming service
    scope: str         # scope — operation class (e.g., "mpc")
    issued_at: int     # iat — Unix timestamp
    expires_at: int    # exp — Unix timestamp
    jti: str           # jti — unique receipt ID
    issuer: Optional[str] = None  # iss — issuing service (optional)


class ReceiptIssuer:
    """
    Issues short-lived signed receipts after step-up authentication.

    Args:
        secret: HS256 signing key (shared with consuming service).
                Must be >= 32 bytes. Use ``secrets.token_hex(32)`` to generate.
        issuer: Optional ``iss`` claim (e.g., "fabric-auth").
        default_audience: Default ``aud`` claim (e.g., "fabric-wallet").
        default_scope: Default ``scope`` claim (e.g., "mpc").
        default_ttl_seconds: Default receipt lifetime. 120s recommended.
    """

    def __init__(
        self,
        secret: str,
        *,
        issuer: Optional[str] = None,
        default_audience: str = "fabric-wallet",
        default_scope: str = "mpc",
        default_ttl_seconds: int = 120,
    ):
        if not secret or len(secret) < 32:
            raise ValueError("Receipt secret must be at least 32 characters")
        self._secret = secret
        self._issuer = issuer
        self._default_audience = default_audience
        self._default_scope = default_scope
        self._default_ttl = default_ttl_seconds

    def issue(
        self,
        subject: str,
        *,
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """
        Issue a step-up receipt for the given subject.

        Args:
            subject: User or consumer ID (stored as ``sub``).
            audience: Override default audience.
            scope: Override default scope.
            ttl_seconds: Override default TTL.

        Returns:
            Signed JWT string.
        """
        now = int(time.time())
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        jti = secrets.token_hex(16)

        claims = {
            "sub": str(subject),
            "type": RECEIPT_TYPE,
            "aud": audience or self._default_audience,
            "scope": scope or self._default_scope,
            "iat": now,
            "exp": now + ttl,
            "jti": jti,
        }
        if self._issuer:
            claims["iss"] = self._issuer

        token = jwt.encode(claims, self._secret, algorithm="HS256")
        logger.info(
            "Step-up receipt issued",
            extra={"sub": subject, "aud": claims["aud"], "scope": claims["scope"], "jti": jti},
        )
        return token


class ReceiptValidator:
    """
    Validates step-up receipts on the consuming service side.

    Args:
        secret: HS256 signing key (shared with issuing service).
        expected_audience: Required ``aud`` value (e.g., "fabric-wallet").
        expected_scope: Required ``scope`` value (e.g., "mpc").
    """

    def __init__(
        self,
        secret: str,
        *,
        expected_audience: str = "fabric-wallet",
        expected_scope: str = "mpc",
    ):
        if not secret or len(secret) < 32:
            raise ValueError("Receipt secret must be at least 32 characters")
        self._secret = secret
        self._expected_audience = expected_audience
        self._expected_scope = expected_scope

    def validate(
        self,
        token: str,
        *,
        expected_subject: Optional[str] = None,
    ) -> ReceiptClaims:
        """
        Validate a step-up receipt token.

        Args:
            token: The JWT string from the ``X-TOTP-Receipt`` header.
            expected_subject: If provided, ``sub`` must match (anti-IDOR).

        Returns:
            ReceiptClaims on success.

        Raises:
            ReceiptValidationError on any validation failure.
        """
        # Decode and verify signature + expiry
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                audience=self._expected_audience,
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Receipt expired", extra={"aud": self._expected_audience})
            raise ReceiptValidationError("Receipt validation failed", code="receipt_expired")
        except jwt.InvalidAudienceError:
            logger.warning(
                "Receipt audience mismatch",
                extra={"expected_aud": self._expected_audience},
            )
            raise ReceiptValidationError("Receipt validation failed", code="receipt_audience_mismatch")
        except jwt.InvalidSignatureError:
            logger.warning("Receipt signature invalid")
            raise ReceiptValidationError("Receipt validation failed", code="receipt_signature_invalid")
        except jwt.DecodeError:
            logger.warning("Receipt malformed — could not decode JWT")
            raise ReceiptValidationError("Receipt validation failed", code="receipt_malformed")
        except jwt.InvalidTokenError:
            logger.warning("Receipt invalid — generic JWT error")
            raise ReceiptValidationError("Receipt validation failed", code="receipt_invalid")

        # Validate type claim
        receipt_type = payload.get("type")
        if receipt_type != RECEIPT_TYPE:
            logger.warning("Wrong receipt type", extra={"got": receipt_type, "expected": RECEIPT_TYPE})
            raise ReceiptValidationError("Receipt validation failed", code="receipt_wrong_type")

        # Validate scope claim
        receipt_scope = payload.get("scope")
        if receipt_scope != self._expected_scope:
            logger.warning(
                "Receipt scope mismatch",
                extra={"expected": self._expected_scope, "got": receipt_scope},
            )
            raise ReceiptValidationError("Receipt validation failed", code="receipt_scope_mismatch")

        # Validate subject (anti-IDOR)
        receipt_sub = payload.get("sub")
        if not receipt_sub:
            logger.warning("Receipt missing subject claim")
            raise ReceiptValidationError("Receipt validation failed", code="receipt_no_subject")
        if expected_subject and receipt_sub != str(expected_subject):
            logger.warning("Receipt subject mismatch (possible IDOR attempt)")
            raise ReceiptValidationError("Receipt validation failed", code="receipt_subject_mismatch")

        claims = ReceiptClaims(
            subject=receipt_sub,
            audience=payload.get("aud", ""),
            scope=receipt_scope,
            issued_at=payload.get("iat", 0),
            expires_at=payload.get("exp", 0),
            jti=payload.get("jti", ""),
            issuer=payload.get("iss"),
        )

        logger.info(
            "Step-up receipt validated",
            extra={"sub": claims.subject, "jti": claims.jti, "scope": claims.scope},
        )
        return claims
