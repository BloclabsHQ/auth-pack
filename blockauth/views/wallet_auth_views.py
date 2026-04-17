"""Wallet authentication views.

Includes:

* :class:`WalletChallengeView` — ``POST /login/wallet/challenge/``, mints a
  server-issued EIP-4361 SIWE challenge. Clients sign the returned
  ``message`` verbatim with the wallet's private key.
* :class:`WalletAuthLoginView` — ``POST /login/wallet/``, consumes the
  nonce, verifies the signature, and issues JWTs. Response shape is
  ``{"access", "refresh", "user"}`` (issue #97 — parity with basic-login).
* :class:`WalletEmailAddView` / :class:`WalletLinkView` — unchanged from
  pre-SIWE behavior.

Background: issue #90 (upstream port of fabric-auth #401 / #402).
"""

import logging
from typing import Union

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.wallet_auth_docs import wallet_email_add_docs
from blockauth.enums import AuthenticationType
from blockauth.models.otp import OTPSubject
from blockauth.notification import send_otp
from blockauth.serializers.wallet_auth_serializers import (
    WalletChallengeRequestSerializer,
    WalletChallengeResponseSerializer,
    WalletLoginRequestSerializer,
    WalletLoginResponseSerializer,
)
from blockauth.serializers.wallet_serializers import (
    WalletEmailAddSerializer,
    WalletLinkSerializer,
)
from blockauth.services.wallet_login_service import (
    WalletLoginError,
    get_wallet_login_service,
)
from blockauth.services.wallet_user_linker import (
    WalletUserLinkError,
    wallet_user_linker,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.utils.auth_state import build_user_payload, issue_auth_tokens
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.custom_exception import ValidationErrorWithCode, WalletConflictError
from blockauth.utils.generics import model_to_json, sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.rate_limiter import (
    EnhancedThrottle,
    WalletChallengeThrottle,
    WalletLoginThrottle,
)

logger = logging.getLogger(__name__)
_User = get_block_auth_user_model()


# Error codes surfaced to clients. Each failure mode has a distinct code so
# client devs can distinguish "bad nonce" from "bad signature" without
# grepping error text.
_AUTH_ERROR_STATUS_MAP = {
    "invalid_address": status.HTTP_400_BAD_REQUEST,
    "malformed_message": status.HTTP_400_BAD_REQUEST,
    "address_mismatch": status.HTTP_400_BAD_REQUEST,
    "unsupported_version": status.HTTP_400_BAD_REQUEST,
    "domain_mismatch": status.HTTP_401_UNAUTHORIZED,
    "domain_not_allowed": status.HTTP_400_BAD_REQUEST,
    "not_yet_valid": status.HTTP_401_UNAUTHORIZED,
    "expired": status.HTTP_401_UNAUTHORIZED,
    "nonce_invalid": status.HTTP_401_UNAUTHORIZED,
    "nonce_domain_mismatch": status.HTTP_401_UNAUTHORIZED,
    "nonce_chain_mismatch": status.HTTP_401_UNAUTHORIZED,
    "nonce_expired": status.HTTP_401_UNAUTHORIZED,
    "malleable_signature": status.HTTP_400_BAD_REQUEST,
    "invalid_signature": status.HTTP_400_BAD_REQUEST,
    "signature_recovery_failed": status.HTTP_400_BAD_REQUEST,
    "signature_mismatch": status.HTTP_401_UNAUTHORIZED,
    # #5: a library regression in signature recovery is NOT a 400.
    "signature_internal_error": status.HTTP_500_INTERNAL_SERVER_ERROR,
    # #4: default wallet-not-registered surfaces as a generic 401 so the
    # endpoint doesn't work as a registration oracle. A deployment that
    # explicitly opts into the 403 via WALLET_LOGIN_EXPOSE_REGISTRATION_STATUS
    # still gets the distinct code.
    "login_failed": status.HTTP_401_UNAUTHORIZED,
    "auto_create_disabled": status.HTTP_403_FORBIDDEN,
}


def _reject(error: Union[WalletLoginError, WalletUserLinkError]) -> Response:
    """Shape a service-layer error into an HTTP response."""
    http_status = _AUTH_ERROR_STATUS_MAP.get(error.code, status.HTTP_400_BAD_REQUEST)
    return Response(
        {"error": {"code": error.code, "message": error.message}},
        status=http_status,
    )


class WalletChallengeView(APIView):
    """``POST /login/wallet/challenge/`` — mint a SIWE plaintext for signing.

    Public endpoint: the caller is by definition not yet authenticated.
    Throttle scope is separate from ``/login/wallet/`` so one endpoint's
    rate-limit bucket can't starve the other.
    """

    permission_classes = (AllowAny,)
    authentication_classes: list = []
    throttle_classes = [WalletChallengeThrottle]

    @extend_schema(
        operation_id="wallet-login-challenge",
        summary="Wallet login — issue SIWE challenge",
        description=(
            "Returns an EIP-4361 plaintext that the caller must sign with "
            "the private key controlling the supplied address. The server "
            "records the embedded nonce so it can reject replays on the "
            "subsequent `/login/wallet/` call. TTL defaults to 5 minutes; "
            "the nonce is single-use."
        ),
        request=WalletChallengeRequestSerializer,
        responses={200: WalletChallengeResponseSerializer},
        tags=["Wallet"],
    )
    def post(self, request):
        serializer = WalletChallengeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        service = get_wallet_login_service()
        try:
            result = service.issue_challenge(
                address=serializer.validated_data["address"],
                chain_id=serializer.validated_data.get("chain_id"),
                domain=serializer.validated_data.get("domain"),
                uri=serializer.validated_data.get("uri"),
            )
        except WalletLoginError as exc:
            blockauth_logger.info(
                "Wallet challenge rejected",
                sanitize_log_context({"error_code": exc.code}),
            )
            return _reject(exc)

        response_serializer = WalletChallengeResponseSerializer(
            {
                "message": result.message,
                "nonce": result.nonce,
                "domain": result.domain,
                "chain_id": result.chain_id,
                "uri": result.uri,
                "issued_at": result.issued_at,
                "expires_at": result.expires_at,
            }
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class WalletAuthLoginView(APIView):
    """``POST /login/wallet/`` — SIWE-backed wallet authentication.

    Flow:

    1. Parse the signed SIWE plaintext and validate every mandatory EIP-4361
       field (domain, URI, chain_id, nonce, issuedAt, expirationTime).
    2. Look up and atomically consume the matching server-issued nonce row.
    3. Verify the signature (with low-s malleability bound).
    4. Delegate user lookup/creation + token issuance to the linker service.

    The response shape is ``{"access", "refresh", "user"}`` -- the ``user``
    payload includes ``id``, ``email``, ``is_verified``, and
    ``wallet_address`` so clients can hydrate in one round-trip (issue #97).
    """

    permission_classes = (AllowAny,)
    authentication_classes: list = []
    throttle_classes = [WalletLoginThrottle]

    @extend_schema(
        operation_id="wallet-login",
        summary="Wallet login — verify signed SIWE challenge",
        description=(
            "Consumes a nonce issued by `/login/wallet/challenge/` and a "
            "valid EIP-4361 signature to authenticate the wallet holder. "
            "Returns `{access, refresh, user}` -- the `user` object "
            "includes `id`, `email`, `is_verified`, and `wallet_address` "
            "so clients can hydrate without a second round-trip. Nonces "
            "are single-use and expire after the configured TTL (default "
            "5 minutes)."
        ),
        request=WalletLoginRequestSerializer,
        responses={200: WalletLoginResponseSerializer},
        tags=["Wallet"],
    )
    def post(self, request):
        serializer = WalletLoginRequestSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as exc:
            raise ValidationErrorWithCode(detail=exc.detail)

        service = get_wallet_login_service()
        try:
            verified = service.verify_login(
                wallet_address=serializer.validated_data["wallet_address"],
                message=serializer.validated_data["message"],
                signature=serializer.validated_data["signature"],
            )
        except WalletLoginError as exc:
            blockauth_logger.warning(
                "Wallet login rejected",
                sanitize_log_context({"error_code": exc.code}),
            )
            return _reject(exc)

        try:
            linked = wallet_user_linker.link(wallet_address=verified.address)
        except WalletUserLinkError as exc:
            blockauth_logger.warning(
                "Wallet login link rejected",
                sanitize_log_context({"error_code": exc.code}),
            )
            return _reject(exc)

        blockauth_logger.success(
            "Wallet login successful",
            sanitize_log_context({"user": linked.user_id, "created": linked.created}),
        )

        user = linked.user
        response_serializer = WalletLoginResponseSerializer(
            {
                "access": linked.access_token,
                "refresh": linked.refresh_token,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_verified": user.is_verified,
                    "wallet_address": user.wallet_address,
                    "first_name": getattr(user, "first_name", None),
                    "last_name": getattr(user, "last_name", None),
                },
            }
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class WalletEmailAddView(APIView):
    """
    API endpoint for wallet users to add an email address and automatically send verification.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = WalletEmailAddSerializer

    @extend_schema(**wallet_email_add_docs)
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        blockauth_logger.info("Wallet email add attempt", sanitize_log_context(request.data))

        try:
            serializer.is_valid(raise_exception=True)
            data = serializer.validated_data

            # Update user's email
            user = request.user
            user.email = data["email"]
            user.is_verified = False  # Reset verification status
            user.save()

            # Automatically send verification
            otp_data = {"identifier": data["email"], "method": "email", "verification_type": data["verification_type"]}
            send_otp(otp_data, OTPSubject.WALLET_EMAIL_VERIFICATION)

            # api-optimization #110: issue fresh tokens + user so any
            # custom-claims provider that pins email into the access token
            # sees the newly-added address. is_verified flips to False here
            # — the new tokens correctly carry the unverified state.
            access_token, refresh_token = issue_auth_tokens(user)
            blockauth_logger.success(
                "Wallet email added and verification sent", sanitize_log_context(request.data, {"user": user.id})
            )
            auth_state = AuthStateResponseSerializer(
                {
                    "access": access_token,
                    "refresh": refresh_token,
                    "user": build_user_payload(user),
                }
            ).data
            return Response(
                {
                    "message": f'Email added successfully. {data["verification_type"]} sent via email.',
                    **auth_state,
                },
                status=status.HTTP_200_OK,
            )

        except ValidationError as e:
            blockauth_logger.warning(
                "Wallet email add validation failed", sanitize_log_context(request.data, {"errors": e.detail})
            )
            raise ValidationErrorWithCode(detail=e.detail)
        except Exception as e:
            blockauth_logger.error("Wallet email add failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet email add request failed: {e}", exc_info=True)
            raise APIException()


class WalletLinkView(APIView):
    """
    API endpoint for authenticated users to link a MetaMask (or compatible) wallet.

    The user must already hold a valid JWT. They sign a structured JSON message
    with their wallet and submit address + message + signature. Full replay
    protection (nonce + timestamp) is enforced by WalletAuthenticator.
    """

    permission_classes = (IsAuthenticated,)
    serializer_class = WalletLinkSerializer
    link_throttle = EnhancedThrottle(rate=(10, 60), max_failures=5, cooldown_minutes=15)

    def post(self, request):
        if not self.link_throttle.allow_request(request, "wallet_link"):
            reason = self.link_throttle.get_block_reason()
            msg = (
                "Too many failed attempts. Please try again later."
                if reason == "cooldown"
                else "Rate limit exceeded. Please try again later."
            )
            return Response(data={"detail": msg}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        serializer = self.serializer_class(data=request.data, context={"request": request})
        blockauth_logger.info("Wallet link attempt", sanitize_log_context(request.data))

        try:
            serializer.is_valid(raise_exception=True)

            user = request.user
            wallet_address = serializer.validated_data["wallet_address"]

            user.wallet_address = wallet_address
            user.add_authentication_type(AuthenticationType.WALLET)
            user.save()

            user_data = model_to_json(user, remove_fields=("password",))
            post_wallet_link_trigger = get_config("POST_WALLET_LINK_TRIGGER")()
            post_wallet_link_trigger.trigger(context={"user": user_data, "wallet_address": wallet_address})

            # api-optimization #110: issue fresh tokens + user so any
            # custom-claims provider that pins wallet_address into the
            # access token sees the newly-linked address. Token issuance
            # re-reads the user from the DB (see
            # blockauth.jwt.token_manager.JWTTokenManager.generate_token)
            # so the trigger fan-out above can't race the claims read.
            access_token, refresh_token = issue_auth_tokens(user)
            self.link_throttle.record_success(request, "wallet_link")
            blockauth_logger.success(
                "Wallet linked successfully",
                sanitize_log_context(request.data, {"user": user.id}),
            )
            auth_state = AuthStateResponseSerializer(
                {
                    "access": access_token,
                    "refresh": refresh_token,
                    "user": build_user_payload(user),
                }
            ).data
            return Response(
                data={
                    "message": "Wallet linked successfully.",
                    "wallet_address": wallet_address,
                    **auth_state,
                },
                status=status.HTTP_200_OK,
            )

        except WalletConflictError:
            self.link_throttle.record_failure(request, "wallet_link")
            raise

        except ValidationError as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.warning(
                "Wallet link validation failed",
                sanitize_log_context(request.data, {"errors": e.detail}),
            )
            raise ValidationErrorWithCode(detail=e.detail)

        except Exception as e:
            self.link_throttle.record_failure(request, "wallet_link")
            blockauth_logger.error("Wallet link failed", sanitize_log_context(request.data, {"error": str(e)}))
            logger.error(f"Wallet link request failed: {e}", exc_info=True)
            raise APIException()
