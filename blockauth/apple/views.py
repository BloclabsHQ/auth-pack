"""Apple Sign-In views.

`AppleWebAuthorizeView` builds the 302 redirect with PKCE + nonce. The state,
raw nonce, and PKCE verifier are stored in HttpOnly cookies for the callback
to read. SameSite=None+Secure is required because Apple's `form_post` callback
is a cross-site POST.

`AppleWebCallbackView` handles the `form_post` POST. It verifies state,
exchanges code for tokens with the cached client_secret, verifies the id_token
including nonce, then upserts a SocialIdentity and issues blockauth JWTs.

`AppleNativeVerifyView` (added in Phase 9) and the S2S webhook
(`AppleServerToServerNotificationView`, Phase 11) live in this same module.

Note: local-http development cannot exercise the form_post callback because
SameSite=None requires Secure (TLS); use a tunnel (ngrok/cloudflared) or
deploy to a TLS-fronted environment to test the callback path.
"""

import json
import logging
from urllib.parse import urlencode

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.apple._settings import apple_setting
from blockauth.apple.client_secret import apple_client_secret_builder
from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.exceptions import (
    AppleClientSecretConfigError,
    AppleIdTokenVerificationFailed,
    AppleNonceMismatch,
    AppleNotificationVerificationFailed,
    AppleTokenExchangeFailed,
)
from blockauth.apple.id_token_verifier import AppleIdTokenVerifier
from blockauth.apple.nonce import (
    clear_nonce_cookie,
    generate_raw_nonce,
    hash_raw_nonce,
    read_nonce_cookie,
    set_nonce_cookie,
)
from blockauth.apple.notification_service import AppleNotificationService
from blockauth.apple.serializers import (
    AppleNativeVerifyRequestSerializer,
    AppleServerToServerNotificationRequestSerializer,
)
from blockauth.apple.throttles import (
    AppleNativeVerifyThrottle,
    AppleNotificationThrottle,
    AppleWebCallbackThrottle,
)
from blockauth.docs.apple_docs import (
    apple_authorize_schema,
    apple_callback_schema,
    apple_native_verify_schema,
    apple_notifications_schema,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer

# SocialIdentityConflictError extends APIException with status_code=409 and
# is allowed to propagate naturally from the views below — see callsite
# comments. The import is kept so the symbol resolves for type-checking
# and so a future change that catches it explicitly doesn't have to re-add
# the import.
from blockauth.social.exceptions import (  # noqa: F401
    SocialIdentityConflictError,
)
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    OAUTH_STATE_COOKIE_NAME,
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state_values,
)
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)


def _client_id_from_audience(audience) -> str:
    if isinstance(audience, (list, tuple)):
        return str(audience[0]) if audience else ""
    return str(audience or "")


def _samesite_for_callback() -> str:
    return str(apple_setting("APPLE_CALLBACK_COOKIE_SAMESITE") or "None")


def _build_auth_state_response(result) -> Response:
    """Build the standard success response shape for any Apple flow."""
    serializer = AuthStateResponseSerializer(
        {
            "access": result.access_token,
            "refresh": result.refresh_token,
            "user": build_user_payload(result.user),
        }
    )
    return Response(data=serializer.data, status=drf_status.HTTP_200_OK)


class AppleWebAuthorizeView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**apple_authorize_schema)
    def get(self, request):
        services_id = apple_setting("APPLE_SERVICES_ID")
        redirect_uri = apple_setting("APPLE_REDIRECT_URI")
        if not services_id or not redirect_uri:
            raise ValidationError({"detail": "Apple Sign-In is not configured"}, 4020)

        state = generate_state()
        raw_nonce = generate_raw_nonce()
        pair = generate_pkce_pair()

        params = {
            "response_type": "code",
            "response_mode": "form_post",
            "client_id": services_id,
            "redirect_uri": redirect_uri,
            "scope": "name email",
            "state": state,
            "nonce": hash_raw_nonce(raw_nonce),
            "code_challenge": pair.challenge,
            "code_challenge_method": "S256",
        }
        url = f"{AppleEndpoints.AUTHORIZE}?{urlencode(params)}"

        blockauth_logger.info(
            "apple.web.authorize_started",
            {"client_id_suffix": services_id[-6:]},
        )

        response = redirect(url)
        samesite = _samesite_for_callback()
        set_state_cookie(response, state, samesite=samesite)
        set_pkce_verifier_cookie(response, pair.verifier, samesite=samesite)
        set_nonce_cookie(response, raw_nonce, samesite=samesite)
        return response


class AppleWebCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()
    throttle_classes = [AppleWebCallbackThrottle]

    def handle_exception(self, exc):
        # Any error path must clear the state/PKCE/nonce cookies; otherwise
        # a retry could replay stale credentials. DRF builds the error
        # response in `super().handle_exception(...)`, so we mutate it
        # before returning.
        response = super().handle_exception(exc)
        samesite = _samesite_for_callback()
        clear_state_cookie(response, samesite=samesite)
        clear_pkce_verifier_cookie(response, samesite=samesite)
        clear_nonce_cookie(response, samesite=samesite)
        return response

    @extend_schema(**apple_callback_schema)
    def post(self, request):
        code = request.data.get("code")
        form_state = request.data.get("state")
        if not code:
            raise ValidationError({"detail": "Missing authorization code"}, 4054)

        cookie_state = request.COOKIES.get(OAUTH_STATE_COOKIE_NAME)
        verify_state_values(cookie_state, form_state)

        pkce_verifier = read_pkce_verifier_cookie(request)
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        raw_nonce = read_nonce_cookie(request)
        if not raw_nonce:
            raise ValidationError({"detail": "Apple nonce cookie missing"}, 4055)

        try:
            client_secret = apple_client_secret_builder.build()
        except AppleClientSecretConfigError as exc:
            raise ValidationError({"detail": "Apple Sign-In is not configured"}, 4020) from exc

        try:
            token_response = requests.post(
                AppleEndpoints.TOKEN,
                data={
                    "client_id": apple_setting("APPLE_SERVICES_ID"),
                    "client_secret": client_secret,
                    "code": code,
                    "code_verifier": pkce_verifier,
                    "grant_type": "authorization_code",
                    "redirect_uri": apple_setting("APPLE_REDIRECT_URI"),
                },
                timeout=10,
            )
        except requests.exceptions.RequestException as exc:
            blockauth_logger.warning(
                "apple.web.token_endpoint_unreachable",
                {"error_type": type(exc).__name__},
            )
            raise ValidationError({"detail": "Apple token endpoint unreachable"}, 4053) from exc

        if token_response.status_code != 200:
            blockauth_logger.error(
                "apple.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            # Preserve the original AppleTokenExchangeFailed in the cause
            # chain so log/sentry breadcrumbs still see the structured
            # exception type, but raise as ValidationError so DRF maps
            # it to HTTP 400 with our error code.
            inner = AppleTokenExchangeFailed(token_response.status_code)
            raise ValidationError({"detail": "Apple token exchange failed"}, 4053) from inner

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        refresh_token = token_payload.get("refresh_token")
        if not id_token:
            raise ValidationError({"detail": "Apple did not return id_token"}, 4054)

        expected_nonce = hash_raw_nonce(raw_nonce)
        try:
            claims = AppleIdTokenVerifier().verify(id_token, expected_nonce=expected_nonce)
        except AppleNonceMismatch as exc:
            blockauth_logger.warning(
                "apple.web.id_token_nonce_mismatch",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Apple id_token nonce mismatch"}, 4055) from exc
        except AppleIdTokenVerificationFailed as exc:
            blockauth_logger.error(
                "apple.web.id_token_verify_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Apple id_token verification failed"}, 4054) from exc

        # SocialIdentityConflictError extends APIException with
        # status_code=409 + default_code="SOCIAL_IDENTITY_CONFLICT"; let it
        # propagate so the HTTP-semantic Conflict (409) reaches the client
        # rather than being demoted to 400 by an extra ValidationError wrap.
        # Apple identities never auto-link by email per AccountLinkingPolicy.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="apple",
            subject=claims.sub,
            email=claims.email,
            email_verified=claims.email_verified,
            extra_claims={"is_private_email": claims.is_private_email},
            refresh_token=refresh_token,
        )

        result = social_login_data(
            email=claims.email or "",
            name="",
            provider_data={"provider": "apple", "user_info": claims.raw, "preexisting_user": user},
        )

        response = _build_auth_state_response(result)
        samesite = _samesite_for_callback()
        clear_state_cookie(response, samesite=samesite)
        clear_pkce_verifier_cookie(response, samesite=samesite)
        clear_nonce_cookie(response, samesite=samesite)
        return response


class AppleNativeVerifyView(APIView):
    """Native (mobile / Web One Tap) id_token verification.

    Receives a platform-issued id_token from a mobile / web client that
    invoked Apple's native auth UI. The client passes the raw nonce that
    was used to seed the request — we hash it server-side and compare
    against the id_token's nonce claim (when nonce_supported=True).

    Optional authorization_code: if the client also obtains the auth code
    (Apple supplies one alongside the id_token), the server redeems it
    here for a refresh token and stores it AES-GCM-encrypted on the
    SocialIdentity. This is the only path through which the integrator
    can later revoke the user's Apple session.
    """

    permission_classes = (AllowAny,)
    authentication_classes = ()
    throttle_classes = [AppleNativeVerifyThrottle]

    @extend_schema(**apple_native_verify_schema)
    def post(self, request):
        serializer = AppleNativeVerifyRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        expected_nonce = hash_raw_nonce(validated["raw_nonce"])
        try:
            claims = AppleIdTokenVerifier().verify(validated["id_token"], expected_nonce=expected_nonce)
        except AppleNonceMismatch as exc:
            blockauth_logger.warning(
                "apple.native.id_token_nonce_mismatch",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Apple id_token nonce mismatch"}, 4055) from exc
        except AppleIdTokenVerificationFailed as exc:
            blockauth_logger.error(
                "apple.native.id_token_verify_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Apple id_token verification failed"}, 4054) from exc

        refresh_token: str | None = None
        authorization_code = validated.get("authorization_code")
        if authorization_code:
            try:
                client_id = _client_id_from_audience(claims.raw.get("aud")) or apple_setting("APPLE_SERVICES_ID")
                client_secret = apple_client_secret_builder.build(client_id=client_id)
            except AppleClientSecretConfigError as exc:
                raise ValidationError({"detail": "Apple Sign-In is not configured"}, 4020) from exc

            # Apple's native auth flow has no redirect_uri. Apple requires
            # client_secret.sub to match the client_id used to generate tokens,
            # so redeem against the id_token audience (App ID / bundle ID for
            # native, Services ID for web-style clients).
            try:
                token_response = requests.post(
                    AppleEndpoints.TOKEN,
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "code": authorization_code,
                        "grant_type": "authorization_code",
                    },
                    timeout=10,
                )
            except requests.exceptions.RequestException as exc:
                # Code redemption is a best-effort enrichment, not a
                # verification gate. Swallow transport errors with a
                # warning log and continue without a refresh token —
                # the id_token-verified user/identity link is still valid.
                blockauth_logger.warning(
                    "apple.native.code_redemption_unreachable",
                    {"error_class": exc.__class__.__name__},
                )
            else:
                if token_response.status_code == 200:
                    refresh_token = token_response.json().get("refresh_token")
                else:
                    blockauth_logger.warning(
                        "apple.native.code_redemption_failed",
                        {"status_code": token_response.status_code},
                    )

        # SocialIdentityConflictError (status_code=409) is allowed to propagate
        # natively to DRF — Apple's policy never auto-links by email, so a
        # collision with an existing user is a true conflict (RFC 7231 §6.5.8),
        # not a bad request. Wrapping it as ValidationError (400) would lose
        # that semantic and make the conflict indistinguishable from a generic
        # validation failure for clients.
        #
        # `first_name` / `last_name` come from Apple's first-sign-in payload —
        # Apple sends the user object exactly once, on the very first consent.
        # Forwarding them via extra_user_fields persists the name on the
        # initial create_user call so we don't lose it. SocialIdentityService
        # filters these against the user model's schema; integrators whose
        # user model lacks first_name / last_name simply ignore the values.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="apple",
            subject=claims.sub,
            email=claims.email,
            email_verified=claims.email_verified,
            extra_claims={"is_private_email": claims.is_private_email},
            refresh_token=refresh_token,
            extra_user_fields={
                "first_name": validated.get("first_name") or "",
                "last_name": validated.get("last_name") or "",
            },
        )

        result = social_login_data(
            email=claims.email or "",
            name=" ".join(filter(None, [validated.get("first_name") or "", validated.get("last_name") or ""])).strip(),
            provider_data={"provider": "apple", "user_info": claims.raw, "preexisting_user": user},
        )
        return _build_auth_state_response(result)


class AppleServerToServerNotificationView(APIView):
    """POST /apple/notifications/ — Apple's server-to-server webhook.

    Apple sends {"payload": "<JWT>"} for events like consent-revoked,
    account-deleted, email-disabled, email-enabled. We verify the JWT
    inside AppleNotificationService.dispatch and let it apply state
    changes; duplicate fresh notifications are idempotently suppressed. On any
    verification or parse failure, we return 400 with code 4056 so Apple's retry
    logic gets a meaningful signal.
    """

    permission_classes = (AllowAny,)
    authentication_classes = ()
    throttle_classes = [AppleNotificationThrottle]

    @extend_schema(**apple_notifications_schema)
    def post(self, request):
        serializer = AppleServerToServerNotificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            AppleNotificationService().dispatch(serializer.validated_data["payload"])
        except (
            AppleIdTokenVerificationFailed,
            AppleNotificationVerificationFailed,
            json.JSONDecodeError,
            TypeError,
            KeyError,
            ValueError,
        ) as exc:
            blockauth_logger.error(
                "apple.notification.verification_failed",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Invalid Apple notification payload"}, 4056)
        return Response(status=drf_status.HTTP_200_OK)
