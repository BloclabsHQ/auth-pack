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
"""

import logging
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.apple.client_secret import apple_client_secret_builder
from blockauth.apple.constants import AppleEndpoints
from blockauth.apple.docs import apple_authorize_schema, apple_callback_schema
from blockauth.apple.exceptions import (
    AppleClientSecretConfigError,
    AppleIdTokenVerificationFailed,
    AppleNonceMismatch,
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
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.exceptions import SocialIdentityConflictError
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


def _apple_setting(key: str, default=None):
    """Read an Apple-specific value directly from `BLOCK_AUTH_SETTINGS`.

    The other Apple modules (client_secret, id_token_verifier) read settings
    this way so `override_settings(BLOCK_AUTH_SETTINGS=...)` in tests
    propagates without depending on the conf-module's `auth_settings`
    snapshot, which is captured at import time and only re-syncs the
    user-settings overlay (not the defaults dict). Keeping the access
    pattern uniform across the sub-package makes the test fixtures
    mirror what production sees.
    """
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    return block_settings.get(key, default)


def _samesite_for_callback() -> str:
    return str(_apple_setting("APPLE_CALLBACK_COOKIE_SAMESITE") or "None")


class AppleWebAuthorizeView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**apple_authorize_schema)
    def get(self, request):
        services_id = _apple_setting("APPLE_SERVICES_ID")
        redirect_uri = _apple_setting("APPLE_REDIRECT_URI")
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

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

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
            raise ValidationError({"detail": str(exc)}, 4020)

        token_response = requests.post(
            AppleEndpoints.TOKEN,
            data={
                "client_id": _apple_setting("APPLE_SERVICES_ID"),
                "client_secret": client_secret,
                "code": code,
                "code_verifier": pkce_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": _apple_setting("APPLE_REDIRECT_URI"),
            },
            timeout=10,
        )
        if token_response.status_code != 200:
            blockauth_logger.error(
                "apple.web.token_exchange_failed",
                {"status_code": token_response.status_code},
            )
            raise AppleTokenExchangeFailed(token_response.status_code, token_response.text)

        token_payload = token_response.json()
        id_token = token_payload.get("id_token")
        refresh_token = token_payload.get("refresh_token")
        if not id_token:
            raise ValidationError({"detail": "Apple did not return id_token"}, 4054)

        expected_nonce = hash_raw_nonce(raw_nonce)
        try:
            claims = AppleIdTokenVerifier().verify(id_token, expected_nonce=expected_nonce)
        except AppleNonceMismatch as exc:
            raise ValidationError({"detail": str(exc)}, 4055)
        except AppleIdTokenVerificationFailed as exc:
            raise ValidationError({"detail": str(exc)}, 4054)

        try:
            user, _, _ = SocialIdentityService().upsert_and_link(
                provider="apple",
                subject=claims.sub,
                email=claims.email,
                email_verified=claims.email_verified,
                extra_claims={"is_private_email": claims.is_private_email},
                refresh_token=refresh_token,
            )
        except SocialIdentityConflictError as exc:
            raise ValidationError({"detail": "Email already linked to another account"}, 4090) from exc

        result = social_login_data(
            email=claims.email or "",
            name="",
            provider_data={"provider": "apple", "user_info": claims.raw, "preexisting_user": user},
        )

        response = self.build_success_response(request, result)
        samesite = _samesite_for_callback()
        clear_state_cookie(response, samesite=samesite)
        clear_pkce_verifier_cookie(response, samesite=samesite)
        clear_nonce_cookie(response, samesite=samesite)
        return response
