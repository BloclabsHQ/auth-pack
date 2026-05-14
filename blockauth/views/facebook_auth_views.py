"""Facebook OAuth web flow.

Facebook is NOT OIDC. The flow uses standard OAuth 2.0 + PKCE (S256). After
the code-for-token exchange we call Graph `/me?fields=id,name,email` to get
the user info — Facebook does not issue id_tokens on the standard login flow.

User matching: `(facebook, user_info["id"])` via SocialIdentityService.
Email is treated as verified when present (Facebook only returns the email
field for users who have verified it).
"""

import logging
import urllib.parse

import requests
from django.conf import settings
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework import status as drf_status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import facebook_auth_callback_schema, facebook_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
    social_user_info_missing,
)
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.social.service import SocialIdentityService
from blockauth.utils.auth_state import build_user_payload
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import (
    clear_pkce_verifier_cookie,
    clear_state_cookie,
    generate_state,
    read_pkce_verifier_cookie,
    set_pkce_verifier_cookie,
    set_state_cookie,
    verify_state,
)
from blockauth.utils.outbound_http import get_social_outbound_timeout
from blockauth.utils.pkce import generate_pkce_pair
from blockauth.utils.social import social_login_data

logger = logging.getLogger(__name__)

FACEBOOK_AUTHORIZE_URL = "https://www.facebook.com/v18.0/dialog/oauth"
FACEBOOK_TOKEN_URL = "https://graph.facebook.com/v18.0/oauth/access_token"
FACEBOOK_USERINFO_URL = "https://graph.facebook.com/me"


def _provider_setting(key, default=None):
    block_settings = getattr(settings, "BLOCK_AUTH_SETTINGS", {}) or {}
    providers = block_settings.get("AUTH_PROVIDERS", {}) or {}
    nested = providers.get("FACEBOOK", {}) or {}
    if key in nested:
        return nested[key]
    return block_settings.get(f"FACEBOOK_{key}", default)


class FacebookAuthLoginView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    @extend_schema(**facebook_auth_login_schema)
    def get(self, request):
        client_id = _provider_setting("CLIENT_ID")
        redirect_uri = _provider_setting("REDIRECT_URI")
        if not client_id or not redirect_uri:
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        pair = generate_pkce_pair()

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "email,public_profile",
            "response_type": "code",
            "state": state,
            "code_challenge": pair.challenge,
            "code_challenge_method": "S256",
        }
        url = f"{FACEBOOK_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

        blockauth_logger.info("facebook.web.authorize_started", {"client_id_suffix": client_id[-6:]})

        response = redirect(url)
        set_state_cookie(response, state, provider="facebook")
        set_pkce_verifier_cookie(response, pair.verifier, provider="facebook")
        return response


def clear_facebook_callback_cookies(response, samesite: str | None = None) -> None:
    """Clear every cookie the Facebook web auth flow sets.

    `FacebookAuthLoginView` sets two cookies before the redirect — the
    OAuth state token and the PKCE verifier. Facebook is not OIDC and
    does not set a nonce cookie. The callback consumes and clears them
    on success; on any error response a retry must not replay stale
    values.

    Subclasses that override `handle_exception` to swap the response
    shape (e.g. HttpOnly cookies + 302 redirect instead of DRF's default
    JSON body) can call this helper instead of re-implementing the
    state/PKCE clear. Mirrors `clear_apple_callback_cookies` (v0.16.5)
    and the sibling Google / LinkedIn helpers.
    """
    clear_state_cookie(response, provider="facebook", samesite=samesite)
    clear_pkce_verifier_cookie(response, provider="facebook", samesite=samesite)


class FacebookAuthCallbackView(APIView):
    permission_classes = (AllowAny,)
    authentication_classes = ()

    def handle_exception(self, exc):
        # Any error path must clear the state/PKCE cookies so a retry
        # can't replay stale credentials. The clear list is owned by
        # `clear_facebook_callback_cookies` so subclasses that swap
        # the response shape can re-use the same single source of
        # truth.
        response = super().handle_exception(exc)
        clear_facebook_callback_cookies(response)
        return response

    def build_success_response(self, request, result) -> Response:
        serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**facebook_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            raise ValidationError(social_authorization_code.value)

        client_id = _provider_setting("CLIENT_ID")
        client_secret = _provider_setting("CLIENT_SECRET")
        redirect_uri = _provider_setting("REDIRECT_URI")
        if not all([client_id, client_secret, redirect_uri]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        verify_state(request, provider="facebook")

        pkce_verifier = read_pkce_verifier_cookie(request, provider="facebook")
        if not pkce_verifier:
            raise ValidationError({"detail": "PKCE verifier missing"}, 4051)

        try:
            token_response = requests.get(
                FACEBOOK_TOKEN_URL,
                params={
                    "code": code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "redirect_uri": redirect_uri,
                    "code_verifier": pkce_verifier,
                },
                timeout=get_social_outbound_timeout(),
            )
        except requests.exceptions.RequestException as exc:
            blockauth_logger.warning(
                "facebook.web.token_endpoint_unreachable",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Facebook token endpoint unreachable"}, 4080) from exc

        if token_response.status_code != 200:
            blockauth_logger.error("facebook.web.token_exchange_failed", {"status_code": token_response.status_code})
            raise ValidationError({"detail": "Token exchange failed"}, 4080)

        access_token = token_response.json().get("access_token")
        try:
            userinfo_response = requests.get(
                FACEBOOK_USERINFO_URL,
                params={
                    # `first_name` / `last_name` ride alongside `name` so we can
                    # populate the user model's name fields directly on signup
                    # (the full `name` is kept as a fallback for callers that
                    # still display the full string). All three are part of the
                    # `public_profile` permission so no additional scope is
                    # required.
                    "fields": "id,name,first_name,last_name,email",
                    "access_token": access_token,
                },
                timeout=get_social_outbound_timeout(),
            )
        except requests.exceptions.RequestException as exc:
            blockauth_logger.warning(
                "facebook.web.userinfo_endpoint_unreachable",
                {"error_class": exc.__class__.__name__},
            )
            raise ValidationError({"detail": "Facebook Graph API unreachable"}, 4080) from exc

        if userinfo_response.status_code != 200:
            blockauth_logger.error(
                "facebook.web.userinfo_failed",
                {"status_code": userinfo_response.status_code},
            )
            raise ValidationError({"detail": "Facebook Graph API rejected request"}, 4080)

        user_info = userinfo_response.json()
        fb_user_id = user_info.get("id")
        email = user_info.get("email")
        name = user_info.get("name")
        if not fb_user_id or not name:
            raise ValidationError(social_user_info_missing.value, 4080)

        email_verified = bool(email)  # Facebook only returns email when verified

        # SocialIdentityConflictError extends APIException with status_code=409;
        # let it propagate (Phase 9 cross-flow consistency).
        #
        # `extra_user_fields` seeds the user model on first-OAuth signup so
        # the Creator (or any custom AUTH_USER_MODEL with name fields) lands
        # with the user's name from Facebook rather than NULL. Facebook's
        # Graph API ships `first_name` / `last_name` under the
        # `public_profile` permission (no additional scope needed); absent
        # values fall back to empty strings. SocialIdentityService filters
        # these against the user model's schema.
        user, _, _ = SocialIdentityService().upsert_and_link(
            provider="facebook",
            subject=str(fb_user_id),
            email=email,
            email_verified=email_verified,
            extra_claims={},
            extra_user_fields={
                "first_name": user_info.get("first_name") or "",
                "last_name": user_info.get("last_name") or "",
            },
        )

        result = social_login_data(
            email=email or "",
            name=name,
            provider_data={"provider": "facebook", "user_info": user_info, "preexisting_user": user},
        )
        response = self.build_success_response(request, result)
        clear_facebook_callback_cookies(response)
        return response
