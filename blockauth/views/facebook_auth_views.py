import logging
import urllib.parse

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import facebook_auth_callback_schema, facebook_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
    social_user_info_missing,
)
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import clear_state_cookie, generate_state, set_state_cookie, verify_state
from blockauth.utils.social import SocialLoginResult, social_login_data
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.utils.auth_state import build_user_payload
from rest_framework import status as drf_status

logger = logging.getLogger(__name__)
_User = get_block_auth_user_model()


class FacebookAuthLoginView(APIView):
    """
    Redirects user to Facebook's OAuth 2.0 authorization endpoint.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

    @extend_schema(**facebook_auth_login_schema)
    def get(self, request):
        facebook_client_id = get_config("FACEBOOK_CLIENT_ID")
        callback_url = get_config("FACEBOOK_REDIRECT_URI")

        if not all([facebook_client_id, callback_url]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        state = generate_state()
        facebook_login_url = "https://www.facebook.com/v11.0/dialog/oauth?"
        params = {
            "client_id": facebook_client_id,
            "redirect_uri": callback_url,
            "scope": "email,public_profile",
            "response_type": "code",
            "state": state,
            "response_mode": "form_post",
        }
        url = facebook_login_url + urllib.parse.urlencode(params)
        blockauth_logger.info("Facebook login attempt", {"client_id": facebook_client_id, "redirect_uri": callback_url})
        response = redirect(url)
        set_state_cookie(response, state)
        return response


class FacebookAuthCallbackView(APIView):
    """
    Handles Facebook OAuth2 callback, exchanges the code for a Facebook token, and returns JWT tokens.

    Subclass and override :meth:`build_success_response` to ship tokens
    via HttpOnly cookies + a 302 to the shell origin (BFF, fabric-auth#533).
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

    def build_success_response(self, request, result: SocialLoginResult) -> Response:
        """Default: return the ``{access, refresh, user}`` JSON body.

        See :meth:`GoogleAuthCallbackView.build_success_response` for the
        integrator-override contract; same hook surface so fabric-auth
        can share one BFF mixin across Google / Facebook / LinkedIn.
        """
        response_serializer = AuthStateResponseSerializer(
            {
                "access": result.access_token,
                "refresh": result.refresh_token,
                "user": build_user_payload(result.user),
            }
        )
        return Response(data=response_serializer.data, status=drf_status.HTTP_200_OK)

    @extend_schema(**facebook_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        facebook_client_id = get_config("FACEBOOK_CLIENT_ID")
        facebook_client_secret = get_config("FACEBOOK_CLIENT_SECRET")
        callback_url = get_config("FACEBOOK_REDIRECT_URI")

        if not code:
            raise ValidationError(social_authorization_code.value)

        if not all([facebook_client_id, facebook_client_secret, callback_url]):
            raise ValidationError(social_invalid_auth_config.value)

        # CSRF protection — must run BEFORE the token exchange so a probe
        # cannot consume a real authorization code.
        verify_state(request)

        # Exchange authorization code for access token
        token_url = "https://graph.facebook.com/v11.0/oauth/access_token"
        token_data = {
            "code": code,
            "client_id": facebook_client_id,
            "client_secret": facebook_client_secret,
            "redirect_uri": callback_url,
        }
        token_response = requests.get(token_url, params=token_data)
        if token_response.status_code != 200:
            token_response_data = token_response.json()
            blockauth_logger.error(
                "Facebook login failed (token exchange)",
                {
                    "error": token_response_data.get("error", {}).get("message"),
                    "status_code": token_response.status_code,
                },
            )
            return Response(data={"detail": token_response_data["error"]["message"]}, status=token_response.status_code)

        token_json = token_response.json()
        access_token = token_json.get("access_token")

        # # Get user info using the access token
        user_info_url = "https://graph.facebook.com/me"
        user_info_params = {
            "fields": "id,name,email",
            "access_token": access_token,
        }
        user_info_response = requests.get(user_info_url, params=user_info_params)
        if user_info_response.status_code != 200:
            user_info_response_data = user_info_response.json()
            blockauth_logger.error(
                "Facebook login failed (user info)",
                {"error": user_info_response_data.get("message"), "status_code": user_info_response.status_code},
            )
            return Response(data={"detail": user_info_response_data["message"]}, status=user_info_response.status_code)

        # Find or create a user
        user_info = user_info_response.json()
        email, name = user_info.get("email"), user_info.get("name")
        if not email or not name:
            raise ValidationError(social_user_info_missing.value)

        try:
            provider_data = {"provider": "facebook", "user_info": user_info}
            blockauth_logger.success(
                "Facebook login successful", {"user_id": user_info.get("id"), "email": email, "name": name}
            )
            result = social_login_data(email=email, name=name, provider_data=provider_data)
            response = self.build_success_response(request, result)
            clear_state_cookie(response)
            return response
        except ValidationError as ve:
            blockauth_logger.error(
                "Facebook login validation error", {"error": str(ve), "data": sanitize_log_context(request.data)}
            )
            raise APIException()
        except Exception as e:
            blockauth_logger.error(
                "Facebook login unexpected error", {"error": str(e), "data": sanitize_log_context(request.data)}
            )
            raise APIException()
