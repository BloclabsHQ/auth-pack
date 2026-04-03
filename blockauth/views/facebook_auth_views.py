import logging
import urllib.parse

import requests
from django.shortcuts import redirect
from django.utils import timezone
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
from blockauth.utils.social import social_login

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

        facebook_login_url = "https://www.facebook.com/v11.0/dialog/oauth?"
        params = {
            "client_id": facebook_client_id,
            "redirect_uri": callback_url,
            "scope": "email,public_profile",
            "response_type": "code",
            "state": f"blockauth#{timezone.now().timestamp()}",
            "response_mode": "form_post",
        }
        url = facebook_login_url + urllib.parse.urlencode(params)
        blockauth_logger.info("Facebook login attempt", {"client_id": facebook_client_id, "redirect_uri": callback_url})
        return redirect(url)


class FacebookAuthCallbackView(APIView):
    """
    Handles Facebook OAuth2 callback, exchanges the code for a Facebook token, and returns JWT tokens.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

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
            return social_login(email=email, name=name, provider_data=provider_data)
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
