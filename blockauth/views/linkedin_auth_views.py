import logging
import urllib.parse

import requests
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.docs.social_auth_docs import linkedin_auth_callback_schema, linkedin_auth_login_schema
from blockauth.schemas.examples.social_auth import (
    social_authorization_code,
    social_invalid_auth_config,
    social_user_info_missing,
)
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import sanitize_log_context
from blockauth.utils.logger import blockauth_logger
from blockauth.utils.oauth_state import clear_state_cookie, generate_state, set_state_cookie, verify_state
from blockauth.utils.social import social_login

logger = logging.getLogger(__name__)
_User = get_block_auth_user_model()


class LinkedInAuthLoginView(APIView):
    """
    Redirects user to Linkedins's OAuth 2.0 authorization endpoint.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

    @extend_schema(**linkedin_auth_login_schema)
    def get(self, request):
        linkedin_client_id = get_config("LINKEDIN_CLIENT_ID")
        callback_url = get_config("LINKEDIN_REDIRECT_URI")

        if not all([linkedin_client_id, callback_url]):
            raise ValidationError({"detail": "Auth provider settings for linkedin is not properly configured"}, 4020)

        state = generate_state()
        params = {
            "response_type": "code",
            "client_id": linkedin_client_id,
            "redirect_uri": callback_url,
            "scope": "profile email openid",
            "state": state,
        }
        linkein_auth_url = "https://www.linkedin.com/oauth/v2/authorization?" + urllib.parse.urlencode(params)
        blockauth_logger.info("LinkedIn login attempt", sanitize_log_context(request.GET))
        response = redirect(linkein_auth_url)
        set_state_cookie(response, state)
        return response


class LinkedInAuthCallbackView(APIView):
    """
    Handles LinkedIn OAuth2 callback, exchanges the code for a LinkedIn token, and returns JWT tokens.
    """

    permission_classes = (AllowAny,)
    authentication_classes = []

    @extend_schema(**linkedin_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get("code")
        linkedin_client_id = get_config("LINKEDIN_CLIENT_ID")
        linkedin_client_secret = get_config("LINKEDIN_CLIENT_SECRET")
        callback_url = get_config("LINKEDIN_REDIRECT_URI")

        if not code:
            raise ValidationError(social_authorization_code.value, 4020)

        if not all([linkedin_client_id, linkedin_client_secret, callback_url]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        # CSRF protection — must run BEFORE the token exchange so a probe
        # cannot consume a real authorization code.
        verify_state(request)

        # Exchange authorization code for access token
        token_url = "https://www.linkedin.com/oauth/v2/accessToken"
        token_data = {
            "code": code,
            "client_id": linkedin_client_id,
            "client_secret": linkedin_client_secret,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
        }
        token_response = requests.post(token_url, data=token_data)
        if token_response.status_code != 200:
            token_response_data = token_response.json()
            blockauth_logger.error(
                "LinkedIn login failed (token exchange)",
                {"error": token_response_data.get("error"), "status_code": token_response.status_code},
            )
            return Response(data={"detail": token_response_data["error"]}, status=token_response.status_code)

        token_json = token_response.json()
        access_token = token_json.get("access_token")

        # # Get user info using the access token
        user_info_url = "https://api.linkedin.com/v2/userinfo"
        user_info_response = requests.get(user_info_url, headers={"Authorization": f"Bearer {access_token}"})
        if user_info_response.status_code != 200:
            user_info_response_data = user_info_response.json()
            blockauth_logger.error(
                "LinkedIn login failed (user info)",
                {"error": user_info_response_data.get("message"), "status_code": user_info_response.status_code},
            )
            return Response(data={"detail": user_info_response_data["message"]}, status=user_info_response.status_code)

        # Find or create a user
        user_info = user_info_response.json()
        email, name = user_info.get("email"), user_info.get("name")
        if not email or not name:
            raise ValidationError(social_user_info_missing.value, 4020)

        try:
            provider_data = {"provider": "linkedin", "user_info": user_info}
            blockauth_logger.success("LinkedIn login successful", {"email": email, "name": name})
            response = social_login(email=email, name=name, provider_data=provider_data)
            clear_state_cookie(response)
            return response
        except ValidationError as ve:
            blockauth_logger.error(
                "LinkedIn login validation error", {"error": str(ve), "data": sanitize_log_context(request.data)}
            )
            raise APIException()
        except Exception as e:
            blockauth_logger.error(
                "LinkedIn login unexpected error", {"error": str(e), "data": sanitize_log_context(request.data)}
            )
            raise APIException()
