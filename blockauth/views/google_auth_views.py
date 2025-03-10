import logging
import requests
from django.contrib.auth import get_user_model
from django.shortcuts import redirect
from drf_spectacular.utils import extend_schema
from rest_framework.exceptions import ValidationError, APIException
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.schemas.examples.social_auth import social_invalid_auth_config, social_authorization_code, social_user_info_missing
from blockauth.schemas.social_auth import google_auth_login_schema, google_auth_callback_schema
from blockauth.utils.config import get_config
from blockauth.utils.social import social_login

logger = logging.getLogger(__name__)
_User = get_user_model()

class GoogleAuthLoginView(APIView):
    """
    ### Redirects user to Google's OAuth 2.0 authorization endpoint.
    """
    permission_classes = (AllowAny,)

    @extend_schema(summary='Google Login', tags=['Social Auth'], **google_auth_login_schema)
    def get(self, request):
        google_client_id = get_config('GOOGLE_CLIENT_ID')
        callback_url = get_config('GOOGLE_REDIRECT_URI')

        if not all([google_client_id, callback_url]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        google_auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            "response_type=code&"
            f"client_id={google_client_id}&"
            f"redirect_uri={callback_url}&"
            "scope=email profile&"
            "prompt=consent"
        )
        return redirect(google_auth_url)


class GoogleAuthCallbackView(APIView):
    """
    ### Handles Google OAuth2 callback, exchanges the code for a Google token, and returns JWT tokens.
    """
    permission_classes = (AllowAny,)

    @extend_schema(summary='Google Login Callback', tags=['Social Auth'], **google_auth_callback_schema)
    def get(self, request):
        code = request.query_params.get('code')
        google_client_id = get_config('GOOGLE_CLIENT_ID')
        google_client_secret = get_config('GOOGLE_CLIENT_SECRET')
        callback_url = get_config('GOOGLE_REDIRECT_URI')

        if not code:
            raise ValidationError(social_authorization_code.value, 4020)

        if not all([google_client_id, google_client_secret, callback_url]):
            raise ValidationError(social_invalid_auth_config.value, 4020)

        # Exchange authorization code for access token
        token_url = 'https://www.googleapis.com/oauth2/v4/token'
        token_data = {
            'code': code,
            'client_id': google_client_id,
            'client_secret': google_client_secret,
            'redirect_uri': callback_url,
            'grant_type': 'authorization_code'
        }
        token_response = requests.post(token_url, data=token_data)
        if token_response.status_code != 200:
            token_response_data = token_response.json()
            return Response(data={'detail': token_response_data['error']}, status=token_response.status_code)

        token_json = token_response.json()
        access_token = token_json.get('access_token')

        # Get user info using the access token
        user_info_url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        user_info_response = requests.get(user_info_url, headers={
            'Authorization': f'Bearer {access_token}'
        })
        if user_info_response.status_code != 200:
            user_info_response_data = user_info_response.json()
            return Response(
                data={'detail': user_info_response_data['error']['message']},
                status=user_info_response.status_code
            )

        # Find or create a user
        user_info = user_info_response.json()
        email, name = user_info.get('email'), user_info.get('name')
        if not email or not name:
            raise ValidationError(social_user_info_missing.value, 4020)

        try:
            provider_data = {'provider': 'google', 'user_info': user_info}
            return social_login(email=email, name=name, provider_data=provider_data)
        except Exception as e:
            logger.error(f'Login failed: {str(e)}', exc_info=True)
            raise APIException()