from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from blockauth.models.user import AuthenticationType
from blockauth.utils.config import get_config, get_block_auth_user_model
from blockauth.utils.generics import model_to_json
from blockauth.utils.token import generate_auth_token, AUTH_TOKEN_CLASS

_User = get_block_auth_user_model()

def social_login(email: str, name: str, provider_data: dict) -> Response:
    user, created = _User.objects.get_or_create(email=email, defaults={'first_name': name, 'email': email, 'is_verified': True})
    user.last_login = timezone.now()
    
    # Add authentication type based on provider
    provider = provider_data.get('provider', '').upper()
    if provider in [AuthenticationType.GOOGLE, AuthenticationType.FACEBOOK, AuthenticationType.LINKEDIN]:
        user.add_authentication_type(provider)
    
    user.save()

    user_data = model_to_json(user)
    context = {'user': user_data, 'provider_data': provider_data, 'timestamp': user.last_login.timestamp()}

    if created:
        post_sign_up_trigger = get_config('POST_SIGNUP_TRIGGER')()
        post_sign_up_trigger.trigger(context=context)

    post_login_trigger = get_config('POST_LOGIN_TRIGGER')()
    post_login_trigger.trigger(context=context)

    access_token, refresh_token = generate_auth_token(
        token_class=AUTH_TOKEN_CLASS(), 
        user_id=user.id.hex
    )
    return Response(data={"access": access_token, "refresh": refresh_token}, status=status.HTTP_200_OK)