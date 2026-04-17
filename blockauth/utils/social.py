from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from blockauth.enums import AuthenticationType
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import model_to_json
from blockauth.utils.token import AUTH_TOKEN_CLASS, generate_auth_token

_User = get_block_auth_user_model()


def social_login(email: str, name: str, provider_data: dict) -> Response:
    user, created = _User.objects.get_or_create(
        email=email, defaults={"first_name": name, "email": email, "is_verified": True}
    )
    user.last_login = timezone.now()

    # Add authentication type based on provider
    provider = provider_data.get("provider", "").upper()
    if provider in [AuthenticationType.GOOGLE, AuthenticationType.FACEBOOK, AuthenticationType.LINKEDIN]:
        user.add_authentication_type(provider)

    user.save()

    user_data = model_to_json(user)
    context = {"user": user_data, "provider_data": provider_data, "timestamp": user.last_login.timestamp()}

    if created:
        post_sign_up_trigger = get_config("POST_SIGNUP_TRIGGER")()
        post_sign_up_trigger.trigger(context=context)

    post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
    post_login_trigger.trigger(context=context)

    # Generate tokens with custom claims support
    try:
        from blockauth.utils.token import generate_auth_token_with_custom_claims

        access_token, refresh_token = generate_auth_token_with_custom_claims(
            token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id)
        )
    except ImportError:
        # Fall back to original implementation
        access_token, refresh_token = generate_auth_token(token_class=AUTH_TOKEN_CLASS(), user_id=str(user.id))

    # api-optimization: return the full {access, refresh, user} tuple so
    # OAuth-signup clients don't have to issue a follow-up /me/ to hydrate
    # profile state. Mirrors the shape returned by /login/basic/,
    # /login/passwordless/confirm/, and /login/wallet/.
    response_serializer = AuthStateResponseSerializer(
        {
            "access": access_token,
            "refresh": refresh_token,
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
    return Response(data=response_serializer.data, status=status.HTTP_200_OK)
