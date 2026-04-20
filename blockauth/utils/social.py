from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from blockauth.enums import AuthenticationType
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.utils.auth_state import build_user_payload, issue_auth_tokens
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import model_to_json

_User = get_block_auth_user_model()


def _user_model_has_field(field_name: str) -> bool:
    """True if the configured user model declares `field_name`. Cached
    result is fine — we never swap the user model mid-process."""
    try:
        _User._meta.get_field(field_name)
        return True
    except Exception:
        return False


def social_login(email: str, name: str, provider_data: dict) -> Response:
    # Only include `first_name` in defaults if the configured user model
    # actually defines it. Otherwise get_or_create raises FieldError on
    # the create path (first OAuth signup for a new email). See #109.
    defaults = {"email": email, "is_verified": True}
    if _user_model_has_field("first_name"):
        defaults["first_name"] = name

    user, created = _User.objects.get_or_create(email=email, defaults=defaults)
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

    access_token, refresh_token = issue_auth_tokens(user)
    # api-optimization: return the full {access, refresh, user} tuple so
    # OAuth-signup clients don't have to issue a follow-up /me/ to hydrate
    # profile state. Mirrors the shape returned by /login/basic/,
    # /login/passwordless/confirm/, and /login/wallet/.
    response_serializer = AuthStateResponseSerializer(
        {
            "access": access_token,
            "refresh": refresh_token,
            "user": build_user_payload(user),
        }
    )
    return Response(data=response_serializer.data, status=status.HTTP_200_OK)
