"""Social-login funnel used by the Google / Facebook / LinkedIn callbacks.

`social_login_data()` is the core: it upserts the user, fires triggers,
mints tokens, and returns the raw `(user, access, refresh)` tuple so
callers can decide the wire shape (JSON body, redirect + cookie, etc).

`social_login()` wraps that data into the legacy JSON response so existing
callers that expect a DRF ``Response`` back continue to work unchanged.
Integrators who want to BFF-ify the OAuth callback (set HttpOnly cookies +
302 to the shell — fabric-auth#533) subclass the view and use
`social_login_data()` directly.
"""

from dataclasses import dataclass
from typing import Any

from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

from blockauth.enums import AuthenticationType
from blockauth.serializers.user_account_serializers import AuthStateResponseSerializer
from blockauth.utils.auth_state import build_user_payload, issue_auth_tokens
from blockauth.utils.config import get_block_auth_user_model, get_config
from blockauth.utils.generics import model_to_json

_User = get_block_auth_user_model()


@dataclass(frozen=True)
class SocialLoginResult:
    """Outcome of a social-login attempt.

    Carries the raw user model + freshly-issued token pair so callers
    can build whatever response shape their integration needs:
    - legacy JSON body (via ``social_login()``)
    - BFF cookie + redirect (fabric-auth#533)
    - popup + postMessage
    """

    user: Any
    access_token: str
    refresh_token: str
    created: bool


def _user_model_has_field(field_name: str) -> bool:
    """True if the configured user model declares `field_name`. Cached
    result is fine — we never swap the user model mid-process."""
    try:
        _User._meta.get_field(field_name)
        return True
    except Exception:
        return False


def social_login_data(email: str, name: str, provider_data: dict) -> SocialLoginResult:
    """Core social-login pipeline — returns data, not a Response.

    Upserts the user, tags the authentication type, promotes
    `is_verified` to True for Google (OIDC-verified email claim — see
    #533 side-bug), fires post-signup / post-login triggers, and mints a
    fresh access/refresh pair. The caller decides the response shape.
    """
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

    # #533/#537 side-bug: Google returns OIDC-verified email claims. If the
    # account was previously created by email/password and the user never
    # clicked the verification link, the Google sign-in is proof the address
    # is theirs — promote so downstream gates on ``is_verified`` don't bounce
    # them. Only Google guarantees verified email at the OIDC layer;
    # Facebook/LinkedIn do NOT, so we stay conservative there.
    if provider == AuthenticationType.GOOGLE and not user.is_verified:
        user.is_verified = True

    user.save()

    user_data = model_to_json(user)
    context = {"user": user_data, "provider_data": provider_data, "timestamp": user.last_login.timestamp()}

    if created:
        post_sign_up_trigger = get_config("POST_SIGNUP_TRIGGER")()
        post_sign_up_trigger.trigger(context=context)

    post_login_trigger = get_config("POST_LOGIN_TRIGGER")()
    post_login_trigger.trigger(context=context)

    access_token, refresh_token = issue_auth_tokens(user)
    return SocialLoginResult(
        user=user,
        access_token=access_token,
        refresh_token=refresh_token,
        created=created,
    )


def social_login(email: str, name: str, provider_data: dict) -> Response:
    """Legacy JSON-body wrapper around ``social_login_data``.

    Kept so existing integrators that expect a ``Response`` back don't
    break during the BFF-cookie migration (fabric-auth#533). New code
    should call ``social_login_data()`` directly.
    """
    result = social_login_data(email=email, name=name, provider_data=provider_data)
    # api-optimization: return the full {access, refresh, user} tuple so
    # OAuth-signup clients don't have to issue a follow-up /me/ to hydrate
    # profile state. Mirrors the shape returned by /login/basic/,
    # /login/passwordless/confirm/, and /login/wallet/.
    response_serializer = AuthStateResponseSerializer(
        {
            "access": result.access_token,
            "refresh": result.refresh_token,
            "user": build_user_payload(result.user),
        }
    )
    return Response(data=response_serializer.data, status=status.HTTP_200_OK)
