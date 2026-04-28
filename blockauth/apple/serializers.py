"""Request serializers for Apple endpoints.

`AppleNativeVerifyRequestSerializer` validates the body posted by mobile
clients with the platform-supplied id_token + raw nonce. Optional name fields
mirror Apple's "first sign-in only" contract — clients pass them on the very
first ASAuthorization and never again, so the field is optional.

`AppleServerToServerNotificationRequestSerializer` validates the
`{"payload": "..."}` envelope Apple delivers to the webhook.

`AppleWebCallbackRequestSerializer` describes the `form_post` body Apple
delivers to the web callback. The view reads these fields directly from
``request.data``; the serializer exists so drf-spectacular renders the
endpoint's request body in the OpenAPI schema instead of falling back
to "unable to guess".
"""

from rest_framework import serializers


class AppleNativeVerifyRequestSerializer(serializers.Serializer):
    id_token = serializers.CharField()
    raw_nonce = serializers.CharField()
    authorization_code = serializers.CharField(required=False, allow_blank=True)
    first_name = serializers.CharField(required=False, allow_blank=True, max_length=120)
    last_name = serializers.CharField(required=False, allow_blank=True, max_length=120)


class AppleServerToServerNotificationRequestSerializer(serializers.Serializer):
    payload = serializers.CharField()


class AppleWebCallbackRequestSerializer(serializers.Serializer):
    code = serializers.CharField(help_text="Apple authorization code from the form_post body.")
    state = serializers.CharField(help_text="CSRF state echoed back from the authorize step.")
    user = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text=(
            "JSON-encoded user object Apple includes only on the very first "
            "consent (`{name: {firstName, lastName}, email}`)."
        ),
    )
