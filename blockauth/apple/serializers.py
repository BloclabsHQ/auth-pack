"""Request serializers for Apple endpoints.

`AppleNativeVerifyRequestSerializer` validates the body posted by mobile
clients with the platform-supplied id_token + raw nonce. Optional name fields
mirror Apple's "first sign-in only" contract — clients pass them on the very
first ASAuthorization and never again, so the field is optional.

`AppleServerToServerNotificationRequestSerializer` validates the
`{"payload": "..."}` envelope Apple delivers to the webhook.
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
