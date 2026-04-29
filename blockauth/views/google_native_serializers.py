"""Request serializer for the Google native id_token verify endpoint.

Lives in its own module so both ``views/google_native_views.py`` and
``docs/social_auth_docs.py`` can reference it without a circular import.
The view also imports the OpenAPI schema dict that documents this
endpoint, so the schema dict cannot import from the view module — hence
the split.
"""

from rest_framework.serializers import CharField, Serializer


class GoogleNativeIdTokenVerifyRequestSerializer(Serializer):
    id_token = CharField()
    raw_nonce = CharField()
