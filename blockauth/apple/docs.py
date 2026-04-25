"""drf-spectacular schemas for Apple endpoints.

Kept minimal — only request/response examples that are not fully expressed by
the serializers. Heavy descriptions live in the README to avoid bloating
generated OpenAPI files.
"""

from drf_spectacular.utils import OpenApiResponse

apple_authorize_schema = {
    "summary": "Initiate Apple Sign-In (web)",
    "responses": {302: OpenApiResponse(description="Redirect to Apple authorize endpoint")},
}

apple_callback_schema = {
    "summary": "Apple Sign-In callback (web, form_post)",
    "responses": {200: OpenApiResponse(description="JWT tokens")},
}

apple_native_verify_schema = {
    "summary": "Verify Apple id_token from native client",
    "responses": {200: OpenApiResponse(description="JWT tokens")},
}

apple_notifications_schema = {
    "summary": "Apple server-to-server notifications webhook",
    "responses": {200: OpenApiResponse(description="OK")},
}
