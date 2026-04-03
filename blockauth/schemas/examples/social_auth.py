from drf_spectacular.utils import OpenApiExample

social_authorization_code = OpenApiExample(
    name="social_authorization_code",
    summary="Empty authorization code",
    value={"detail": "Providers authorization code is required"},
)

social_invalid_auth_config = OpenApiExample(
    name="social_invalid_auth_config",
    summary="Invalid social auth config",
    value={"detail": "Auth provider settings is not properly configured"},
)

social_user_info_missing = OpenApiExample(
    name="social_user_info_missing",
    summary="User info missing in provider response",
    value={"detail": "Email or Name not found in user info"},
)
