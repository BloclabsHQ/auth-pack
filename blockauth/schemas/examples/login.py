from drf_spectacular.utils import OpenApiExample

"""basic login"""
login_passwordless_account = OpenApiExample(
    name="login_passwordless_account",
    summary="Passwordless account",
    value={"detail": "Passwordless account. Please login via passwordless method, social account or reset password."},
)

login_incorrect_identifier = OpenApiExample(
    name="login_incorrect_identifier", summary="Incorrect identifier", value={"detail": ["Incorrect identifier"]}
)

login_incorrect_password = OpenApiExample(
    name="login_incorrect_password", summary="Incorrect password", value={"detail": ["Incorrect password"]}
)

login_signup_incomplete = OpenApiExample(
    name="login_signup_incomplete",
    summary="Incomplete signup",
    value={"detail": ["Account is not verified. Complete signup process or login via passwordless method"]},
)


basic_login_schema_examples = [login_incorrect_identifier, login_incorrect_password, login_signup_incomplete]
