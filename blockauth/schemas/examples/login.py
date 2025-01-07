from drf_spectacular.utils import OpenApiExample

"""basic login"""
login_passwordless_account = OpenApiExample(
    name='login_passwordless_account',
    summary='Passwordless account',
    value={
        "detail": "Passwordless account. Please login via passwordless method, social account or reset password."
    }
)

login_incorrect_email_password = OpenApiExample(
    name='login_incorrect_email_password',
    summary='Incorrect email & password',
    value={
        "detail": "username or password incorrect"
    }
)

login_signup_incomplete = OpenApiExample(
    name='login_signup_incomplete',
    summary='Incomplete signup',
    value={
        "detail": "Account is not verified. Complete signup process or login via passwordless method."
    }
)


basic_login_schema_examples = [
    login_passwordless_account,
    login_incorrect_email_password,
    login_signup_incomplete
]