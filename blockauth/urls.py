from blockauth.utils.config import is_social_auth_configured
from blockauth.views.basic_auth_views import AuthRefreshTokenView, \
    PasswordResetConfirmView, \
    PasswordChangeView, EmailChangeConfirmView, PasswordlessLoginView, PasswordlessLoginConfirmView, \
    BasicAuthLoginView, \
    PasswordResetView, EmailChangeView, SignUpView, SignUpConfirmView, SignUpResendOTPView
from blockauth.views.facebook_auth_views import FacebookAuthLoginView, FacebookAuthCallbackView
from blockauth.views.google_auth_views import GoogleAuthLoginView, GoogleAuthCallbackView
from blockauth.views.linkedin_auth_views import LinkedInAuthLoginView, LinkedInAuthCallbackView
from django.urls import path


urlpatterns = [
    # signup
    path('signup/', SignUpView.as_view(), name='signup'),
    path('signup/otp/resend/', SignUpResendOTPView.as_view(), name='signup-otp-resend'),
    path('signup/confirm/', SignUpConfirmView.as_view(), name='signup-confirm'),

    # login
    path('login/basic/', BasicAuthLoginView.as_view(), name='basic-login'),
    path('login/passwordless/', PasswordlessLoginView.as_view(), name='passwordless-login'),
    path('login/passwordless/confirm/', PasswordlessLoginConfirmView.as_view(), name='passwordless-login-confirm'),
    path('token/refresh/', AuthRefreshTokenView.as_view(), name='refresh-token'),

    # password reset
    path('password/reset/', PasswordResetView.as_view(), name='password-reset'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    # password change
    path('password/change/', PasswordChangeView.as_view(), name='change-password'),

    # email change
    path('email/change/', EmailChangeView.as_view(), name='email-change'),
    path('email/change/confirm/', EmailChangeConfirmView.as_view(), name='confirm-email-change'),
]


if is_social_auth_configured('google'):
    urlpatterns += [
        path('google/', GoogleAuthLoginView.as_view(), name='google-login'),
        path('google/callback/', GoogleAuthCallbackView.as_view(), name='google-login-callback'),
    ]

if is_social_auth_configured('facebook'):
    urlpatterns += [
        path('facebook/', FacebookAuthLoginView.as_view(), name='facebook-login'),
        path('facebook/callback/', FacebookAuthCallbackView.as_view(), name='facebook-login-callback'),
    ]

if is_social_auth_configured('linkedin'):
    urlpatterns += [
        path('linkedin/', LinkedInAuthLoginView.as_view(), name='linkedin-login'),
        path('linkedin/callback/', LinkedInAuthCallbackView.as_view(), name='linkedin-login-callback'),
    ]

