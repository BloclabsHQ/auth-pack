"""URL config for the E2E test project.

Mounts ``blockauth.urls`` under ``/auth/`` and layers dev-only helper
endpoints (prefixed ``_test/``) on top for OTP retrieval and fixture
reset.  TOTP and step-up routes are also wired here so the pytest
suite can reach them.
"""

from django.urls import include, path

from blockauth.totp import urls as totp_urls
from tests_e2e.test_views import (
    LatestOTPView,
    ResetUsersView,
    StepupIssueView,
    StepupValidateView,
)

urlpatterns = [
    # Dev-only helpers — MUST stay behind DEBUG.
    path("auth/_test/otp/<path:identifier>/", LatestOTPView.as_view()),
    path("auth/_test/reset/", ResetUsersView.as_view()),
    path("auth/_test/stepup/issue/", StepupIssueView.as_view()),
    path("auth/_test/stepup/validate/", StepupValidateView.as_view()),
    # Production-shape URLs.
    path("auth/totp/", include((totp_urls, "totp"), namespace="totp")),
    path("auth/", include("blockauth.urls")),
]
