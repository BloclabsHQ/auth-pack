"""Dev-only helper endpoints used by the E2E suite.

These endpoints MUST remain behind the ``DEBUG`` flag.  They expose OTP
codes and allow bulk user resets so pytest can drive the flows
deterministically.  They are registered only in ``tests_e2e.urls`` and
never imported by ``blockauth.urls``.
"""

from django.conf import settings
from django.http import Http404, JsonResponse
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from blockauth.models.otp import OTP


def _require_debug():
    if not settings.DEBUG:
        raise Http404()


class LatestOTPView(APIView):
    """GET /auth/_test/otp/<identifier>/ — return the latest active OTP.

    Used by the pytest suite to bridge the OTP gap (no real email / SMS
    in dev).  Returns ``{"code": "...", "subject": "..."}`` for the
    most recent un-consumed OTP matching the identifier.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def get(self, request, identifier):
        _require_debug()
        otp = (
            OTP.objects.filter(identifier=identifier, is_used=False)
            .order_by("-created_at")
            .first()
        )
        if not otp:
            return JsonResponse({"detail": "no active otp"}, status=404)
        return JsonResponse({"code": otp.code, "subject": otp.subject})


class ResetUsersView(APIView):
    """POST /auth/_test/reset/ — wipe E2EUser + OTP tables.

    Called at the start of each pytest flow so tests are isolated
    without needing full DB teardown.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        _require_debug()
        from tests_e2e.models import E2EUser

        user_count = E2EUser.objects.count()
        otp_count = OTP.objects.count()
        E2EUser.objects.all().delete()
        OTP.objects.all().delete()
        return Response({"deleted": {"users": user_count, "otps": otp_count}})


class StepupIssueView(APIView):
    """POST /auth/_test/stepup/issue/ — mint a receipt for the given subject.

    The stepup module is Django-independent, so the E2E test needs a
    tiny HTTP surface to exercise issue + validate across a boundary.
    """

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        _require_debug()
        from blockauth.stepup import ReceiptIssuer

        issuer = ReceiptIssuer(
            secret=settings.STEPUP_RECEIPT_SECRET,
            issuer="e2e-auth",
            default_audience="e2e-wallet",
            default_scope="mpc",
            default_ttl_seconds=120,
        )
        subject = request.data.get("subject")
        if not subject:
            return Response({"detail": "subject required"}, status=400)
        token = issuer.issue(subject=subject)
        return Response({"receipt": token})


class StepupValidateView(APIView):
    """POST /auth/_test/stepup/validate/ — validate a receipt."""

    permission_classes = [AllowAny]
    authentication_classes: list = []

    def post(self, request):
        _require_debug()
        from blockauth.stepup import ReceiptValidator
        from blockauth.stepup.receipt import ReceiptValidationError

        validator = ReceiptValidator(
            secret=settings.STEPUP_RECEIPT_SECRET,
            expected_audience="e2e-wallet",
            expected_scope="mpc",
        )
        token = request.data.get("receipt")
        expected_subject = request.data.get("expected_subject")
        if not token:
            return Response({"detail": "receipt required"}, status=400)
        try:
            claims = validator.validate(token, expected_subject=expected_subject)
        except ReceiptValidationError as exc:
            return Response({"valid": False, "code": exc.code}, status=401)
        return Response(
            {
                "valid": True,
                "subject": claims.subject,
                "audience": claims.audience,
                "scope": claims.scope,
                "jti": claims.jti,
            }
        )
