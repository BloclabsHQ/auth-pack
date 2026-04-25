"""Smoke test that drf-spectacular generates the OpenAPI schema for the
Apple Sign-In and Google native verify endpoints without errors, and that
each endpoint surfaces the expected status codes (200/302/400/409/500)."""

import pytest
from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(autouse=True)
def _enable_apple_google_features(settings):
    cfg = dict(settings.BLOCK_AUTH_SETTINGS)
    cfg["FEATURES"] = {**cfg.get("FEATURES", {}), "APPLE_LOGIN": True, "GOOGLE_NATIVE_LOGIN": True}
    cfg.setdefault("APPLE_SERVICES_ID", "com.example.svc")
    cfg.setdefault("APPLE_REDIRECT_URI", "https://example.com/auth/apple/callback/")
    cfg.setdefault("GOOGLE_NATIVE_AUDIENCES", ["test-google-client-id"])
    settings.BLOCK_AUTH_SETTINGS = cfg


@pytest.fixture
def schema():
    return SchemaGenerator().get_schema(request=None, public=True)


def _ops(schema, *path_fragments):
    out = {}
    for path, methods in schema.get("paths", {}).items():
        for fragment in path_fragments:
            if fragment in path:
                for method, op in methods.items():
                    if not method.startswith("x-"):
                        out[(path, method)] = op
    return out


def test_apple_endpoints_present(schema):
    apple_ops = _ops(schema, "/apple/")
    paths = sorted({p for p, _ in apple_ops.keys()})
    assert any(p.endswith("/apple/") for p in paths), paths
    assert any(p.endswith("/apple/callback/") for p in paths), paths
    assert any(p.endswith("/apple/verify/") for p in paths), paths
    assert any(p.endswith("/apple/notifications/") for p in paths), paths


def test_google_native_endpoint_present(schema):
    ops = _ops(schema, "/google/native/verify/")
    assert ops, "google native verify endpoint missing from generated schema"


@pytest.mark.parametrize(
    "fragment, expected_status_codes",
    [
        ("/apple/", {"302", "400", "500"}),  # apple/ authorize
        ("/apple/callback/", {"200", "400", "409", "500"}),
        ("/apple/verify/", {"200", "400", "409", "500"}),
        ("/apple/notifications/", {"200", "400", "500"}),
        ("/google/native/verify/", {"200", "400", "409", "500"}),
    ],
)
def test_endpoint_responses_have_expected_status_codes(schema, fragment, expected_status_codes):
    ops = _ops(schema, fragment)
    assert ops, f"no operation found for {fragment}"
    # Only the most-specific path for this fragment matters when multiple match
    most_specific = min(ops.keys(), key=lambda key: len(key[0]) - len(fragment))
    op = ops[most_specific]
    statuses = set((op.get("responses") or {}).keys())
    missing = expected_status_codes - statuses
    assert not missing, f"{fragment} {most_specific[1]} missing statuses {missing}; got {statuses}"


def test_apple_operation_ids_unique_and_descriptive(schema):
    apple_ops = _ops(schema, "/apple/")
    op_ids = [op.get("operationId") for op in apple_ops.values()]
    assert all(op_ids), f"missing operationId on apple ops: {op_ids}"
    assert len(set(op_ids)) == len(op_ids), f"duplicate operationIds: {op_ids}"
    for op_id in op_ids:
        assert op_id.startswith("apple_"), op_id


def test_google_native_operation_id(schema):
    ops = _ops(schema, "/google/native/verify/")
    op = next(iter(ops.values()))
    assert op.get("operationId") == "google_native_verify"


def test_apple_authentication_tag_applied(schema):
    apple_ops = _ops(schema, "/apple/")
    for (path, method), op in apple_ops.items():
        tags = op.get("tags") or []
        assert "Apple Authentication" in tags, f"{method} {path} tags={tags}"
