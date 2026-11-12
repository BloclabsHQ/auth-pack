"""Logout OpenAPI generation emits no warning for that path."""

from drf_spectacular.drainage import GENERATOR_STATS, reset_generator_stats
from drf_spectacular.generators import SchemaGenerator


def test_logout_schema_has_no_warning():
    reset_generator_stats()
    schema = SchemaGenerator().get_schema(request=None, public=True)
    messages = [
        *GENERATOR_STATS._error_cache,
        *GENERATOR_STATS._warn_cache,
    ]
    logout = []
    for message in messages:
        names_view = "AuthLogoutView" in message
        names_serializer = "serializer" in message
        if names_view and names_serializer:
            logout.append(message)
    assert logout == []
    paths = []
    for path in schema.get("paths", {}):
        if path.endswith("/token/logout/"):
            paths.append(path)
    assert len(paths) == 1
    operation = schema["paths"][paths[0]]["post"]
    assert "requestBody" in operation
    assert operation["operationId"] == "token_logout"
