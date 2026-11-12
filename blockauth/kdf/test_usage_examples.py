"""SEC-19: shipped example error bodies stay generic."""

import importlib
import sys
import types
from pathlib import Path

_SOURCE = Path(__file__).resolve().parent / "usage_examples.py"
_MODULE_NAME = "blockauth.kdf.usage_examples"


def test_example_responses_omit_exception_text():
    text = _SOURCE.read_text(encoding="utf-8")
    assert "str(e)" not in text


def test_usage_examples_module_imports(monkeypatch):
    _install_optional_stubs(monkeypatch)
    loaded_here = _MODULE_NAME not in sys.modules
    module = importlib.import_module(_MODULE_NAME)
    assert callable(module.create_user_with_wallet)
    assert callable(module.create_wallet_flask)
    if loaded_here:
        _drop_after_test(monkeypatch, _MODULE_NAME)
    monkeypatch.undo()
    if loaded_here:
        assert _MODULE_NAME not in sys.modules
    pydantic = importlib.import_module("pydantic")
    assert pydantic.Field is not None


def _drop_after_test(monkeypatch, name):
    """Remove a module this test loaded and keep it removed at teardown."""
    sys.modules.pop(name, None)
    monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules.pop(name, None)


def _install_optional_stubs(monkeypatch):
    if "fastapi" not in sys.modules:
        monkeypatch.setitem(sys.modules, "fastapi", _fastapi_stub())
    if "pydantic" not in sys.modules:
        monkeypatch.setitem(sys.modules, "pydantic", _pydantic_stub())
    if "flask" not in sys.modules:
        monkeypatch.setitem(sys.modules, "flask", _flask_stub())


def _fastapi_stub():
    fastapi = types.ModuleType("fastapi")

    class HTTPException(Exception):
        def __init__(self, status_code=500, detail=""):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class FastAPI:
        def post(self, *args, **kwargs):
            return lambda fn: fn

    fastapi.FastAPI = FastAPI
    fastapi.HTTPException = HTTPException
    return fastapi


def _pydantic_stub():
    pydantic = types.ModuleType("pydantic")

    class BaseModel:
        pass

    pydantic.BaseModel = BaseModel
    return pydantic


def _flask_stub():
    flask = types.ModuleType("flask")

    class Flask:
        def __init__(self, name):
            self.name = name

        def route(self, *args, **kwargs):
            return lambda fn: fn

    flask.Flask = Flask
    flask.jsonify = lambda payload: payload
    flask.request = None
    return flask
