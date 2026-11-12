"""SEC-19: shipped example error bodies stay generic."""

import importlib
import sys
import types
from pathlib import Path

_SOURCE = Path(__file__).resolve().parent / "usage_examples.py"


def test_example_responses_omit_exception_text():
    text = _SOURCE.read_text(encoding="utf-8")
    assert "str(e)" not in text


def test_usage_examples_module_imports():
    _install_optional_stubs()
    module = importlib.import_module("blockauth.kdf.usage_examples")
    assert callable(module.create_user_with_wallet)
    assert callable(module.create_wallet_flask)


def _install_optional_stubs():
    if "fastapi" not in sys.modules:
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
        sys.modules["fastapi"] = fastapi

    if "pydantic" not in sys.modules:
        pydantic = types.ModuleType("pydantic")

        class BaseModel:
            pass

        pydantic.BaseModel = BaseModel
        sys.modules["pydantic"] = pydantic

    if "flask" not in sys.modules:
        flask = types.ModuleType("flask")

        class Flask:
            def __init__(self, name):
                self.name = name

            def route(self, *args, **kwargs):
                return lambda fn: fn

        flask.Flask = Flask
        flask.jsonify = lambda payload: payload
        flask.request = None
        sys.modules["flask"] = flask
