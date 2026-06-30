import os
import pytest
from unittest.mock import patch, MagicMock
import sys
import types
import asyncio

# Mocking dependencies before anything else
def mock_deps():
    def create_dummy(name):
        m = types.ModuleType(name)
        sys.modules[name] = m
        return m

    if "fastapi" not in sys.modules:
        fastapi = create_dummy("fastapi")
        class MockApp:
            def add_middleware(self, *args, **kwargs): pass
            def post(self, *args, **kwargs): return lambda f: f
            def get(self, *args, **kwargs): return lambda f: f
        fastapi.FastAPI = lambda **kwargs: MockApp()
        fastapi.BackgroundTasks = object
        class HTTPException(Exception):
            def __init__(self, status_code, detail):
                self.status_code = status_code
                self.detail = detail
        fastapi.HTTPException = HTTPException
        fastapi.Header = lambda *args, **kwargs: None
        fastapi.Depends = lambda *args, **kwargs: None

    if "fastapi.middleware.cors" not in sys.modules:
        fastapi_middleware_cors = create_dummy("fastapi.middleware.cors")
        fastapi_middleware_cors.CORSMiddleware = object

    if "pydantic" not in sys.modules:
        pydantic = create_dummy("pydantic")
        class BaseModel:
            def __init_subclass__(cls, **kwargs):
                pass
        pydantic.BaseModel = BaseModel

mock_deps()

def test_api_keys_loading(monkeypatch):
    monkeypatch.setenv("TRACETREE_API_KEYS", "key1, key2 ,  ")

    if "api.main" in sys.modules:
        del sys.modules["api.main"]

    import api.main
    assert api.main.VALID_API_KEYS == {"key1", "key2"}

def test_api_keys_missing(monkeypatch):
    monkeypatch.delenv("TRACETREE_API_KEYS", raising=False)

    if "api.main" in sys.modules:
        del sys.modules["api.main"]

    with pytest.raises(RuntimeError, match="TRACETREE_API_KEYS environment variable is not set"):
        import api.main

def test_verify_api_key_valid(monkeypatch):
    monkeypatch.setenv("TRACETREE_API_KEYS", "secret_key")
    if "api.main" in sys.modules:
        del sys.modules["api.main"]

    import api.main
    result = asyncio.run(api.main.verify_api_key("secret_key"))
    assert result == "secret_key"

def test_verify_api_key_invalid(monkeypatch):
    monkeypatch.setenv("TRACETREE_API_KEYS", "secret_key")
    if "api.main" in sys.modules:
        del sys.modules["api.main"]

    import api.main
    with pytest.raises(api.main.HTTPException) as excinfo:
        asyncio.run(api.main.verify_api_key("wrong_key"))
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Invalid API key"
