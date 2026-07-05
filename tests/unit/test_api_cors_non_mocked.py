import os
import sys
import pytest

def test_api_cors_and_non_production(monkeypatch):
    monkeypatch.setenv("TRACETREE_API_KEYS", "key1")
    monkeypatch.setenv("TRACETREE_CORS_ORIGINS", "https://example.com, https://test.org")

    # Clear api.main from sys.modules so it reloads
    if "api.main" in sys.modules:
        del sys.modules["api.main"]

    # Clear mocked fastapi modules from sys.modules to load the real ones
    for key in list(sys.modules.keys()):
        if key == "fastapi" or key.startswith("fastapi.") or key == "pydantic":
            del sys.modules[key]

    from fastapi.middleware.cors import CORSMiddleware
    import importlib
    import api.main
    importlib.reload(api.main)

    # 1. Verify description contains NON-PRODUCTION
    assert "[NON-PRODUCTION]" in api.main.app.description
    
    # 2. Verify CORS middleware allow_origins
    cors_middleware = None
    for middleware in api.main.app.user_middleware:
        if middleware.cls == CORSMiddleware:
            cors_middleware = middleware
            break
            
    assert cors_middleware is not None
    assert cors_middleware.kwargs["allow_origins"] == ["https://example.com", "https://test.org"]
