"""Error responses must carry CORS headers so the browser can show the real message."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
ORIGIN = "http://127.0.0.1:5500"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'c.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", ORIGIN)
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.rate_limit import reset_rate_limits
    reset_rate_limits()
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def cors(r):
    return r.headers.get("access-control-allow-origin")


def test_rate_limited_responses_are_readable_by_the_browser(client):
    codes = []
    for i in range(8):
        r = client.post("/auth/signup", json={"email": f"u{i}@x.com", "password": "correct-horse-battery-1", "organization_name": "O"},
                        headers={"Origin": ORIGIN})
        codes.append(r.status_code)
        assert cors(r) == ORIGIN, (i, r.status_code)       # every response, including the 429s
    assert 429 in codes


def test_oversized_bodies_are_readable_by_the_browser(client):
    r = client.post("/auth/login", content=b'{"x":"' + b"a" * (1024 * 1024 + 5) + b'"}',
                    headers={"Origin": ORIGIN, "Content-Type": "application/json"})
    assert r.status_code == 413 and cors(r) == ORIGIN


def test_unexpected_errors_become_a_json_500_with_cors(client, monkeypatch):
    from app.main import app
    from fastapi import APIRouter
    boom = APIRouter()

    @boom.get("/__boom")
    def _boom():
        raise RuntimeError("secret internal detail")

    app.include_router(boom)
    r = client.get("/__boom", headers={"Origin": ORIGIN})
    assert r.status_code == 500 and cors(r) == ORIGIN
    assert r.json() == {"detail": "Internal server error"} and "secret" not in r.text


def test_disallowed_origins_still_get_no_cors_headers(client):
    r = client.get("/health", headers={"Origin": "http://evil.example"})
    assert cors(r) is None
