import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import httpx
import pytest
from fastapi.testclient import TestClient

from mock_http import MockRouter


@pytest.fixture()
def client_and_headers(tmp_path, monkeypatch):
    db_file = tmp_path / "oauth_test.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("ENABLE_LEGACY_GITHUB_OAUTH", "true")

    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]

    from app.main import app
    from app.database import init_db
    init_db()

    with TestClient(app) as c:
        signup = c.post("/auth/signup", json={
            "email": "oauth@acme.com", "password": "hunterpassword22", "organization_name": "OAuthOrg"
        }).json()
        headers = {"Authorization": f"Bearer {signup['access_token']}"}
        yield c, headers


def test_authorize_requires_client_id(monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_CLIENT_ID", raising=False)
    db_file = tmp_path / "oauth_test2.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    from app.database import init_db
    init_db()
    with TestClient(app) as c:
        signup = c.post("/auth/signup", json={
            "email": "noconfig@acme.com", "password": "hunterpassword22", "organization_name": "NoConfig"
        }).json()
        headers = {"Authorization": f"Bearer {signup['access_token']}"}
        r = c.get("/integrations/github/authorize", headers=headers)
        assert r.status_code == 501


def test_authorize_returns_valid_github_url(client_and_headers):
    client, headers = client_and_headers
    r = client.get("/integrations/github/authorize", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["authorize_url"].startswith("https://github.com/login/oauth/authorize?")
    assert "client_id=test-client-id" in data["authorize_url"]
    assert "state=" in data["authorize_url"]


def test_callback_exchanges_code_and_stores_token(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    import app.routers.github_oauth as gh

    auth_resp = client.get("/integrations/github/authorize", headers=headers).json()
    state = auth_resp["state"]

    router = MockRouter()
    router.add("POST", "https://github.com/login/oauth/access_token",
               httpx.Response(200, json={"access_token": "gho_fake_token_123", "token_type": "bearer"}))
    monkeypatch.setattr(gh, "_http_client", router.client)

    r = client.get(f"/integrations/github/callback?code=fake_code&state={state}")
    assert r.status_code == 200
    assert r.json()["connected"] is True


def test_repos_endpoint_uses_stored_token(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    import app.routers.github_oauth as gh

    auth_resp = client.get("/integrations/github/authorize", headers=headers).json()
    state = auth_resp["state"]

    router = MockRouter()
    router.add("POST", "https://github.com/login/oauth/access_token",
               httpx.Response(200, json={"access_token": "gho_fake_token_456"}))
    router.add("GET", "https://api.github.com/user/repos", httpx.Response(200, json=[
        {"full_name": "acme/backend", "clone_url": "https://github.com/acme/backend.git",
         "private": True, "default_branch": "main"},
    ]))
    monkeypatch.setattr(gh, "_http_client", router.client)

    client.get(f"/integrations/github/callback?code=abc&state={state}")

    r = client.get("/integrations/github/repos", headers=headers)
    assert r.status_code == 200
    repos = r.json()
    assert repos[0]["full_name"] == "acme/backend"


def test_repos_endpoint_handles_expired_token(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    import app.routers.github_oauth as gh

    auth_resp = client.get("/integrations/github/authorize", headers=headers).json()
    state = auth_resp["state"]

    router = MockRouter()
    router.add("POST", "https://github.com/login/oauth/access_token",
               httpx.Response(200, json={"access_token": "gho_expired"}))
    router.add("GET", "https://api.github.com/user/repos", httpx.Response(401, json={}))
    monkeypatch.setattr(gh, "_http_client", router.client)

    client.get(f"/integrations/github/callback?code=abc&state={state}")

    r = client.get("/integrations/github/repos", headers=headers)
    assert r.status_code == 401


def test_repos_without_connection_fails_cleanly(client_and_headers):
    client, headers = client_and_headers
    r = client.get("/integrations/github/repos", headers=headers)
    assert r.status_code == 400

def _prepare_app_install_test(monkeypatch, account_login="acme", app_id=12345, status=200):
    import app.routers.github_oauth as gh

    monkeypatch.setattr(gh, "GITHUB_APP_SLUG", "ai-safety-checkup-pilot")
    monkeypatch.setattr(gh, "GITHUB_APP_ID", "12345")
    monkeypatch.setattr(gh, "_github_app_jwt", lambda: "test-jwt")

    router = MockRouter()
    router.add(
        "GET",
        "https://api.github.com/app/installations/987",
        httpx.Response(
            status,
            json={
                "id": 987,
                "app_id": app_id,
                "account": {"login": account_login},
            },
        ),
    )
    monkeypatch.setattr(gh, "_http_client", router.client)


def _start_app_install(client, headers, login="acme"):
    response = client.get(
        "/integrations/github/app/install",
        params={"github_account_login": login},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()["state"]


def test_app_install_accepts_verified_installation(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    _prepare_app_install_test(monkeypatch)

    state = _start_app_install(client, headers)
    response = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )

    assert response.status_code == 200, response.text
    assert response.json()["connected"] is True

    # A successful callback consumes its state; replay must fail.
    replay = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )
    assert replay.status_code == 400


def test_app_install_rejects_wrong_account(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    _prepare_app_install_test(monkeypatch, account_login="someone-else")

    state = _start_app_install(client, headers)
    response = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )

    assert response.status_code == 400
    assert "account" in response.json()["detail"].lower()


def test_app_install_rejects_wrong_app_id(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    _prepare_app_install_test(monkeypatch, app_id=99999)

    state = _start_app_install(client, headers)
    response = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )

    assert response.status_code == 400
    assert "app" in response.json()["detail"].lower()


def test_app_install_rejects_github_api_failure(client_and_headers, monkeypatch):
    client, headers = client_and_headers
    _prepare_app_install_test(monkeypatch, status=404)

    state = _start_app_install(client, headers)
    response = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )

    assert response.status_code == 400


def test_app_install_allows_github_account_selection(
    client_and_headers, monkeypatch
):
    client, headers = client_and_headers
    _prepare_app_install_test(
        monkeypatch,
        account_login="selected-account",
    )

    # Do not specify github_account_login; GitHub lets the user select an account.
    response = client.get(
        "/integrations/github/app/install",
        headers=headers,
    )
    assert response.status_code == 200, response.text

    state = response.json()["state"]
    callback = client.get(
        "/integrations/github/app/callback",
        params={"installation_id": 987, "state": state},
    )

    assert callback.status_code == 200, callback.text
    assert callback.json()["connected"] is True
