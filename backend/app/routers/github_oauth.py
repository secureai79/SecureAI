"""GitHub integration.

Production deployments should use the GitHub App flow below. It grants
repository-scoped, read-only access and avoids broad user OAuth permissions.
The legacy OAuth-App flow remains available only when explicitly enabled for
existing installations/migrations.
"""
import base64
import datetime as dt
import hashlib
import os
import re
import secrets
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from .. import models, auth, audit
from ..database import get_db

router = APIRouter(prefix="/integrations/github", tags=["github"])

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_REDIRECT_URI = os.environ.get("GITHUB_OAUTH_REDIRECT_URI", "http://localhost:8000/integrations/github/callback")
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID", "")
GITHUB_APP_SLUG = os.environ.get("GITHUB_APP_SLUG", "")
GITHUB_APP_PRIVATE_KEY = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")

if not GITHUB_APP_PRIVATE_KEY:
    private_key_file = os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE", "").strip()

    if private_key_file:
        try:
            with open(private_key_file, encoding="utf-8") as _fh:
                GITHUB_APP_PRIVATE_KEY = _fh.read()
        except FileNotFoundError:
            GITHUB_APP_PRIVATE_KEY = ""
def legacy_oauth_enabled() -> bool:
    return os.environ.get("ENABLE_LEGACY_GITHUB_OAUTH", "false").lower() in {"1", "true", "yes", "on"}

from ..keyring import build_fernet

_fernet = build_fernet("GITHUB_TOKEN_ENCRYPTION_KEY")


def _http_client() -> httpx.Client:
    return httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0), follow_redirects=False)


def encrypt_token(token: str) -> str:
    return _fernet.encrypt(token.encode("utf-8")).decode("utf-8")


def decrypt_token(token: str) -> str:
    try:
        return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Stored GitHub credentials could not be decrypted") from exc


def _hash_state(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()



def _save_state(
    db: Session,
    user: models.User,
    state: str,
    github_account_login: str | None = None,
):
    now = dt.datetime.now(dt.UTC)

    # Remove stale states for this organization.
    db.query(models.OAuthState).filter(
        models.OAuthState.organization_id == user.organization_id,
        models.OAuthState.expires_at < now,
    ).delete(synchronize_session=False)

    db.add(models.OAuthState(
        state_hash=_hash_state(state),
        user_id=user.id,
        organization_id=user.organization_id,
        expires_at=now + dt.timedelta(minutes=10),
        github_account_login=github_account_login,
    ))
    db.commit()



def _consume_state(db: Session, state: str) -> models.OAuthState:
    if not state or len(state) > 256:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    record = db.query(models.OAuthState).filter(models.OAuthState.state_hash == _hash_state(state)).first()
    now = dt.datetime.now(dt.UTC)
    expires = record.expires_at.replace(tzinfo=dt.UTC) if record and record.expires_at and record.expires_at.tzinfo is None else (record.expires_at if record else None)
    if not record or record.used_at is not None or expires < now:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")
    record.used_at = now
    db.commit()
    return record


def _get_pending_app_state(
    db: Session,
    state: str,
) -> models.OAuthState:
    if not state or len(state) > 256:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state",
        )

    record = db.query(models.OAuthState).filter(
        models.OAuthState.state_hash == _hash_state(state)
    ).first()

    if not record:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state",
        )

    now = dt.datetime.now(dt.UTC)
    expires = record.expires_at
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.UTC)

    if record.used_at is not None or not expires or expires < now:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state",
        )

    # github_account_login is optional: when absent, GitHub's App installation
    # page lets the user choose the account. If supplied, callback verification
    # still enforces that exact account.
    return record



def _github_app_jwt() -> str:
    if not GITHUB_APP_ID or not GITHUB_APP_PRIVATE_KEY:
        raise HTTPException(status_code=501, detail="GitHub App is not configured")
    now = int(dt.datetime.now(dt.UTC).timestamp())
    return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": GITHUB_APP_ID}, GITHUB_APP_PRIVATE_KEY, algorithm="RS256")


def _verify_github_installation(
    installation_id: int,
    expected_login: str | None = None,
) -> None:
    if installation_id <= 0:
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub installation ID",
        )

    if not GITHUB_APP_ID:
        raise HTTPException(
            status_code=501,
            detail="GitHub App is not configured",
        )

    try:
        with _http_client() as client:
            response = client.get(
                f"https://api.github.com/app/installations/{installation_id}",
                headers={
                    "Authorization": f"Bearer {_github_app_jwt()}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="Could not verify the GitHub installation",
        ) from exc

    if response.status_code != 200:
        raise HTTPException(
            status_code=400,
            detail="GitHub installation could not be verified",
        )

    try:
        payload = response.json()
        app_id = int(payload.get("app_id", 0))
        account = payload.get("account")
        actual_login = account.get("login") if isinstance(account, dict) else None
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=502,
            detail="GitHub returned an invalid installation response",
        )

    if app_id != int(GITHUB_APP_ID):
        raise HTTPException(
            status_code=400,
            detail="Installation belongs to a different GitHub App",
        )

    if not isinstance(actual_login, str) or not actual_login:
        raise HTTPException(
            status_code=502,
            detail="GitHub did not return the installation account",
        )

    if expected_login and actual_login.casefold() != expected_login.casefold():
        raise HTTPException(
            status_code=400,
            detail="GitHub account does not match the requested account",
        )


def _integration(db: Session, org_id: str) -> models.Integration | None:
    return db.query(models.Integration).filter(
        models.Integration.organization_id == org_id,
        models.Integration.type == "github",
    ).first()


@router.get("/authorize")
def github_authorize(user: models.User = Depends(auth.require_verified_admin), db: Session = Depends(get_db)):
    # Legacy OAuth Apps can request broad private-repository access. Never use
    # this path in production; GitHub App installation is the production path.
    if os.environ.get("ENVIRONMENT", "development").lower() == "production" or not legacy_oauth_enabled():
        raise HTTPException(status_code=501, detail="GitHub App installation is required; legacy OAuth is disabled")
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET or not GITHUB_OAUTH_REDIRECT_URI:
        raise HTTPException(status_code=501, detail="Legacy GitHub OAuth is not configured")
    state = secrets.token_urlsafe(32)
    _save_state(db, user, state)
    params = {"client_id": GITHUB_CLIENT_ID, "redirect_uri": GITHUB_OAUTH_REDIRECT_URI, "scope": "repo:status read:org", "state": state}
    return {"authorize_url": f"https://github.com/login/oauth/authorize?{urlencode(params)}", "state": state}


@router.get("/callback")
def github_callback(code: str, state: str, db: Session = Depends(get_db)):
    if os.environ.get("ENVIRONMENT", "development").lower() == "production" or not legacy_oauth_enabled():
        raise HTTPException(status_code=501, detail="Legacy GitHub OAuth is disabled")
    record = _consume_state(db, state)
    with _http_client() as client:
        resp = client.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"}, data={
            "client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET, "code": code, "redirect_uri": GITHUB_OAUTH_REDIRECT_URI,
        })
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="GitHub authorization exchange failed")
    payload = resp.json()
    token = payload.get("access_token")
    if not token:
        raise HTTPException(status_code=400, detail="GitHub authorization exchange failed")
    integration = _integration(db, record.organization_id)
    encrypted = encrypt_token(token)
    if integration:
        integration.encrypted_credentials = encrypted
        integration.status = "active"
    else:
        db.add(models.Integration(organization_id=record.organization_id, type="github", encrypted_credentials=encrypted, status="active"))
    db.commit()
    frontend_url = os.environ.get("FRONTEND_URL", "").rstrip("/")
    if frontend_url:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=f"{frontend_url}/dashboard.html?github=connected", status_code=303)
    return {"connected": True}



@router.get("/app/install")
def github_app_install(
    github_account_login: str | None = None,
    user: models.User = Depends(auth.require_verified_admin),
    db: Session = Depends(get_db),
):
    if not GITHUB_APP_SLUG:
        raise HTTPException(
            status_code=501,
            detail="GitHub App is not configured on the server",
        )

    if github_account_login is not None:
        github_account_login = github_account_login.strip()
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?",
            github_account_login,
        ):
            raise HTTPException(
                status_code=422,
                detail="Enter a valid GitHub account username",
            )

    state = secrets.token_urlsafe(32)
    _save_state(
        db,
        user,
        state,
        github_account_login=github_account_login,
    )

    install_url = (
    f"https://github.com/apps/{GITHUB_APP_SLUG}"
    f"/installations/new?state={state}"
    )

    return {
        "install_url": install_url,
        "state": state,
    }




@router.get("/app/callback")
def github_app_callback(
    installation_id: int,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    # Require a state created by our authenticated installation endpoint.
    # Reconnect existing integrations through the normal flow.
    if not state:
        raise HTTPException(
            status_code=400,
            detail="Please reconnect GitHub to verify the installation safely.",
        )

    # Validate state without consuming it yet.
    record = _get_pending_app_state(db, state)

    # Verify installation ownership with GitHub before changing our database.
    _verify_github_installation(
        installation_id,
        record.github_account_login,
    )


    # Atomically consume the state only if it is still unused and unexpired.
    now = dt.datetime.now(dt.UTC)
    updated = (
        db.query(models.OAuthState)
        .filter(
            models.OAuthState.id == record.id,
            models.OAuthState.used_at.is_(None),
            models.OAuthState.expires_at > now,
        )
        .update(
            {models.OAuthState.used_at: now},
            synchronize_session=False,
        )
    )

    if updated != 1:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state",
        )

    record.used_at = now


    integration = _integration(db, record.organization_id)
    encrypted = encrypt_token(str(installation_id))

    if integration:
        integration.encrypted_credentials = encrypted
        integration.status = "active"
    else:
        integration = models.Integration(
            organization_id=record.organization_id,
            type="github",
            encrypted_credentials=encrypted,
            status="active",
        )
        db.add(integration)

    db.commit()
    audit.record(db, None, "github.app_connected", user_id=record.user_id, organization_id=record.organization_id, installation=str(installation_id))

    frontend_url = os.environ.get("FRONTEND_URL", "").rstrip("/")
    if frontend_url:
        from fastapi.responses import RedirectResponse
        return RedirectResponse(
            url=f"{frontend_url}/dashboard.html?github=connected",
            status_code=303,
        )

    return {"connected": True}


def get_installation_id(db: Session, org_id: str) -> int:
    integration = _integration(db, org_id)
    if not integration or not integration.encrypted_credentials:
        raise HTTPException(status_code=400, detail="GitHub App is not connected for this organization")
    try:
        return int(decrypt_token(integration.encrypted_credentials))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="GitHub integration needs to be reconnected")


def get_installation_token(db: Session, org_id: str) -> str:
    installation_id = get_installation_id(db, org_id)
    with _http_client() as client:
        resp = client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {_github_app_jwt()}", "Accept": "application/vnd.github+json"},
            json={},
        )
    if resp.status_code in {401, 404}:
        raise HTTPException(status_code=401, detail="GitHub App installation is unavailable â€” reconnect required")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="GitHub integration request failed")
    payload = resp.json()
    token = payload.get("token")
    if not token:
        raise HTTPException(status_code=502, detail="GitHub integration did not return an access token")
    return token


@router.get("/repos")
def github_list_repos(db: Session = Depends(get_db), user: models.User = Depends(auth.require_verified_user)):
    if GITHUB_APP_SLUG and GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
        token = get_installation_token(db, user.organization_id)
        with _http_client() as client:
            resp = client.get(
                "https://api.github.com/installation/repositories",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                params={"per_page": 100},
            )
        if resp.status_code >= 400:
            raise HTTPException(status_code=502, detail="Could not list GitHub repositories")
        return [{
            "full_name": r["full_name"], "clone_url": r["clone_url"],
            "private": r["private"], "default_branch": r.get("default_branch", "main"),
        } for r in resp.json().get("repositories", [])]

    if not legacy_oauth_enabled():
        raise HTTPException(status_code=501, detail="Connect the GitHub App; legacy OAuth is disabled")
    integration = _integration(db, user.organization_id)
    if not integration or not integration.encrypted_credentials:
        raise HTTPException(status_code=400, detail="GitHub is not connected for this organization")
    token = decrypt_token(integration.encrypted_credentials)
    with _http_client() as client:
        resp = client.get("https://api.github.com/user/repos", headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}, params={"per_page": 100, "sort": "updated"})
    if resp.status_code == 401:
        integration.status = "expired"
        db.commit()
        raise HTTPException(status_code=401, detail="GitHub authorization expired â€” reconnect required")
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail="Could not list GitHub repositories")
    return [{"full_name": r["full_name"], "clone_url": r["clone_url"], "private": r["private"], "default_branch": r.get("default_branch", "main")} for r in resp.json()]


@router.get("/status")
def github_status(db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Is GitHub connected for this organisation, and as which account (best effort)?"""
    integration = _integration(db, user.organization_id)
    if not integration or not integration.encrypted_credentials:
        return {"connected": False, "account": None}
    account = None
    try:
        installation_id = get_installation_id(db, user.organization_id)
        with _http_client() as client:
            resp = client.get(
                f"https://api.github.com/app/installations/{installation_id}",
                headers={"Authorization": f"Bearer {_github_app_jwt()}", "Accept": "application/vnd.github+json"},
            )
        if resp.status_code == 200:
            account = (resp.json().get("account") or {}).get("login")
    except Exception:  # status must never fail because GitHub is unreachable
        account = None
    return {"connected": True, "account": account}


@router.delete("/disconnect")
def github_disconnect(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_admin),
):
    """Forget the stored GitHub App installation for this organisation.

    SecureAI can no longer read the organisation's repositories after this. Access on GitHub's side
    is removed by uninstalling the app in GitHub (Settings > Applications), which the UI links to.
    """
    integration = _integration(db, user.organization_id)
    if integration:
        db.delete(integration)
        db.commit()
        audit.record(db, request, "github.disconnected", user_id=user.id, organization_id=user.organization_id)
    return {"disconnected": True}



def test_app_install_allows_github_account_selection(
    client_and_headers, monkeypatch
):
    client, headers = client_and_headers
    _prepare_app_install_test(monkeypatch, account_login="selected-account")

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
