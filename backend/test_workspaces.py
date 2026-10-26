"""One account, several workspaces: accepting invitations as an existing user, switching, leaving, removal."""
import datetime as dt
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'w.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "false")
    monkeypatch.setenv("FRONTEND_URL", "http://127.0.0.1:5500")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        c.outbox = email_service.OUTBOX
        yield c


def H(t):
    return {"Authorization": f"Bearer {t}"}


def signup(client, email, org):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": org})
    client.outbox.clear()
    return r.json()["access_token"]


def invite(client, tok, email, role="member"):
    r = client.post("/team/invitations", json={"email": email, "role": role}, headers=H(tok))
    assert r.status_code == 200, r.text
    return re.search(r"#token=([A-Za-z0-9_-]+)", client.outbox[-1]["text"]).group(1), r.json()


def me(client, tok):
    return client.get("/auth/me", headers=H(tok)).json()


@pytest.fixture()
def two(client):
    """alice owns Alpha, bob owns Beta. alice invites bob to Alpha."""
    a = signup(client, "alice@alpha.com", "Alpha")
    b = signup(client, "bob@beta.com", "Beta")
    raw, inv = invite(client, a, "bob@beta.com")
    return client, a, b, raw, inv


def test_the_reported_case_an_address_with_its_own_workspace_is_told_to_log_in(two):
    client, a, b, raw, _ = two
    pv = client.post("/team/invitations/preview", json={"token": raw}).json()
    assert pv["account_exists"] is True and pv["organization_name"] == "Alpha"
    r = client.post("/team/invitations/accept", json={"token": raw, "password": PW})
    assert r.status_code == 409 and "log in" in r.json()["detail"].lower()


def test_invitee_finds_the_invitation_inside_the_app_and_accepts_it(two):
    client, a, b, raw, inv = two
    mine = client.get("/team/my-invitations", headers=H(b)).json()["invitations"]
    assert len(mine) == 1 and mine[0]["organization_name"] == "Alpha" and mine[0]["invited_by"] == "alice@alpha.com"
    assert mine[0]["role"] == "member"
    assert client.get("/team/my-invitations", headers=H(a)).json()["invitations"] == []        # not visible to anyone else
    r = client.post(f"/team/my-invitations/{mine[0]['id']}/accept", headers=H(b))
    assert r.status_code == 200 and r.json()["organization_name"] == "Alpha" and r.json()["role"] == "member"
    assert me(client, b)["organization_name"] == "Alpha" and me(client, b)["role"] == "member"
    assert client.get("/team/my-invitations", headers=H(b)).json()["invitations"] == []
    team = client.get("/team", headers=H(a)).json()
    assert sorted(m["email"] for m in team["members"]) == ["alice@alpha.com", "bob@beta.com"]
    assert client.post(f"/team/my-invitations/{mine[0]['id']}/accept", headers=H(b)).status_code == 404   # single use


def test_emailed_link_works_for_a_logged_in_existing_account_but_only_for_the_invited_address(two):
    client, a, b, raw, _ = two
    carol = signup(client, "carol@gamma.com", "Gamma")
    assert client.post("/team/invitations/accept-existing", json={"token": raw}, headers=H(carol)).status_code == 400
    assert client.post("/team/invitations/accept-existing", json={"token": raw}, headers=H(b)).status_code == 200
    assert me(client, b)["organization_name"] == "Alpha"
    assert client.post("/team/invitations/accept-existing", json={"token": raw}, headers=H(b)).status_code == 400


def test_decline_removes_the_invitation(two):
    client, a, b, raw, _ = two
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    assert client.post(f"/team/my-invitations/{inv_id}/decline", headers=H(b)).status_code == 200
    assert client.get("/team/my-invitations", headers=H(b)).json()["invitations"] == []
    assert client.post("/team/invitations/preview", json={"token": raw}).status_code == 400
    assert client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b)).status_code == 404
    assert client.get("/team", headers=H(a)).json()["invitations"] == []


def test_nobody_can_accept_or_decline_someone_elses_invitation(two):
    client, a, b, raw, _ = two
    carol = signup(client, "carol@gamma.com", "Gamma")
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    assert client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(carol)).status_code == 404
    assert client.post(f"/team/my-invitations/{inv_id}/decline", headers=H(carol)).status_code == 404
    assert client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(a)).status_code == 404


def test_switching_workspaces_changes_what_you_see_and_roles_are_per_workspace(two):
    client, a, b, raw, _ = two
    repo = client.post("/repositories", json={"repo_url": "https://github.com/octo/alpha-only"}, headers=H(a)).json()
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b))
    # in Alpha bob is a member: sees Alpha's repository, cannot manage the team
    assert [r["id"] for r in client.get("/repositories", headers=H(b)).json()] == [repo["id"]]
    assert client.post("/team/invitations", json={"email": "x@y.com"}, headers=H(b)).status_code == 403
    ws = client.get("/team/workspaces", headers=H(b)).json()["workspaces"]
    assert sorted((w["name"], w["role"], w["active"]) for w in ws) == [("Alpha", "member", True), ("Beta", "owner", False)]
    beta = [w["id"] for w in ws if w["name"] == "Beta"][0]
    assert client.post("/team/workspaces/switch", json={"organization_id": beta}, headers=H(b)).status_code == 200
    # back in Beta bob is the owner again, and Alpha's data is gone from view
    assert me(client, b)["role"] == "owner" and me(client, b)["organization_name"] == "Beta"
    assert client.get("/repositories", headers=H(b)).json() == []
    assert client.post("/team/invitations", json={"email": "x@y.com"}, headers=H(b)).status_code == 200
    assert client.get(f"/repositories/{repo['id']}/scans", headers=H(b)).status_code == 404
    alpha = [w["id"] for w in ws if w["name"] == "Alpha"][0]
    client.post("/team/workspaces/switch", json={"organization_id": alpha}, headers=H(b))
    assert me(client, b)["role"] == "member"


def test_cannot_switch_into_a_workspace_you_do_not_belong_to(two):
    client, a, b, raw, _ = two
    alpha = client.get("/team/workspaces", headers=H(a)).json()["workspaces"][0]["id"]
    assert client.post("/team/workspaces/switch", json={"organization_id": alpha}, headers=H(b)).status_code == 404
    assert me(client, b)["organization_name"] == "Beta"


def test_removing_a_member_who_has_another_workspace_keeps_their_account(two):
    client, a, b, raw, _ = two
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b))
    bob_id = [m["id"] for m in client.get("/team", headers=H(a)).json()["members"] if m["email"] == "bob@beta.com"][0]
    assert client.delete(f"/team/members/{bob_id}", headers=H(a)).status_code == 200
    assert client.get("/auth/me", headers=H(b)).status_code == 401                      # old session ended
    login = client.post("/auth/login", json={"email": "bob@beta.com", "password": PW})
    assert login.status_code == 200
    again = me(client, login.json()["access_token"])
    assert again["organization_name"] == "Beta" and again["role"] == "owner"            # lands in his own workspace
    assert [m["email"] for m in client.get("/team", headers=H(a)).json()["members"]] == ["alice@alpha.com"]


def test_leaving_a_workspace(two):
    client, a, b, raw, _ = two
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b))
    alpha = me(client, b)["organization_id"]
    owner_alpha = client.get("/team/workspaces", headers=H(a)).json()["workspaces"][0]["id"]
    assert client.post(f"/team/workspaces/{owner_alpha}/leave", headers=H(a)).status_code == 400   # owners cannot leave
    r = client.post(f"/team/workspaces/{alpha}/leave", headers=H(b))
    assert r.status_code == 200 and r.json()["left"] is True and r.json()["account_deleted"] is False
    assert client.get("/auth/me", headers=H(r.json()["access_token"])).json()["organization_name"] == "Beta"
    assert client.get("/auth/me", headers=H(b)).status_code == 401              # the old session ended
    login = client.post("/auth/login", json={"email": "bob@beta.com", "password": PW}).json()["access_token"]
    assert [w["name"] for w in client.get("/team/workspaces", headers=H(login)).json()["workspaces"]] == ["Beta"]


def test_role_changes_apply_in_the_workspace_where_they_were_made(two):
    client, a, b, raw, _ = two
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b))
    bob_id = [m["id"] for m in client.get("/team", headers=H(a)).json()["members"] if m["email"] == "bob@beta.com"][0]
    assert client.patch(f"/team/members/{bob_id}", json={"role": "admin"}, headers=H(a)).status_code == 200
    assert me(client, b)["role"] == "admin"                                              # active workspace updated at once
    beta = [w["id"] for w in client.get("/team/workspaces", headers=H(b)).json()["workspaces"] if w["name"] == "Beta"][0]
    client.post("/team/workspaces/switch", json={"organization_id": beta}, headers=H(b))
    assert me(client, b)["role"] == "owner"                                              # Beta untouched


def test_legacy_users_without_membership_rows_are_backfilled(client):
    a = signup(client, "legacy@old.com", "Old")
    from app import models, workspaces
    from app.database import SessionLocal
    with SessionLocal() as db:
        db.query(models.Membership).delete()
        db.commit()
        assert workspaces.backfill(db) == 1
        assert db.query(models.Membership).count() == 1
    with SessionLocal() as db:                                                           # lazily repaired too
        db.query(models.Membership).delete()
        db.commit()
    assert [m["email"] for m in client.get("/team", headers=H(a)).json()["members"]] == ["legacy@old.com"]
    assert client.get("/team/workspaces", headers=H(a)).json()["workspaces"][0]["role"] == "owner"


def test_seats_count_members_of_this_workspace_only(two):
    client, a, b, raw, _ = two
    seats = client.get("/team", headers=H(a)).json()["seats"]
    assert seats == {"used": 2, "limit": 10}                                             # alice + the pending invitation
    inv_id = client.get("/team/my-invitations", headers=H(b)).json()["invitations"][0]["id"]
    client.post(f"/team/my-invitations/{inv_id}/accept", headers=H(b))
    assert client.get("/team", headers=H(a)).json()["seats"] == {"used": 2, "limit": 10}
    assert client.get("/team", headers=H(b)).json()["seats"]["used"] == 2
    assert client.post("/team/invitations", json={"email": "bob@beta.com"}, headers=H(a)).status_code == 400   # already a member


def test_expired_invitations_are_not_offered(two):
    client, a, b, raw, _ = two
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        row = db.query(models.Invitation).first()
        row.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
        db.commit()
    assert client.get("/team/my-invitations", headers=H(b)).json()["invitations"] == []
    inv = client.post("/team/invitations/accept-existing", json={"token": raw}, headers=H(b))
    assert inv.status_code == 400


def test_team_endpoints_for_workspaces_require_login(client):
    for method, path in (("get", "/team/my-invitations"), ("get", "/team/workspaces"),
                         ("post", "/team/workspaces/switch"), ("post", "/team/invitations/accept-existing")):
        r = getattr(client, method)(path)
        assert r.status_code in (401, 403, 422), (path, r.status_code)
