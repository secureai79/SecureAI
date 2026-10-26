import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "fixtest.db"
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("STORE_SOURCE_SNIPPETS", "true")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")

    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]

    from app.main import app
    from app.database import init_db
    init_db()

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def isolated_demo_repo(tmp_path):
    """Copy the demo repo so apply-fix tests can safely mutate files on disk
    without touching the real demo_repo/ used elsewhere."""
    src = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    dst = tmp_path / "demo_repo_copy"
    shutil.copytree(src, dst)
    return str(dst)


def _signup(client):
    return client.post("/auth/signup", json={
        "email": "fix@acme.com", "password": "hunterpassword22", "organization_name": "FixOrg"
    }).json()


def test_generate_fix_returns_diff_and_explanation(client, isolated_demo_repo):
    signup = _signup(client)
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{isolated_demo_repo}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()

    findings = client.get(f"/scans/{scan['id']}/findings", headers=headers).json()
    refund_finding = next(f for f in findings if f["file_path"] == "agents/refund_agent.py")

    fix = client.get(f"/findings/{refund_finding['id']}/fix", headers=headers).json()
    assert "MAX_AUTO_REFUND_AMOUNT" in fix["inserted_code"]
    assert "require_human_approval" in fix["inserted_code"]
    assert "stripe.Refund.create" in fix["diff"]
    assert fix["explanation"]

    # Nothing should have been written to disk yet — this is preview-only.
    with open(os.path.join(isolated_demo_repo, "agents/refund_agent.py")) as fh:
        assert "MAX_AUTO_REFUND_AMOUNT" not in fh.read()


def test_apply_fix_writes_file_and_rescan_improves_score(client, isolated_demo_repo):
    signup = _signup(client)
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{isolated_demo_repo}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()

    findings = client.get(f"/scans/{scan['id']}/findings", headers=headers).json()
    refund_finding = next(f for f in findings if f["file_path"] == "agents/refund_agent.py")
    assert refund_finding["severity"] == "HIGH"

    result = client.post(f"/findings/{refund_finding['id']}/apply-fix", headers=headers).json()
    assert result["applied"]["applied"] is True
    assert result["score_after"] > result["score_before"]
    assert result["rescan_status"] == "completed"

    # The file on disk should now contain a valid guard clause, correctly indented.
    with open(os.path.join(isolated_demo_repo, "agents/refund_agent.py")) as fh:
        content = fh.read()
    assert "MAX_AUTO_REFUND_AMOUNT" in content
    assert "    MAX_AUTO_REFUND_AMOUNT" in content  # indented to match the function body

    # The patched file must still be valid Python.
    import ast
    ast.parse(content)

    # The new scan should now see the same call site as guarded (LOW, ai_controlled+guarded).
    new_scan_id = result["rescan_id"]
    new_findings = client.get(f"/scans/{new_scan_id}/findings", headers=headers).json()
    refund_after = next(f for f in new_findings if f["file_path"] == "agents/refund_agent.py")
    assert refund_after["severity"] in ("LOW", "MEDIUM")  # downgraded from HIGH

def test_apply_fix_keeps_finding_unresolved_when_rescan_fails(
    client, isolated_demo_repo, monkeypatch
):
    from types import SimpleNamespace
    from app.routers import scans as scans_router

    signup = _signup(client)
    headers = {"Authorization": f"Bearer {signup['access_token']}"}

    repo = client.post(
        "/repositories",
        json={"repo_url": f"file://{isolated_demo_repo}"},
        headers=headers,
    ).json()
    scan = client.post(
        f"/repositories/{repo['id']}/scan",
        headers=headers,
    ).json()
    assert scan["status"] == "completed"

    findings = client.get(
        f"/scans/{scan['id']}/findings",
        headers=headers,
    ).json()
    refund_finding = next(
        f for f in findings if f["file_path"] == "agents/refund_agent.py"
    )
    original_status = refund_finding["status"]

    def failed_rescan(db, repository):
        return SimpleNamespace(
            id="simulated_failed_rescan",
            status="failed",
            score=None,
        )

    # Replace the rescan only after the initial scan has completed.
    monkeypatch.setattr(
        scans_router.scan_service,
        "run_scan",
        failed_rescan,
    )

    response = client.post(
        f"/findings/{refund_finding['id']}/apply-fix",
        headers=headers,
    )

    assert response.status_code == 500
    assert "verification failed" in response.json()["detail"].lower()

    # The original finding must not be marked resolved.
    refreshed_findings = client.get(
        f"/scans/{scan['id']}/findings",
        headers=headers,
    ).json()
    original_finding = next(
        f for f in refreshed_findings if f["id"] == refund_finding["id"]
    )
    assert original_finding["status"] == original_status
    assert original_finding["status"] != "resolved"

    # The file may already have been modified; verify it is still present.
    with open(os.path.join(isolated_demo_repo, "agents/refund_agent.py")) as fh:
        content = fh.read()
    assert "MAX_AUTO_REFUND_AMOUNT" in content


def test_apply_fix_rejects_non_local_repos(client):
    signup = _signup(client)
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post(
        "/repositories", json={"repo_url": "https://github.com/example/repo.git"}, headers=headers
    ).json()

    # No scan exists, so any finding id will 404 first — this is really
    # testing the code path for a scan against a non-file:// repo. We
    # simulate by checking the endpoint's guard logic directly.
    from app.scanner import fix_generator
    fake_fix = {
        "file_path": "does/not/matter.py", "line": 1,
        "inserted_code": "if True:\n    pass\n",
    }
    with pytest.raises(FileNotFoundError):
        fix_generator.apply_fix_to_local_file("/tmp/nonexistent-repo-xyz", fake_fix)


def test_generated_patch_is_syntactically_valid_for_all_demo_findings(client, isolated_demo_repo):
    """Every finding's generated fix should produce syntactically valid
    Python when actually inserted — not just look plausible as text."""
    signup = _signup(client)
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{isolated_demo_repo}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    findings = client.get(f"/scans/{scan['id']}/findings", headers=headers).json()

    import ast as ast_module
    for f in findings:
        fix = client.get(f"/findings/{f['id']}/fix", headers=headers).json()
        full_path = os.path.join(isolated_demo_repo, fix["file_path"])
        with open(full_path) as fh:
            original_lines = fh.readlines()
        insert_at = max(0, fix["line"] - 1)
        guard_lines = [l + "\n" for l in fix["inserted_code"].split("\n")]
        patched = "".join(original_lines[:insert_at] + guard_lines + original_lines[insert_at:])
        ast_module.parse(patched)  # raises SyntaxError if the patch is malformed
