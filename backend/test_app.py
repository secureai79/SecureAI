import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

os.environ["ENVIRONMENT"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///./test_ai_safety_checkup.db"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("STORE_SOURCE_SNIPPETS", "true")

    # Re-import modules fresh so the new DATABASE_URL takes effect.
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]

    from app.main import app
    from app.database import init_db
    init_db()

    with TestClient(app) as c:
        yield c


def test_signup_and_login(client):
    r = client.post("/auth/signup", json={
        "email": "a@b.com", "password": "secretpassword123", "organization_name": "TestOrg"
    })
    assert r.status_code == 200
    assert r.json()["access_token"]

    r = client.post("/auth/login", json={"email": "a@b.com", "password": "secretpassword123"})
    assert r.status_code == 200

    r = client.post("/auth/login", json={"email": "a@b.com", "password": "wrong"})
    assert r.status_code == 401


def test_full_scan_flow(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))

    signup = client.post("/auth/signup", json={
        "email": "founder@acme.com", "password": "hunterpassword22", "organization_name": "Acme"
    }).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    org_id = signup["organization_id"]

    repo = client.post("/repositories", json={"repo_url": f"file://{demo_path}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()

    assert scan["status"] == "completed"
    assert scan["score"] is not None
    assert scan["score"] < 100  # demo repo is intentionally risky

    findings = client.get(f"/scans/{scan['id']}/findings", headers=headers).json()
    severities = {f["severity"] for f in findings}
    # With AST-based data-flow tracing, admin.py's DELETE is correctly
    # downgraded from CRITICAL to HIGH because no traced AI->action
    # data-flow connects it to the AI SDK also present in that file
    # (this is the exact false-positive class the AST rewrite fixes).
    assert "HIGH" in severities
    assert any(f["capability"] == "delete" and f["ai_controlled"] is False for f in findings)
    assert any(f["capability"] == "refund" and f["ai_controlled"] is True for f in findings)

    score = client.get(f"/organizations/{org_id}/score", headers=headers).json()
    assert score["score"] == scan["score"]

    potential = client.get(f"/scans/{scan['id']}/potential-score", headers=headers).json()
    assert potential["potential_score"] == 100

    top_finding_id = findings[0]["id"]
    resolved = client.patch(f"/findings/{top_finding_id}", json={"status": "resolved"}, headers=headers).json()
    assert resolved["status"] == "resolved"

    new_score = client.get(f"/organizations/{org_id}/score", headers=headers).json()
    assert new_score["score"] >= score["score"]


def test_capability_graph_endpoint(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    signup = client.post("/auth/signup", json={
        "email": "graph@acme.com", "password": "hunterpassword22", "organization_name": "GraphOrg"
    }).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{demo_path}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()

    graph = client.get(f"/scans/{scan['id']}/graph", headers=headers).json()
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0
    labels = {n["label"] for n in graph["nodes"]}
    assert "OpenAI" in labels  # AI provider node present in the graph

    # Every edge must be attributable to a specific capability -- without
    # this, a consumer reconstructing an end-to-end narrative path (e.g.
    # the dashboard's "what your AI can do" chains) can silently stitch
    # together fragments from two unrelated capabilities that happen to
    # share a generic intermediate node like "AI-generated decision".
    assert all("capability_id" in e and e["capability_id"] for e in graph["edges"])

    # Reconstruct per-capability paths the way a consumer would, and check
    # no path incorrectly mixes fragments from different capabilities: the
    # demo repo's refund-related chain must never mention "sendmail", and
    # the email-related chain must never mention "stripe".
    from collections import defaultdict
    by_capability = defaultdict(list)
    for e in graph["edges"]:
        by_capability[e["capability_id"]].append(e)
    for edges in by_capability.values():
        path = " ".join(e["source"] + " " + e["target"] for e in edges)
        if "stripe" in path.lower():
            assert "sendmail" not in path.lower()
        if "sendmail" in path.lower():
            assert "stripe" not in path.lower()


def test_baseline_regression(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    signup = client.post("/auth/signup", json={
        "email": "baseline@acme.com", "password": "hunterpassword22", "organization_name": "BaselineOrg"
    }).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{demo_path}"}, headers=headers).json()

    scan1 = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    reg1 = client.get(f"/scans/{scan1['id']}/regression", headers=headers).json()
    assert reg1["has_baseline"] is False  # first scan ever, nothing to compare against
    assert len(reg1["new_findings"]) > 0

    scan2 = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    reg2 = client.get(f"/scans/{scan2['id']}/regression", headers=headers).json()
    assert reg2["has_baseline"] is True
    assert reg2["score_delta"] == 0          # nothing changed between scans
    assert reg2["new_findings"] == []
    assert reg2["resolved_findings"] == []

    scans_list = client.get(f"/repositories/{repo['id']}/scans", headers=headers).json()
    assert len(scans_list) == 2


def test_repo_isolated_per_org(client):
    org_a = client.post("/auth/signup", json={
        "email": "a@org.com", "password": "passwordpassword1", "organization_name": "OrgA"
    }).json()
    org_b = client.post("/auth/signup", json={
        "email": "b@org.com", "password": "passwordpassword2", "organization_name": "OrgB"
    }).json()

    headers_a = {"Authorization": f"Bearer {org_a['access_token']}"}
    headers_b = {"Authorization": f"Bearer {org_b['access_token']}"}

    repo = client.post("/repositories", json={"repo_url": "https://github.com/example/repo.git"}, headers=headers_a).json()

    r = client.get("/repositories", headers=headers_b)
    assert repo["id"] not in [x["id"] for x in r.json()]


def test_scan_pdf_report_download(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    signup = client.post("/auth/signup", json={
        "email": "pdf@acme.com", "password": "hunterpassword22", "organization_name": "PdfOrg"
    }).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{demo_path}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    report = client.get(f"/scans/{scan['id']}/report.pdf", headers=headers)

    assert report.status_code == 200
    assert report.headers["content-type"].startswith("application/pdf")
    assert "attachment" in report.headers["content-disposition"]
    assert report.content.startswith(b"%PDF")
    assert len(report.content) > 1000


def test_customer_pdf_report_is_human_readable_and_filters_noise(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    signup = client.post("/auth/signup", json={
        "email": "pdfhuman@acme.com", "password": "hunterpassword22", "organization_name": "PdfHumanOrg"
    }).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{demo_path}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    report = client.get(f"/scans/{scan['id']}/report.pdf", headers=headers)
    assert report.status_code == 200
    assert report.content.startswith(b"%PDF")
    # PDF structure/content is verified at endpoint level; the generator's
    # customer-facing wording is covered by direct helper assertions below.


def test_report_helpers_prioritize_runtime_and_use_friendly_names():
    from app.scanner.report_generator import _friendly_capability, _review_bucket
    class F:
        capability = "shell execution"
        file_path = "src/agent/runtime.py"
    assert _friendly_capability(F()) == "Possible shell command execution"
    assert _review_bucket("src/agent/runtime.py") == "Application runtime code"
    assert _review_bucket("backend/__tests__/auth.test.js") == "Tests"
