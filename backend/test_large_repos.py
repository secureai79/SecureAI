"""Large repositories: graceful partial scans with honest coverage, cheap clones, plan-scaled limits."""
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

AGENT = "import openai\n\ndef run(x):\n    return openai.chat.completions.create(model='gpt-4o', messages=[])\n"


def make_repo(root, n_plain=30, with_agent=True):
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    for i in range(n_plain):
        (root / "pkg" / f"util_{i:03d}.py").write_text(f"def f{i}():\n    return {i}\n")
    if with_agent:
        (root / "agents").mkdir(exist_ok=True)
        (root / "agents" / "support_agent.py").write_text(AGENT)
    return root


def stats(root):
    from app.scanner import pipeline
    return pipeline.analyze_directory(str(root))


# ------------------------------------------------------------------ pipeline
def test_over_the_file_cap_scans_the_most_relevant_files_and_reports_the_rest(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_FILES", "5")
    make_repo(tmp_path)
    r = stats(tmp_path)
    s = r["stats"]
    assert s["files"] == 5 and s["files_total"] == 31 and s["skipped_over_limit"] == 26
    assert any(a["file_path"] == "agents/support_agent.py" for a in r["agents"])   # AI code scanned first
    assert s["unscanned_examples"]


def test_absurdly_large_repositories_are_still_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_FILES", "1")
    make_repo(tmp_path, n_plain=40)
    with pytest.raises(ValueError, match="too many scannable files"):
        stats(tmp_path)


def test_oversized_single_files_are_skipped_but_reported_not_hidden(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_FILE_BYTES", "1000")
    make_repo(tmp_path, n_plain=2)
    (tmp_path / "pkg" / "huge.py").write_text("x = 1\n" * 1000)
    s = stats(tmp_path)["stats"]
    assert s["skipped_large"] == 1 and "pkg/huge.py" in s["unscanned_examples"]
    monkeypatch.setenv("MAX_SCAN_FILE_BYTES", "100000")
    assert stats(tmp_path)["stats"]["skipped_large"] == 0                      # and scanned when allowed


def test_byte_budget_is_soft_too(tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_BYTES", "200")
    make_repo(tmp_path, n_plain=20)
    s = stats(tmp_path)["stats"]
    assert 0 < s["files"] < 21 and s["skipped_over_limit"] > 0 and s["bytes"] <= 200


def test_time_budget_returns_a_partial_result_instead_of_failing(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_TIME_BUDGET_SECONDS", "0")
    make_repo(tmp_path)
    r = stats(tmp_path)
    assert r["stats"]["time_limited"] is True and r["stats"]["files"] < 31


def test_generated_and_lock_files_are_never_analysed(tmp_path):
    from app.scanner import file_selector
    make_repo(tmp_path, n_plain=1)
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "app.min.js").write_text("var a=1;")
    assert not [f for f in file_selector.select_files(str(tmp_path)) if "lock" in f or ".min." in f]


# ------------------------------------------------------------------ worker protocol
def test_hostile_coverage_values_are_sanitised():
    from app.scanner import worker_protocol as wp
    base = {"version": 1, "agents": [], "ai_findings": [], "injection_findings": [], "security_findings": []}
    out = wp.validate_result({**base, "stats": {
        "files": 3, "bytes": 9, "repo_has_ai": False, "files_total": -5, "skipped_large": "lots",
        "skipped_over_limit": 10 ** 12, "time_limited": 1, "unscanned_examples": ["ok/file.py", "../../etc/passwd", 7]}})
    s = out["stats"]
    assert s["files_total"] == 0 and s["skipped_large"] == 0 and s["skipped_over_limit"] == 0
    assert s["unscanned_examples"] == ["ok/file.py"] and s["time_limited"] is True


# ------------------------------------------------------------------ end to end through the API
@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'big.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    with TestClient(app) as c:
        yield c


def _scan(client, repo_dir):
    r = client.post("/auth/signup", json={"email": "u@x.com", "password": "correct-horse-battery-1", "organization_name": "O"})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    repo = client.post("/repositories", json={"repo_url": f"file://{repo_dir}"}, headers=h).json()
    return client.post(f"/repositories/{repo['id']}/scan", headers=h).json(), h


def test_partial_scan_is_completed_and_exposes_coverage(client, tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_FILES", "5")
    scan, h = _scan(client, make_repo(tmp_path / "big"))
    assert scan["status"] == "completed" and scan["error"] is None
    cov = scan["coverage"]
    assert cov["files_scanned"] == 5 and cov["files_total"] == 31 and cov["skipped_over_limit"] == 26
    assert client.get(f"/scans/{scan['id']}", headers=h).json()["coverage"]["files_scanned"] == 5


def test_complete_scan_has_no_coverage_warning(client, tmp_path):
    scan, _ = _scan(client, make_repo(tmp_path / "small", n_plain=2))
    assert scan["status"] == "completed" and scan["coverage"] is None


# ------------------------------------------------------------------ clone
def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def test_clone_downloads_only_scannable_source_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app").mkdir()
    (src / "app" / "main.py").write_text("print(1)\n")
    (src / "app" / "config.yaml").write_text("a: 1\n")
    (src / "package.json").write_text("{}")
    (src / "assets").mkdir()
    (src / "assets" / "video.mp4").write_bytes(b"\0" * 3_000_000)
    (src / "assets" / "logo.png").write_bytes(b"\0" * 10_000)
    (src / "data.csv").write_text("a,b\n" * 1000)
    (src / "node_modules" / "dep").mkdir(parents=True)
    (src / "node_modules" / "dep" / "index.js").write_text("x=1")
    (src / "yarn.lock").write_text("lock")
    (src / "web.min.js").write_text("a=1")
    _git("init", "-q", "-b", "main", cwd=src)
    _git("config", "uploadpack.allowFilter", "true", cwd=src)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=src)
    _git("add", "-A", cwd=src)
    _git("commit", "-q", "-m", "init", cwd=src)
    from app.scanner import scan_service
    dest = tmp_path / "clone"
    scan_service._clone_repo(f"file://{src}", str(dest))
    present = sorted(os.path.relpath(os.path.join(d, f), dest).replace(os.sep, "/")
                     for d, dn, fs in os.walk(dest) if ".git" not in d.split(os.sep) for f in fs)
    assert present == ["app/config.yaml", "app/main.py", "package.json"], present


def test_clone_refuses_a_checkout_bigger_than_the_cap(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.json").write_text("[" + "1," * 400_000 + "1]")
    _git("init", "-q", "-b", "main", cwd=src)
    _git("config", "uploadpack.allowFilter", "true", cwd=src)
    _git("add", "-A", cwd=src)
    _git("commit", "-q", "-m", "init", cwd=src)
    from app.scanner import scan_service
    monkeypatch.setenv("MAX_CLONE_MB", "0")
    with pytest.raises(ValueError, match="larger than 0 MB"):
        scan_service._clone_repo(f"file://{src}", str(tmp_path / "c"))


# ------------------------------------------------------------------ plans
def test_plan_multiplies_limits_and_unknown_plans_fall_back_to_pilot():
    from app import limits
    base = limits.for_plan("pilot")
    team = limits.for_plan("team")
    assert team["max_files"] == base["max_files"] * 2 and team["time_budget"] == base["time_budget"] * 2
    assert limits.for_plan("nonsense") == base and limits.for_plan(None) == base
    assert limits.worker_env("team")["MAX_SCAN_FILES"] == str(team["max_files"])


def test_isolated_scans_hand_the_org_plan_limits_to_the_worker(tmp_path, monkeypatch):
    from app.scanner import scan_service
    env = scan_service._sandbox_env(str(tmp_path), "business")
    assert int(env["MAX_SCAN_FILES"]) == 20000 * 5 and "JWT_SECRET" not in env and "DATABASE_URL" not in env


def _pdf_text(data: bytes) -> bytes:
    """Concatenate the decoded content streams of a ReportLab PDF (ASCII85 + Flate)."""
    import base64
    import re as _re
    import zlib
    out = b""
    for m in _re.findall(rb"stream\r?\n(.*?)endstream", data, _re.S):
        chunk = m.strip()
        try:
            if chunk.endswith(b"~>"):
                chunk = base64.a85decode(chunk[:-2])
            out += zlib.decompress(chunk)
        except Exception:
            continue
    return out


def test_pdf_report_states_when_the_scan_was_partial(client, tmp_path, monkeypatch):
    monkeypatch.setenv("MAX_SCAN_FILES", "5")
    scan, h = _scan(client, make_repo(tmp_path / "big2"))
    partial = client.get(f"/scans/{scan['id']}/report.pdf", headers=h)
    assert partial.status_code == 200 and partial.content.startswith(b"%PDF")
    assert b"Partial scan" in _pdf_text(partial.content)
    monkeypatch.setenv("MAX_SCAN_FILES", "20000")
    scan2, h2 = _scan_again(client, h, tmp_path / "big2")
    full = client.get(f"/scans/{scan2['id']}/report.pdf", headers=h2)
    assert b"Partial scan" not in _pdf_text(full.content)


def _scan_again(client, h, repo_dir):
    repo = client.get("/repositories", headers=h).json()[0]
    return client.post(f"/repositories/{repo['id']}/scan", headers=h).json(), h
