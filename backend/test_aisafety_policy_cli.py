import datetime as dt
import http.server
import json
import os
import subprocess
import sys
import threading

sys.path.insert(0, os.path.dirname(__file__))

import pytest

from aisafety import cli, github, policy as pol, reports, scan as scan_mod

HERE = os.path.dirname(__file__)
TODAY = dt.date(2026, 10, 18)


def F(sev="HIGH", category="INFRASTRUCTURE", capability="execute", path="app/agent.py", line=10, fp=None, **kw):
    base = {"severity": sev, "category": category, "capability": capability, "file_path": path, "line": line,
            "title": f"{sev} {category} {capability}", "recommendation": "fix it", "finding_domain": "AI_SAFETY",
            "fingerprint": fp or f"{category}-{capability}-{path}-{line}", "scored": True, "confidence": 0.9,
            "ai_controlled": True, "human_approval_detected": False}
    base.update(kw)
    return base


def parse(d):
    return pol.parse_policy(d, "test")


def ev(policy, findings, score=80, base=None):
    return pol.evaluate(policy, findings, score=score, base_fingerprints=base, today=TODAY)


# ------------------------------------------------------------ policy parsing
@pytest.mark.parametrize("bad,msg", [
    ({"fial_on": "high"}, "unknown key"),
    ({"fail_on": "severe"}, "not a severity"),
    ({"min_score": 101}, "min_score"),
    ({"min_score": True}, "min_score"),
    ({"max_findings": {"urgent": 1}}, "not a severity"),
    ({"max_findings": {"high": -1}}, "non-negative"),
    ({"version": 2}, "unsupported version"),
    ({"new_only": "yes"}, "true or false"),
    ({"ignore_paths": "tests/**"}, "list of glob"),
    ({"rules": [{"id": "a", "match": {"categroy": "X"}, "action": "block"}]}, "unknown match key"),
    ({"rules": [{"id": "a", "match": {"category": "X"}, "action": "deny"}]}, "action must be"),
    ({"rules": [{"match": {"category": "X"}, "action": "block"}]}, "'id' is required"),
    ({"rules": [{"id": "a", "match": {}, "action": "block"}]}, "non-empty"),
    ({"rules": [{"id": "a", "match": {"category": "X"}, "action": "block"},
                {"id": "a", "match": {"category": "Y"}, "action": "warn"}]}, "duplicate rule id"),
    ({"rules": [{"id": "a", "match": {"domain": "NOPE"}, "action": "block"}]}, "domain must be"),
    ({"suppressions": [{"fingerprint": "x", "reason": "short", "expires": "2027-01-01"}]}, "reason"),
    ({"suppressions": [{"fingerprint": "x", "reason": "a long enough reason"}]}, "expires"),
    ({"suppressions": [{"fingerprint": "x", "reason": "a long enough reason", "expires": "soon"}]}, "date like"),
    ({"suppressions": [{"reason": "a long enough reason", "expires": "2027-01-01"}]}, "fingerprint"),
    (["not", "a", "mapping"], "mapping"),
])
def test_invalid_policies_are_rejected_loudly(bad, msg):
    with pytest.raises(pol.PolicyError, match=msg):
        parse(bad)


def test_valid_policy_parses_and_empty_policy_uses_defaults():
    p = parse({"fail_on": "critical", "min_score": 50, "max_findings": {"high": 2}, "ignore_paths": ["tests/**"],
               "rules": [{"id": "r", "match": {"severity": ">=high", "category": ["FINANCIAL", "data"]}, "action": "warn"}],
               "suppressions": [{"fingerprint": "abc", "reason": "accepted by security", "expires": "2027-01-31"}]})
    assert p.fail_on == "CRITICAL" and p.max_findings == {"HIGH": 2} and p.suppressions[0].expires == dt.date(2027, 1, 31)
    assert parse(None).fail_on == "HIGH" and parse({"fail_on": "none"}).fail_on is None


def test_yaml_policy_file_loads_and_uses_safe_loader(tmp_path):
    f = tmp_path / ".aisafety.yml"
    f.write_text("version: 1\nfail_on: medium\n", encoding="utf-8")
    assert pol.load_policy(str(f)).fail_on == "MEDIUM"
    evil = tmp_path / "evil.yml"
    evil.write_text("fail_on: !!python/object/apply:os.system ['touch /tmp/YAML_RCE']\n", encoding="utf-8")
    with pytest.raises(pol.PolicyError):
        pol.load_policy(str(evil))
    assert not os.path.exists("/tmp/YAML_RCE")
    j = tmp_path / ".aisafety.json"
    j.write_text('{"fail_on": "low"}', encoding="utf-8")
    assert pol.load_policy(str(j)).fail_on == "LOW"
    assert pol.find_policy_file(str(tmp_path)).endswith(".aisafety.yml")


def test_shipped_example_policy_is_valid():
    p = pol.load_policy(os.path.join(HERE, "..", "examples", "aisafety.example.yml"))
    assert len(p.rules) == 4 and len(p.suppressions) == 1


# ---------------------------------------------------------------- evaluation
def test_default_threshold_blocks_high_and_critical_only():
    d = ev(parse({}), [F("CRITICAL", fp="a"), F("HIGH", fp="b"), F("MEDIUM", fp="c"), F("LOW", fp="d")])
    assert not d.passed
    assert [e.finding["severity"] for e in d.by_status("blocking")] == ["CRITICAL", "HIGH"]
    assert len(d.by_status("warning")) == 2


def test_fail_on_none_never_blocks_and_medium_threshold():
    assert ev(parse({"fail_on": "none"}), [F("CRITICAL")]).passed
    assert not ev(parse({"fail_on": "medium"}), [F("MEDIUM")]).passed


def test_new_only_lets_existing_findings_through_but_worse_ones_block():
    f = F("HIGH", fp="x")
    assert ev(parse({}), [f], base={"x"}).passed                      # already on base
    assert not ev(parse({}), [f], base=set()).passed                  # introduced by the PR
    assert not ev(parse({"new_only": False}), [f], base={"x"}).passed # new_only disabled


def test_rule_precedence_first_match_wins_and_actions():
    p = parse({"rules": [
        {"id": "allow-tests", "match": {"path": "tests/**"}, "action": "ignore"},
        {"id": "no-shell", "match": {"category": "INFRASTRUCTURE", "capability": "execute"}, "action": "block", "message": "no shell"},
        {"id": "soft", "match": {"category": "DATA"}, "action": "warn"},
    ]})
    d = ev(p, [F("LOW", path="tests/t.py", fp="1"), F("LOW", fp="2"), F("CRITICAL", category="DATA", capability="delete", fp="3")])
    st = {e.finding["fingerprint"]: (e.status, e.rule_id) for e in d.evaluated}
    assert st == {"1": ("ignored", "allow-tests"), "2": ("blocking", "no-shell"), "3": ("warning", "soft")}
    assert d.by_status("blocking")[0].reason == "no shell"


def test_rule_even_if_existing_blocks_pre_existing_findings():
    p = parse({"rules": [{"id": "tri", "match": {"capability": "lethal_trifecta"}, "action": "block", "even_if_existing": True},
                         {"id": "shell", "match": {"capability": "execute"}, "action": "block"}]})
    tri = F("CRITICAL", category="PROMPT_INJECTION", capability="lethal_trifecta", fp="t")
    sh = F("HIGH", fp="s")
    d = ev(p, [tri, sh], base={"t", "s"})
    assert [e.finding["fingerprint"] for e in d.by_status("blocking")] == ["t"]
    assert [e.finding["fingerprint"] for e in d.by_status("existing")] == ["s"]


@pytest.mark.parametrize("match,finding,expected", [
    ({"severity": ">=high"}, F("CRITICAL"), True), ({"severity": ">=high"}, F("MEDIUM"), False),
    ({"severity": ["low", "medium"]}, F("MEDIUM"), True), ({"domain": "PROJECT_SECURITY"}, F(), False),
    ({"ai_controlled": False}, F(), False), ({"human_approval": False}, F(), True),
    ({"title_contains": "EXECUTE"}, F(), True), ({"path": ["app/*.py"]}, F(), True),
    ({"category": "infrastructure"}, F(), True), ({"capability": ["a", "b"]}, F(), False),
])
def test_match_conditions(match, finding, expected):
    p = parse({"fail_on": "none", "rules": [{"id": "r", "match": match, "action": "block"}]})
    assert (len(ev(p, [finding]).by_status("blocking")) == 1) is expected


def test_min_score_and_max_findings():
    d = ev(parse({"fail_on": "none", "min_score": 70}), [], score=65)
    assert not d.passed and "below min_score 70" in d.reasons[0]
    d = ev(parse({"fail_on": "none", "max_findings": {"high": 1}}), [F("HIGH", fp="a"), F("HIGH", fp="b")])
    assert not d.passed and "exceed max_findings.high=1" in d.reasons[0]
    assert ev(parse({"fail_on": "none", "min_score": 70}), [], score=70).passed


def test_suppressions_need_to_be_unexpired():
    ok = {"fingerprint": "fp1", "reason": "accepted after security review", "expires": "2027-01-31"}
    old = {"fingerprint": "fp2", "reason": "accepted after security review", "expires": "2026-01-01"}
    p = parse({"suppressions": [ok, old]})
    d = ev(p, [F("CRITICAL", fp="fp1"), F("CRITICAL", fp="fp2")])
    assert [e.finding["fingerprint"] for e in d.by_status("suppressed")] == ["fp1"]
    assert [e.finding["fingerprint"] for e in d.by_status("blocking")] == ["fp2"]       # expired -> enforced again
    assert any("expired" in n for n in d.notes)


def test_unscored_leads_and_ignored_paths_do_not_block():
    p = parse({"ignore_paths": ["vendor/**"]})
    d = ev(p, [F("CRITICAL", scored=False, fp="u"), F("CRITICAL", path="vendor/x.py", fp="v")])
    assert d.passed and [e.status for e in d.evaluated] == ["ignored"]
    assert not ev(parse({"include_unscored": True}), [F("CRITICAL", scored=False)]).passed


# ------------------------------------------------------------------ reports
HOSTILE = "@octocat [click](http://evil.example/x) <img src=x onerror=alert(1)> `` ``` **bold** www.evil.io\n# heading"


def hostile_decision():
    f = F("HIGH", title=HOSTILE, path="a`b|c.py", recommendation=HOSTILE, capability_chain=[HOSTILE, "Prompt", "Tool"])
    return ev(parse({}), [f]), f


def make_result(findings):
    from app.scanner import risk_engine
    return scan_mod.ScanResult(root=".", findings=findings, score=risk_engine.calculate_score(findings),
                               domain_scores=risk_engine.calculate_domain_scores(findings), stats={})


def test_markdown_neutralises_attacker_controlled_text():
    d, f = hostile_decision()
    md = reports.render_markdown(make_result([f]), d, parse({}))
    assert md.startswith(reports.MARKER)
    assert "<img" not in md and "](http" not in md and "http://evil" not in md and "www.evil" not in md
    assert "@octocat" not in md and "@\u200boctocat" in md
    assert "\n# heading" not in md and "```" not in md


def test_markdown_is_truncated_for_huge_result_sets():
    fs = [F("HIGH", fp=f"f{i}", line=i) for i in range(200)]
    d = ev(parse({}), fs)
    md = reports.render_markdown(make_result(fs), d, parse({}))
    assert "and 175 more" in md and len(md) < 60000


def test_workflow_annotations_cannot_inject_commands():
    line = github.annotation("error", "a.py\n::error::pwned,x:y", 5, "t%\n::set-output name=x::1", "msg\r\n::error::owned")
    assert "\n" not in line and "\r" not in line
    assert line.startswith("::error file=a.py%0A%3A%3Aerror%3A%3Apwned%2Cx%3Ay,line=5,title=")
    # GitHub only recognises a command at the START of a physical line; with every newline escaped
    # the whole annotation is a single line, so nothing in the data can start a second command.
    assert len(line.splitlines()) == 1


def test_sarif_is_structurally_valid_and_marks_suppressions():
    p = parse({"suppressions": [{"fingerprint": "s", "reason": "accepted after security review", "expires": "2027-01-31"}]})
    fs = [F("CRITICAL", fp="a"), F("MEDIUM", fp="b", category="DATA", capability="delete"), F("LOW", fp="s")]
    d = ev(p, fs)
    s = json.loads(reports.render_sarif(make_result(fs), d, p))
    assert s["version"] == "2.1.0" and s["$schema"].endswith("sarif-2.1.0.json")
    run = s["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))
    levels = {r["partialFingerprints"]["aiSafetyFingerprint/v1"]: r["level"] for r in run["results"]}
    assert levels == {"a": "error", "b": "warning", "s": "note"}
    assert all(r["ruleId"] in ids and r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in run["results"])
    assert [r for r in run["results"] if r.get("suppressions")][0]["partialFingerprints"]["aiSafetyFingerprint/v1"] == "s"


def test_json_and_text_reports():
    d, f = hostile_decision()
    data = json.loads(reports.render_json(make_result([f]), d, parse({})))
    assert data["passed"] is False and data["findings"][0]["status"] == "blocking"
    text = reports.render_text(make_result([f]), d, parse({}))
    assert "FAILED" in text and "BLOCKING" in text


# ------------------------------------------------------------- end-to-end CLI
AGENT_SAFE = '''
from openai import OpenAI
client = OpenAI()
def answer(q):
    return client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
'''
AGENT_RISKY = '''
import subprocess
from openai import OpenAI
client = OpenAI()
def answer(q):
    out = client.chat.completions.create(model="m", messages=[{"role": "user", "content": q}])
    subprocess.run(out.choices[0].message.content, shell=True)
'''


def git(repo, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.x", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@e.x", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "proj"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "agent.py").write_text(AGENT_SAFE, encoding="utf-8")
    git(r, "add", "-A"); git(r, "commit", "-qm", "base")
    return r


def run_cli(*argv, capsys=None):
    return cli.main(list(argv))


def test_pr_mode_blocks_new_findings_only(repo, capsys, tmp_path):
    (repo / "agent.py").write_text(AGENT_RISKY, encoding="utf-8")
    git(repo, "commit", "-qam", "add shell")
    sarif, md, js = tmp_path / "o.sarif", tmp_path / "o.md", tmp_path / "o.json"
    code = run_cli("scan", str(repo), "--base-ref", "HEAD~1", "--sarif", str(sarif), "--markdown", str(md),
                   "--json", str(js), "--github-annotations")
    out = capsys.readouterr().out
    assert code == 1
    assert "::error file=agent.py" in out
    assert json.loads(js.read_text(encoding="utf-8"))["passed"] is False
    assert md.read_text(encoding="utf-8").startswith(reports.MARKER)
    assert json.loads(sarif.read_text(encoding="utf-8"))["runs"][0]["results"]
    # nothing new relative to itself -> passes even though a HIGH exists
    assert run_cli("scan", str(repo), "--base-ref", "HEAD") == 0
    # without a base, the finding blocks
    assert run_cli("scan", str(repo)) == 1


def test_baseline_mode_and_write_baseline(repo, tmp_path, capsys):
    (repo / "agent.py").write_text(AGENT_RISKY, encoding="utf-8")
    base = tmp_path / "baseline.json"
    assert run_cli("scan", str(repo), "--write-baseline", str(base)) == 0
    assert run_cli("scan", str(repo), "--baseline", str(base)) == 0
    (repo / "agent2.py").write_text(AGENT_RISKY.replace("def answer", "def answer2"), encoding="utf-8")
    assert run_cli("scan", str(repo), "--baseline", str(base)) == 1


def test_policy_file_is_discovered_and_overrides_work(repo):
    (repo / "agent.py").write_text(AGENT_RISKY, encoding="utf-8")
    assert run_cli("scan", str(repo)) == 1
    (repo / ".aisafety.yml").write_text("version: 1\nignore_paths: ['agent.py']\n", encoding="utf-8")
    assert run_cli("scan", str(repo)) == 0
    assert run_cli("scan", str(repo), "--policy", os.devnull) == 1         # empty policy = built-in defaults
    (repo / ".aisafety.yml").write_text("fail_on: none\n", encoding="utf-8")
    assert run_cli("scan", str(repo)) == 0
    assert run_cli("scan", str(repo), "--fail-on", "high") == 1


def test_error_exit_codes(repo, tmp_path, capsys):
    (repo / ".aisafety.yml").write_text("fial_on: high\n", encoding="utf-8")
    assert run_cli("scan", str(repo)) == 2
    (repo / ".aisafety.yml").unlink()
    assert run_cli("scan", str(tmp_path / "missing")) == 3
    assert run_cli("scan", str(repo), "--base-ref", "no-such-ref") == 3
    assert run_cli("scan", str(repo), "--base-ref=--output=x") == 3        # option-injection guard
    assert run_cli("scan", str(repo), "--base-ref", "HEAD", "--baseline", "x") == 2
    assert run_cli("policy-check", str(repo / "nope.yml")) == 2


def test_base_ref_rejects_option_injection(repo):
    with pytest.raises(scan_mod.ScanError):
        scan_mod.scan_git_ref(str(repo), "--output=/tmp/pwn")
    with pytest.raises(scan_mod.ScanError):
        scan_mod.scan_git_ref(str(repo), "HEAD\n--x")


def test_subdirectory_scan_with_base_ref(repo):
    sub = repo / "svc"
    sub.mkdir()
    (sub / "agent.py").write_text(AGENT_SAFE, encoding="utf-8")
    git(repo, "add", "-A"); git(repo, "commit", "-qm", "svc")
    (sub / "agent.py").write_text(AGENT_RISKY, encoding="utf-8")
    git(repo, "commit", "-qam", "risky")
    assert run_cli("scan", str(sub), "--base-ref", "HEAD~1") == 1


# ------------------------------------------------------------ GitHub comments
class FakeGitHub(http.server.BaseHTTPRequestHandler):
    comments = []
    forbid = False
    log = []

    def _send(self, code, body=None):
        raw = json.dumps(body if body is not None else {}).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def _body(self):
        return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0) or b"{}")

    def do_GET(self):
        FakeGitHub.log.append(("GET", self.path, self.headers.get("Authorization")))
        self._send(403) if FakeGitHub.forbid else self._send(200, FakeGitHub.comments)

    def do_POST(self):
        FakeGitHub.log.append(("POST", self.path, None))
        if FakeGitHub.forbid:
            return self._send(403)
        c = {"id": len(FakeGitHub.comments) + 1, "body": self._body()["body"]}
        FakeGitHub.comments.append(c); self._send(201, c)

    def do_PATCH(self):
        FakeGitHub.log.append(("PATCH", self.path, None))
        cid = int(self.path.rsplit("/", 1)[1])
        for c in FakeGitHub.comments:
            if c["id"] == cid:
                c["body"] = self._body()["body"]
        self._send(200, {})

    def log_message(self, *a):
        pass


@pytest.fixture()
def fake_github():
    FakeGitHub.comments, FakeGitHub.forbid, FakeGitHub.log = [], False, []
    srv = http.server.HTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_comment_is_created_then_updated_not_duplicated(fake_github):
    body1 = reports.MARKER + "\nfirst"
    assert github.post_or_update_comment("o/r", 7, body1, "tok", fake_github) == "created"
    assert github.post_or_update_comment("o/r", 7, reports.MARKER + "\nsecond", "tok", fake_github) == "updated"
    assert len(FakeGitHub.comments) == 1 and "second" in FakeGitHub.comments[0]["body"]
    assert FakeGitHub.log[0][2] == "Bearer tok"


def test_other_peoples_comments_are_never_touched(fake_github):
    FakeGitHub.comments.append({"id": 1, "body": "unrelated human comment"})
    assert github.post_or_update_comment("o/r", 7, reports.MARKER + "x", "tok", fake_github) == "created"
    assert FakeGitHub.comments[0]["body"] == "unrelated human comment" and len(FakeGitHub.comments) == 2


def test_fork_prs_with_readonly_token_do_not_fail_the_check(fake_github):
    FakeGitHub.forbid = True
    assert github.post_or_update_comment("o/r", 7, "x", "tok", fake_github).startswith("skipped: GitHub returned 403")
    assert github.post_or_update_comment("o/r", 7, "x", "tok", "http://127.0.0.1:9").startswith("skipped")


def test_cli_comment_flag_posts_and_reads_pr_number_from_event(repo, fake_github, tmp_path, monkeypatch):
    (repo / "agent.py").write_text(AGENT_RISKY, encoding="utf-8")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 42}}), encoding="utf-8")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_API_URL", fake_github)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert run_cli("scan", str(repo), "--comment", "--repo", "o/r") == 1
    assert FakeGitHub.comments and FakeGitHub.comments[0]["body"].startswith(reports.MARKER)
    assert any("/issues/42/comments" in p for _, p, _ in FakeGitHub.log)
    assert summary.read_text(encoding="utf-8").startswith(reports.MARKER)


# ------------------------------------------------------------------- action
def test_action_yml_is_well_formed_and_avoids_script_injection():
    import yaml
    path = os.path.join(HERE, "..", "action.yml")
    a = yaml.safe_load(open(path, encoding="utf-8"))
    assert a["runs"]["using"] == "composite"
    run_blocks = [s["run"] for s in a["runs"]["steps"] if "run" in s]
    assert all("${{" not in r for r in run_blocks), "never interpolate ${{ }} expressions into shell scripts"
    assert {"path", "policy", "fail-on", "base-ref", "comment", "sarif", "github-token"} <= set(a["inputs"])
    scan_step = next(s for s in a["runs"]["steps"] if s.get("id") == "scan")
    assert scan_step["env"]["INPUT_POLICY"] == "${{ inputs.policy }}"
    assert any(s.get("uses", "").startswith("github/codeql-action/upload-sarif@") for s in a["runs"]["steps"])
    wf = yaml.safe_load(open(os.path.join(HERE, "..", "docs", "ci", "ai-safety.yml"), encoding="utf-8"))
    assert wf["permissions"]["security-events"] == "write" and wf["permissions"]["pull-requests"] == "write"