import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import capability_extractor, risk_engine


def test_regex_fallback_finding_is_not_scored_and_capped_low():
    """A .ts/.js file always goes through the regex fallback (no AST for
    those languages), which real-repo validation showed produces heavy
    false positives -- it must never contribute CRITICAL/HIGH to the score."""
    src = '''
import { OpenAI } from "openai";
const client = new OpenAI();

function useDeleteTaskHandler() {
  // just a UI button handler, nothing destructive
  return function handleDelete() { removeFromList(); };
}
'''
    analysis = capability_extractor.analyze_file("src/components/TaskList.tsx", src)
    findings = risk_engine.build_findings_for_file(analysis, True)
    assert len(findings) >= 1
    for f in findings:
        assert f["scored"] is False
        assert f["severity"] == "LOW"
        assert f["potential_points"] == 0
        assert "Potential capability detected" in f["title"]
        assert any("Not scored" in e for e in f["evidence"])


def test_ast_finding_in_test_directory_is_not_scored():
    """The same dangerous call, same file content, differs only by path:
    a real agents/ file should score, a tests/ file should not."""
    src = '''
import subprocess
from openai import OpenAI
client = OpenAI()

def run_something():
    subprocess.run(["some", "command"])
'''
    runtime_analysis = capability_extractor.analyze_file("agents/tool.py", src)
    test_analysis = capability_extractor.analyze_file("tests/test_tool.py", src)

    runtime_findings = risk_engine.build_findings_for_file(runtime_analysis, True)
    test_findings = risk_engine.build_findings_for_file(test_analysis, True)

    assert len(runtime_findings) == 1
    assert runtime_findings[0]["scored"] is True
    assert runtime_findings[0]["severity"] == "MEDIUM"  # HIGH base, downgraded one step since ai_controlled=False

    assert len(test_findings) == 1
    assert test_findings[0]["scored"] is False
    assert test_findings[0]["severity"] == "LOW"


def test_tools_directory_is_not_treated_as_non_runtime():
    """agent frameworks commonly put real agent capabilities under a
    `tools/` directory (e.g. a PersistentShellTool) -- this must NOT be
    excluded the way tests/scripts/docs/examples are."""
    src = '''
import subprocess
from openai import OpenAI
client = OpenAI()

def run_shell_tool():
    subprocess.run(["echo", "hi"])
'''
    analysis = capability_extractor.analyze_file("src/agents/tools/built_in/ShellTool.py", src)
    findings = risk_engine.build_findings_for_file(analysis, True)
    assert len(findings) == 1
    assert findings[0]["scored"] is True


def test_calculate_score_excludes_unscored_findings():
    scored_high = {"severity": "HIGH", "status": "open", "scored": True}
    unscored_critical = {"severity": "LOW", "status": "open", "scored": False}  # already capped by the gate

    result = risk_engine.calculate_score([scored_high, unscored_critical])
    assert result["score"] == 100 - risk_engine.SEVERITY_POINTS["HIGH"]
    assert result["counts"]["HIGH"] == 1
    assert result["counts"]["LOW"] == 0  # the unscored one must not appear in counts either
    assert result["unscored_count"] == 1


def test_deploy_false_positive_fixed():
    """The exact false positive found in real-repo validation: a method
    literally named `.deploy()` on an unrelated object (OpenAI's own
    `swarm.deploy()`) must not match."""
    from app.scanner import ast_detector

    src = '''
from openai import OpenAI
client = OpenAI()

class Swarm:
    def deploy(self, test_mode=False):
        pass

swarm = Swarm()
swarm.deploy(test_mode=True)
'''
    result = ast_detector.analyze_python_ast("swarm.py", src)
    assert len(result.findings) == 0


def test_deploy_still_detected_for_real_infra_calls():
    from app.scanner import ast_detector

    src = '''
from openai import OpenAI
import boto3
client = OpenAI()
ecs_client = boto3.client("ecs")

def deploy_infra():
    ecs_client.deploy(cluster="prod")
'''
    result = ast_detector.analyze_python_ast("infra.py", src)
    assert len(result.findings) == 1
    assert result.findings[0].operation == "deploy"


def test_deploy_detected_via_subprocess_command_keyword():
    from app.scanner import ast_detector

    src = '''
from openai import OpenAI
import subprocess
client = OpenAI()

def deploy():
    subprocess.run(["docker", "deploy", "stack", "myapp"])
'''
    result = ast_detector.analyze_python_ast("deploy.py", src)
    assert len(result.findings) == 1
    assert result.findings[0].operation == "deploy"


def test_plain_subprocess_call_stays_execute_not_deploy():
    from app.scanner import ast_detector

    src = '''
from openai import OpenAI
import subprocess
client = OpenAI()

def run_tests():
    subprocess.run(["pytest", "-v"])
'''
    result = ast_detector.analyze_python_ast("run_tests.py", src)
    assert len(result.findings) == 1
    assert result.findings[0].operation == "execute"

def test_generic_capability_in_non_runtime_path_is_suppressed():
    """Generic capability keywords in test/tooling paths should not become
    potential leads unless stronger dangerous-library evidence exists."""
    src = '''
import { OpenAI } from "openai";

function testSomething() {
  items.push(value);
  removeFromList();
}
'''

    analysis = capability_extractor.analyze_file(
        "tests/skills/algorithmic-art/templates/generator_template.js",
        src,
    )

    findings = risk_engine.build_findings_for_file(analysis, True)

    assert findings == []


def test_generic_capability_in_runtime_path_remains_potential_lead():
    """The same generic capability in a runtime path should remain visible
    as an unscored LOW lead for manual review."""
    src = '''
import { OpenAI } from "openai";

function updateAgentState() {
  items.push(value);
}
'''

    analysis = capability_extractor.analyze_file(
        "src/agent/state.js",
        src,
    )

    findings = risk_engine.build_findings_for_file(analysis, True)

    assert len(findings) >= 1

    for finding in findings:
        assert finding["scored"] is False
        assert finding["severity"] == "LOW"
        assert finding["potential_points"] == 0
        assert "Potential capability detected" in finding["title"]

def test_dom_anchor_remove_is_not_detected_as_data_removal():
    """Removing a temporary DOM anchor after a browser download is not
    application data deletion."""
    src = '''
function download(entry) {
  const a = document.createElement("a");
  a.href = entry.url;
  a.download = `ranano-${entry.id}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}
'''

    analysis = capability_extractor.analyze_file(
        "frontend/src/components/HistoryGallery.jsx",
        src,
    )

    findings = risk_engine.build_findings_for_file(analysis, True)

    assert not any(
        f.get("capability") == "remove"
        for f in findings
    )


def test_control_status_without_approval_or_limit():
    assert risk_engine._control_status(False, False) == "UNCONTROLLED"


def test_control_status_with_approval_only():
    assert risk_engine._control_status(True, False) == "PARTIALLY_CONTROLLED"


def test_control_status_with_limit_only():
    assert risk_engine._control_status(False, True) == "PARTIALLY_CONTROLLED"


def test_control_status_with_approval_and_limit():
    assert risk_engine._control_status(True, True) == "CONTROLLED"


def test_ast_finding_includes_control_status():
    src = '''
import subprocess
from openai import OpenAI

client = OpenAI()

def run_something():
    subprocess.run(["echo", "hello"])
'''
    analysis = capability_extractor.analyze_file("agents/tool.py", src)
    findings = risk_engine.build_findings_for_file(analysis, True)

    assert findings
    assert "control_status" in findings[0]
    assert findings[0]["control_status"] in {
        "UNCONTROLLED",
        "PARTIALLY_CONTROLLED",
        "CONTROLLED",
    }


def test_regex_finding_includes_control_status():
    src = '''
import { OpenAI } from "openai";
const client = new OpenAI();
function refundCustomer() {
    refundCustomer();
}
'''
    analysis = capability_extractor.analyze_file("src/agent.js", src)
    findings = risk_engine.build_findings_for_file(analysis, True)

    assert findings
    assert all("control_status" in finding for finding in findings)
