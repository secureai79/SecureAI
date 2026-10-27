"""Regression tests for generic detector false positives.

Run from the repository root with:
    python -m pytest -q backend/tests/test_remove_false_positive.py
"""
import importlib.util
from pathlib import Path

DETECTORS = Path(__file__).parents[1] / "app" / "scanner" / "detectors.py"
spec = importlib.util.spec_from_file_location("secureai_detectors_under_test", DETECTORS)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_ui_remove_function_definition_is_not_data_deletion():
    source = """
function remove() {
  if (bar && bar.parentNode) bar.parentNode.removeChild(bar);
  bar = null;
}
"""
    findings = module.detect_dangerous_functions(source)
    assert not any(f["keyword"] == "remove" for f in findings)


def test_dom_remove_call_is_not_data_deletion():
    source = "function closeBanner() { banner.remove(); }"
    findings = module.detect_dangerous_functions(source)
    assert not any(f["keyword"] == "remove" for f in findings)


def test_persistent_storage_remove_remains_detectable():
    source = "storage.remove(key)"
    findings = module.detect_dangerous_functions(source)
    assert any(f["keyword"] == "remove" for f in findings)


def test_raw_sql_delete_remains_detectable():
    source = "cursor.execute('DELETE FROM users WHERE id = 1')"
    findings = module.detect_dangerous_functions(source)
    assert any(f["keyword"] == "delete" for f in findings)
