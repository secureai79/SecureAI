from app.scanner.detectors import detect_dangerous_functions


def test_dom_and_ui_remove_calls_are_not_data_deletion():
    source = """
    overlay.remove();
    old.remove();
    document.removeEventListener("keydown", onKey, true);
    """
    findings = detect_dangerous_functions(source)
    assert not any(f["keyword"] == "remove" for f in findings)


def test_filesystem_remove_remains_detectable():
    findings = detect_dangerous_functions('os.remove("/tmp/example.txt")')
    assert any(f["keyword"] == "remove" and f["object"] == "os" for f in findings)


def test_array_push_is_not_code_push():
    findings = detect_dangerous_functions("candidates.push(answer)")
    assert not any(f["keyword"] == "push" for f in findings)


def test_unknown_terminate_and_deploy_methods_are_not_inferred_as_infrastructure():
    findings = detect_dangerous_functions("workflow.terminate(); swarm.deploy();")
    assert not any(f["keyword"] in {"terminate", "deploy"} for f in findings)
