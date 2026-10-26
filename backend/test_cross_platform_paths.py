import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import file_selector


def test_select_files_always_returns_forward_slash_paths(tmp_path, monkeypatch):
    """On Windows, os.path.relpath returns backslash-separated paths
    (e.g. 'agents\\refund_agent.py'), which broke anything downstream that
    assumed forward slashes -- reported as a real StopIteration test
    failure when running on Windows. select_files() must normalize to
    forward slashes regardless of the OS it runs on, matching how
    git/GitHub always display paths."""
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    (agents_dir / "refund_agent.py").write_text("# hi\n")

    files = file_selector.select_files(str(tmp_path))
    assert "agents/refund_agent.py" in files
    assert not any("\\" in f for f in files)


def test_select_files_normalizes_even_if_os_sep_is_backslash(tmp_path, monkeypatch):
    """Directly force the Windows code path (os.sep == '\\\\') to prove the
    normalization logic itself is correct, not just that it's a no-op on
    the Linux/macOS environments tests normally run in."""
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    (agents_dir / "refund_agent.py").write_text("# hi\n")

    real_relpath = os.path.relpath

    def fake_relpath(path, start):
        # Simulate Windows' relpath by taking the real (forward-slash, on
        # this test-running OS) result and converting it to backslashes,
        # the way it would actually come back on a Windows machine.
        return real_relpath(path, start).replace("/", "\\")

    monkeypatch.setattr(os.path, "relpath", fake_relpath)
    monkeypatch.setattr(file_selector.os.path, "sep", "\\", raising=False)
    monkeypatch.setattr(file_selector.os, "sep", "\\", raising=False)

    files = file_selector.select_files(str(tmp_path))
    assert "agents/refund_agent.py" in files
    assert not any("\\" in f for f in files)


def test_is_non_runtime_path_handles_backslash_paths_too():
    """Defense in depth: even if a backslash path somehow reaches this
    function directly, it should still classify correctly."""
    assert file_selector.is_non_runtime_path("tests\\test_something.py") is True
    assert file_selector.is_non_runtime_path("agents\\refund_agent.py") is False
