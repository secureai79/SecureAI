
from app.scanner import llm_analyzer


def test_refine_findings_preserves_findings_marked_false_positive(monkeypatch):
    original = {
        "capability": "refund",
        "category": "financial",
        "file_path": "app.py",
        "snippet": "refund(amount)",
        "confidence": 0.8,
        "ai_connected": True,
        "human_approval_detected": False,
        "limit_detected": False,
        "severity": "HIGH",
    }

    monkeypatch.setattr(
        llm_analyzer,
        "_client",
        lambda: object(),
    )

    def fake_refine(finding):
        result = dict(finding)
        result["_llm_suggested_false_positive"] = True
        return result

    monkeypatch.setattr(
        llm_analyzer,
        "refine_finding",
        fake_refine,
    )
    monkeypatch.setattr(
        llm_analyzer,
        "external_llm_enabled",
        lambda: True,
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    results = llm_analyzer.refine_findings([original])

    assert len(results) == 1
    assert results[0]["severity"] == "HIGH"
    assert results[0]["_llm_suggested_false_positive"] is True
