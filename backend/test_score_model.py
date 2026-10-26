import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import risk_engine


def _mk(sev, scored=True, status="open"):
    return {"severity": sev, "status": status, "scored": scored}


def test_single_finding_per_tier_matches_old_flat_model():
    """A single finding of each severity should cost exactly the old flat
    per-finding amount -- the diminishing schedule's first step must equal
    SEVERITY_POINTS, so a lightly-flagged repo's score doesn't shift under
    the new model."""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        result = risk_engine.calculate_score([_mk(sev)])
        assert result["score"] == 100 - risk_engine.SEVERITY_POINTS[sev], sev


def test_many_medium_findings_do_not_zero_the_score():
    """The exact problem found in validation: a large repo with 50+
    legitimate-but-numerous MEDIUM findings and zero CRITICAL/HIGH must not
    score 0/100 -- that reads as "totally broken" when nothing severe was found."""
    findings = [_mk("MEDIUM") for _ in range(50)]
    result = risk_engine.calculate_score(findings)
    assert result["score"] > 0
    assert result["score"] >= 70  # MEDIUM tier is capped well below "wipe out the whole score"


def test_tier_deduction_is_capped():
    """However many findings pile up in one tier, that tier's total
    contribution to the deduction never exceeds its cap."""
    for sev, schedule in risk_engine.SEVERITY_SCHEDULE.items():
        many = risk_engine._tier_deduction(1000, schedule)
        assert many == schedule["cap"]


def test_tier_deduction_is_monotonically_non_decreasing():
    """More findings in a tier should never *reduce* the deduction (no
    perverse incentive to add more findings)."""
    for sev, schedule in risk_engine.SEVERITY_SCHEDULE.items():
        prev = 0
        for count in range(0, 30):
            d = risk_engine._tier_deduction(count, schedule)
            assert d >= prev
            prev = d


def test_single_real_critical_still_hurts_a_lot():
    """A genuine single CRITICAL finding (e.g. one real unguarded DB DELETE)
    must still meaningfully tank the score -- diminishing returns is about
    volume dilution, not about making real findings cheap."""
    result = risk_engine.calculate_score([_mk("CRITICAL")])
    assert result["score"] <= 75
    assert result["label"] in ("HIGH RISK", "CRITICAL RISK")


def test_resolved_and_unscored_findings_excluded_from_tier_counts():
    findings = [
        _mk("MEDIUM", status="resolved"),
        _mk("MEDIUM", scored=False),
        _mk("HIGH"),
    ]
    result = risk_engine.calculate_score(findings)
    assert result["counts"]["MEDIUM"] == 0
    assert result["counts"]["HIGH"] == 1
    assert result["unscored_count"] == 1


def test_mixed_realistic_repo_profile():
    """Roughly AutoGPT's real v8 profile (0 CRITICAL, 0 HIGH, 22 MEDIUM, 64
    LOW, scored only) -- under the old flat model this scored 0/100. Under
    the new model it should be well above zero, reflecting "no severe
    findings, high volume of low/medium noise" rather than "catastrophic"."""
    findings = [_mk("MEDIUM") for _ in range(22)] + [_mk("LOW") for _ in range(64)]
    result = risk_engine.calculate_score(findings)
    assert result["score"] > 50
    assert result["label"] != "CRITICAL RISK"
