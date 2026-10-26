import pytest

from analysis.scoring import RiskEngine
from core.models import Finding

def test_critical_score():
    f = Finding("critical test", "vuln", impact=10, exploitability=10, confidence=1, exposure=10)
    f = RiskEngine().score(f)
    assert f.score == 100
    assert f.severity == "critical"


@pytest.mark.parametrize(
    ("value", "expected_score", "expected_severity"),
    [
        (1.99, 19.9, "info"),
        (2.00, 20.0, "low"),
        (3.99, 39.9, "low"),
        (4.00, 40.0, "medium"),
        (6.49, 64.9, "medium"),
        (6.50, 65.0, "high"),
        (8.49, 84.9, "high"),
        (8.50, 85.0, "critical"),
    ],
)
def test_severity_threshold_boundaries(
    value, expected_score, expected_severity
):
    finding = Finding(
        title="Boundary test",
        category="vuln",
        impact=value,
        exploitability=value,
        confidence=value,
        exposure=value,
    )

    result = RiskEngine().score(finding)

    assert result.score == expected_score
    assert result.severity == expected_severity


def test_observation_always_has_zero_risk():
    finding = Finding(
        title="Service fingerprint",
        category="observation",
        impact=10,
        exploitability=10,
        confidence=1,
        exposure=10,
        score=99,
        severity="critical",
    )

    result = RiskEngine().score(finding)

    assert result.score == 0.0
    assert result.severity == "info"


@pytest.mark.parametrize(
    ("value",),
    [
        (20,),
        (-10,),
        (float("nan"),),
        (float("inf"),),
        (None,),
        (True,),
    ],
)
def test_score_rejects_invalid_or_out_of_range_input(value):
    finding = Finding(
        title="Score clamping test",
        category="vuln",
        impact=value,
        exploitability=value,
        confidence=value,
        exposure=value,
    )

    with pytest.raises(ValueError, match="finite number from 0 to 10"):
        RiskEngine().score(finding)


@pytest.mark.parametrize(
    ("confidence", "normalized", "interpretation"),
    [
        (0.5, 5.0, "fraction converted to 0-10"),
        (1.0, 10.0, "fraction converted to 0-10"),
        (5.0, 5.0, "already on 0-10 scale"),
    ],
)
def test_confidence_scale_and_explainable_breakdown(confidence, normalized, interpretation):
    finding = Finding(
        title="Confidence scale",
        category="vuln",
        impact=4,
        exploitability=6,
        confidence=confidence,
        exposure=2,
    )

    scored = RiskEngine().score(finding)

    assert scored.score_breakdown["normalized_inputs"]["confidence"] == normalized
    assert scored.score_breakdown["confidence_interpretation"] == interpretation
    assert scored.score_breakdown["score"] == scored.score
    assert scored.score == round(sum(scored.score_breakdown["contributions"].values()), 1)


def test_score_all_validates_entire_batch_before_mutating_findings():
    valid = Finding("valid", "vuln", impact=10, exploitability=10, confidence=1, exposure=10)
    invalid = Finding("invalid", "vuln", impact=float("nan"))

    with pytest.raises(ValueError):
        RiskEngine().score_all([valid, invalid])

    assert valid.score == 0.0
    assert valid.score_breakdown == {}


def test_score_all_scores_each_finding():
    findings = [
        Finding(
            title="Low risk",
            category="vuln",
            impact=2,
            exploitability=2,
            confidence=2,
            exposure=2,
        ),
        Finding(
            title="Critical risk",
            category="vuln",
            impact=10,
            exploitability=10,
            confidence=1,
            exposure=10,
        ),
    ]

    results = RiskEngine().score_all(findings)

    assert len(results) == 2
    assert results[0].score == 20.0
    assert results[0].severity == "low"
    assert results[1].score == 100.0
    assert results[1].severity == "critical"
