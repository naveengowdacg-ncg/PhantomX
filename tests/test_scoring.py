from analysis.scoring import RiskEngine
from core.models import Finding

def test_critical_score():
    f = Finding("critical test", "vuln", impact=10, exploitability=10, confidence=1, exposure=10)
    f = RiskEngine().score(f)
    assert f.score == 100
    assert f.severity == "critical"
