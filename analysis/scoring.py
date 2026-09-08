from core.models import Finding

class RiskEngine:
    """Configurable scoring engine; intentionally independent of any single scanner."""
    WEIGHTS = {"impact": 0.35, "exploitability": 0.30, "confidence": 0.25, "exposure": 0.10}

    def score(self, finding: Finding) -> Finding:
        # Inputs are 0-10. Confidence is accepted as 0-1 and converted.
        confidence = finding.confidence * 10 if finding.confidence <= 1 else finding.confidence
        raw = (
            finding.impact * self.WEIGHTS["impact"] +
            finding.exploitability * self.WEIGHTS["exploitability"] +
            confidence * self.WEIGHTS["confidence"] +
            finding.exposure * self.WEIGHTS["exposure"]
        ) * 10
        finding.score = round(max(0.0, min(100.0, raw)), 1)
        if finding.score >= 85: finding.severity = "critical"
        elif finding.score >= 65: finding.severity = "high"
        elif finding.score >= 40: finding.severity = "medium"
        elif finding.score >= 20: finding.severity = "low"
        else: finding.severity = "info"
        return finding

    def score_all(self, findings):
        return [self.score(f) for f in findings]
