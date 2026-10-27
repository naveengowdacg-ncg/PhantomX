import math

from core.models import Finding

class RiskEngine:
    """Score findings using the stable PhantomX weighted risk model.

    Impact, exploitability, and exposure use a 0-10 scale. Confidence accepts
    either a 0-1 fraction (including 1.0 for full confidence) or a 0-10 value;
    values in the inclusive 0-1 range retain the historical fraction rule.
    """
    WEIGHTS = {"impact": 0.35, "exploitability": 0.30, "confidence": 0.25, "exposure": 0.10}

    def score(self, finding: Finding) -> Finding:
        # Observations provide context/evidence, not a security risk.
        if finding.category == "observation":
            finding.score = 0.0
            finding.severity = "info"
            finding.score_breakdown = {
                "method": "observation",
                "reason": "Observations are informational and are not risk-scored.",
                "score": 0.0,
                "severity": "info",
            }
            return finding

        impact = self._validated_input("impact", finding.impact)
        exploitability = self._validated_input("exploitability", finding.exploitability)
        exposure = self._validated_input("exposure", finding.exposure)
        confidence_input = self._validated_input("confidence", finding.confidence)
        confidence = confidence_input * 10 if confidence_input <= 1 else confidence_input

        normalized = {
            "impact": impact,
            "exploitability": exploitability,
            "confidence": confidence,
            "exposure": exposure,
        }
        contributions = {
            name: value * self.WEIGHTS[name] * 10
            for name, value in normalized.items()
        }
        raw = sum(contributions.values())

        finding.score = round(raw, 1)

        if finding.score >= 85:
            finding.severity = "critical"
        elif finding.score >= 65:
            finding.severity = "high"
        elif finding.score >= 40:
            finding.severity = "medium"
        elif finding.score >= 20:
            finding.severity = "low"
        else:
            finding.severity = "info"

        finding.score_breakdown = {
            "input_scale": {
                "impact": "0-10",
                "exploitability": "0-10",
                "confidence": "0-1 fraction or 0-10; 0-1 is interpreted as a fraction",
                "exposure": "0-10",
            },
            "normalized_inputs": normalized,
            "weights": dict(self.WEIGHTS),
            "contributions": contributions,
            "confidence_interpretation": (
                "fraction converted to 0-10"
                if confidence_input <= 1
                else "already on 0-10 scale"
            ),
            "score": finding.score,
            "severity": finding.severity,
        }

        return finding

    @staticmethod
    def _validated_input(name, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a finite number from 0 to 10.")
        if value < 0 or value > 10 or not math.isfinite(value):
            raise ValueError(f"{name} must be a finite number from 0 to 10.")
        return float(value)

    def score_all(self, findings):
        # Materialize a single-pass iterable once. Batch validation must finish
        # before scoring so one bad input cannot leave a partial result.
        findings = findings if isinstance(findings, (list, tuple)) else list(findings)
        for finding in findings:
            if finding.category == "observation":
                continue
            self._validated_input("impact", finding.impact)
            self._validated_input("exploitability", finding.exploitability)
            self._validated_input("confidence", finding.confidence)
            self._validated_input("exposure", finding.exposure)
        return [self.score(f) for f in findings]
