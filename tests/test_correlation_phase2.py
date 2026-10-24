from core.models import Finding
from analysis.correlation import CorrelationEngine


def make(title, *, tool="nmap", category="web", target="127.0.0.1",
         metadata=None, evidence=""):
    return Finding(
        title=title, category=category, target=target, source_tool=tool,
        metadata=metadata or {}, evidence=evidence,
    )


def test_same_service_discovery_correlates_across_tools():
    findings = [
        make("HTTP service", tool="nmap", category="network",
             metadata={"port": 80, "protocol": "tcp"}),
        make("HTTP detected", tool="whatweb", category="network",
             metadata={"port": 80, "protocol": "tcp"}),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert len(groups) == 1
    assert len(groups[0].findings) == 2
    assert groups[0].sources == ["nmap", "whatweb"]
    assert groups[0].confidence == 0.85


def test_unrelated_findings_on_same_port_stay_separate():
    findings = [
        make("Missing security header", tool="nikto",
             metadata={"port": 443, "protocol": "tcp"}),
        make("Directory listing exposed", tool="gobuster",
             metadata={"port": 443, "protocol": "tcp"}),
    ]
    assert len(CorrelationEngine().correlate(findings)) == 2


def test_same_cve_correlates_across_different_titles():
    findings = [
        make("Possible issue", tool="scanner-a", metadata={"cve": "CVE-2024-12345"}),
        make("Detected CVE-2024-12345", tool="scanner-b"),
    ]
    groups = CorrelationEngine().correlate(findings)
    assert len(groups) == 1
    assert len(groups[0].findings) == 2


def test_same_category_without_port_does_not_merge_different_findings():
    findings = [
        make("Missing security header"),
        make("Exposed backup file"),
    ]
    assert len(CorrelationEngine().correlate(findings)) == 2
