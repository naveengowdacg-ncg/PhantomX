from core.models import (
    Endpoint,
    Finding,
    Observation,
    Service,
    ToolResult,
)
from analysis.correlation import CorrelationEngine
from modules.nmap.parser import NmapParser
from modules.whatweb.parser import WhatWebParser
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine


def test_nested_model_serialization():
    endpoint = Endpoint(
        url="http://127.0.0.1",
        scheme="http",
        host="127.0.0.1",
        port=80,
        source_tool="nmap",
    )
    observation = Observation(
        title="HTTP service discovered",
        category="service-discovery",
        target="127.0.0.1",
        source_tool="nmap",
        endpoint=endpoint,
    )
    result = ToolResult(
        tool="nmap",
        category="recon",
        target="127.0.0.1",
        started_at="",
        finished_at="",
        return_code=0,
        endpoints=[endpoint],
        observations=[observation],
    )

    data = result.as_dict()

    assert data["endpoints"][0]["port"] == 80
    assert data["observations"][0]["endpoint"]["url"] == (
        "http://127.0.0.1"
    )


def test_model_default_lists_are_independent():
    first = ToolResult(
        tool="nmap", category="recon", target="127.0.0.1",
        started_at="", finished_at="", return_code=0,
    )
    second = ToolResult(
        tool="nmap", category="recon", target="127.0.0.1",
        started_at="", finished_at="", return_code=0,
    )

    first.services.append(
        Service(
            port=80, protocol="tcp", state="open", service="http"
        )
    )

    assert second.services == []


def test_nmap_parser_extracts_tcp_udp_and_versions():
    output = """
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Apache httpd 2.4
53/udp  open  domain
443/tcp closed https
invalid line
"""

    services = NmapParser().parse(output)

    assert len(services) == 3
    assert services[0].port == 80
    assert services[0].protocol == "tcp"
    assert services[0].state == "open"
    assert services[0].version == "Apache httpd 2.4"
    assert services[1].protocol == "udp"
    assert services[1].version == ""
    assert services[2].state == "closed"


def test_whatweb_parser_extracts_fingerprint():
    output = (
        "\x1b[32mhttp://127.0.0.1 [200 OK] "
        "Apache[2.4], Title[Test Page]\x1b[0m"
    )

    observations = WhatWebParser().parse(output, "127.0.0.1")

    assert len(observations) == 1
    assert observations[0].source_tool == "whatweb"
    assert observations[0].metadata["http_status"] == 200
    assert observations[0].metadata["url"] == "http://127.0.0.1"
    assert "Apache[2.4]" in observations[0].metadata["fingerprint"]
    assert "\x1b" not in observations[0].evidence


def test_whatweb_parser_handles_empty_and_invalid_output():
    parser = WhatWebParser()

    assert parser.parse("", "127.0.0.1") == []
    assert parser.parse("unrecognized scanner output", "127.0.0.1") == []


def test_correlation_groups_same_service():
    findings = [
        Finding(
            title="HTTP service",
            category="network",
            target="127.0.0.1",
            source_tool="nmap",
            metadata={"port": 80, "protocol": "tcp"},
        ),
        Finding(
            title="HTTP detected",
            category="network",
            target="127.0.0.1",
            source_tool="whatweb",
            metadata={"port": 80, "protocol": "tcp"},
        ),
        Finding(
            title="HTTPS service",
            category="network",
            target="127.0.0.1",
            source_tool="nmap",
            metadata={"port": 443, "protocol": "tcp"},
        ),
    ]

    groups = CorrelationEngine().correlate(findings)

    assert len(groups) == 2

    http_group = next(
        group for group in groups
        if any(f.metadata.get("port") == 80 for f in group.findings)
    )

    assert len(http_group.findings) == 2
    assert http_group.sources == ["nmap", "whatweb"]
    assert http_group.confidence == 0.70


def test_correlation_separates_targets():
    findings = [
        Finding(
            title="HTTP service",
            category="network",
            target=target,
            source_tool="nmap",
            metadata={"port": 80, "protocol": "tcp"},
        )
        for target in ("127.0.0.1", "127.0.0.2")
    ]

    groups = CorrelationEngine().correlate(findings)

    assert len(groups) == 2
    assert {group.target for group in groups} == {
        "127.0.0.1", "127.0.0.2"
    }


def test_service_discovery_and_technology_fingerprints_are_zero_risk_observations():
    normalizer = Normalizer()
    risk = RiskEngine()
    nmap = ToolResult(
        tool="nmap", category="recon", target="127.0.0.1",
        started_at="", finished_at="", return_code=0,
        services=[Service(80, "tcp", "open", "http", "Apache")],
    )
    whatweb = ToolResult(
        tool="whatweb", category="web", target="http://127.0.0.1",
        started_at="", finished_at="", return_code=0,
        stdout="http://127.0.0.1 [200 OK] Apache[2.4]",
    )

    for result in (nmap, whatweb):
        normalizer.parse(result)
        risk.score_all(result.findings)
        assert result.findings[0].category == "observation"
        assert result.findings[0].score == 0
        assert result.findings[0].severity == "info"
    assert nmap.findings[0].metadata["finding_type"] == "service_discovery"
    assert whatweb.findings[0].metadata["finding_type"] == "technology_fingerprint"


def test_nuclei_matches_require_verification():
    import json

    from modules.nuclei.parser import NucleiParser

    event = {
        "template-id": "example-cve-check",
        "matched-at": "http://127.0.0.1/example",
        "info": {"name": "Example CVE match", "severity": "high", "tags": ["cve"]},
    }
    findings = NucleiParser().parse(json.dumps(event), "127.0.0.1")

    assert len(findings) == 1
    assert findings[0].category == "vulnerability"
    assert findings[0].metadata["verification_status"] == "scanner_match_unverified"
