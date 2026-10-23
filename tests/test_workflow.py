from core.models import Service
from core.workflow import WorkflowEngine


class DummyLogger:
    def info(self, *args, **kwargs):
        pass


class DummyRegistry:
    def list(self):
        return [
            {
                "name": "nmap",
                "category": "recon",
                "enabled": True,
            },
            {
                "name": "whatweb",
                "category": "web",
                "enabled": True,
            },
        ]


class DummyExecutor:
    def run(self, tool, target):
        from core.models import ToolResult

        if tool["name"] == "nmap":
            return ToolResult(
                tool="nmap",
                category="recon",
                target=target,
                started_at="",
                finished_at="",
                return_code=0,
                status="success",
                services=[
                    Service(
                        port=80,
                        protocol="tcp",
                        state="open",
                        service="http",
                        version="Apache",
                    )
                ],
            )

        return ToolResult(
            tool=tool["name"],
            category=tool["category"],
            target=target,
            started_at="",
            finished_at="",
            return_code=0,
            status="success",
        )


class DummyAdapterManager:
    def run(self, tool, target, fallback_executor, extra_args=None):
        return fallback_executor.run(tool, target)

class DummyNormalizer:
    def parse(self, result):
        return result


class DummyRiskEngine:
    def score_all(self, findings):
        return findings


class DummySession:
    def __init__(self):
        self.profile = "standard"
        self.target = "127.0.0.1"
        self.results = []
        self.notes = []


def main():
    print("=" * 60)
    print("PHANTOMX - WORKFLOW TEST")
    print("=" * 60)

    engine = WorkflowEngine(
        registry=DummyRegistry(),
        executor=DummyExecutor(),
        adapter_manager=DummyAdapterManager(),
        normalizer=DummyNormalizer(),
        risk_engine=DummyRiskEngine(),
        logger=DummyLogger(),
    )

    session = DummySession()

    session = engine.run(session)

    print()
    print("--- RESULTS ---")

    for result in session.results:
        print(f"Tool: {result.tool}")
        print(f"Target: {result.target}")
        print(f"Endpoints: {len(result.endpoints)}")
        print()

    print("--- NOTES ---")

    for note in session.notes:
        print(note)

    print()
    print("--- VERIFICATION ---")

    tool_names = [result.tool for result in session.results]

    assert "nmap" in tool_names
    assert "whatweb" in tool_names

    whatweb_results = [
        result
        for result in session.results
        if result.tool == "whatweb"
    ]

    assert len(whatweb_results) == 1

    whatweb_result = whatweb_results[0]

    assert len(whatweb_result.endpoints) == 1

    endpoint = whatweb_result.endpoints[0]

    assert endpoint.url == "http://127.0.0.1"
    assert endpoint.port == 80
    assert endpoint.scheme == "http"
    assert endpoint.source_tool == "nmap"

    print("[+] Nmap discovered HTTP service.")
    print("[+] PhantomX derived HTTP endpoint.")
    print("[+] WhatWeb received derived endpoint.")
    print("[+] Endpoint context preserved.")
    print()
    print("[+] NMAP -> WHATWEB HANDOFF SUCCESSFUL.")
    print("=" * 60)


if __name__ == "__main__":
    main()
def test_workflow_hands_nmap_endpoint_to_whatweb():
    main()
