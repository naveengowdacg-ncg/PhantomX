import json
from pathlib import Path


PROJECT_DISCOVERY_TOOLS = {"nuclei", "subfinder", "dnsx", "httpx", "katana"}


def test_projectdiscovery_tools_disable_background_update_checks():
    config_path = Path(__file__).resolve().parents[1] / "config" / "tools.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    tools = {tool["name"]: tool for tool in config["tools"]}

    assert PROJECT_DISCOVERY_TOOLS <= tools.keys()
    for name in PROJECT_DISCOVERY_TOOLS:
        assert "-duc" in tools[name]["args"], name