import json
from pathlib import Path
from typing import Dict, List, Optional

class ToolRegistry:
    def __init__(self, path: str = "config/tools.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._save({"tools": []})
        self.data = self._load()

    def _load(self):
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data):
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def list(self) -> List[Dict]:
        return self.data.get("tools", [])

    def get(self, name: str) -> Optional[Dict]:
        return next((t for t in self.list() if t["name"] == name), None)

    def add(self, name: str, category: str, executable: str, args: List[str], timeout: int = 120, description: str = ""):
        if self.get(name):
            raise ValueError(f"Tool already exists: {name}")
        self.data.setdefault("tools", []).append({
            "name": name, "category": category, "executable": executable,
            "args": args, "enabled": True, "timeout": timeout,
            "description": description
        })
        self._save(self.data)

    def remove(self, name: str):
        before = len(self.list())
        self.data["tools"] = [t for t in self.list() if t["name"] != name]
        if len(self.data["tools"]) == before:
            raise ValueError(f"Tool not found: {name}")
        self._save(self.data)

    def set_enabled(self, name: str, enabled: bool):
        tool = self.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")
        tool["enabled"] = enabled
        self._save(self.data)
