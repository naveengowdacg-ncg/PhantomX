import json
from pathlib import Path
from typing import Dict, List, Optional

class ToolRegistry:
    def __init__(self, path: str = "config/tools.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.load_error = None
        if not self.path.exists():
            self._save({"tools": []})
        self.data = self._load()

    def _load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.load_error = (
                f"Could not parse {self.path}: {exc}. Repair the JSON tool registry."
            )
            return {"tools": []}
        if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
            self.load_error = (
                f"Malformed {self.path}: expected a JSON object with a 'tools' list."
            )
            return {"tools": []}
        return data

    def _save(self, data):
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def list(self) -> List[Dict]:
        return self.data.get("tools", [])

    def get(self, name: str) -> Optional[Dict]:
        return next((t for t in self.list() if isinstance(t, dict) and t.get("name") == name), None)

    def _ensure_valid_config(self):
        if self.load_error:
            raise ValueError(self.load_error)

    def add(self, name: str, category: str, executable: str, args: List[str], timeout: int = 120, description: str = ""):
        self._ensure_valid_config()
        if self.get(name):
            raise ValueError(f"Tool already exists: {name}")
        self.data.setdefault("tools", []).append({
            "name": name, "category": category, "executable": executable,
            "args": args, "enabled": True, "timeout": timeout,
            "description": description
        })
        self._save(self.data)

    def remove(self, name: str):
        self._ensure_valid_config()
        before = len(self.list())
        self.data["tools"] = [
            t for t in self.list()
            if not isinstance(t, dict) or t.get("name") != name
        ]
        if len(self.data["tools"]) == before:
            raise ValueError(f"Tool not found: {name}")
        self._save(self.data)

    def set_enabled(self, name: str, enabled: bool):
        self._ensure_valid_config()
        tool = self.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")
        tool["enabled"] = enabled
        self._save(self.data)
