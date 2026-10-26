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

    def add(
        self,
        name: str,
        category: str,
        executable: str,
        args: List[str],
        timeout: int = 120,
        description: str = "",
        retries: int = 0,
        retry_on_timeout: bool = False,
    ):
        self._ensure_valid_config()
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Tool name must be a non-empty string.")
        if not isinstance(category, str) or not category.strip():
            raise ValueError("Tool category must be a non-empty string.")
        if not isinstance(executable, str) or not executable.strip():
            raise ValueError("Tool executable must be a non-empty string.")
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise ValueError("Tool args must be a list of strings.")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 1:
            raise ValueError("Tool timeout must be a positive integer.")
        if not isinstance(description, str):
            raise ValueError("Tool description must be a string.")
        if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 3:
            raise ValueError("Tool retries must be an integer from 0 to 3.")
        if not isinstance(retry_on_timeout, bool):
            raise ValueError("Tool retry_on_timeout must be true or false.")
        if any(
            isinstance(item, dict)
            and isinstance(item.get("name"), str)
            and item["name"].casefold() == name.strip().casefold()
            for item in self.list()
        ):
            raise ValueError(f"Tool already exists: {name}")
        self.data.setdefault("tools", []).append({
            "name": name.strip(), "category": category.strip(), "executable": executable.strip(),
            "args": args, "enabled": True, "timeout": timeout,
            "description": description, "retries": retries,
            "retry_on_timeout": retry_on_timeout,
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
        if not isinstance(enabled, bool):
            raise ValueError("Tool enabled state must be true or false.")
        tool = self.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")
        tool["enabled"] = enabled
        self._save(self.data)
