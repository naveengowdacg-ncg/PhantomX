import json

import main as main_module
from core.scope import TargetScope


class DummyLogger:
    def info(self, *args, **kwargs):
        pass


class CapturingWorkflow:
    def __init__(self, *args, scope=None, **kwargs):
        self.scope = scope


def test_app_passes_configured_scope_validator_into_workflow(tmp_path, monkeypatch):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "default_profile": "standard",
        "allowed_profiles": ["standard"],
        "authorized_targets": ["lab.test"],
    }), encoding="utf-8")

    monkeypatch.setattr(main_module, "WorkflowEngine", CapturingWorkflow)
    monkeypatch.setattr(main_module, "ToolRegistry", lambda: object())
    monkeypatch.setattr(main_module, "get_logger", lambda reports_dir: DummyLogger())
    monkeypatch.setattr(main_module, "ToolExecutor", lambda logger: object())
    monkeypatch.setattr(main_module, "AdapterManager", lambda: object())
    monkeypatch.setattr(main_module, "Normalizer", lambda: object())
    monkeypatch.setattr(main_module, "RiskEngine", lambda: object())
    monkeypatch.setattr(main_module, "Reporter", lambda reports_dir: object())
    monkeypatch.setattr(main_module, "SQLiteSessionStore", lambda path: object())

    app = main_module.App(str(settings))

    assert isinstance(app.scope, TargetScope)
    assert app.scope.authorized_targets == ["lab.test"]
    assert app.workflow.scope is app.scope
