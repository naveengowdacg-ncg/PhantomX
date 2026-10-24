import json

from core.models import (
    Endpoint, Finding, Observation, Service, Session, ToolResult,
)
from core.storage import SQLiteSessionStore


def sample_session(session_id="test-session-1"):
    endpoint = Endpoint(
        url="http://127.0.0.1", scheme="http", host="127.0.0.1",
        port=80, source_tool="whatweb", metadata={"status": 200},
    )
    finding = Finding(
        title="HTTP service", category="network", target="127.0.0.1",
        source_tool="nmap", score=42.5, metadata={"port": 80, "protocol": "tcp"},
    )
    observation = Observation(
        title="HTTP endpoint", category="web", target="127.0.0.1",
        source_tool="whatweb", endpoint=endpoint,
    )
    result = ToolResult(
        tool="nmap", category="recon", target="127.0.0.1",
        started_at="start", finished_at="finish", return_code=0,
        services=[Service(80, "tcp", "open", "http", "Apache")],
        endpoints=[endpoint], observations=[observation], findings=[finding],
    )
    return Session(
        target="127.0.0.1", profile="standard", results=[result],
        notes=["test note"], session_id=session_id,
    )


def test_sqlite_round_trip_restores_nested_models(tmp_path):
    store = SQLiteSessionStore(tmp_path / "history.sqlite3")
    original = sample_session()
    store.save(original)

    restored = store.load(original.session_id)

    assert restored is not None
    assert restored.as_dict() == original.as_dict()
    assert isinstance(restored.results[0].services[0], Service)
    assert isinstance(restored.results[0].endpoints[0], Endpoint)
    assert isinstance(restored.results[0].observations[0], Observation)
    assert isinstance(restored.results[0].observations[0].endpoint, Endpoint)
    assert isinstance(restored.results[0].findings[0], Finding)


def test_history_is_ordered_and_missing_session_returns_none(tmp_path):
    store = SQLiteSessionStore(tmp_path / "history.sqlite3")
    first = sample_session("first")
    second = sample_session("second")
    second.started_at = "9999-01-01T00:00:00+00:00"
    store.save(first)
    store.save(second)

    assert store.count() == 2
    assert store.list_sessions()[0]["session_id"] == "second"
    assert store.load("not-found") is None


def test_save_updates_existing_session(tmp_path):
    store = SQLiteSessionStore(tmp_path / "history.sqlite3")
    session = sample_session()
    store.save(session)
    session.notes.append("updated")
    store.save(session)

    assert store.count() == 1
    assert store.load(session.session_id).notes[-1] == "updated"
