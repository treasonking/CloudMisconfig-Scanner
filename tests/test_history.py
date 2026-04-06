import json
from pathlib import Path

from app.main import load_scan_history


def test_load_scan_history_reads_recent_json(tmp_path, monkeypatch):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "context": {"started_at": "2026-04-06T00:00:00Z"},
        "errors": ["x"],
        "findings": [
            {"status": "FAIL"},
            {"status": "PASS"},
        ],
    }
    (reports_dir / "scan-20260406-000000.json").write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr("app.main.ROOT", tmp_path)

    out = load_scan_history(limit=5)

    assert len(out) == 1
    assert out[0]["fail"] == 1
    assert out[0]["pass"] == 1
    assert out[0]["errors"] == 1
