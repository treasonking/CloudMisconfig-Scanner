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


def test_load_scan_history_skips_invalid_json(tmp_path, monkeypatch):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    (reports_dir / "scan-20260406-000000.json").write_text("{invalid json", encoding="utf-8")
    (reports_dir / "scan-20260406-000001.json").write_text(
        json.dumps({"context": {"started_at": "x"}, "findings": [{"status": "PASS"}], "errors": []}),
        encoding="utf-8",
    )

    monkeypatch.setattr("app.main.ROOT", tmp_path)

    out = load_scan_history(limit=10)

    assert len(out) == 1
    assert out[0]["total"] == 1


def test_load_scan_history_respects_limit(tmp_path, monkeypatch):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    for idx in range(3):
        (reports_dir / f"scan-20260406-00000{idx}.json").write_text(
            json.dumps({"context": {"started_at": f"t{idx}"}, "findings": [], "errors": []}),
            encoding="utf-8",
        )

    monkeypatch.setattr("app.main.ROOT", tmp_path)

    out = load_scan_history(limit=2)

    assert len(out) == 2
