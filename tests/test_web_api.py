from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.web import app
from scanner.core.models import Finding, ScanContext, ScanResult


def _fake_result() -> ScanResult:
    result = ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", started_at=datetime.now(timezone.utc)),
        data={"service_status": {"s3": {"status": "SUCCESS", "errors": []}}},
        errors=[],
        findings=[
            Finding(
                check_id="AWS.S3.PublicExposure",
                title="S3 bucket public exposure",
                status="FAIL",
                severity="HIGH",
                resource="s3://risk-bucket",
                message="Bucket policy is public",
            ),
            Finding(
                check_id="AWS.S3.EncryptionEnabled",
                title="S3 encryption",
                status="PASS",
                severity="INFO",
                resource="s3://safe-bucket",
                message="Encryption configured",
            ),
        ],
    )
    return result


def test_scan_endpoint_returns_summary_and_service_status(monkeypatch):
    monkeypatch.setattr("app.web.run_scan", lambda profile_name, region_name, reporters, role_arn=None, external_id=None: _fake_result())
    client = TestClient(app)

    response = client.get("/scan")

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total"] == 2
    assert payload["summary"]["fail"] == 1
    assert payload["service_status"]["s3"]["status"] == "SUCCESS"


def test_scan_assume_role_endpoint(monkeypatch):
    monkeypatch.setattr(
        "app.web.run_scan",
        lambda profile_name, region_name, reporters, role_arn, external_id: _fake_result(),
    )
    client = TestClient(app)

    response = client.get("/scan-assume-role?role_arn=arn:aws:iam::111111111111:role/SecurityAudit")

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["total"] == 2


def test_results_endpoint_has_cursor():
    client = TestClient(app)

    response = client.get("/results?limit=1&cursor=0")

    assert response.status_code == 200
    payload = response.json()
    assert "reports" in payload
    assert "next_cursor" in payload


def test_scan_multi_endpoint_returns_aggregate(monkeypatch):
    monkeypatch.setattr(
        "app.web.run_multi_scan",
        lambda profiles, region_name: {
            "profiles": [{"profile": p, "total": 1, "fail": 0, "pass": 1, "errors": 0} for p in profiles],
            "totals": {"profiles": len(profiles), "findings": len(profiles), "fail": 0, "pass": len(profiles), "errors": 0},
        },
    )
    client = TestClient(app)

    response = client.get("/scan-multi?profiles=default,prod")

    assert response.status_code == 200
    payload = response.json()
    assert payload["totals"]["profiles"] == 2
    assert len(payload["profiles"]) == 2


def test_scan_multi_endpoint_rejects_empty_profiles():
    client = TestClient(app)

    response = client.get("/scan-multi?profiles=,,,")

    assert response.status_code == 400


def test_results_endpoint_rejects_invalid_cursor():
    client = TestClient(app)

    response = client.get("/results?cursor=abc")

    assert response.status_code == 400


def test_dashboard_endpoint_rejects_invalid_severity():
    client = TestClient(app)

    response = client.get("/dashboard?severity=INVALID")

    assert response.status_code == 400


def test_trend_endpoint_returns_history(monkeypatch):
    monkeypatch.setattr(
        "app.web.load_scan_history",
        lambda limit=20: [{"filename": "scan-1.json", "total": 2, "fail": 1, "pass": 1, "errors": 0, "started_at": "x"}],
    )
    client = TestClient(app)

    response = client.get("/trend?limit=5")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["history"]) == 1


def test_export_history_csv(monkeypatch):
    monkeypatch.setattr(
        "app.web.load_scan_history",
        lambda limit=20: [{"filename": "scan-1.json", "started_at": "x", "total": 2, "fail": 1, "pass": 1, "errors": 0}],
    )
    client = TestClient(app)

    response = client.get("/export/history.csv?limit=5")

    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "filename,started_at,total,fail,pass,errors" in response.text


def test_export_findings_csv(tmp_path, monkeypatch):
    report_file = tmp_path / "scan-1.json"
    report_file.write_text(
        '{"findings":[{"check_id":"A","status":"FAIL","severity":"HIGH","resource":"r","message":"m","recommendation":"x"}]}',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "app.web._report_list",
        lambda limit=50, cursor=0: ([{"type": "json", "path": str(report_file), "filename": "scan-1.json"}], None),
    )
    client = TestClient(app)

    response = client.get("/export/findings.csv")

    assert response.status_code == 200
    assert "check_id,status,severity,resource,message,recommendation" in response.text
    assert "A,FAIL,HIGH,r,m,x" in response.text
