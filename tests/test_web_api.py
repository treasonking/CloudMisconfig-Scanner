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
    monkeypatch.setattr("app.web.run_scan", lambda profile_name, region_name, reporters: _fake_result())
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
