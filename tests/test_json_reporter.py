import json
from datetime import datetime, timezone

from scanner.core.models import Finding, ScanContext, ScanResult
from scanner.reporting.json_reporter import JsonReporter


def test_json_reporter_includes_quality_and_scope(tmp_path):
    result = ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", started_at=datetime.now(timezone.utc)),
        data={
            "benchmark_cases": [
                {"check_id": "AWS.S3.PublicExposure", "resource": "s3://risk", "expected": "FAIL"},
                {"check_id": "AWS.S3.EncryptionEnabled", "resource": "s3://safe", "expected": "PASS"},
            ],
            "test_scope": {"total_cases": 20, "normal_cases": 8, "misconfigured_cases": 12},
        },
        findings=[
            Finding(
                check_id="AWS.S3.PublicExposure",
                title="t",
                status="FAIL",
                severity="HIGH",
                resource="s3://risk",
                message="Bucket policy is public",
                recommendation="fix",
                evidence={"is_public": True},
            ),
            Finding(
                check_id="AWS.S3.EncryptionEnabled",
                title="t",
                status="PASS",
                severity="INFO",
                resource="s3://safe",
                message="Encryption enabled",
            ),
        ],
    )

    reporter = JsonReporter(output_dir=tmp_path)
    reporter.render(result)

    files = list(tmp_path.glob("scan-*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 2
    assert payload["test_scope"]["total_cases"] == 20
    assert payload["detection_quality"]["available"] is True
    assert "limitations" in payload
    assert "improvement_directions" in payload
