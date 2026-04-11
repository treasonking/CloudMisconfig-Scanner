from scanner.core.models import Finding
from scanner.reporting.analysis import (
    build_detection_quality,
    build_finding_rows,
    build_summary,
    build_test_scope,
)


def _finding(check_id: str, resource: str, status: str, severity: str = "HIGH") -> Finding:
    return Finding(
        check_id=check_id,
        title="t",
        status=status,
        severity=severity,
        resource=resource,
        message="reason",
        recommendation="fix",
        evidence={"k": "v"},
    )


def test_build_finding_rows_contains_reason_risk_and_evidence():
    rows = build_finding_rows([_finding("AWS.S3.PublicExposure", "s3://a", "FAIL")])

    assert rows[0]["reason"] == "reason"
    assert "unauthorized access" in rows[0]["risk"].lower()
    assert rows[0]["evidence"]["k"] == "v"


def test_build_detection_quality_calculates_tp_fp_fn():
    rows = build_finding_rows(
        [
            _finding("AWS.S3.PublicExposure", "s3://risk", "FAIL"),
            _finding("AWS.S3.EncryptionEnabled", "s3://safe", "FAIL", severity="MEDIUM"),
            _finding("AWS.IAM.UserMFA", "iam:user/u1", "PASS", severity="INFO"),
        ]
    )
    benchmark_cases = [
        {"check_id": "AWS.S3.PublicExposure", "resource": "s3://risk", "expected": "FAIL"},
        {"check_id": "AWS.S3.EncryptionEnabled", "resource": "s3://safe", "expected": "PASS"},
        {"check_id": "AWS.IAM.UserMFA", "resource": "iam:user/u1", "expected": "FAIL"},
    ]

    quality = build_detection_quality(rows, benchmark_cases=benchmark_cases)

    assert quality["available"] is True
    assert quality["detected_success"] == 1
    assert quality["false_positives"] == 1
    assert quality["missed_detections"] == 1


def test_build_test_scope_uses_override_first():
    rows = build_finding_rows([_finding("X", "r", "PASS", severity="INFO")])
    summary = build_summary(rows)
    scope = build_test_scope(summary, override_scope={"total_cases": 20, "normal_cases": 8, "misconfigured_cases": 12})

    assert scope["total_cases"] == 20
    assert scope["normal_cases"] == 8
    assert scope["misconfigured_cases"] == 12
