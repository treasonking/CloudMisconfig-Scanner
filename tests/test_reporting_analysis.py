from scanner.core.models import Finding
from scanner.reporting.analysis import (
    build_case_matrix,
    build_detection_quality,
    build_finding_rows,
    build_scope_warnings,
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
    assert quality["not_evaluated"] == 0


def test_build_test_scope_uses_override_first():
    rows = build_finding_rows([_finding("X", "r", "PASS", severity="INFO")])
    summary = build_summary(rows)
    scope = build_test_scope(summary, override_scope={"total_cases": 20, "normal_cases": 8, "misconfigured_cases": 12})

    assert scope["total_cases"] == 20
    assert scope["normal_cases"] == 8
    assert scope["misconfigured_cases"] == 12


def test_build_case_matrix_marks_mismatch():
    rows = build_finding_rows([_finding("AWS.IAM.UserMFA", "iam:user/cms-safe-user", "FAIL", severity="MEDIUM")])
    benchmark_cases = [
        {
            "check_id": "AWS.IAM.UserMFA",
            "resource": "iam:user/cms-safe-user",
            "expected": "PASS",
            "note": "safe-user should have MFA enabled",
        }
    ]

    matrix = build_case_matrix(rows, benchmark_cases=benchmark_cases)

    assert matrix["available"] is True
    assert matrix["mismatch_count"] == 1
    assert matrix["cases"][0]["outcome"] == "FP"


def test_build_scope_warnings_when_scope_without_benchmark():
    warnings = build_scope_warnings(
        test_scope={"total_cases": 20, "normal_cases": 8, "misconfigured_cases": 12},
        benchmark_cases=None,
        case_matrix={"available": False, "mismatch_count": 0},
    )
    assert len(warnings) == 1
    assert "benchmark-file" in warnings[0]
