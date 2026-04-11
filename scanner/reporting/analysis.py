from __future__ import annotations

from typing import Any

from scanner.core.models import Finding


DEFAULT_LIMITATIONS = [
    "태그 기반 예외처리(allowlist) 미지원",
    "CSPM 수준의 리소스 문맥 인식 부족",
    "멀티클라우드 정책 차이 미반영",
]

DEFAULT_IMPROVEMENTS = [
    "규칙 세분화 및 서비스별 예외 조건 보완",
    "Severity 산정 기준 정교화",
    "태그/리소스 기반 allowlist 정책 추가",
    "리소스 간 연관 분석(예: SG-EC2-RDS) 고도화",
]

_SEVERITY_RISK = {
    "CRITICAL": "Immediate high-impact security risk",
    "HIGH": "High risk of unauthorized access or privilege abuse",
    "MEDIUM": "Moderate security risk requiring remediation",
    "LOW": "Low security risk or policy hygiene gap",
    "INFO": "Informational finding",
}

_CHECK_RISK_HINT = {
    "AWS.S3.PublicExposure": "External unauthorized access to bucket objects",
    "AWS.IAM.WildcardPolicy": "Privilege escalation from overly broad IAM permissions",
    "AWS.IAM.RoleWildcardPolicy": "Privilege escalation through over-privileged IAM role",
    "AWS.IAM.RoleTrustPolicy": "Untrusted principals may assume sensitive role",
    "AWS.EC2.SG.PublicIngress": "Public network exposure of admin or database ports",
}


def build_finding_rows(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        reason = finding.message
        if finding.status == "PASS":
            risk = "No immediate risk detected"
        else:
            risk = _CHECK_RISK_HINT.get(finding.check_id, _SEVERITY_RISK.get(finding.severity, "Security risk"))
        rows.append(
            {
                "check_id": finding.check_id,
                "title": finding.title,
                "status": finding.status,
                "severity": finding.severity,
                "resource": finding.resource,
                "reason": reason,
                "risk": risk,
                "recommendation": finding.recommendation,
                "evidence": finding.evidence or {},
            }
        )
    return rows


def build_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(rows),
        "fail": sum(1 for f in rows if f["status"] == "FAIL"),
        "pass": sum(1 for f in rows if f["status"] == "PASS"),
        "critical": sum(1 for f in rows if f["severity"] == "CRITICAL"),
        "high": sum(1 for f in rows if f["severity"] == "HIGH"),
        "medium": sum(1 for f in rows if f["severity"] == "MEDIUM"),
        "low": sum(1 for f in rows if f["severity"] == "LOW"),
        "info": sum(1 for f in rows if f["severity"] == "INFO"),
    }


def _expected_status(case: dict[str, Any]) -> str:
    raw = str(case.get("expected", "")).strip().upper()
    if raw in {"FAIL", "MISCONFIG", "RISK", "RISKY", "BAD"}:
        return "FAIL"
    if raw in {"PASS", "SAFE", "NORMAL", "GOOD"}:
        return "PASS"
    if isinstance(case.get("expected_fail"), bool):
        return "FAIL" if case["expected_fail"] else "PASS"
    if isinstance(case.get("is_misconfigured"), bool):
        return "FAIL" if case["is_misconfigured"] else "PASS"
    return "UNKNOWN"


def _case_key(check_id: str, resource: str) -> str:
    return f"{check_id}::{resource}"


def build_detection_quality(rows: list[dict[str, Any]], benchmark_cases: list[dict[str, Any]] | None) -> dict[str, Any]:
    if not benchmark_cases:
        return {
            "available": False,
            "message": "No benchmark cases provided. Add --benchmark-file to compute detection metrics.",
        }

    actual = {_case_key(row["check_id"], row["resource"]): row["status"] for row in rows}

    tp = 0
    fp = 0
    fn = 0
    tn = 0
    unknown = 0
    misconfigured_cases = 0
    normal_cases = 0

    for case in benchmark_cases:
        check_id = case.get("check_id")
        resource = case.get("resource")
        if not check_id or not resource:
            unknown += 1
            continue

        expected = _expected_status(case)
        if expected == "UNKNOWN":
            unknown += 1
            continue

        actual_status = actual.get(_case_key(str(check_id), str(resource)))
        if expected == "FAIL":
            misconfigured_cases += 1
            if actual_status == "FAIL":
                tp += 1
            else:
                fn += 1
        else:
            normal_cases += 1
            if actual_status == "FAIL":
                fp += 1
            else:
                tn += 1

    total_eval = misconfigured_cases + normal_cases
    precision = (tp / (tp + fp)) if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 0.0

    return {
        "available": True,
        "total_cases": total_eval,
        "normal_cases": normal_cases,
        "misconfigured_cases": misconfigured_cases,
        "detected_success": tp,
        "false_positives": fp,
        "missed_detections": fn,
        "true_negatives": tn,
        "unknown_cases": unknown,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
    }


def build_test_scope(
    summary: dict[str, int],
    benchmark_cases: list[dict[str, Any]] | None = None,
    override_scope: dict[str, int] | None = None,
) -> dict[str, int]:
    if override_scope:
        total = int(override_scope.get("total_cases", 0))
        normal = int(override_scope.get("normal_cases", 0))
        misconfig = int(override_scope.get("misconfigured_cases", 0))
        return {
            "total_cases": total if total > 0 else normal + misconfig,
            "normal_cases": normal,
            "misconfigured_cases": misconfig,
        }

    if benchmark_cases:
        normal = 0
        misconfig = 0
        for case in benchmark_cases:
            expected = _expected_status(case)
            if expected == "FAIL":
                misconfig += 1
            elif expected == "PASS":
                normal += 1
        return {
            "total_cases": normal + misconfig,
            "normal_cases": normal,
            "misconfigured_cases": misconfig,
        }

    return {
        "total_cases": summary["total"],
        "normal_cases": summary["pass"],
        "misconfigured_cases": summary["fail"],
    }
