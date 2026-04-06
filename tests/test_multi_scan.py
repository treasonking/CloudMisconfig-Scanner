from datetime import datetime, timezone

from app.main import run_multi_scan
from scanner.core.models import ScanContext, ScanResult, Finding


def _result(profile: str, fail_count: int, pass_count: int, error_count: int) -> ScanResult:
    findings = []
    for _ in range(fail_count):
        findings.append(
            Finding(
                check_id="X",
                title="t",
                status="FAIL",
                severity="HIGH",
                resource="r",
                message="m",
            )
        )
    for _ in range(pass_count):
        findings.append(
            Finding(
                check_id="Y",
                title="t",
                status="PASS",
                severity="INFO",
                resource="r",
                message="m",
            )
        )
    return ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", profile=profile, started_at=datetime.now(timezone.utc)),
        findings=findings,
        errors=["e"] * error_count,
    )


def test_run_multi_scan_aggregates_profiles(monkeypatch):
    fake = {
        "default": _result("default", fail_count=2, pass_count=1, error_count=0),
        "prod": _result("prod", fail_count=1, pass_count=2, error_count=1),
    }

    monkeypatch.setattr("app.main.run_scan", lambda profile_name, region_name: fake[profile_name])

    out = run_multi_scan(["default", "prod"], region_name="ap-northeast-2")

    assert out["totals"]["profiles"] == 2
    assert out["totals"]["findings"] == 6
    assert out["totals"]["fail"] == 3
    assert out["totals"]["pass"] == 3
    assert out["totals"]["errors"] == 1
