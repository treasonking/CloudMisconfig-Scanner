import json
from datetime import datetime, timezone

from app.main import parse_assume_role_targets_file, parse_profiles_arg, run_multi_scan, save_multi_scan_summary
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


def test_save_multi_scan_summary_writes_json(tmp_path, monkeypatch):
    aggregate = {
        "profiles": [{"profile": "default", "total": 1, "fail": 0, "pass": 1, "errors": 0}],
        "totals": {"profiles": 1, "findings": 1, "fail": 0, "pass": 1, "errors": 0},
    }
    monkeypatch.setattr("app.main.ROOT", tmp_path)

    output = save_multi_scan_summary(aggregate)

    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["totals"]["profiles"] == 1


def test_parse_profiles_arg_supports_file_and_comments(tmp_path):
    profiles_file = tmp_path / "profiles.txt"
    profiles_file.write_text("# comment\ndefault\nprod\n", encoding="utf-8")

    parsed = parse_profiles_arg(profiles="dev,prod", profiles_file=str(profiles_file))

    assert parsed == ["dev", "prod", "default"]


def test_parse_assume_role_targets_file(tmp_path):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text(
        "# role_arn,profile,external_id\n"
        "arn:aws:iam::111111111111:role/SecurityAudit,default,\n"
        "arn:aws:iam::222222222222:role/SecurityAudit,prod,my-external\n",
        encoding="utf-8",
    )

    targets = parse_assume_role_targets_file(str(targets_file))

    assert len(targets) == 2
    assert targets[0]["source_profile"] == "default"
    assert targets[1]["external_id"] == "my-external"
