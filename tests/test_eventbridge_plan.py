import json

from app.main import build_eventbridge_targets, save_eventbridge_targets


def test_build_eventbridge_targets_scan_payload():
    targets = build_eventbridge_targets(
        target_id="t1",
        target_arn="arn:aws:lambda:ap-northeast-2:111111111111:function:scanner",
        invoke_role_arn="arn:aws:iam::111111111111:role/events-invoke",
        scan_mode="scan",
        region_name="ap-northeast-2",
        profile_name="default",
        role_arn="arn:aws:iam::222222222222:role/SecurityAudit",
        external_id="ext-1",
    )

    assert len(targets) == 1
    target = targets[0]
    payload = json.loads(target["Input"])
    assert target["Id"] == "t1"
    assert payload["scan_mode"] == "scan"
    assert payload["profile"] == "default"
    assert payload["role_arn"].endswith("SecurityAudit")
    assert payload["external_id"] == "ext-1"


def test_save_eventbridge_targets_writes_json(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.ROOT", tmp_path)
    payload = [{"Id": "t1", "Arn": "arn:aws:lambda:::fn", "RoleArn": "arn:aws:iam:::role/r", "Input": "{}"}]
    output = save_eventbridge_targets("daily-scan", payload)

    assert output.exists()
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded[0]["Id"] == "t1"
