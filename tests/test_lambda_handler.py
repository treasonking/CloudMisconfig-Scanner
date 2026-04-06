from app.lambda_handler import handler


def test_lambda_handler_scan_mode(monkeypatch):
    monkeypatch.setattr(
        "app.lambda_handler.run_scan",
        lambda profile_name, region_name, role_arn, external_id: type("R", (), {"findings": [], "errors": [], "context": type("C", (), {"profile": profile_name})(), "data": {}})(),
    )
    monkeypatch.setattr("app.lambda_handler._build_single_target_aggregate", lambda result: {"totals": {"profiles": 1}})

    out = handler({"scan_mode": "scan", "profile": "default", "region": "ap-northeast-2"}, None)
    assert out["mode"] == "scan"
    assert out["aggregate"]["totals"]["profiles"] == 1


def test_lambda_handler_scan_multi_mode(monkeypatch):
    monkeypatch.setattr("app.lambda_handler.parse_profiles_arg", lambda profiles, profiles_file: ["default", "prod"])
    monkeypatch.setattr("app.lambda_handler.run_multi_scan", lambda profiles, region_name: {"totals": {"profiles": len(profiles)}})

    out = handler({"scan_mode": "scan-multi", "profiles": "default,prod", "region": "ap-northeast-2"}, None)
    assert out["mode"] == "scan-multi"
    assert out["aggregate"]["totals"]["profiles"] == 2
