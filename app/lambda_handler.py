from __future__ import annotations

from app.main import (
    _build_single_target_aggregate,
    parse_assume_role_targets_file,
    parse_profiles_arg,
    run_assume_role_multi_scan,
    run_multi_scan,
    run_scan,
)


def handler(event, context):
    scan_mode = (event or {}).get("scan_mode", "scan")
    region = (event or {}).get("region", "ap-northeast-2")

    if scan_mode == "scan":
        result = run_scan(
            profile_name=(event or {}).get("profile", "default"),
            region_name=region,
            role_arn=(event or {}).get("role_arn"),
            external_id=(event or {}).get("external_id"),
        )
        return {"mode": "scan", "aggregate": _build_single_target_aggregate(result)}

    if scan_mode == "scan-multi":
        profiles = parse_profiles_arg(
            profiles=(event or {}).get("profiles"),
            profiles_file=(event or {}).get("profiles_file"),
        )
        return {"mode": "scan-multi", "aggregate": run_multi_scan(profiles=profiles, region_name=region)}

    if scan_mode == "scan-assume-role-multi":
        targets_file = (event or {}).get("targets_file")
        targets = parse_assume_role_targets_file(targets_file)
        return {"mode": "scan-assume-role-multi", "aggregate": run_assume_role_multi_scan(targets=targets, region_name=region)}

    raise ValueError("Unsupported scan_mode. Use scan | scan-multi | scan-assume-role-multi")
