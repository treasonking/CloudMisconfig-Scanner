from __future__ import annotations

from datetime import datetime, timezone

from scanner.checks.aws import (
    IAMRoleTrustPolicyCheck,
    IAMRoleWildcardPolicyCheck,
    IAMWildcardPolicyCheck,
    S3EncryptionCheck,
    SecurityGroupExposureCheck,
)
from scanner.core.models import ScanContext, ScanResult


def _base_result(data: dict) -> ScanResult:
    return ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", started_at=datetime.now(timezone.utc)),
        data=data,
    )


def test_iam_wildcard_policy_check_flags_fail_when_wildcard_exists():
    result = _base_result(
        {
            "iam_user_policy_risk": [
                {
                    "user_name": "risk-user",
                    "wildcard_admin_policies": [
                        {"policy_name": "admin-star", "policy_arn": "arn:aws:iam::aws:policy/Admin", "source": "managed"}
                    ],
                }
            ]
        }
    )

    findings = IAMWildcardPolicyCheck().evaluate(result)

    assert len(findings) == 1
    assert findings[0].status == "FAIL"
    assert findings[0].severity == "HIGH"


def test_s3_encryption_check_detects_missing_encryption():
    result = _base_result(
        {
            "s3_bucket_security": [
                {"name": "safe-bucket", "encryption_enabled": True},
                {"name": "risk-bucket", "encryption_enabled": False},
            ]
        }
    )

    findings = S3EncryptionCheck().evaluate(result)

    assert len(findings) == 2
    assert findings[0].status == "PASS"
    assert findings[1].status == "FAIL"
    assert "encryption" in findings[1].message.lower()


def test_security_group_exposure_check_detects_public_ssh():
    result = _base_result(
        {
            "security_groups": [
                {
                    "group_id": "sg-safe",
                    "group_name": "safe",
                    "ingress_rules": [
                        {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["10.0.0.0/8"]}
                    ],
                },
                {
                    "group_id": "sg-risk",
                    "group_name": "risk",
                    "ingress_rules": [
                        {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"]}
                    ],
                },
            ]
        }
    )

    findings = SecurityGroupExposureCheck().evaluate(result)

    assert len(findings) == 2
    assert findings[0].status == "PASS"
    assert findings[1].status == "FAIL"
    assert "ssh" in findings[1].message.lower()


def test_iam_role_trust_policy_check_flags_open_trust():
    result = _base_result(
        {
            "iam_role_trust_risk": [
                {"role_name": "safe-role", "open_trust": False, "evidence": {}},
                {"role_name": "risk-role", "open_trust": True, "evidence": {"Statement": [{"Principal": "*"}]}},
            ]
        }
    )

    findings = IAMRoleTrustPolicyCheck().evaluate(result)

    assert len(findings) == 2
    assert findings[0].status == "PASS"
    assert findings[1].status == "FAIL"
    assert findings[1].severity == "HIGH"


def test_iam_role_wildcard_policy_check_flags_risky_role():
    result = _base_result(
        {
            "iam_role_policy_risk": [
                {"role_name": "safe-role", "wildcard_admin_policies": []},
                {
                    "role_name": "risk-role",
                    "wildcard_admin_policies": [{"policy_name": "admin-star", "source": "managed"}],
                },
            ]
        }
    )

    findings = IAMRoleWildcardPolicyCheck().evaluate(result)

    assert len(findings) == 2
    assert findings[0].status == "PASS"
    assert findings[1].status == "FAIL"
    assert "admin-star" in findings[1].message
