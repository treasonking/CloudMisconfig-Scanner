from __future__ import annotations

from scanner.core.models import Finding, ScanResult


class S3PublicExposureCheck:
    check_id = "AWS.S3.PublicExposure"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []
        buckets = result.data.get("s3_bucket_security", [])

        for bucket in buckets:
            exposed = bucket.get("is_exposed", False)
            reasons = bucket.get("reasons", [])
            reason_text = ", ".join(reasons) if reasons else "No public exposure detected"
            recommendation = None
            if exposed:
                recommendation = (
                    "Enable all S3 Public Access Block settings and remove public ACL/policy statements."
                )

            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="S3 bucket public exposure",
                    status="FAIL" if exposed else "PASS",
                    severity="HIGH" if exposed else "INFO",
                    resource=f"s3://{bucket.get('name', '-')}",
                    message=reason_text,
                    recommendation=recommendation,
                )
            )

        return findings


class IAMUserMfaCheck:
    check_id = "AWS.IAM.UserMFA"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []
        users = result.data.get("iam_user_mfa", [])

        for user in users:
            enabled = user.get("mfa_enabled", False)
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="IAM user MFA enabled",
                    status="PASS" if enabled else "FAIL",
                    severity="INFO" if enabled else "MEDIUM",
                    resource=f"iam:user/{user.get('user_name', '-')}",
                    message="MFA enabled" if enabled else "MFA device not configured",
                    recommendation=(
                        None
                        if enabled
                        else "Assign at least one MFA device to the IAM user and enforce MFA in sign-in policy."
                    ),
                )
            )

        return findings
