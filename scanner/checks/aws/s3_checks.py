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
                recommendation = "Enable all S3 Public Access Block settings and remove public ACL/policy statements."

            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="S3 bucket public exposure",
                    status="FAIL" if exposed else "PASS",
                    severity="HIGH" if exposed else "INFO",
                    resource=f"s3://{bucket.get('name', '-')}",
                    message=reason_text,
                    recommendation=recommendation,
                    evidence={
                        "is_exposed": exposed,
                        "reasons": reasons,
                    },
                )
            )

        return findings


class S3EncryptionCheck:
    check_id = "AWS.S3.EncryptionEnabled"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for bucket in result.data.get("s3_bucket_security", []):
            enc = bucket.get("encryption_enabled", True)
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="S3 server-side encryption",
                    status="PASS" if enc else "FAIL",
                    severity="INFO" if enc else "MEDIUM",
                    resource=f"s3://{bucket.get('name', '-')}",
                    message="Encryption configured" if enc else "Server-side encryption not configured",
                    recommendation=(
                        None if enc else "Enable default bucket encryption using SSE-S3 or SSE-KMS."
                    ),
                    evidence={"encryption_enabled": enc},
                )
            )

        return findings
