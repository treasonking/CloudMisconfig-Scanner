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
                    evidence={"mfa_enabled": enabled},
                )
            )

        return findings


class IAMWildcardPolicyCheck:
    check_id = "AWS.IAM.WildcardPolicy"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for item in result.data.get("iam_user_policy_risk", []):
            policies = item.get("wildcard_admin_policies", [])
            risky = len(policies) > 0
            policy_names = [p.get("policy_name", "") for p in policies]
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="IAM wildcard admin policy",
                    status="FAIL" if risky else "PASS",
                    severity="HIGH" if risky else "INFO",
                    resource=f"iam:user/{item.get('user_name', '-')}",
                    message=(
                        f"Wildcard admin policy detected: {', '.join(policy_names)}"
                        if risky
                        else "No wildcard admin policy detected"
                    ),
                    recommendation=(
                        "Replace wildcard permissions with least-privilege scoped actions and resources."
                        if risky
                        else None
                    ),
                    evidence={"wildcard_admin_policies": policies},
                )
            )

        return findings


class SecurityGroupExposureCheck:
    check_id = "AWS.EC2.SG.PublicIngress"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for sg in result.data.get("security_groups", []):
            group_resource = f"sg:{sg.get('group_id', '-')}/{sg.get('group_name', '-') }"
            risky_messages: list[str] = []
            risky_evidence: list[dict] = []

            for rule in sg.get("ingress_rules", []):
                for cidr in rule.get("cidrs", []):
                    if cidr not in {"0.0.0.0/0", "::/0"}:
                        continue

                    proto = rule.get("ip_protocol")
                    from_port = rule.get("from_port")
                    to_port = rule.get("to_port")

                    if proto == "-1":
                        risky_messages.append("All protocols open to public")
                        risky_evidence.append({"cidr": cidr, "ip_protocol": proto})
                        continue

                    if self._contains_port(from_port, to_port, 22):
                        risky_messages.append("Public SSH(22) access")
                        risky_evidence.append({"cidr": cidr, "from_port": from_port, "to_port": to_port})

                    if self._contains_port(from_port, to_port, 3389):
                        risky_messages.append("Public RDP(3389) access")
                        risky_evidence.append({"cidr": cidr, "from_port": from_port, "to_port": to_port})

                    if any(self._contains_port(from_port, to_port, p) for p in [3306, 5432, 27017]):
                        risky_messages.append("Public DB port exposure")
                        risky_evidence.append({"cidr": cidr, "from_port": from_port, "to_port": to_port})

                    if from_port == 0 and to_port == 65535:
                        risky_messages.append("All TCP ports open to public")
                        risky_evidence.append({"cidr": cidr, "from_port": from_port, "to_port": to_port})

            risky = len(risky_messages) > 0
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="Security Group public ingress",
                    status="FAIL" if risky else "PASS",
                    severity="HIGH" if risky else "INFO",
                    resource=group_resource,
                    message=("; ".join(sorted(set(risky_messages))) if risky else "No risky public ingress rule detected"),
                    recommendation=(
                        "Restrict inbound rules to trusted CIDRs and remove public access to admin/DB ports."
                        if risky
                        else None
                    ),
                    evidence={"risky_rules": risky_evidence},
                )
            )

        return findings

    @staticmethod
    def _contains_port(from_port: int | None, to_port: int | None, port: int) -> bool:
        if from_port is None or to_port is None:
            return False
        return from_port <= port <= to_port
