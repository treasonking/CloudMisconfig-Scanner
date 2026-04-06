from __future__ import annotations

from scanner.core.models import Finding, ScanResult


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


class IAMRoleTrustPolicyCheck:
    check_id = "AWS.IAM.RoleTrustPolicy"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for item in result.data.get("iam_role_trust_risk", []):
            risky = item.get("open_trust", False)
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="IAM role trust policy openness",
                    status="FAIL" if risky else "PASS",
                    severity="HIGH" if risky else "INFO",
                    resource=f"iam:role/{item.get('role_name', '-')}",
                    message=("Role trust policy allows wildcard principal" if risky else "Role trust policy is restricted"),
                    recommendation=(
                        "Restrict trust policy principals to specific AWS accounts/services."
                        if risky
                        else None
                    ),
                    evidence=item.get("evidence", {}),
                )
            )

        return findings


class IAMRoleWildcardPolicyCheck:
    check_id = "AWS.IAM.RoleWildcardPolicy"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for item in result.data.get("iam_role_policy_risk", []):
            policies = item.get("wildcard_admin_policies", [])
            risky = len(policies) > 0
            policy_names = [p.get("policy_name", "") for p in policies]
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="IAM role wildcard admin policy",
                    status="FAIL" if risky else "PASS",
                    severity="HIGH" if risky else "INFO",
                    resource=f"iam:role/{item.get('role_name', '-')}",
                    message=(
                        f"Wildcard admin policy detected: {', '.join(policy_names)}"
                        if risky
                        else "No wildcard admin policy detected"
                    ),
                    recommendation=(
                        "Replace wildcard role permissions with least-privilege scoped actions/resources."
                        if risky
                        else None
                    ),
                    evidence={"wildcard_admin_policies": policies},
                )
            )

        return findings
