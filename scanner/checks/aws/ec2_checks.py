from __future__ import annotations

from scanner.core.models import Finding, ScanResult


class SecurityGroupExposureCheck:
    check_id = "AWS.EC2.SG.PublicIngress"

    def evaluate(self, result: ScanResult) -> list[Finding]:
        findings: list[Finding] = []

        for sg in result.data.get("security_groups", []):
            group_resource = f"sg:{sg.get('group_id', '-')}/{sg.get('group_name', '-')}"
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
