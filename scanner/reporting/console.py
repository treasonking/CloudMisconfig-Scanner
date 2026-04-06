from __future__ import annotations

from scanner.core.models import ScanResult


class ConsoleReporter:
    def render(self, result: ScanResult) -> str:
        lines: list[str] = []

        if result.errors:
            lines.append("=== Errors ===")
            for err in result.errors:
                lines.append(f"[ERROR] {err}")
            lines.append("")

        identity = result.data.get("identity", {})
        if identity:
            lines.append("=== AWS 인증 성공 ===")
            lines.append(f"Account: {identity.get('account', '-')}")
            lines.append(f"ARN: {identity.get('arn', '-')}")
            lines.append("")

        lines.append("=== S3 버킷 목록 ===")
        buckets = result.data.get("s3_buckets", [])
        if not buckets:
            lines.append("버킷이 없습니다.")
        else:
            lines.extend([f"- {name}" for name in buckets])
        lines.append("")

        lines.append("=== IAM 사용자 목록 ===")
        users = result.data.get("iam_users", [])
        if not users:
            lines.append("IAM 사용자가 없습니다.")
        else:
            lines.extend([f"- {name}" for name in users])
        lines.append("")

        lines.append("=== IAM 역할 목록 ===")
        roles = result.data.get("iam_roles", [])
        if not roles:
            lines.append("IAM 역할이 없습니다.")
        else:
            lines.extend([f"- {name}" for name in roles])
        lines.append("")

        lines.append("=== Security Groups ===")
        groups = result.data.get("security_groups", [])
        if not groups:
            lines.append("Security Group이 없습니다.")
        else:
            lines.extend([f"- {g.get('group_id', '-')} ({g.get('group_name', '-')})" for g in groups])
        lines.append("")

        lines.append("=== Service Status ===")
        service_status = result.data.get("service_status", {})
        if not service_status:
            lines.append("서비스 상태 정보가 없습니다.")
        else:
            for svc, status in service_status.items():
                state = status.get("status", "UNKNOWN")
                errors = status.get("errors", [])
                lines.append(f"- {svc.upper()}: {state}")
                for err in errors:
                    lines.append(f"  -> {err}")
        lines.append("")

        lines.append("=== Checks ===")
        if not result.findings:
            lines.append("체크 결과가 없습니다.")
            return "\n".join(lines)

        for finding in result.findings:
            line = (
                f"[{finding.status}] ({finding.severity}) {finding.check_id} | "
                f"{finding.resource} | {finding.message}"
            )
            lines.append(line)
            if finding.recommendation:
                lines.append(f"  -> Remediation: {finding.recommendation}")

        return "\n".join(lines)
