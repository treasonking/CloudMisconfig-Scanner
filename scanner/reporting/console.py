from __future__ import annotations

from scanner.core.models import ScanResult


class ConsoleReporter:
    def render(self, result: ScanResult) -> str:
        lines: list[str] = []

        if result.errors:
            for err in result.errors:
                lines.append(f"[AWS 오류] {err}")
            return "\n".join(lines)

        identity = result.data.get("identity", {})
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
