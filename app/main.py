from pathlib import Path
import argparse
import json
from datetime import datetime, timezone
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.checks.aws_checks import (
    IAMRoleTrustPolicyCheck,
    IAMRoleWildcardPolicyCheck,
    IAMUserMfaCheck,
    IAMWildcardPolicyCheck,
    S3EncryptionCheck,
    S3PublicExposureCheck,
    SecurityGroupExposureCheck,
)
from scanner.core.interfaces import Reporter
from scanner.notifications.email import send_email_smtp
from scanner.core.scanner import MisconfigScanner
from scanner.notifications.slack import send_slack_message
from scanner.providers.aws.provider import AWSProvider
from scanner.reporting.console import ConsoleReporter
from scanner.reporting.html_reporter import HtmlReporter
from scanner.reporting.json_reporter import JsonReporter

WEEKLY_ROADMAP = """[4주 로드맵]
1주차
- 프로젝트 구조 생성
- boto3 연결
- AWS 테스트 환경 구성
- S3 스캐너 구현

2주차
- IAM 스캐너 구현
- Security Group 스캐너 구현
- 공통 결과 모델 정리

3주차
- JSON 저장
- HTML 리포트 생성
- CLI 완성

4주차
- FastAPI 웹 추가
- 예외처리 안정화
- README/시연 자료 준비
"""

TODAY_CHECKLIST = """[오늘 할 일]
1. Python 가상환경/의존성 확인
2. AWS 인증 연결 확인 (profile 또는 env)
3. `python app/main.py scan --profile default` 실행
4. `reports/`에 JSON/HTML 생성 확인
5. `python -m pytest -q` 실행
"""


def default_reporters() -> list[Reporter]:
    return [
        ConsoleReporter(),
        JsonReporter(output_dir=ROOT / "reports"),
        HtmlReporter(output_dir=ROOT / "reports", template_dir=ROOT / "app" / "templates"),
    ]


def build_scanner(
    profile_name: str | None = "default",
    region_name: str = "ap-northeast-2",
    reporters: list[Reporter] | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
) -> MisconfigScanner:
    provider = AWSProvider(
        region_name=region_name,
        profile_name=profile_name,
        role_arn=role_arn,
        external_id=external_id,
    )
    return MisconfigScanner(
        provider=provider,
        reporters=reporters if reporters is not None else default_reporters(),
        checks=[
            S3PublicExposureCheck(),
            S3EncryptionCheck(),
            IAMUserMfaCheck(),
            IAMWildcardPolicyCheck(),
            IAMRoleTrustPolicyCheck(),
            IAMRoleWildcardPolicyCheck(),
            SecurityGroupExposureCheck(),
        ],
    )


def run_scan(
    profile_name: str | None = "default",
    region_name: str = "ap-northeast-2",
    reporters: list[Reporter] | None = None,
    role_arn: str | None = None,
    external_id: str | None = None,
):
    scanner = build_scanner(
        profile_name=profile_name,
        region_name=region_name,
        reporters=reporters,
        role_arn=role_arn,
        external_id=external_id,
    )
    return scanner.run()


def test_aws_connection(profile_name: str | None = "default", region_name: str = "ap-northeast-2"):
    return run_scan(profile_name=profile_name, region_name=region_name)


def _summarize_scan_result(result, target: str | None = None) -> dict:
    return {
        "target": target or result.context.profile or "default",
        "profile": result.context.profile or "default",
        "account": result.data.get("identity", {}).get("account", "-"),
        "total": len(result.findings),
        "fail": sum(1 for f in result.findings if f.status == "FAIL"),
        "pass": sum(1 for f in result.findings if f.status == "PASS"),
        "errors": len(result.errors),
    }


def run_multi_scan(profiles: list[str], region_name: str = "ap-northeast-2") -> dict:
    summaries: list[dict] = []
    for profile in profiles:
        result = run_scan(profile_name=profile, region_name=region_name)
        summaries.append(_summarize_scan_result(result, target=profile))

    total_profiles = len(summaries)
    aggregate = {
        "mode": "profiles",
        "profiles": summaries,
        "totals": {
            "profiles": total_profiles,
            "findings": sum(item["total"] for item in summaries),
            "fail": sum(item["fail"] for item in summaries),
            "pass": sum(item["pass"] for item in summaries),
            "errors": sum(item["errors"] for item in summaries),
        },
    }
    return aggregate


def parse_profiles_arg(profiles: str | None = None, profiles_file: str | None = None) -> list[str]:
    items: list[str] = []
    if profiles:
        items.extend([p.strip() for p in profiles.split(",") if p.strip()])
    if profiles_file:
        file_path = Path(profiles_file)
        if not file_path.exists():
            raise FileNotFoundError(f"Profiles file not found: {profiles_file}")
        lines = [line.strip() for line in file_path.read_text(encoding="utf-8").splitlines()]
        items.extend([line for line in lines if line and not line.startswith("#")])

    unique = list(dict.fromkeys(items))
    return unique


def parse_assume_role_targets_file(targets_file: str) -> list[dict]:
    path = Path(targets_file)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {targets_file}")

    targets: list[dict] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split(",")]
        role_arn = parts[0]
        source_profile = parts[1] if len(parts) >= 2 and parts[1] else "default"
        external_id = parts[2] if len(parts) >= 3 and parts[2] else None

        targets.append({"role_arn": role_arn, "source_profile": source_profile, "external_id": external_id})

    return targets


def run_assume_role_multi_scan(targets: list[dict], region_name: str = "ap-northeast-2") -> dict:
    summaries: list[dict] = []

    for target in targets:
        role_arn = target["role_arn"]
        source_profile = target.get("source_profile") or "default"
        external_id = target.get("external_id")

        result = run_scan(
            profile_name=source_profile,
            region_name=region_name,
            role_arn=role_arn,
            external_id=external_id,
        )
        summaries.append(_summarize_scan_result(result, target=role_arn))

    aggregate = {
        "mode": "assume-role-targets",
        "profiles": summaries,
        "totals": {
            "profiles": len(summaries),
            "findings": sum(item["total"] for item in summaries),
            "fail": sum(item["fail"] for item in summaries),
            "pass": sum(item["pass"] for item in summaries),
            "errors": sum(item["errors"] for item in summaries),
        },
    }
    return aggregate


def save_multi_scan_summary(aggregate: dict) -> Path:
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_file = reports_dir / f"multi-scan-{timestamp}.json"
    output_file.write_text(json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_file


def print_multi_scan_summary(aggregate: dict) -> None:
    print("[Multi Scan Summary]")
    for item in aggregate["profiles"]:
        print(
            f"- {item['target']}: account={item['account']}, total={item['total']}, "
            f"fail={item['fail']}, pass={item['pass']}, errors={item['errors']}"
        )
    totals = aggregate["totals"]
    print(
        f"[Totals] targets={totals['profiles']}, findings={totals['findings']}, "
        f"fail={totals['fail']}, pass={totals['pass']}, errors={totals['errors']}"
    )


def notify_slack_for_aggregate(aggregate: dict, webhook_url: str) -> None:
    totals = aggregate["totals"]
    text = (
        "CloudMisconfig Scan Summary\\n"
        f"targets={totals['profiles']}, findings={totals['findings']}, "
        f"fail={totals['fail']}, pass={totals['pass']}, errors={totals['errors']}"
    )
    send_slack_message(webhook_url, text)


def notify_email_for_aggregate(
    aggregate: dict,
    recipient: str,
    smtp_host: str,
    smtp_port: int,
    sender: str,
    smtp_user: str | None = None,
    smtp_password: str | None = None,
) -> None:
    totals = aggregate["totals"]
    subject = "CloudMisconfig Scan Summary"
    body = (
        f"targets={totals['profiles']}\n"
        f"findings={totals['findings']}\n"
        f"fail={totals['fail']}\n"
        f"pass={totals['pass']}\n"
        f"errors={totals['errors']}\n"
    )
    send_email_smtp(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
        username=smtp_user,
        password=smtp_password,
    )


def print_plan(mode: str = "today") -> None:
    if mode == "weekly":
        print(WEEKLY_ROADMAP)
        return
    print(TODAY_CHECKLIST)


def load_scan_history(limit: int = 20) -> list[dict]:
    reports_dir = ROOT / "reports"
    if not reports_dir.exists():
        return []

    files = sorted(reports_dir.glob("scan-*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
    history: list[dict] = []
    for path in files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        findings = payload.get("findings", [])
        history.append(
            {
                "filename": path.name,
                "started_at": payload.get("context", {}).get("started_at"),
                "total": len(findings),
                "fail": sum(1 for f in findings if f.get("status") == "FAIL"),
                "pass": sum(1 for f in findings if f.get("status") == "PASS"),
                "errors": len(payload.get("errors", [])),
            }
        )
    return history


def print_scan_history(limit: int = 20) -> None:
    history = load_scan_history(limit=limit)
    print("[Scan History]")
    if not history:
        print("- no scan history found")
        return
    for item in history:
        print(
            f"- {item['filename']}: total={item['total']}, fail={item['fail']}, "
            f"pass={item['pass']}, errors={item['errors']}, started_at={item['started_at']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud misconfiguration scanner")
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Run AWS scan")
    scan_parser.add_argument("--profile", default="default", help="AWS profile name")
    scan_parser.add_argument("--region", default="ap-northeast-2", help="AWS region")
    scan_parser.add_argument("--role-arn", default=None, help="AssumeRole target ARN")
    scan_parser.add_argument("--external-id", default=None, help="AssumeRole external id")
    scan_parser.add_argument("--slack-webhook", default=None, help="Slack webhook URL for summary notification")
    scan_parser.add_argument("--email-to", default=None, help="Email recipient for summary notification")
    scan_parser.add_argument("--smtp-host", default=None, help="SMTP host")
    scan_parser.add_argument("--smtp-port", default=587, type=int, help="SMTP port")
    scan_parser.add_argument("--smtp-from", default=None, help="SMTP sender email")
    scan_parser.add_argument("--smtp-user", default=None, help="SMTP username")
    scan_parser.add_argument("--smtp-password", default=None, help="SMTP password")

    scan_multi_parser = sub.add_parser("scan-multi", help="Run AWS scan for multiple profiles")
    scan_multi_parser.add_argument(
        "--profiles",
        required=False,
        help="Comma-separated profile names (e.g., default,prod,dev)",
    )
    scan_multi_parser.add_argument(
        "--profiles-file",
        required=False,
        help="Text file containing AWS profile names (one profile per line)",
    )
    scan_multi_parser.add_argument("--region", default="ap-northeast-2", help="AWS region")
    scan_multi_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write aggregated summary file under reports/",
    )
    scan_multi_parser.add_argument("--slack-webhook", default=None, help="Slack webhook URL for summary notification")
    scan_multi_parser.add_argument("--email-to", default=None, help="Email recipient for summary notification")
    scan_multi_parser.add_argument("--smtp-host", default=None, help="SMTP host")
    scan_multi_parser.add_argument("--smtp-port", default=587, type=int, help="SMTP port")
    scan_multi_parser.add_argument("--smtp-from", default=None, help="SMTP sender email")
    scan_multi_parser.add_argument("--smtp-user", default=None, help="SMTP username")
    scan_multi_parser.add_argument("--smtp-password", default=None, help="SMTP password")

    assume_multi_parser = sub.add_parser("scan-assume-role-multi", help="Run multi-account scan via AssumeRole targets file")
    assume_multi_parser.add_argument("--targets-file", required=True, help="Targets file: role_arn[,source_profile][,external_id]")
    assume_multi_parser.add_argument("--region", default="ap-northeast-2", help="AWS region")
    assume_multi_parser.add_argument("--no-save", action="store_true", help="Do not write aggregated summary file")
    assume_multi_parser.add_argument("--slack-webhook", default=None, help="Slack webhook URL for summary notification")
    assume_multi_parser.add_argument("--email-to", default=None, help="Email recipient for summary notification")
    assume_multi_parser.add_argument("--smtp-host", default=None, help="SMTP host")
    assume_multi_parser.add_argument("--smtp-port", default=587, type=int, help="SMTP port")
    assume_multi_parser.add_argument("--smtp-from", default=None, help="SMTP sender email")
    assume_multi_parser.add_argument("--smtp-user", default=None, help="SMTP username")
    assume_multi_parser.add_argument("--smtp-password", default=None, help="SMTP password")

    history_parser = sub.add_parser("history", help="Show recent scan history")
    history_parser.add_argument("--limit", default=20, type=int, help="Number of recent scan files to summarize")

    plan_parser = sub.add_parser("plan", help="Print execution plan/checklist")
    plan_parser.add_argument("--mode", default="today", choices=["today", "weekly"], help="Plan mode")

    args = parser.parse_args()

    if args.command in {"scan", None}:
        profile = getattr(args, "profile", "default")
        region = getattr(args, "region", "ap-northeast-2")
        result = run_scan(
            profile_name=profile,
            region_name=region,
            role_arn=getattr(args, "role_arn", None),
            external_id=getattr(args, "external_id", None),
        )
        if getattr(args, "slack_webhook", None):
            aggregate = {
                "profiles": [_summarize_scan_result(result)],
                "totals": {
                    "profiles": 1,
                    "findings": len(result.findings),
                    "fail": sum(1 for f in result.findings if f.status == "FAIL"),
                    "pass": sum(1 for f in result.findings if f.status == "PASS"),
                    "errors": len(result.errors),
                },
            }
            notify_slack_for_aggregate(aggregate, args.slack_webhook)
        if getattr(args, "email_to", None):
            if not (args.smtp_host and args.smtp_from):
                raise SystemExit("--email-to 사용 시 --smtp-host, --smtp-from 이 필요합니다.")
            notify_email_for_aggregate(
                aggregate=aggregate,
                recipient=args.email_to,
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                sender=args.smtp_from,
                smtp_user=args.smtp_user,
                smtp_password=args.smtp_password,
            )
        return 0

    if args.command == "scan-multi":
        profiles = parse_profiles_arg(profiles=args.profiles, profiles_file=args.profiles_file)
        if not profiles:
            raise SystemExit("No profiles provided. Use --profiles or --profiles-file.")
        aggregate = run_multi_scan(profiles=profiles, region_name=args.region)
        print_multi_scan_summary(aggregate)
        if not args.no_save:
            output_file = save_multi_scan_summary(aggregate)
            print(f"[REPORT] Multi summary saved: {output_file}")
        if args.slack_webhook:
            notify_slack_for_aggregate(aggregate, args.slack_webhook)
        if args.email_to:
            if not (args.smtp_host and args.smtp_from):
                raise SystemExit("--email-to 사용 시 --smtp-host, --smtp-from 이 필요합니다.")
            notify_email_for_aggregate(
                aggregate=aggregate,
                recipient=args.email_to,
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                sender=args.smtp_from,
                smtp_user=args.smtp_user,
                smtp_password=args.smtp_password,
            )
        return 0

    if args.command == "scan-assume-role-multi":
        targets = parse_assume_role_targets_file(args.targets_file)
        if not targets:
            raise SystemExit("No targets found in file.")
        aggregate = run_assume_role_multi_scan(targets=targets, region_name=args.region)
        print_multi_scan_summary(aggregate)
        if not args.no_save:
            output_file = save_multi_scan_summary(aggregate)
            print(f"[REPORT] Multi summary saved: {output_file}")
        if args.slack_webhook:
            notify_slack_for_aggregate(aggregate, args.slack_webhook)
        if args.email_to:
            if not (args.smtp_host and args.smtp_from):
                raise SystemExit("--email-to 사용 시 --smtp-host, --smtp-from 이 필요합니다.")
            notify_email_for_aggregate(
                aggregate=aggregate,
                recipient=args.email_to,
                smtp_host=args.smtp_host,
                smtp_port=args.smtp_port,
                sender=args.smtp_from,
                smtp_user=args.smtp_user,
                smtp_password=args.smtp_password,
            )
        return 0

    if args.command == "plan":
        print_plan(mode=args.mode)
        return 0
    if args.command == "history":
        print_scan_history(limit=args.limit)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
