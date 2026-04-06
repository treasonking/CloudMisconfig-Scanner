from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.checks.aws_checks import (
    IAMUserMfaCheck,
    IAMWildcardPolicyCheck,
    S3EncryptionCheck,
    S3PublicExposureCheck,
    SecurityGroupExposureCheck,
)
from scanner.core.interfaces import Reporter
from scanner.core.scanner import MisconfigScanner
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
) -> MisconfigScanner:
    provider = AWSProvider(region_name=region_name, profile_name=profile_name)
    return MisconfigScanner(
        provider=provider,
        reporters=reporters if reporters is not None else default_reporters(),
        checks=[
            S3PublicExposureCheck(),
            S3EncryptionCheck(),
            IAMUserMfaCheck(),
            IAMWildcardPolicyCheck(),
            SecurityGroupExposureCheck(),
        ],
    )


def run_scan(
    profile_name: str | None = "default",
    region_name: str = "ap-northeast-2",
    reporters: list[Reporter] | None = None,
):
    scanner = build_scanner(profile_name=profile_name, region_name=region_name, reporters=reporters)
    return scanner.run()


def test_aws_connection(profile_name: str | None = "default", region_name: str = "ap-northeast-2"):
    return run_scan(profile_name=profile_name, region_name=region_name)


def print_plan(mode: str = "today") -> None:
    if mode == "weekly":
        print(WEEKLY_ROADMAP)
        return
    print(TODAY_CHECKLIST)


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud misconfiguration scanner")
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Run AWS scan")
    scan_parser.add_argument("--profile", default="default", help="AWS profile name")
    scan_parser.add_argument("--region", default="ap-northeast-2", help="AWS region")
    plan_parser = sub.add_parser("plan", help="Print execution plan/checklist")
    plan_parser.add_argument("--mode", default="today", choices=["today", "weekly"], help="Plan mode")

    args = parser.parse_args()

    if args.command in {"scan", None}:
        profile = getattr(args, "profile", "default")
        region = getattr(args, "region", "ap-northeast-2")
        run_scan(profile_name=profile, region_name=region)
        return 0
    if args.command == "plan":
        print_plan(mode=args.mode)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
