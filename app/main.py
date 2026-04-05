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


def main() -> int:
    parser = argparse.ArgumentParser(description="Cloud misconfiguration scanner")
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Run AWS scan")
    scan_parser.add_argument("--profile", default="default", help="AWS profile name")
    scan_parser.add_argument("--region", default="ap-northeast-2", help="AWS region")

    args = parser.parse_args()

    if args.command in {"scan", None}:
        profile = getattr(args, "profile", "default")
        region = getattr(args, "region", "ap-northeast-2")
        run_scan(profile_name=profile, region_name=region)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
