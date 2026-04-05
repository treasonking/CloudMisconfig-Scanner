from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.checks.aws_checks import IAMUserMfaCheck, S3PublicExposureCheck
from scanner.core.scanner import MisconfigScanner
from scanner.providers.aws.provider import AWSProvider
from scanner.reporting.console import ConsoleReporter
from scanner.reporting.json_reporter import JsonReporter


def test_aws_connection(profile_name: str | None = "default", region_name: str = "ap-northeast-2"):
    provider = AWSProvider(region_name=region_name, profile_name=profile_name)
    scanner = MisconfigScanner(
        provider=provider,
        reporters=[
            ConsoleReporter(),
            JsonReporter(output_dir=ROOT / "reports"),
        ],
        checks=[S3PublicExposureCheck(), IAMUserMfaCheck()],
    )
    return scanner.run()


if __name__ == "__main__":
    test_aws_connection()
