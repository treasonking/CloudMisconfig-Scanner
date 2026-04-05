from datetime import datetime, timezone

from scanner.core.models import ScanContext, ScanResult
from scanner.providers.aws.provider import AWSProvider


def test_service_status_transitions_to_partial_on_mixed_result():
    provider = AWSProvider()
    result = ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", started_at=datetime.now(timezone.utc)),
        data={"service_status": {"s3": {"status": "PENDING", "errors": []}}},
    )

    provider._mark_service_success(result, "s3")
    assert result.data["service_status"]["s3"]["status"] == "SUCCESS"

    provider._mark_service_failed(result, "s3", "AccessDenied")
    assert result.data["service_status"]["s3"]["status"] == "PARTIAL"
    assert "AccessDenied" in result.data["service_status"]["s3"]["errors"]
