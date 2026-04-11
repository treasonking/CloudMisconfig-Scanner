from datetime import datetime, timezone

from scanner.core.models import Finding, ScanContext, ScanResult
from scanner.reporting.html_reporter import HtmlReporter


def test_html_reporter_renders_quality_sections(tmp_path):
    template_dir = tmp_path / "templates"
    template_dir.mkdir(parents=True, exist_ok=True)
    template = template_dir / "report.html.j2"
    template.write_text(
        "{{ summary.total }}|{{ test_scope.total_cases }}|{{ detection_quality.available }}|{{ findings[0].reason }}|{{ findings[0].risk }}",
        encoding="utf-8",
    )

    result = ScanResult(
        context=ScanContext(provider="aws", region="ap-northeast-2", started_at=datetime.now(timezone.utc)),
        data={
            "benchmark_cases": [{"check_id": "AWS.S3.PublicExposure", "resource": "s3://risk", "expected": "FAIL"}],
            "test_scope": {"total_cases": 20, "normal_cases": 8, "misconfigured_cases": 12},
        },
        findings=[
            Finding(
                check_id="AWS.S3.PublicExposure",
                title="t",
                status="FAIL",
                severity="HIGH",
                resource="s3://risk",
                message="public access enabled",
                recommendation="disable public access",
                evidence={"k": "v"},
            )
        ],
    )

    reporter = HtmlReporter(output_dir=tmp_path, template_dir=template_dir)
    reporter.render(result)

    files = list(tmp_path.glob("scan-*.html"))
    assert len(files) == 1
    html = files[0].read_text(encoding="utf-8")
    assert "1|20|True|public access enabled" in html
