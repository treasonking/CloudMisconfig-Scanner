from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.core.models import ScanResult
from scanner.reporting.analysis import (
    DEFAULT_IMPROVEMENTS,
    DEFAULT_LIMITATIONS,
    build_detection_quality,
    build_finding_rows,
    build_summary,
    build_test_scope,
)


class HtmlReporter:
    def __init__(self, output_dir: Path, template_dir: Path):
        self.output_dir = output_dir
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render(self, result: ScanResult) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        template = self.env.get_template("report.html.j2")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"scan-{timestamp}.html"

        findings = build_finding_rows(result.findings)
        summary = build_summary(findings)
        benchmark_cases = result.data.get("benchmark_cases")
        scope_override = result.data.get("test_scope")
        test_scope = build_test_scope(summary, benchmark_cases=benchmark_cases, override_scope=scope_override)
        detection_quality = build_detection_quality(findings, benchmark_cases=benchmark_cases)

        html = template.render(
            context={
                "provider": result.context.provider,
                "region": result.context.region,
                "profile": result.context.profile,
                "started_at": result.context.started_at.isoformat(),
            },
            errors=result.errors,
            findings=findings,
            summary=summary,
            test_scope=test_scope,
            detection_quality=detection_quality,
            limitations=result.data.get("limitations") or DEFAULT_LIMITATIONS,
            improvements=result.data.get("improvements") or DEFAULT_IMPROVEMENTS,
            to_json=lambda value: json.dumps(value, ensure_ascii=False),
        )
        output_file.write_text(html, encoding="utf-8")
        return f"[REPORT] HTML saved: {output_file}"
