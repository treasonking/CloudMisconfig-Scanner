from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.core.models import ScanResult


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

        findings = [
            {
                "check_id": f.check_id,
                "title": f.title,
                "status": f.status,
                "severity": f.severity,
                "resource": f.resource,
                "message": f.message,
                "recommendation": f.recommendation,
            }
            for f in result.findings
        ]

        summary = {
            "total": len(findings),
            "fail": sum(1 for f in findings if f["status"] == "FAIL"),
            "pass": sum(1 for f in findings if f["status"] == "PASS"),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low_info": sum(1 for f in findings if f["severity"] in {"LOW", "INFO"}),
        }

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
        )
        output_file.write_text(html, encoding="utf-8")
        return f"[REPORT] HTML saved: {output_file}"
