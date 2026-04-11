from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scanner.core.models import ScanResult
from scanner.reporting.analysis import (
    DEFAULT_IMPROVEMENTS,
    DEFAULT_LIMITATIONS,
    build_detection_quality,
    build_finding_rows,
    build_summary,
    build_test_scope,
)


class JsonReporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def render(self, result: ScanResult) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"scan-{timestamp}.json"
        rows = build_finding_rows(result.findings)
        summary = build_summary(rows)
        benchmark_cases = result.data.get("benchmark_cases")
        scope_override = result.data.get("test_scope")
        payload = result.to_dict()
        payload["findings"] = rows
        payload["summary"] = summary
        payload["test_scope"] = build_test_scope(summary, benchmark_cases=benchmark_cases, override_scope=scope_override)
        payload["detection_quality"] = build_detection_quality(rows, benchmark_cases=benchmark_cases)
        payload["limitations"] = result.data.get("limitations") or DEFAULT_LIMITATIONS
        payload["improvement_directions"] = result.data.get("improvements") or DEFAULT_IMPROVEMENTS

        output_file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return f"[REPORT] JSON saved: {output_file}"
