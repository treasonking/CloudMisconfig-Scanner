from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from scanner.core.models import ScanResult


class JsonReporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def render(self, result: ScanResult) -> str:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_file = self.output_dir / f"scan-{timestamp}.json"
        output_file.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return f"[REPORT] JSON saved: {output_file}"
