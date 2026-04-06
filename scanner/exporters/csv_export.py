from __future__ import annotations

import csv
import io


def findings_to_csv(findings: list[dict]) -> str:
    output = io.StringIO()
    fieldnames = ["check_id", "status", "severity", "resource", "message", "recommendation"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow(
            {
                "check_id": f.get("check_id", ""),
                "status": f.get("status", ""),
                "severity": f.get("severity", ""),
                "resource": f.get("resource", ""),
                "message": f.get("message", ""),
                "recommendation": f.get("recommendation", ""),
            }
        )
    return output.getvalue()


def history_to_csv(history: list[dict]) -> str:
    output = io.StringIO()
    fieldnames = ["filename", "started_at", "total", "fail", "pass", "errors"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for item in history:
        writer.writerow(
            {
                "filename": item.get("filename", ""),
                "started_at": item.get("started_at", ""),
                "total": item.get("total", ""),
                "fail": item.get("fail", ""),
                "pass": item.get("pass", ""),
                "errors": item.get("errors", ""),
            }
        )
    return output.getvalue()
