from __future__ import annotations

from pathlib import Path
import sys

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import run_scan
from scanner.reporting.html_reporter import HtmlReporter
from scanner.reporting.json_reporter import JsonReporter


REPORTS_DIR = ROOT / "reports"
TEMPLATE_DIR = ROOT / "app" / "templates"

app = FastAPI(title="CloudMisconfig Scanner API", version="0.1.0")


def _scan_reporters():
    return [
        JsonReporter(output_dir=REPORTS_DIR),
        HtmlReporter(output_dir=REPORTS_DIR, template_dir=TEMPLATE_DIR),
    ]


@app.get("/")
def home():
    return {
        "message": "CloudMisconfig Scanner API",
        "endpoints": ["/scan", "/results", "/report/{filename}"],
    }


@app.get("/scan")
def scan(profile: str = Query("default"), region: str = Query("ap-northeast-2")):
    result = run_scan(profile_name=profile, region_name=region, reporters=_scan_reporters())
    payload = result.to_dict()
    payload["summary"] = {
        "total": len(result.findings),
        "fail": sum(1 for f in result.findings if f.status == "FAIL"),
        "pass": sum(1 for f in result.findings if f.status == "PASS"),
        "critical": sum(1 for f in result.findings if f.severity == "CRITICAL"),
        "high": sum(1 for f in result.findings if f.severity == "HIGH"),
        "medium": sum(1 for f in result.findings if f.severity == "MEDIUM"),
        "low_info": sum(1 for f in result.findings if f.severity in {"LOW", "INFO"}),
    }
    payload["service_status"] = result.data.get("service_status", {})
    return payload


@app.get("/results")
def results(limit: int = Query(20, ge=1, le=100)):
    if not REPORTS_DIR.exists():
        return {"reports": []}

    files = sorted(REPORTS_DIR.glob("scan-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    items = []
    for p in files[:limit]:
        items.append(
            {
                "filename": p.name,
                "path": str(p),
                "size": p.stat().st_size,
                "modified": p.stat().st_mtime,
                "type": p.suffix.lstrip("."),
            }
        )
    return {"reports": items}


@app.get("/report/{filename}")
def report_file(filename: str):
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    target = REPORTS_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "text/html" if target.suffix.lower() == ".html" else "application/json"
    return FileResponse(path=target, media_type=media_type, filename=target.name)
