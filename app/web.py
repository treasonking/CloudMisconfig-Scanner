from __future__ import annotations

from pathlib import Path
import sys

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import run_scan
from scanner.reporting.html_reporter import HtmlReporter
from scanner.reporting.json_reporter import JsonReporter


REPORTS_DIR = ROOT / "reports"
TEMPLATE_DIR = ROOT / "app" / "templates"
TEMPLATES = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

app = FastAPI(title="CloudMisconfig Scanner API", version="0.1.0")


def _scan_reporters():
    return [
        JsonReporter(output_dir=REPORTS_DIR),
        HtmlReporter(output_dir=REPORTS_DIR, template_dir=TEMPLATE_DIR),
    ]


def _report_list(limit: int = 20, cursor: int = 0) -> tuple[list[dict], str | None]:
    if not REPORTS_DIR.exists():
        return [], None

    files = sorted(REPORTS_DIR.glob("scan-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    start = max(cursor, 0)
    end = start + limit
    items = []
    for p in files[start:end]:
        items.append(
            {
                "filename": p.name,
                "path": str(p),
                "size": p.stat().st_size,
                "modified": p.stat().st_mtime,
                "type": p.suffix.lstrip("."),
            }
        )
    next_cursor = str(end) if end < len(files) else None
    return items, next_cursor


@app.get("/")
def home():
    return {
        "message": "CloudMisconfig Scanner API",
        "endpoints": ["/scan", "/results", "/report/{filename}", "/dashboard"],
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
def results(limit: int = Query(20, ge=1, le=100), cursor: str | None = Query(None)):
    offset = int(cursor) if cursor and cursor.isdigit() else 0
    reports, next_cursor = _report_list(limit=limit, cursor=offset)
    return {"reports": reports, "next_cursor": next_cursor}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    profile: str = Query("default"),
    region: str = Query("ap-northeast-2"),
    only_fail: bool = Query(False),
    severity: str | None = Query(None),
):
    reports, _ = _report_list(limit=20)

    latest_json = next((r for r in reports if r["type"] == "json"), None)
    summary = {"total": 0, "fail": 0, "pass": 0, "errors": 0}
    findings: list[dict] = []

    if latest_json:
        import json

        payload = json.loads(Path(latest_json["path"]).read_text(encoding="utf-8"))
        findings = payload.get("findings", [])
        summary = {
            "total": len(findings),
            "fail": sum(1 for f in findings if f.get("status") == "FAIL"),
            "pass": sum(1 for f in findings if f.get("status") == "PASS"),
            "errors": len(payload.get("errors", [])),
        }

    shown_findings = [f for f in findings if f.get("status") == "FAIL"] if only_fail else findings
    if severity:
        normalized = severity.upper()
        shown_findings = [f for f in shown_findings if str(f.get("severity", "")).upper() == normalized]

    html = TEMPLATES.get_template("dashboard.html.j2").render(
        reports=reports,
        summary=summary,
        findings=shown_findings,
        profile=profile,
        region=region,
        only_fail=only_fail,
        severity=(severity or "").upper(),
    )
    return HTMLResponse(content=html)


@app.get("/report/{filename}")
def report_file(filename: str):
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    target = REPORTS_DIR / filename
    if not target.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    media_type = "text/html" if target.suffix.lower() == ".html" else "application/json"
    return FileResponse(path=target, media_type=media_type, filename=target.name)
