from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, HttpUrl

from app.database.db import fetch_scan_by_id, init_db, save_scan
from app.reports.generator import generate_html_report, generate_pdf_report, generate_tex_report
from app.scanner.crawler import crawl_target
from app.scanner.forms import analyze_forms
from app.scanner.headers import scan_security_headers
from app.scanner.risk_engine import calculate_risk_score
from app.scanner.ssl_check import check_ssl_tls
from app.scanner.tech_detect import detect_technologies

app = FastAPI(
    title="SentinelScan",
    description="Defensive web vulnerability scanner for security analyst portfolio",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    target_url: HttpUrl


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/health")
def health_check() -> dict:
    return {"status": "ok"}


@app.post("/scan")
def scan_target(request: ScanRequest) -> dict:
    target = str(request.target_url)

    headers_result = scan_security_headers(target)
    crawl_result = crawl_target(target)
    form_result = analyze_forms(target, crawl_result.get("forms", []))
    ssl_result = check_ssl_tls(target)
    tech_result = detect_technologies(target)

    findings = []
    for result in (headers_result, form_result, ssl_result, tech_result):
        findings.extend(result.get("findings", []))

    risk_result = calculate_risk_score(findings)

    scan_record = {
        "target": target,
        "headers": headers_result,
        "crawl": crawl_result,
        "forms": form_result,
        "ssl": ssl_result,
        "technology": tech_result,
        "risk": risk_result,
        "findings": findings,
    }
    scan_id = save_scan(scan_record)

    return {
        "scan_id": scan_id,
        "target": target,
        "headers": headers_result,
        "crawl": crawl_result,
        "forms": form_result,
        "ssl": ssl_result,
        "technology": tech_result,
        "risk": risk_result,
        "findings": findings,
    }


@app.get("/scan/{scan_id}")
def get_scan(scan_id: int) -> dict:
    scan = fetch_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/report/{scan_id}")
def get_report_html(scan_id: int) -> dict:
    scan = fetch_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan_id, "html": generate_html_report(scan)}


@app.get("/report/{scan_id}/tex")
def get_report_tex(scan_id: int):
    scan = fetch_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    tex = generate_tex_report(scan)
    return Response(
        content=tex,
        media_type="application/x-tex",
        headers={"Content-Disposition": f'attachment; filename="sentinelscan-{scan_id}.tex"'},
    )


@app.get("/report/{scan_id}/pdf")
def get_report_pdf(scan_id: int):
    scan = fetch_scan_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        return generate_pdf_report(scan)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
