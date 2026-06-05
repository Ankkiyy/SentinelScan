from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.responses import Response
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def generate_html_report(scan: dict[str, Any]) -> str:
    template = _environment().get_template("report.html")
    return template.render(scan=scan)


def generate_pdf_report(scan: dict[str, Any]) -> Response:
    html = generate_html_report(scan)
    pdf_bytes = HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="sentinelscan-{scan.get("scan_id", "report")}.pdf"'},
    )
