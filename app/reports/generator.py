from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.responses import Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

SYSTEM_NAME = "SentinelScan"
SYSTEM_VERSION = "1.0.0"


def _escape_latex(value: Any) -> str:
    text = "" if value is None else str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "tex"]),
    )
    environment.filters["latex_escape"] = _escape_latex
    return environment


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = str(finding.get("severity", "")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def _report_context(scan: dict[str, Any]) -> dict[str, Any]:
    findings = list(scan.get("findings", []))
    risk = scan.get("risk", {})
    counts = _severity_counts(findings)
    return {
        "system_name": SYSTEM_NAME,
        "system_version": SYSTEM_VERSION,
        "findings": findings,
        "severity_counts": counts,
        "risk": risk,
        "target": scan.get("target") or scan.get("target_url", ""),
        "created_at": scan.get("created_at", ""),
        "scan_id": scan.get("scan_id", "report"),
        "scan": scan,
    }


def generate_html_report(scan: dict[str, Any]) -> str:
    template = _environment().get_template("report.html")
    return template.render(scan=scan)


def generate_tex_report(scan: dict[str, Any]) -> str:
    template = _environment().get_template("report.tex.j2")
    return template.render(**_report_context(scan))


def generate_pdf_report(scan: dict[str, Any]) -> Response:
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "PDF report generation requires WeasyPrint and its system libraries. "
            "Install the native dependencies described in the WeasyPrint documentation "
            "or use the HTML report endpoint instead."
        ) from exc

    html = generate_html_report(scan)
    pdf_bytes = HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf()
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="sentinelscan-{scan.get("scan_id", "report")}.pdf"'},
    )
