from __future__ import annotations

import requests

from app.utils.http_client import fetch_page

SECURITY_HEADERS = {
    "Content-Security-Policy": "Protects against XSS and data injection attacks.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS.",
    "X-Frame-Options": "Protects against clickjacking.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "Referrer-Policy": "Controls referrer data leakage.",
    "Permissions-Policy": "Restricts browser feature access.",
}

SEVERITY_MAP = {
    "Content-Security-Policy": "High",
    "Strict-Transport-Security": "High",
    "X-Frame-Options": "Medium",
    "X-Content-Type-Options": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}


def severity_for_header(header: str) -> str:
    return SEVERITY_MAP.get(header, "Low")


def scan_security_headers(url: str) -> dict:
    findings = []

    try:
        response = fetch_page(url)
        headers = response.headers

        for header, description in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    {
                        "name": f"Missing {header}",
                        "severity": severity_for_header(header),
                        "description": description,
                        "evidence": f"{header} header not present in HTTP response.",
                        "recommendation": f"Configure the {header} header on the web server.",
                    }
                )

        server_header = headers.get("Server")
        if server_header:
            findings.append(
                {
                    "name": "Server header exposed",
                    "severity": "Low",
                    "description": "The Server header can reveal web server software and version details.",
                    "evidence": f"Server: {server_header}",
                    "recommendation": "Suppress or normalize the Server header when practical.",
                }
            )

        return {
            "status": "completed",
            "status_code": response.status_code,
            "findings": findings,
        }
    except requests.RequestException as error:
        return {
            "status": "failed",
            "error": str(error),
            "findings": [],
        }
