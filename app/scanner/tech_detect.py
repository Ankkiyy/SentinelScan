from __future__ import annotations

import re

import requests
from bs4 import BeautifulSoup

from app.utils.http_client import fetch_page

FRAMEWORK_HINTS = {
    "react": ["react", "_next/static", "data-reactroot"],
    "vue": ["vue", "data-v-"],
    "angular": ["ng-version", "angular"],
    "django": ["csrfmiddlewaretoken", "django"],
    "laravel": ["laravel", "XSRF-TOKEN"],
    "wordpress": ["wp-content", "wp-includes"],
}

VERSION_PATTERN = re.compile(r"(?:v|version)[\s:=/-]*([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE)


def detect_technologies(url: str) -> dict:
    findings = []
    detected = []

    try:
        response = fetch_page(url)
        soup = BeautifulSoup(response.text, "html.parser")

        server_header = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")

        if server_header:
            detected.append({"name": "Server header", "value": server_header})
            findings.append(
                {
                    "name": "Server header reveals platform metadata",
                    "severity": "Low",
                    "description": "The Server header discloses software metadata that may aid fingerprinting.",
                    "evidence": f"Server: {server_header}",
                    "recommendation": "Minimize version disclosure where possible.",
                }
            )

        if powered_by:
            detected.append({"name": "X-Powered-By", "value": powered_by})
            findings.append(
                {
                    "name": "X-Powered-By header reveals framework metadata",
                    "severity": "Low",
                    "description": "The X-Powered-By header exposes implementation details.",
                    "evidence": f"X-Powered-By: {powered_by}",
                    "recommendation": "Remove or normalize the X-Powered-By header when feasible.",
                }
            )

        html_text = response.text.lower()
        for framework, hints in FRAMEWORK_HINTS.items():
            if any(hint.lower() in html_text for hint in hints):
                detected.append({"name": "Framework hint", "value": framework})
                break

        meta_generator = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if meta_generator and meta_generator.get("content"):
            detected.append({"name": "Meta generator", "value": meta_generator["content"]})
            findings.append(
                {
                    "name": "Generator meta tag exposed",
                    "severity": "Low",
                    "description": "The page discloses generator metadata through a meta tag.",
                    "evidence": f"Generator: {meta_generator['content']}",
                    "recommendation": "Remove nonessential generator metadata in production.",
                }
            )

        exposed_versions = []
        for candidate in [server_header or "", powered_by or "", response.text[:20000]]:
            match = VERSION_PATTERN.search(candidate)
            if match:
                exposed_versions.append(match.group(1))

        if exposed_versions:
            findings.append(
                {
                    "name": "Exposed version hint",
                    "severity": "Low",
                    "description": "The application reveals an identifiable version string.",
                    "evidence": ", ".join(exposed_versions[:3]),
                    "recommendation": "Avoid exposing version strings in public responses and markup.",
                }
            )

        return {
            "status": "completed",
            "detected": detected,
            "findings": findings,
        }
    except requests.RequestException as error:
        return {
            "status": "failed",
            "error": str(error),
            "detected": [],
            "findings": [],
        }
