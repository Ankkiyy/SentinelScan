from __future__ import annotations

from urllib.parse import urlparse

from app.utils.http_client import is_https


def analyze_forms(page_url: str, forms: list[dict]) -> dict:
    findings = []
    page_https = is_https(page_url)

    for form in forms:
        action_url = form.get("action", "")
        method = str(form.get("method", "GET")).upper()
        inputs = form.get("inputs", [])
        input_types = {str(item.get("type", "text")).lower() for item in inputs}
        input_names = {str(item.get("name", "")).lower() for item in inputs if item.get("name")}

        has_password_field = "password" in input_types
        csrf_like_fields = {"csrf", "csrf_token", "token", "authenticity_token", "_token"}
        has_csrf_field = any(name in csrf_like_fields or "csrf" in name or "token" in name for name in input_names)

        if has_password_field and action_url:
            parsed_action = urlparse(action_url)
            if parsed_action.scheme == "http" or (not parsed_action.scheme and not page_https):
                findings.append(
                    {
                        "name": "Password field submitted over insecure transport",
                        "severity": "Critical",
                        "description": "A password field is present on a form that can submit without HTTPS protection.",
                        "evidence": f"Form action: {action_url}",
                        "recommendation": "Ensure authentication forms are served and submitted only over HTTPS.",
                    }
                )

        if method == "POST" and not has_csrf_field:
            findings.append(
                {
                    "name": "Missing CSRF-like hidden field",
                    "severity": "Medium",
                    "description": "The form does not include an obvious anti-CSRF hidden field.",
                    "evidence": f"Form action: {action_url}",
                    "recommendation": "Add a CSRF token or equivalent server-side request validation.",
                }
            )

        if action_url and action_url.startswith("http://"):
            findings.append(
                {
                    "name": "Form action uses HTTP",
                    "severity": "High",
                    "description": "The form action submits data over unencrypted HTTP.",
                    "evidence": f"Form action: {action_url}",
                    "recommendation": "Use HTTPS endpoints for all sensitive form submissions.",
                }
            )

    return {
        "status": "completed",
        "forms_analyzed": len(forms),
        "findings": findings,
    }
