from __future__ import annotations

SEVERITY_SCORE = {
    "Low": 1,
    "Medium": 3,
    "High": 6,
    "Critical": 10,
}


def calculate_risk_score(findings: list[dict]) -> dict:
    total_score = 0

    for finding in findings:
        total_score += SEVERITY_SCORE.get(finding.get("severity", "Low"), 1)

    if total_score >= 20:
        rating = "Critical"
    elif total_score >= 12:
        rating = "High"
    elif total_score >= 5:
        rating = "Medium"
    else:
        rating = "Low"

    return {
        "total_findings": len(findings),
        "risk_score": total_score,
        "rating": rating,
    }
