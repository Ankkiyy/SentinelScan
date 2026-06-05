from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class ScanFinding:
    name: str
    severity: str
    description: str
    evidence: str
    recommendation: str


@dataclass(slots=True)
class ScanRecord:
    target: str
    headers: dict[str, Any]
    crawl: dict[str, Any]
    forms: dict[str, Any]
    ssl: dict[str, Any]
    technology: dict[str, Any]
    risk: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
