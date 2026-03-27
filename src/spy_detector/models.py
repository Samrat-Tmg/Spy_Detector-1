from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    id: str
    category: str
    severity: str
    title: str
    details: str
    evidence: dict[str, Any]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanSummary:
    hostname: str
    scanned_at: str
    total_findings: int
    high: int
    medium: int
    low: int

    @classmethod
    def from_findings(cls, hostname: str, findings: list[Finding]) -> "ScanSummary":
        by_severity = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            if finding.severity in by_severity:
                by_severity[finding.severity] += 1

        return cls(
            hostname=hostname,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            total_findings=len(findings),
            high=by_severity["high"],
            medium=by_severity["medium"],
            low=by_severity["low"],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
