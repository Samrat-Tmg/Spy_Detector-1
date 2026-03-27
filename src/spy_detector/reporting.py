from __future__ import annotations

import json
from pathlib import Path

from spy_detector.models import Finding, ScanSummary


def build_report(summary: ScanSummary, findings: list[Finding]) -> dict:
    return {
        "summary": summary.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def render_terminal_report(summary: ScanSummary, findings: list[Finding]) -> str:
    lines = [
        f"Host: {summary.hostname}",
        f"Scanned at (UTC): {summary.scanned_at}",
        f"Findings: total={summary.total_findings} high={summary.high} medium={summary.medium} low={summary.low}",
        "",
    ]

    if not findings:
        lines.append("No suspicious indicators were found in this scan.")
        return "\n".join(lines)

    for finding in findings:
        lines.extend(
            [
                f"[{finding.severity.upper()}] {finding.title}",
                f"  id: {finding.id}",
                f"  category: {finding.category}",
                f"  details: {finding.details}",
                f"  recommendation: {finding.recommendation}",
                "",
            ]
        )

    return "\n".join(lines).rstrip()
