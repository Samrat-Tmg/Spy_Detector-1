from __future__ import annotations

import socket
from typing import Any

from spy_detector.detectors import (
    collect_endpoint_inventory,
    collect_launch_agent_inventory,
    collect_process_inventory,
    detect_network_anomalies,
    detect_persistence_anomalies,
    detect_suspicious_processes,
)
from spy_detector.models import Finding, ScanSummary


def build_snapshot() -> dict[str, list[str]]:
    return {
        "processes": collect_process_inventory(),
        "endpoints": collect_endpoint_inventory(),
        "launch_agents": collect_launch_agent_inventory(),
    }


def run_scan(baseline: dict[str, Any]) -> tuple[ScanSummary, list[Finding]]:
    known_processes = set(baseline.get("processes", []))
    known_endpoints = set(baseline.get("endpoints", []))
    known_launch_agents = set(baseline.get("launch_agents", []))

    findings = []
    findings.extend(detect_suspicious_processes(known_processes=known_processes))
    findings.extend(detect_network_anomalies(known_endpoints=known_endpoints))
    findings.extend(detect_persistence_anomalies(known_launch_agents=known_launch_agents))

    summary = ScanSummary.from_findings(hostname=socket.gethostname(), findings=findings)
    return summary, findings
