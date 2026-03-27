from __future__ import annotations

from ipaddress import ip_address
from itertools import count

import psutil

from spy_detector.models import Finding

COMMON_ALLOWED_PORTS = {80, 443, 53, 123}


def _is_private_ip(ip: str) -> bool:
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False


def _safe_net_connections() -> list:
    try:
        return psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return []


def collect_endpoint_inventory() -> list[str]:
    endpoints: set[str] = set()
    for conn in _safe_net_connections():
        if not conn.raddr:
            continue
        host = getattr(conn.raddr, "ip", None)
        port = getattr(conn.raddr, "port", None)
        if host and port:
            endpoints.add(f"{host}:{port}")
    return sorted(endpoints)


def detect_network_anomalies(known_endpoints: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    known_endpoints = known_endpoints or set()
    finding_ids = count(1)

    for conn in _safe_net_connections():
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue

        host = getattr(conn.raddr, "ip", None)
        port = getattr(conn.raddr, "port", None)
        if not host or not port:
            continue

        endpoint = f"{host}:{port}"
        pid = conn.pid

        if not _is_private_ip(host) and port not in COMMON_ALLOWED_PORTS:
            findings.append(
                Finding(
                    id=f"NET-{next(finding_ids):04d}",
                    category="network",
                    severity="medium",
                    title="Outbound connection to uncommon external endpoint",
                    details=f"Established connection to {endpoint}",
                    evidence={
                        "pid": pid,
                        "local": f"{getattr(conn.laddr, 'ip', '')}:{getattr(conn.laddr, 'port', '')}",
                        "remote": endpoint,
                        "status": conn.status,
                    },
                    recommendation="Confirm destination and process legitimacy; monitor for recurring transfer behavior.",
                )
            )

        if endpoint not in known_endpoints:
            findings.append(
                Finding(
                    id=f"NET-{next(finding_ids):04d}",
                    category="baseline-drift",
                    severity="low",
                    title="New remote endpoint not in baseline",
                    details=f"Observed remote endpoint {endpoint}",
                    evidence={"pid": pid, "remote": endpoint},
                    recommendation="Review endpoint owner/use case and update baseline if expected.",
                )
            )

    return findings
