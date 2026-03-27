from __future__ import annotations

from itertools import count

import psutil

from spy_detector.models import Finding

SUSPICIOUS_KEYWORDS = {
    "keylog",
    "tcpdump",
    "wireshark",
    "mitmproxy",
    "ettercap",
    "charles",
    "burpsuite",
    "frida",
    "xpcproxy",
}


def _build_signature(name: str, exe: str, cmdline: str) -> str:
    return "|".join(
        [
            (name or "").strip().lower(),
            (exe or "").strip().lower(),
            (cmdline or "").strip().lower(),
        ]
    )


def collect_process_inventory() -> list[str]:
    inventory: list[str] = []
    for proc in psutil.process_iter(["name", "exe", "cmdline"]):
        info = proc.info
        signature = _build_signature(
            info.get("name") or "",
            info.get("exe") or "",
            " ".join(info.get("cmdline") or []),
        )
        if signature.strip("|"):
            inventory.append(signature)
    return sorted(set(inventory))


def detect_suspicious_processes(known_processes: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    known_processes = known_processes or set()
    finding_ids = count(1)
    seen_new_signatures: set[str] = set()

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = (info.get("exe") or "").lower()
            cmdline = " ".join(info.get("cmdline") or []).lower()
            haystack = " ".join([name, exe, cmdline])

            matched = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in haystack)
            signature = _build_signature(name, exe, cmdline)

            if matched:
                findings.append(
                    Finding(
                        id=f"PROC-{next(finding_ids):04d}",
                        category="process",
                        severity="medium",
                        title="Potential monitoring/capture process running",
                        details=f"Detected keyword(s): {', '.join(matched)}",
                        evidence={
                            "pid": info.get("pid"),
                            "name": info.get("name"),
                            "exe": info.get("exe"),
                            "cmdline": info.get("cmdline") or [],
                            "username": info.get("username"),
                        },
                        recommendation="Verify whether this process is expected; if not, quarantine and investigate.",
                    )
                )

            if signature and signature not in known_processes and signature not in seen_new_signatures:
                seen_new_signatures.add(signature)
                findings.append(
                    Finding(
                        id=f"PROC-{next(finding_ids):04d}",
                        category="baseline-drift",
                        severity="low",
                        title="New process signature not in baseline",
                        details="A process signature appears that was not present in baseline.",
                        evidence={
                            "pid": info.get("pid"),
                            "signature": signature,
                        },
                        recommendation="Review this process and refresh baseline if it is legitimate.",
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return findings
