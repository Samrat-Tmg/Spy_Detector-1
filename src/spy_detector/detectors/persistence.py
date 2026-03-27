from __future__ import annotations

import plistlib
from itertools import count
from pathlib import Path

from spy_detector.models import Finding

PERSISTENCE_PATHS = [
    Path.home() / "Library/LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
]

SUSPICIOUS_PERSISTENCE_KEYWORDS = {
    "keylog",
    "capture",
    "screen",
    "agent",
    "monitor",
    "hidden",
    "stealth",
}


def collect_launch_agent_inventory() -> list[str]:
    inventory: list[str] = []
    for directory in PERSISTENCE_PATHS:
        if not directory.exists():
            continue
        for plist_file in directory.glob("*.plist"):
            inventory.append(str(plist_file))
    return sorted(set(inventory))


def detect_persistence_anomalies(known_launch_agents: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    known_launch_agents = known_launch_agents or set()
    finding_ids = count(1)

    for directory in PERSISTENCE_PATHS:
        if not directory.exists():
            continue

        for plist_file in directory.glob("*.plist"):
            plist_path = str(plist_file)

            if plist_path not in known_launch_agents:
                findings.append(
                    Finding(
                        id=f"PER-{next(finding_ids):04d}",
                        category="baseline-drift",
                        severity="low",
                        title="New startup item not in baseline",
                        details=f"Startup item found: {plist_path}",
                        evidence={"path": plist_path},
                        recommendation="Review source of this startup item and authorize only if expected.",
                    )
                )

            try:
                with plist_file.open("rb") as handle:
                    data = plistlib.load(handle)
            except (plistlib.InvalidFileException, PermissionError, OSError):
                continue

            text_blob = " ".join(
                str(value)
                for value in [
                    data.get("Label", ""),
                    data.get("Program", ""),
                    " ".join(data.get("ProgramArguments", [])),
                ]
            ).lower()

            matched = sorted(keyword for keyword in SUSPICIOUS_PERSISTENCE_KEYWORDS if keyword in text_blob)
            run_at_load = bool(data.get("RunAtLoad", False))

            if matched and run_at_load:
                findings.append(
                    Finding(
                        id=f"PER-{next(finding_ids):04d}",
                        category="persistence",
                        severity="high",
                        title="Potentially suspicious autostart entry",
                        details=f"Keyword(s) found in launch item: {', '.join(matched)}",
                        evidence={
                            "path": plist_path,
                            "label": data.get("Label"),
                            "program": data.get("Program"),
                            "program_arguments": data.get("ProgramArguments", []),
                            "run_at_load": run_at_load,
                        },
                        recommendation="Disable item if unauthorized, then investigate binary origin and user impact.",
                    )
                )

    return findings
