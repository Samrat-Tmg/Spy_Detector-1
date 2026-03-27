from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_BASELINE_PATH = Path.home() / ".spy_detector_baseline.json"


def load_baseline(path: Path | None = None) -> dict[str, Any]:
    baseline_path = path or DEFAULT_BASELINE_PATH
    if not baseline_path.exists():
        return {"processes": [], "endpoints": [], "launch_agents": []}

    with baseline_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    return {
        "processes": list(raw.get("processes", [])),
        "endpoints": list(raw.get("endpoints", [])),
        "launch_agents": list(raw.get("launch_agents", [])),
    }


def save_baseline(snapshot: dict[str, Any], path: Path | None = None) -> Path:
    baseline_path = path or DEFAULT_BASELINE_PATH
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    with baseline_path.open("w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2, sort_keys=True)

    return baseline_path
