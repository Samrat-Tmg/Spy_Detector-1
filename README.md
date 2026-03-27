# Spy Detector (Defensive MVP)

A local-first defensive tool to detect potential indicators of unauthorized data capture on macOS endpoints.

## What it checks

- Process indicators: running processes with known monitoring/capture keywords.
- Network indicators: established outbound connections to uncommon external ports.
- Persistence indicators: suspicious `LaunchAgents` / `LaunchDaemons` entries.
- Baseline drift: new processes/endpoints/startup items compared to a known-good snapshot.

## Installation

From project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

Initialize a baseline on a clean/trusted state:

```bash
spy-detector --init-baseline
```

Run a scan:

```bash
spy-detector
```

Write full JSON report:

```bash
spy-detector --json-output reports/latest.json
```

## Notes

- This tool is for defensive visibility only and may produce false positives.
- Use findings as triage signals and validate with your security team before remediation.
- Elevated permissions can increase visibility into system-level connections and startup entries.
