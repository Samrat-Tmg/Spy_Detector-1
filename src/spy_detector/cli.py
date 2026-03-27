from __future__ import annotations

import argparse
from pathlib import Path

from spy_detector.baseline import DEFAULT_BASELINE_PATH, load_baseline, save_baseline
from spy_detector.reporting import build_report, render_terminal_report, write_json_report
from spy_detector.scanner import build_snapshot, run_scan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="spy-detector",
        description="Detect potential unauthorized monitoring or data capture activity on this host.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE_PATH,
        help="Path to baseline JSON file.",
    )
    parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="Write a fresh baseline and exit.",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="Optional path to write full JSON scan report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.init_baseline:
        baseline_path = save_baseline(build_snapshot(), args.baseline)
        print(f"Baseline saved to: {baseline_path}")
        return 0

    baseline = load_baseline(args.baseline)
    summary, findings = run_scan(baseline)

    print(render_terminal_report(summary, findings))

    if args.json_output:
        report = build_report(summary, findings)
        write_json_report(report, args.json_output)
        print(f"JSON report written: {args.json_output}")

    return 0 if summary.high == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
