#!/usr/bin/env python3
"""
remcheck — Automated Remediation Checker
Entry point: python remcheck.py --finding <path> --output <dir>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time

# Import strategies (this triggers @register decorators)
import src.strategies  # noqa: F401

from src.engine import get_strategy, list_supported_types, build_report
from src.cli_output import (
    print_banner, print_test_progress, print_test_result,
    print_verdict_block, bold, red, yellow, green,
)
from src.ai_analyzer import run_ai_analysis

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")


# ── Exit codes ────────────────────────────────────────────────────────────────
EXIT_VERIFIED    = 0
EXIT_FAILED      = 1
EXIT_INCONCLUSIVE = 2
EXIT_ERROR       = 3


# ── Finding loader & validator ────────────────────────────────────────────────

REQUIRED_FINDING_FIELDS = {"finding_id", "type", "endpoint", "parameter", "base_url", "baseline"}

def load_finding(path: str) -> dict:
    try:
        with open(path) as f:
            finding = json.load(f)
    except FileNotFoundError:
        print(red(f"[ERROR] Finding file not found: {path}"))
        sys.exit(EXIT_ERROR)
    except json.JSONDecodeError as exc:
        print(red(f"[ERROR] Invalid JSON in finding file: {exc}"))
        sys.exit(EXIT_ERROR)

    missing = REQUIRED_FINDING_FIELDS - set(finding.keys())
    if missing:
        print(red(f"[ERROR] Finding record missing required fields: {', '.join(sorted(missing))}"))
        sys.exit(EXIT_ERROR)

    return finding


# ── Report saver ──────────────────────────────────────────────────────────────

def save_report(report, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts = report.generated_at.replace(":", "").replace("-", "")
    filename = f"{report.finding_id}_{ts}.json"
    path = os.path.join(output_dir, filename)

    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)

    return path


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="remcheck",
        description="Automated Remediation Checker v0.1.0",
    )
    parser.add_argument("--finding", metavar="FILE",
                        help="Path to finding JSON file")
    parser.add_argument("--output", default="./evidence", metavar="DIR",
                        help="Directory to save evidence reports (default: ./evidence)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-test output; show only final verdict")
    parser.add_argument("--verbose", action="store_true",
                        help="Include full request/response details per test")
    parser.add_argument("--ai", action="store_true",
                        help="Run AI advisory analysis after tests complete")
    parser.add_argument("--list-types", action="store_true",
                        help="List all supported finding types and exit")
    args, _ = parser.parse_known_args()

    if args.list_types:
        print("Supported finding types:")
        for t in list_supported_types():
            print(f"  • {t}")
        sys.exit(0)

    if not args.finding:
        print("[ERROR] --finding FILE is required.")
        parser.print_help()
        sys.exit(EXIT_ERROR)

    # Load finding
    finding = load_finding(args.finding)
    finding_type = finding["type"]

    # Resolve strategy
    strategy_cls = get_strategy(finding_type)
    if strategy_cls is None:
        print(red(f"[ERROR] No strategy registered for finding type: '{finding_type}'"))
        print(yellow(f"  Supported types: {', '.join(list_supported_types())}"))
        sys.exit(EXIT_ERROR)

    verifier = strategy_cls(finding)
    strategy_name = strategy_cls.__name__

    # Print banner
    if not args.quiet:
        print_banner(finding, strategy_name, finding["base_url"])

    # Build test cases
    test_cases = verifier.build_test_cases()

    if not args.quiet:
        print_test_progress(len(test_cases))

    # Execute tests
    wall_start = time.monotonic()
    results = []

    for tc in test_cases:
        result = verifier.execute_test(tc)
        results.append(result)
        if not args.quiet:
            print_test_result(result, verbose=args.verbose)

    wall_elapsed = time.monotonic() - wall_start

    # AI analysis (advisory)
    ai_analysis = None
    if args.ai:
        if not args.quiet:
            print(yellow("  Running AI advisory analysis..."))
        result_dicts = [r.to_dict() for r in results]
        # We need a preliminary verdict to include in the AI prompt
        from src.engine import _compute_verdict
        prelim_verdict = _compute_verdict(results)
        ai_analysis = run_ai_analysis(finding, result_dicts, prelim_verdict)

    # Build tamper-evident report
    report = build_report(finding, results, ai_analysis=ai_analysis)

    # Save evidence
    evidence_path = save_report(report, args.output)

    # Print verdict
    if not args.quiet:
        print_verdict_block(report, evidence_path, wall_elapsed)
    else:
        # --quiet: one line only
        from src.cli_output import verdict_colour
        print(verdict_colour(report.verdict))

    # Exit code for pipeline integration
    if report.verdict == "REMEDIATION_VERIFIED":
        sys.exit(EXIT_VERIFIED)
    elif report.verdict == "REMEDIATION_FAILED":
        sys.exit(EXIT_FAILED)
    else:
        sys.exit(EXIT_INCONCLUSIVE)


if __name__ == "__main__":
    main()
