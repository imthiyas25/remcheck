"""
src/cli_output.py — Terminal output helpers
Handles color, --quiet, --verbose, progress display.
"""

from __future__ import annotations

import sys


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def green(s: str) -> str:  return f"\033[32m{s}\033[0m" if _supports_color() else s
def red(s: str) -> str:    return f"\033[31m{s}\033[0m" if _supports_color() else s
def yellow(s: str) -> str: return f"\033[33m{s}\033[0m" if _supports_color() else s
def cyan(s: str) -> str:   return f"\033[36m{s}\033[0m" if _supports_color() else s
def bold(s: str) -> str:   return f"\033[1m{s}\033[0m"  if _supports_color() else s
def dim(s: str) -> str:    return f"\033[2m{s}\033[0m"   if _supports_color() else s


def result_colour(result: str) -> str:
    if result == "PASS":
        return green(result)
    if result == "FAIL":
        return red(result)
    return yellow(result)


def verdict_colour(verdict: str) -> str:
    if verdict == "REMEDIATION_VERIFIED":
        return green(verdict)
    if verdict == "REMEDIATION_FAILED":
        return red(verdict)
    return yellow(verdict)


def print_banner(finding: dict, strategy_name: str, base_url: str) -> None:
    print()
    print(bold(cyan("remcheck v0.1.0")))
    print(f"  Loading finding : {bold(finding['finding_id'])} ({finding['type']})")
    print(f"  Target          : {base_url}{finding['endpoint'].split(' ', 1)[1]}")
    print(f"  Strategy        : {strategy_name}")
    bl = finding["baseline"]
    print(
        f"  Baseline        : status={bl.get('status_code')}, "
        f"hash={bl.get('response_hash','?')[:8]}, "
        f"p95={bl.get('response_time_p95','?')}s"
    )
    print()


def print_test_progress(tc_count: int) -> None:
    print(f"  Running test suite ({tc_count} tests)...")
    print()


def print_test_result(result, verbose: bool = False) -> None:
    label = result_colour(result.result)
    time_str = f"{result.response_time:.2f}s"
    print(f"  {result.test_id:<6}  {result.category:<25}  {label}  [{time_str}]")

    if verbose:
        print(f"           Payload  : {result.payload}")
        print(f"           Status   : {result.status_code}")
        print(f"           Hash     : {result.response_hash}")
        print(f"           Body     : {result.raw_body_preview[:120]!r}")

    if result.anomalies:
        for a in result.anomalies:
            print(f"           {red('→')} {a}")

    if verbose:
        print()


def print_verdict_block(report, evidence_path: str, elapsed_total: float) -> None:
    print()
    print("  " + "─" * 52)
    verdict = report.verdict
    print(f"  Verdict      : {bold(verdict_colour(verdict))}")
    s = report.summary
    print(f"  Summary      : {s['passed']} passed, {s['failed']} failed, {s['inconclusive']} inconclusive / {s['total']} total")
    print(f"  Evidence     : {evidence_path}")
    print(f"  Report hash  : {dim(report.report_hash)}")
    print(f"  Done in      : {elapsed_total:.1f}s")
    print()

    if report.ai_analysis and "fix_assessment" in report.ai_analysis:
        ai = report.ai_analysis
        print(bold("  AI Advisory Analysis") + dim("  (does not affect verdict)"))
        print(f"    Assessment  : {ai.get('fix_assessment','?')} (confidence: {ai.get('confidence','?')})")
        print(f"    Reasoning   : {ai.get('reasoning','')}")
        recs = ai.get("recommendations", [])
        if recs:
            print("    Suggestions :")
            for r in recs:
                print(f"      • {r}")
        print()
