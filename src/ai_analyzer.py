"""
src/ai_analyzer.py — AI Integration Layer (Part C, Option 2)
Sends completed test results to Claude for advisory analysis.
The LLM response is ADVISORY ONLY — it never overrides the deterministic verdict.
"""

from __future__ import annotations

import json
import re
import logging

logger = logging.getLogger("remcheck.ai")

# Validation schema for LLM response
REQUIRED_FIELDS = {"fix_assessment", "confidence", "reasoning", "recommendations"}
VALID_ASSESSMENTS = {"complete", "partial", "bypassed", "inconclusive"}

SYSTEM_PROMPT = """You are a security remediation analyst assistant.
You will be given a JSON object containing automated test results from a remediation verification tool.
Respond ONLY with a valid JSON object — no markdown, no preamble, no explanation outside the JSON.

Your JSON must contain exactly these fields:
{
  "fix_assessment": "complete" | "partial" | "bypassed" | "inconclusive",
  "confidence": "high" | "medium" | "low",
  "reasoning": "<2-3 sentence explanation of your assessment>",
  "recommendations": ["<action 1>", "<action 2>", "<action 3>"]
}

Rules:
- fix_assessment must be one of: complete, partial, bypassed, inconclusive
- confidence must be one of: high, medium, low
- recommendations must be a list of 1-5 actionable strings
- Do not reproduce the full test data back in your response
- Do not claim certainty beyond what the test data supports
"""


def _build_prompt(finding: dict, results: list[dict], verdict: str) -> str:
    """Build the prompt sent to Claude."""
    summary = {
        "finding_id":   finding["finding_id"],
        "finding_type": finding["type"],
        "deterministic_verdict": verdict,
        "test_summary": {
            "total":  len(results),
            "passed": sum(1 for r in results if r["result"] == "PASS"),
            "failed": sum(1 for r in results if r["result"] == "FAIL"),
            "errors": sum(1 for r in results if r["result"] == "ERROR"),
        },
        "failed_tests": [
            {
                "test_id":   r["test_id"],
                "category":  r["category"],
                "payload":   r["payload"],
                "anomalies": r["anomalies"],
            }
            for r in results if r["result"] == "FAIL"
        ],
        "all_anomalies": [
            a for r in results for a in r["anomalies"]
        ],
    }
    return (
        "Analyze these remediation verification results and assess whether the fix "
        "appears complete, partial, or bypassed.\n\n"
        f"{json.dumps(summary, indent=2)}"
    )


def _validate_llm_response(raw: str) -> dict | None:
    """
    Validate the LLM JSON response.
    Returns parsed dict on success, None on failure.
    Logs all validation errors — bad output is never passed to the engine.
    """
    # Strip accidental markdown fences
    cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.warning("AI response is not valid JSON: %s | raw=%r", exc, raw[:200])
        return None

    # Field presence check
    missing = REQUIRED_FIELDS - set(parsed.keys())
    if missing:
        logger.warning("AI response missing required fields: %s", missing)
        return None

    # Enum value checks
    if parsed["fix_assessment"] not in VALID_ASSESSMENTS:
        logger.warning(
            "AI fix_assessment '%s' not in allowed values %s",
            parsed["fix_assessment"], VALID_ASSESSMENTS,
        )
        return None

    if parsed["confidence"] not in {"high", "medium", "low"}:
        logger.warning("AI confidence '%s' not valid", parsed["confidence"])
        return None

    if not isinstance(parsed["recommendations"], list):
        logger.warning("AI recommendations is not a list")
        return None

    # Cap recommendations length to avoid runaway output
    parsed["recommendations"] = parsed["recommendations"][:5]

    return parsed


def run_ai_analysis(finding: dict, results: list[dict], verdict: str) -> dict | None:
    """
    Call the Anthropic API and return validated advisory analysis.
    Returns None if the API call fails or validation fails.
    The caller must treat this as advisory — it must NOT override the verdict.
    """
    try:
        import anthropic
        client = anthropic.Anthropic()
    except ImportError:
        logger.warning("anthropic package not installed — skipping AI analysis")
        return {"error": "anthropic package not installed", "advisory_only": True}
    except Exception as exc:
        logger.warning("Failed to initialise Anthropic client: %s", exc)
        return {"error": str(exc), "advisory_only": True}

    prompt = _build_prompt(finding, results, verdict)

    try:
        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw_text = message.content[0].text
    except Exception as exc:
        logger.warning("Anthropic API call failed: %s", exc)
        return {"error": str(exc), "advisory_only": True}

    validated = _validate_llm_response(raw_text)

    if validated is None:
        # Log bad output for audit purposes (Part C requirement)
        logger.warning("AI output failed validation — stored but not used. Raw: %r", raw_text[:500])
        return {
            "error": "LLM output failed validation — not used",
            "raw_output_preview": raw_text[:300],
            "advisory_only": True,
        }

    validated["advisory_only"] = True
    validated["note"] = "This analysis is advisory. It does not affect the deterministic verdict."
    return validated
