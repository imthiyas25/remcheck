# prompts.md — AI Integration Documentation (Part C)

## Option Chosen: Option 2 — Result Analyzer

After all tests complete, the full result set is sent to Claude and an
advisory analysis is returned. The LLM response is validated before use
and **never overrides the deterministic verdict**.

---

## Prompt Used

**System prompt (sent on every request):**

```
You are a security remediation analyst assistant.
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
```

**User prompt (dynamically constructed per run):**

```
Analyze these remediation verification results and assess whether the fix
appears complete, partial, or bypassed.

{
  "finding_id": "FIND-0042",
  "finding_type": "sql_injection",
  "deterministic_verdict": "REMEDIATION_FAILED",
  "test_summary": {
    "total": 8,
    "passed": 7,
    "failed": 1,
    "errors": 0
  },
  "failed_tests": [
    {
      "test_id": "TC-05",
      "category": "time_based_blind",
      "payload": "' AND SLEEP(3)--",
      "anomalies": ["BEHAVIORAL: time-based blind injection delay triggered"]
    }
  ],
  "all_anomalies": ["BEHAVIORAL: time-based blind injection delay triggered"]
}
```

---

## Raw AI Output (example)

```json
{
  "fix_assessment": "partial",
  "confidence": "medium",
  "reasoning": "Classic and error-based injection vectors appear blocked, but the time-based blind payload triggered a delay, indicating the database still executes injected SQL in sleep conditions. This suggests the fix addresses input validation for some patterns but not parameterised query enforcement throughout.",
  "recommendations": [
    "Verify all database queries use parameterised statements or prepared statements, not string concatenation",
    "Test time-based injection on all endpoints that share the same DB connection layer",
    "Review ORM configuration to confirm it is not falling back to raw query execution on this endpoint",
    "Check for any dynamic ORDER BY or LIMIT clauses that may bypass the primary input validation"
  ]
}
```

---

## Critique: What Was Wrong or Unsafe in Raw AI Output

1. **Not reproducible**: LLM output varies between runs — same inputs can produce
   different assessments. We mitigate this by treating it as advisory only and
   logging all raw responses.

2. **Over-confidence possible**: The model said `"confidence": "medium"` but could
   produce `"high"` on a limited test suite. Our validation does not catch
   overconfident reasoning — we document this as a known limitation.

3. **Schema drift**: If the model adds extra fields or nests `recommendations` inside
   another object, our validator catches it, logs it, and skips the analysis.
   This happened once during development — the model wrapped the entire response
   in a `"result"` key:
   ```json
   { "result": { "fix_assessment": "partial", ... } }
   ```
   **Caught by validation** — `REQUIRED_FIELDS` check failed, raw output was logged,
   and the engine proceeded without AI analysis.

4. **Markdown fences**: The model occasionally wraps its JSON in ` ```json ... ``` `.
   Our `_validate_llm_response()` strips these before parsing.

---

## Validation Logic

```python
REQUIRED_FIELDS = {"fix_assessment", "confidence", "reasoning", "recommendations"}
VALID_ASSESSMENTS = {"complete", "partial", "bypassed", "inconclusive"}

def _validate_llm_response(raw: str) -> dict | None:
    cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()
    parsed = json.loads(cleaned)                          # raises on bad JSON
    missing = REQUIRED_FIELDS - set(parsed.keys())        # field presence
    if missing: return None
    if parsed["fix_assessment"] not in VALID_ASSESSMENTS: return None
    if parsed["confidence"] not in {"high","medium","low"}: return None
    if not isinstance(parsed["recommendations"], list):   return None
    parsed["recommendations"] = parsed["recommendations"][:5]  # cap length
    return parsed
```

---

## Example of Caught and Corrected Bad LLM Output

**Bad output (model wrapped response in extra key):**
```json
{
  "result": {
    "fix_assessment": "partial",
    "confidence": "high",
    "reasoning": "...",
    "recommendations": [...]
  }
}
```

**Validation outcome:** `REQUIRED_FIELDS` check failed — `fix_assessment` was not
at the top level. Validation returned `None`. The engine stored this in the report:
```json
{
  "error": "LLM output failed validation — not used",
  "raw_output_preview": "{ \"result\": { \"fix_assessment\": ...",
  "advisory_only": true
}
```

**Correction applied:** System prompt updated to include:
> "Do not nest your response inside any outer key. The top-level object IS your answer."

On the next run the model responded correctly with a flat JSON object.
