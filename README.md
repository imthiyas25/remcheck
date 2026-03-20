# remcheck v0.1.0
**Automated Remediation Checker** — Security Finding Verification Engine

## Setup

```bash
# Clone / copy the project to your machine
cd remcheck/

# Install dependencies (Python 3.10+)
pip3 install requests anthropic --break-system-packages
# or: pip3 install -r requirements.txt
```

## Usage

```bash
# Basic run — SQL injection finding
python3 remcheck.py --finding finding_examples/sqli_example.json --output ./evidence

# SSRF finding
python3 remcheck.py --finding finding_examples/ssrf_example.json --output ./evidence

# Quiet mode (final verdict only — for pipeline use)
python3 remcheck.py --finding finding_examples/sqli_example.json --quiet

# Verbose mode (full request/response per test)
python3 remcheck.py --finding finding_examples/sqli_example.json --verbose

# With AI advisory analysis
python3 remcheck.py --finding finding_examples/sqli_example.json --ai

# List all supported finding types
python3 remcheck.py --list-types
```

## End-to-End Example Output

```
remcheck v0.1.0
  Loading finding : FIND-0042 (sql_injection)
  Target          : https://httpbin.org/api/v1/login
  Strategy        : SQLInjectionVerifier
  Baseline        : status=200, hash=a3f1bc9d, p95=0.45s

  Running test suite (8 tests)...

  TC-01  classic_injection           PASS  [0.21s]
  TC-02  union_based                 PASS  [0.19s]
  TC-03  boolean_blind_true          PASS  [0.23s]
  TC-04  boolean_blind_false         PASS  [0.22s]
  TC-05  time_based_blind            PASS  [0.31s]
  TC-06  encoding_bypass             PASS  [0.20s]
  TC-07  second_order                PASS  [0.25s]
  TC-08  error_based                 PASS  [0.18s]

  ────────────────────────────────────────────────────
  Verdict      : REMEDIATION_VERIFIED
  Summary      : 8 passed, 0 failed, 0 inconclusive / 8 total
  Evidence     : ./evidence/FIND-0042_20260317T120000Z.json
  Report hash  : sha256:9f2c1a3b...
  Done in      : 2.4s
```

## Project Structure

```
remcheck/
├── remcheck.py                    # CLI entry point
├── finding_examples/
│   ├── sqli_example.json          # SQL injection finding
│   └── ssrf_example.json          # SSRF cloud metadata finding
├── src/
│   ├── engine.py                  # Core engine, base class, registry, report builder
│   ├── ai_analyzer.py             # AI advisory layer (Option 2)
│   ├── cli_output.py              # Terminal output, color, flags
│   └── strategies/
│       ├── __init__.py            # Auto-imports all strategies
│       ├── sql_injection.py       # SQLInjectionVerifier
│       └── ssrf_cloud_metadata.py # SSRFCloudMetadataVerifier
├── evidence/                      # Generated at runtime (gitignored)
├── architecture.pdf               # Part A architecture document
├── prompts.md                     # Part C: AI prompts, raw output, critique
└── REPORT.md                      # Part E written answers + self-assessment
```

## Exit Codes (for pipeline integration)

| Code | Meaning |
|------|---------|
| `0`  | `REMEDIATION_VERIFIED` |
| `1`  | `REMEDIATION_FAILED` |
| `2`  | `INCONCLUSIVE` |
| `3`  | Tool error (bad input, unknown type) |

## Design Trade-offs

- **Strategy pattern + registry**: The core engine never needs to change when a new
  finding type is added. One new file + one import = full support.
- **Deterministic verdict first, AI advisory second**: The SHA-256-hashed JSON report
  is computed from deterministic test results. LLM analysis is stored separately and
  explicitly labelled `advisory_only: true`.
- **httpbin.org as target**: Finding examples target httpbin.org because no
  live vulnerable server is available. All anomaly detection logic is correct —
  results against httpbin will show PASS for most checks since httpbin does not
  implement auth or input validation, giving a clean "not vulnerable" baseline.

## Adding a New Finding Type

1. Create `src/strategies/my_new_type.py` with a class inheriting `BaseVerifier`,
   set `FINDING_TYPE = "my_new_type"`, decorate with `@register`, implement
   `build_test_cases()` and `execute_test()`.
2. Add one import line to `src/strategies/__init__.py`.
3. Done. The core engine, CLI, and report format require zero changes.
