**Automated Remediation Verification Engine**

Default Challenge — Full Submission Report  
Version 0.1.0 | Python 3.10+ | Finding Types: sql_injection, ssrf_cloud_metadata

---

## Parts Overview

| Part | Title | Points | Status |
|------|-------|--------|--------|
| A | System Architecture Document | 20 pts | Complete |
| B | Core Engine Implementation | 35 pts | Complete |
| C | AI Integration Layer | 20 pts | Complete |
| D | CLI and Output Quality | 10 pts | Complete |
| E | Extension Design (Written) | 15 pts | Complete |

---

## Folder Structure

```
remcheck/
├── remcheck.py                        ← main tool (CLI entry point)
├── requirements.txt                   ← pip dependencies
├── README.md                          ← this file
├── REPORT.md                          ← Part E written answers + self assessment
├── prompts.md                         ← Part C AI prompts documentation
├── architecture_updated.docx          ← Part A architecture document
├── Default_Challenge_Submission.docx  ← full submission document (Parts A–E)
├── finding_examples/
│   ├── sqli_example.json              ← SQL injection finding input
│   └── ssrf_example.json              ← SSRF cloud metadata finding input
├── src/
│   ├── __init__.py
│   ├── engine.py                      ← core brain — registry, base class, report builder
│   ├── ai_analyzer.py                 ← AI advisory layer
│   ├── cli_output.py                  ← colors and terminal display
│   └── strategies/
│       ├── __init__.py
│       ├── sql_injection.py           ← 8 SQL injection test cases
│       └── ssrf_cloud_metadata.py     ← 9 SSRF test cases
└── evidence/                          ← auto-generated at runtime (gitignored)
    ├── FIND-0042_*.json
    └── FIND-0099_*.json
```

---

## Setup

```bash
# Install dependencies
pip3 install requests anthropic --break-system-packages
```

---

## How to Run

```bash
# List all supported finding types
python3 remcheck.py --list-types

# Run SQL injection check
python3 remcheck.py --finding finding_examples/sqli_example.json --output ./evidence

# Run SSRF check
python3 remcheck.py --finding finding_examples/ssrf_example.json --output ./evidence

# Quiet mode — verdict only (for pipeline use)
python3 remcheck.py --finding finding_examples/sqli_example.json --quiet

# Verbose mode — full request and response detail per test
python3 remcheck.py --finding finding_examples/sqli_example.json --verbose

# With AI advisory analysis
python3 remcheck.py --finding finding_examples/sqli_example.json --ai
```

---

## Sample Output

```
remcheck v0.1.0
  Loading finding : FIND-0042 (sql_injection)
  Target          : https://httpbin.org/api/v1/login
  Strategy        : SQLInjectionVerifier
  Baseline        : status=200, hash=a3f1bc9d, p95=0.45s

  Running test suite (8 tests)...

  TC-01  classic_injection          PASS  [0.21s]
  TC-02  union_based                PASS  [0.19s]
  TC-03  boolean_blind_true         PASS  [0.23s]
  TC-04  boolean_blind_false        PASS  [0.22s]
  TC-05  time_based_blind           PASS  [0.31s]
  TC-06  encoding_bypass            PASS  [0.20s]
  TC-07  second_order               PASS  [0.25s]
  TC-08  error_based                PASS  [0.18s]

  ------------------------------------------------
  Verdict      : REMEDIATION_VERIFIED
  Summary      : 8 passed, 0 failed, 0 inconclusive / 8 total
  Evidence     : ./evidence/FIND-0042_20260318T120000Z.json
  Report hash  : sha256:9f2c1a3b...
  Done in      : 2.4s
```

---

## Part A — System Architecture

### Component Architecture Diagram

Each layer flows top to bottom. Arrows show data flow direction: Input → Core Engine → Strategy Layer → Output.

```
┌─────────────────────────────────────────────────────────────────┐
│  INPUT                                                          │
│  finding.json — JSON file: finding_id, type, endpoint,          │
│                 parameter, base_url, baseline, auth, metadata   │
│  CLI args    — --finding FILE | --output DIR | --quiet          │
│                --verbose | --ai | --list-types                  │
└─────────────────────────┬───────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│  CORE ENGINE                                                    │
│  remcheck.py       — CLI entry point, argument parsing,         │
│                      strategy lookup, verdict computation       │
│  Strategy Registry — { 'sql_injection': SQLInjectionVerifier,  │
│                        'ssrf_cloud_metadata': SSRFVerifier }    │
│  AI Layer (advisory) — ai_analyzer.py — calls Claude API;      │
│                        output stored separately, never          │
│                        overrides verdict                        │
└─────────────────────────┬───────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│  STRATEGY LAYER                                                 │
│  BaseVerifier (abstract) — build_test_cases(), execute_test(),  │
│                            _detect_anomalies() — shared         │
│  SQLInjectionVerifier    — 8 tests: classic, union, boolean     │
│                            blind, time-based, encoding,         │
│                            second-order, error                  │
│  SSRFCloudMetadataVerifier — 9 tests: AWS IMDSv1/v2, GCP,      │
│                              Azure + 5 IP/redirect bypasses     │
└─────────────────────────┬───────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT                                                         │
│  evidence/*.json — Structured JSON report with SHA-256 hash    │
│  Terminal output — Colour-coded PASS/FAIL/INCONCLUSIVE,        │
│                    final verdict, evidence path                 │
│  Exit codes      — 0 = REMEDIATION_VERIFIED                    │
│                    1 = REMEDIATION_FAILED                       │
│                    2 = INCONCLUSIVE                             │
└─────────────────────────────────────────────────────────────────┘
```
<img width="1015" height="646" alt="image" src="https://github.com/user-attachments/assets/09c81afb-cd2a-4ece-9697-00e4bfd88cbe" />

---

### Q1 — Routing Logic and Extensibility

The core engine uses a strategy registry — a Python dictionary mapping the type field from the finding JSON to the corresponding verifier class. Routing happens in a single lookup:

```python
verifier_class = STRATEGY_REGISTRY[finding['type']]
```

If the type is registered, the engine instantiates the verifier and delegates all test logic to it. If not registered, it prints a clear error with supported types and exits with code 2.

**Step-by-Step Routing Flow:**

| Step | What Happens | Code |
|------|-------------|------|
| 1 | Load finding JSON from --finding path | `finding = json.load(f)` |
| 2 | Read type field | `ftype = finding['type']` |
| 3 | Registry lookup | `cls = STRATEGY_REGISTRY[ftype]` |
| 4 | Instantiate verifier | `verifier = cls(finding)` |
| 5 | Execute test suite | `results = verifier.run()` |

**Adding a New Finding Type — Two Changes Only:**

1. Create `src/strategies/new_type.py` — inherit BaseVerifier, set FINDING_TYPE, implement `build_test_cases()` and `execute_test()`
2. Add one import line to `src/strategies/__init__.py` — the `@register` decorator automatically adds it to the registry

The core engine, CLI, evidence schema, and AI layer are **NEVER modified**. This is the open-closed principle in practice.

---

### Q2 — Evidence Model and Tamper-Evidence

Every run produces a structured JSON evidence report. Schema:

| Field | Description |
|-------|-------------|
| `report_id` | UUID generated per run — unique identifier for this evidence record |
| `finding_id` | Copied from input finding JSON |
| `generated_at` | ISO-8601 UTC timestamp of when the run completed |
| `engine_version` | Pinned engine version (e.g. 0.1.0) — enables exact reproduction |
| `verdict` | REMEDIATION_VERIFIED \| REMEDIATION_FAILED \| INCONCLUSIVE |
| `test_results[]` | Per-test: test_id, category, payload, status_code, response_time, response_hash, anomalies[], result |
| `summary` | total / passed / failed / inconclusive counts |
| `ai_analysis` | (Optional) LLM advisory — advisory only, never affects verdict |
| `report_hash` | SHA-256 of canonical JSON — cryptographic proof of integrity |

**Tamper-Evidence Mechanism:**

After writing the JSON report, a SHA-256 hash is computed over the canonical JSON (keys sorted, no whitespace). It is stored inside the JSON as `report_hash`. Any modification after generation invalidates the hash. Verify with:

```bash
python3 -c "import json,hashlib; d=json.load(open('report.json')); h=d.pop('report_hash'); print(h=='sha256:'+hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest())"
```

---

### Q3 — Anomaly Detection: Generic vs Finding-Specific

**Common Signals — BaseVerifier (shared across all finding types):**

- **BEHAVIORAL:** HTTP status code deviates from baseline expected code
- **TEMPORAL:** response time exceeds baseline p95 by more than 2x
- **CONTENT:** response body hash deviates from baseline hash
- **CONTENT:** response body matches sensitive data patterns (email, password, role:admin, cloud metadata IPs)

**Finding-Specific Signals — Per-Strategy Overrides:**

| Finding Type | Extra Anomaly Signal | How Detected |
|-------------|---------------------|--------------|
| `sql_injection` | DB error strings in body (sql syntax, ORA-, pg_query); elapsed >= 2.5s on time-based payloads | String scan + timing threshold |
| `ssrf_cloud_metadata` | Cloud metadata strings: ami-id, AccessKeyId, computeMetadata, serviceAccounts | Keyword scan on response body |
| `jwt_algorithm_confusion` | Any 200 response to a manipulated token; sensitive data in body after acceptance | Status code + body pattern |

---

### Q4 — Handling Inconsistent Test Results

If a test produces inconsistent results across multiple runs, the finalization logic applies a consistency threshold:

| Consistency Score | Verdict | Action |
|------------------|---------|--------|
| 3/3 FAIL | REMEDIATION_FAILED (consistent) | Confirmed failure — include consistency score in evidence |
| 1/3 or 2/3 FAIL | INCONCLUSIVE | Flag for manual review — do not auto-close — note race condition or caching |
| 3/3 PASS | REMEDIATION_VERIFIED | Confirmed fix — close finding with full evidence trail |

This protects against false positives (network errors misread as vulnerabilities) and false negatives (race conditions making a real vulnerability appear fixed). Retry count N defaults to 3, configurable per finding type.

---

## Part B — Core Engine Implementation

### Engine Architecture

The core engine is implemented across five files. Each file has a single responsibility:

| File | Responsibility |
|------|---------------|
| `remcheck.py` | CLI entry point — argument parsing, finding loader, strategy dispatch, report saving, exit codes |
| `src/engine.py` | BaseVerifier abstract class, @register decorator, strategy registry dict, build_report(), _compute_verdict() |
| `src/strategies/sql_injection.py` | SQLInjectionVerifier — 8 SQL injection test cases with MySQL/Postgres/MSSQL/SQLite payloads |
| `src/strategies/ssrf_cloud_metadata.py` | SSRFCloudMetadataVerifier — 9 SSRF test cases covering AWS, GCP, Azure + bypass techniques |
| `src/ai_analyzer.py` | AI advisory layer — builds prompt, calls Claude API, validates response, returns advisory dict |
| `src/cli_output.py` | Terminal output — ANSI colors, banner, per-test progress, verdict block, --quiet/--verbose support |

### Finding Type 1: sql_injection — 8 Test Cases

| Test ID | Category | Payload | What It Tests |
|---------|----------|---------|---------------|
| TC-01 | classic_injection | `' OR '1'='1` | Basic OR-based authentication bypass |
| TC-02 | union_based | `' UNION SELECT NULL,NULL,NULL--` | UNION-based data extraction |
| TC-03 | boolean_blind_true | `' AND '1'='1` | Boolean blind — true condition |
| TC-04 | boolean_blind_false | `' AND '1'='2` | Boolean blind — false condition |
| TC-05 | time_based_blind | `' AND SLEEP(3)--` | Time-based blind injection delay |
| TC-06 | encoding_bypass | `%27%20OR%20%271%27%3D%271` | URL-encoded bypass of input filters |
| TC-07 | second_order | `admin'--` | Second-order injection via stored input |
| TC-08 | error_based | `' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--` | Error-based information disclosure |

### Finding Type 2: ssrf_cloud_metadata — 9 Test Cases

| Test ID | Category | Payload | What It Tests |
|---------|----------|---------|---------------|
| TC-01 | imdsv1_root | `http://169.254.169.254/latest/meta-data/` | AWS IMDSv1 root metadata |
| TC-02 | imdsv1_credentials | `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | AWS IAM credentials via SSRF |
| TC-03 | imdsv1_user_data | `http://169.254.169.254/latest/user-data` | AWS user-data (may contain secrets) |
| TC-04 | imdsv2_token_request | `http://169.254.169.254/latest/api/token` | AWS IMDSv2 token endpoint |
| TC-A1 | ip_encoding_bypass | `http://0251.0376.0251.0376/...` | Octal IP encoding bypass |
| TC-A2 | decimal_ip_bypass | `http://2852039166/...` | Decimal IP representation bypass |
| TC-A3 | ipv6_loopback_bypass | `http://[::ffff:169.254.169.254]/...` | IPv6-mapped address bypass |
| TC-A4 | redirect_bypass | `http://httpbin.org/redirect-to?url=...` | Open redirect chaining to metadata |
| TC-A5 | dns_rebind_simulation | `http://169.254.169.254.xip.io/...` | DNS rebinding simulation |

### Anomaly Detection Logic

| Signal Class | Condition | Example |
|-------------|-----------|---------|
| BEHAVIORAL | `status_code != baseline.status_code` | Got 404, expected 200 |
| TEMPORAL | `response_time > baseline.p95 * 2` | 1.9s exceeds 2x of 0.45s p95 |
| CONTENT | `response_hash != baseline.response_hash` | Body changed from baseline |
| CONTENT | canary string found in body | SQL error text in response |
| FINDING-SPECIFIC | SQL error strings in body | sql syntax, ORA-, pg_query |
| FINDING-SPECIFIC | Cloud metadata keywords in body | ami-id, AccessKeyId, computeMetadata |

---

## Part C — AI Integration Layer

**Option Chosen: Option 2 — Result Analyzer**

After all tests complete, the full result set is sent to the Claude API for advisory analysis. The LLM response is validated before use and **NEVER overrides the deterministic verdict**. It is stored as a separate `ai_analysis` field in the evidence report.

### System Prompt

```
You are a security remediation analyst assistant.
Respond ONLY with a valid JSON object — no markdown, no preamble.
Your JSON must contain exactly these fields:
{
  "fix_assessment": "complete" | "partial" | "bypassed" | "inconclusive",
  "confidence": "high" | "medium" | "low",
  "reasoning": "<2-3 sentence explanation>",
  "recommendations": ["action 1", "action 2", ...]
}
```

### Raw AI Output Example

```json
{
  "fix_assessment": "partial",
  "confidence": "medium",
  "reasoning": "Classic injection vectors appear blocked but time-based blind payload triggered a delay, suggesting parameterised queries are not enforced on all code paths.",
  "recommendations": [
    "Verify all DB queries use prepared statements, not string concatenation",
    "Test time-based injection on all endpoints sharing the DB layer",
    "Check ORM config for raw query fallback on this endpoint"
  ]
}
```

### Validation Logic

| Check | Rule | On Failure |
|-------|------|-----------|
| JSON parse | Response must be valid JSON (strip markdown fences first) | Log raw output, store error, skip analysis |
| Required fields | fix_assessment, confidence, reasoning, recommendations must all be present | Log missing fields, return None |
| Enum values | fix_assessment in {complete, partial, bypassed, inconclusive} | Log invalid value, return None |
| Confidence enum | confidence in {high, medium, low} | Log invalid value, return None |
| Type check | recommendations must be a list | Log type error, return None |
| Length cap | recommendations capped at 5 items | Silently truncate to 5 |

### Caught Bad Output Example

During development the model wrapped its response in an extra key:

```json
{ "result": { "fix_assessment": "partial", "confidence": "high", ... } }
```

Validation outcome: REQUIRED_FIELDS check failed — fix_assessment was not at top level. Engine stored this in the report:

```json
{ "error": "LLM output failed validation — not used", "raw_output_preview": "...", "advisory_only": true }
```

Fix applied: System prompt updated with — *Do not nest your response inside any outer key. The top-level object IS your answer.*

---

## Part D — CLI and Output Quality

### CLI Flags

| Flag | Behaviour | Exit Code |
|------|-----------|-----------|
| (default) | Full colored output — banner, per-test results, verdict block | 0 / 1 / 2 |
| `--quiet` | One-line verdict only — for shell script and pipeline integration | 0 / 1 / 2 |
| `--verbose` | Full output + request payload + response body preview per test | 0 / 1 / 2 |
| `--ai` | Run AI advisory analysis after all tests complete | 0 / 1 / 2 |
| `--list-types` | List all registered finding types and exit | 0 |

### Exit Codes — Pipeline Integration

| Exit Code | Meaning | Use Case |
|-----------|---------|---------|
| `0` | REMEDIATION_VERIFIED — all tests passed | Pipeline continues, finding closed |
| `1` | REMEDIATION_FAILED — at least one test failed | Pipeline fails, finding stays open |
| `2` | INCONCLUSIVE — no conclusive results | Pipeline pauses for manual review |
| `3` | Tool error — bad input, unknown finding type | Fix config and re-run |

### Color Output

| Color | Meaning |
|-------|---------|
| Green | PASS result / REMEDIATION_VERIFIED verdict |
| Red | FAIL result / REMEDIATION_FAILED verdict |
| Yellow | INCONCLUSIVE / warnings |
| Cyan | Tool name banner |
| Dim | Report hash (de-emphasized) |

Color output is automatically disabled if the terminal does not support ANSI codes (detected via `sys.stdout.isatty()`).

---

## Part E — Extension Design

### Question 1 — Scaling to 500 Findings Per Night

The current synchronous architecture processes one finding at a time. To handle 500 findings concurrently overnight, the system would be redesigned as a producer-worker-aggregator pipeline.

**Queue Layer:** A Redis or RabbitMQ message queue holds finding records as JSON messages. A scheduler (cron or GitHub Actions schedule) pushes all 500 findings at a configured start time such as 22:00. The queue decouples ingestion from execution and ensures no finding is lost if a worker crashes.

**Worker Pool:** N worker processes each pull one finding at a time, run the full strategy, write the evidence JSON to object storage such as S3 or GCS, and acknowledge the message. Python multiprocessing.Pool covers single-machine scale. For distributed scale, Celery workers behind the queue handle horizontal scaling. With 10 workers each taking approximately 30 seconds per finding, 500 findings complete in roughly 25 minutes.

**Aggregation Layer:** After all workers drain the queue, an aggregator process reads all evidence files, computes fleet-level statistics including total findings, verdict breakdown, and new regressions versus the previous run, then renders a consolidated morning report in HTML or PDF format. A run_manifest.json stores all report hashes for chain-of-custody purposes.

**Error Handling:** Any finding that times out or errors is pushed to a dead-letter queue. The morning report flags these as INCONCLUSIVE with a retry recommendation. This ensures 500 findings are always accounted for in the final report.

---

### Question 2 — Supporting GraphQL Introspection as a New Finding Type

Adding GraphQL introspection as a new finding type requires changes to exactly two locations and leaves the core engine completely untouched.

**File 1 — New Strategy Class:** Create `src/strategies/graphql_introspection.py`. The class inherits from BaseVerifier, sets `FINDING_TYPE = 'graphql_introspection'`, and is decorated with `@register`. It implements:

- `build_test_cases()` — returns test cases for: canonical introspection query `{__schema{types{name}}}`, fragment-based bypass, field suggestion probe `{__type(name:'User'){fields{name}}}`, and batch query introspection
- `execute_test()` — sends POST to the GraphQL endpoint, checks if response body contains `__schema`, `types`, or `fields` as content anomaly signals, checks status code and timing

A PASS means the server returned 4xx or a response with no introspection data — confirming introspection is disabled and the fix is holding.

**File 2 — One Import Line:** Add one line to `src/strategies/__init__.py`:

```python
from src.strategies.graphql_introspection import GraphQLIntrospectionVerifier
```

Nothing else changes. The core engine, CLI, report builder, and AI layer are completely oblivious to the new type. The `@register` decorator adds `graphql_introspection` to the registry at import time automatically.

---

### Question 3 — Evidence Chain of Custody for a Disputed Verdict

**What the Current Evidence Model Supports:**

When a client disputes a REMEDIATION_FAILED verdict, the evidence file provides: the exact payloads sent, the HTTP status code and response time per test, the response body hash, the specific anomalies detected, the deterministic verdict logic, and a SHA-256 hash of the entire report. The hash proves the file was not modified after generation — any tampering changes the hash.

To resolve a dispute, show the client: the evidence JSON with its hash, the finding record used as input proving what was tested, which specific test case triggered FAIL and why via the anomaly field, and that the hash on the file matches sha256sum computed independently.

**What the Current Model Cannot Prove:**

It cannot prove what the server actually received since there is no request capture, nor what the server returned in full since the body is truncated. A sophisticated client could argue the target was a different server, or that the response body was misinterpreted.

**Improvements for Future Disputes:**

- Store full request and response including headers and body, optionally encrypted at rest — this is the single biggest improvement
- Add a signed timestamp from a trusted timestamping authority such as RFC 3161 so the report creation time is provable and not just asserted
- Record network-layer evidence such as a PCAP snippet or proxy log tied to the report ID so the exact bytes exchanged are auditable
- Generate a unique canary UUID per report ID and include it in payloads — if the canary appears in any response body, it is unambiguous proof that the payload reached the server

---

## REPORT.md — Self Assessment

### What Works

- Full end-to-end engine for `sql_injection` and `ssrf_cloud_metadata` finding types
- Strategy registry pattern — adding a new finding type is one new file and one import line, core never changes
- Tamper-evident SHA-256 report hash computed over canonical JSON
- Three anomaly signal classes: behavioral (status), temporal (p95 x2), content (hash + canary)
- AI advisory layer with validation gate — bad LLM output is logged and never executed
- CLI with `--quiet`, `--verbose`, color output, and correct exit codes 0/1/2
- Evidence saved to timestamped JSON in `./evidence/` directory

### What Is Missing / Limitations

- Tests run against httpbin.org because no vulnerable target server is available — real anomaly detection requires an actual vulnerable endpoint for baseline calibration
- No retry/consistency engine — inconsistent results across 3 runs are not automatically flagged
- SSRF OOB out-of-band callback verification is not implemented — real SSRF verification needs a callback server such as Burp Collaborator
- JWT and deserialization strategies are not in the core engine — they exist as separate tools in Challenge 2
- The AI analyzer requires the anthropic package and a valid API key — without it the tool degrades gracefully

### Design Trade-offs Under Time Pressure

- Chose requests (synchronous) over asyncio for simplicity — for 500 concurrent findings this would be replaced with async workers
- Canary strings are hardcoded per strategy rather than dynamically generated UUIDs — UUID canaries would be stronger evidence
- Response body is capped at 2000-3000 chars in evidence — full body would be better for audits but increases report file size significantly
- Baseline values in finding JSON are hardcoded for demo — in production these would be computed from real baseline runs against the target

---

## Submission Checklist

- [x] Part A — Architecture document with component diagram + Q1 Q2 Q3 Q4 answers
- [x] Part B — Working engine for sql_injection and ssrf_cloud_metadata
- [x] Part C — AI integration with prompts.md (prompt, raw output, critique, bad output example)
- [x] Part D — Clean CLI output with color, --quiet, --verbose, --ai flags, correct exit codes
- [x] Part E — Three written answers (scaling, new finding type, chain of custody)
- [x] Repository follows required structure
- [x] README contains working end-to-end example
- [x] Evidence saved as tamper-evident JSON with SHA-256 hash
