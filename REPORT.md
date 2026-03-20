# REPORT.md — remcheck v0.1.0

## Self-Assessment

### What Works
- Full end-to-end engine for `sql_injection` and `ssrf_cloud_metadata` finding types
- Strategy registry pattern: adding a new finding type is one new file + one import line
- Tamper-evident SHA-256 report hash computed over canonical JSON
- Three anomaly signal classes: behavioral (status), temporal (p95×2), content (hash + canary)
- AI advisory layer with validation gate — bad LLM output is logged, never executed
- CLI with `--quiet`, `--verbose`, color output, correct exit codes (0/1/2)
- Evidence saved to timestamped JSON in `./evidence/`

### What Is Missing / Limitations
- Tests run against `httpbin.org` because we have no vulnerable target server. Real
  anomaly detection requires an actual vulnerable endpoint for baseline calibration.
- No retry/consistency engine (Bonus B). Inconsistent results across 3 runs are not
  automatically flagged — this would be the first addition with more time.
- SSRF OOB (out-of-band) callback verification is not implemented. Real SSRF verification
  needs a callback server (e.g., Burp Collaborator) to confirm DNS/HTTP callbacks.
- JWT and deserialization strategies are not implemented in the core engine (they exist
  as separate tools in Challenge 2).
- The AI analyzer requires the `anthropic` package and a valid API key. Without it,
  the tool degrades gracefully with a logged warning.

### Design Trade-offs Under Time Pressure
- Chose `requests` (synchronous) over `asyncio`/`httpx` for simplicity. For 500
  concurrent findings (Part E Q1) this would be replaced with async workers.
- Canary strings are hardcoded per strategy rather than dynamically generated UUIDs.
  UUID canaries would be stronger evidence.
- Response body is capped at 2000–3000 chars in evidence. Full body would be better
  for audits but increases report file size significantly.

---

## Part E — Extension Design

### Question 1 — Scaling to 500 Findings Per Night

The current synchronous, single-process architecture would be replaced with a
producer-worker-aggregator pipeline.

**Queue layer:** A Redis or RabbitMQ message queue holds finding records as JSON
messages. A scheduler (cron or GitHub Actions `schedule`) pushes all 500 findings
at a configured start time (e.g., 22:00). The queue decouples ingestion from execution.

**Worker pool:** N worker processes (or containers) each pull one finding at a time,
run the full strategy, write the evidence JSON to object storage (S3/GCS), and
acknowledge the message. Python's `multiprocessing.Pool` covers single-machine scale;
for distributed scale, Celery workers behind the queue handle horizontal scaling.
With 10 workers each taking ~30s per finding, 500 findings complete in ~25 minutes.

**Aggregation layer:** After all workers drain the queue, an aggregator process
reads all evidence files, computes fleet-level statistics (total findings, verdict
breakdown, new regressions vs. previous run), and renders a consolidated morning
report in HTML/PDF. It stores a `run_manifest.json` with all report hashes for
chain-of-custody purposes.

**Error handling:** Any finding that times out or errors is pushed to a dead-letter
queue. The morning report flags these as INCONCLUSIVE with a retry recommendation.

---

### Question 2 — Supporting GraphQL Introspection as a New Finding Type

Adding a new finding type to remcheck requires changes to exactly **two locations**
and leaves the core engine untouched.

**File 1 — New strategy class:** Create
`src/strategies/graphql_introspection.py`. The class inherits from `BaseVerifier`,
sets `FINDING_TYPE = "graphql_introspection"`, and implements `build_test_cases()`
and `execute_test()`.

`build_test_cases()` returns test cases covering: the canonical introspection query
(`{__schema{types{name}}}`), a fragment-based introspection bypass, a field
suggestion probe (`{__type(name:"User"){fields{name}}}`), and a batch query
introspection attempt. Each test sends a POST to the GraphQL endpoint.

`execute_test()` sends the payload, then checks: HTTP status, whether the response
body contains `"__schema"`, `"types"`, or `"fields"` (content anomaly), and whether
the response time is anomalous. A `PASS` means the server returned 4xx or returned
a response body with no introspection data — indicating the fix (introspection
disabled) is holding.

**File 2 — Strategy registry import:** Add one line to
`src/strategies/__init__.py`:
```python
from src.strategies.graphql_introspection import GraphQLIntrospectionVerifier
```

**Nothing else changes.** The core engine (`engine.py`), the CLI (`remcheck.py`),
and the report builder are all oblivious to the new type. The `@register` decorator
on the new class automatically adds `"graphql_introspection"` to the registry at
import time.

The finding JSON for this type would add `"graphql_endpoint": "/graphql"` and
`"introspection_enabled_originally": true` to `metadata`, which the strategy
reads directly.

---

### Question 3 — Evidence Chain of Custody for a Disputed Verdict

**What the current evidence model supports:**

When a client disputes a `REMEDIATION_FAILED` verdict, the evidence file
(`FIND-XXXX_<timestamp>.json`) provides: the exact payloads sent, the HTTP status
code and response time per test, the response body hash (not the full body), the
specific anomalies detected, the deterministic verdict logic, and a SHA-256 hash
of the entire report. The hash proves the file was not modified after generation —
any tampering changes the hash.

To resolve a dispute, show the client: (1) the evidence JSON with its hash, (2) the
finding record used as input (proves what was tested), (3) which specific test case
triggered `FAIL` and why (the anomaly field), and (4) that the hash on the file
matches `sha256sum <evidence_file>` computed independently.

**What the current model cannot prove:**

It cannot prove what the server actually received (no request capture), nor what
the server returned in full (body is truncated). A sophisticated client could argue
the target was a different server, or that the response body was misinterpreted.

**What would make future disputes easier to resolve:**

1. **Store full request and response** (headers + body, not just hash) — optionally
   encrypted at rest. This is the single biggest improvement.
2. **Add a signed timestamp** from a trusted timestamping authority (RFC 3161)
   so the report's creation time is provable, not just asserted.
3. **Record network-layer evidence**: PCAP snippet or proxy log tied to the report ID,
   so the exact bytes exchanged are auditable.
4. **Canary UUIDs per run**: Generate a unique canary string per report ID and include
   it in payloads. If the canary appears in any response body, it is unambiguous
   proof that payload reached the server.
