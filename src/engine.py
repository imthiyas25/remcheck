"""
src/engine.py — Core remcheck engine
Strategy registry, base verifier interface, anomaly detection, report generation.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

ENGINE_VERSION = "0.1.0"

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class TestResult:
    test_id: str
    category: str
    payload: str
    status_code: int | None
    response_time: float
    response_hash: str
    anomalies: list[str]
    result: str          # PASS | FAIL | ERROR
    raw_body_preview: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EvidenceReport:
    report_id: str
    finding_id: str
    generated_at: str
    engine_version: str
    verdict: str          # REMEDIATION_VERIFIED | REMEDIATION_FAILED | INCONCLUSIVE
    test_results: list[TestResult]
    summary: dict
    ai_analysis: dict | None = None
    report_hash: str = ""

    def to_dict(self) -> dict:
        d = {
            "report_id": self.report_id,
            "finding_id": self.finding_id,
            "generated_at": self.generated_at,
            "engine_version": self.engine_version,
            "verdict": self.verdict,
            "test_results": [r.to_dict() for r in self.test_results],
            "summary": self.summary,
        }
        if self.ai_analysis:
            d["ai_analysis"] = self.ai_analysis
        d["report_hash"] = self.report_hash
        return d


# ── Strategy base class ───────────────────────────────────────────────────────

class BaseVerifier(ABC):
    """
    All finding strategies inherit from this class.
    The core engine only calls: verifier.run(finding) → list[TestResult]
    Adding a new finding type = new subclass + one registry line. Core never changes.
    """

    # Subclasses set this to their finding type string
    FINDING_TYPE: str = ""

    def __init__(self, finding: dict):
        self.finding = finding
        self.base_url: str = finding["base_url"].rstrip("/")
        self.endpoint: str = finding["endpoint"]
        self.parameter: str = finding["parameter"]
        self.baseline: dict = finding["baseline"]
        self.auth: dict = finding.get("auth", {})
        self.metadata: dict = finding.get("metadata", {})

    # ── Helpers shared across all strategies ──────────────────────────────────

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json", "User-Agent": "remcheck/0.1.0"}
        auth_type = self.auth.get("type", "").lower()
        if auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.auth.get('token', '')}"
        elif auth_type == "basic":
            import base64
            creds = base64.b64encode(
                f"{self.auth.get('username','')}:{self.auth.get('password','')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        return headers

    def _hash_body(self, body: str) -> str:
        return hashlib.sha256(body.encode()).hexdigest()[:16]

    def _detect_anomalies(
        self,
        status_code: int | None,
        response_time: float,
        response_hash: str,
        body: str,
        canary: str | None = None,
        extra_checks: list[tuple[str, bool]] | None = None,
    ) -> list[str]:
        """
        Universal anomaly detector. Returns list of anomaly strings.
        Checks:
          - behavioral: status code deviates from baseline
          - temporal:   response time > baseline p95 * 2
          - content:    response hash changed OR canary string present
          - extra:      finding-specific checks passed in as (label, triggered) tuples
        """
        anomalies = []

        baseline_status = self.baseline.get("status_code")
        if status_code is not None and status_code != baseline_status:
            anomalies.append(
                f"BEHAVIORAL: status {status_code} deviates from baseline {baseline_status}"
            )

        p95 = self.baseline.get("response_time_p95", 0)
        if p95 > 0 and response_time > p95 * 2:
            anomalies.append(
                f"TEMPORAL: {response_time:.3f}s exceeds 2× baseline p95 ({p95}s)"
            )

        baseline_hash = self.baseline.get("response_hash", "")
        if baseline_hash and response_hash and response_hash != baseline_hash[:16]:
            anomalies.append(
                f"CONTENT: response hash {response_hash} deviates from baseline {baseline_hash[:16]}"
            )

        if canary and canary.lower() in body.lower():
            anomalies.append(f"CONTENT: canary string '{canary}' found in response body")

        for label, triggered in (extra_checks or []):
            if triggered:
                anomalies.append(label)

        return anomalies

    # ── Interface methods ──────────────────────────────────────────────────────

    @abstractmethod
    def build_test_cases(self) -> list[dict]:
        """
        Return list of test case dicts:
          { test_id, category, payload, method, inject_in, description }
        """
        ...

    @abstractmethod
    def execute_test(self, tc: dict) -> TestResult:
        """Execute a single test case and return a TestResult."""
        ...

    def run(self) -> list[TestResult]:
        """Run all test cases. Called by the engine."""
        return [self.execute_test(tc) for tc in self.build_test_cases()]


# ── Strategy registry ─────────────────────────────────────────────────────────

_REGISTRY: dict[str, type[BaseVerifier]] = {}


def register(cls: type[BaseVerifier]) -> type[BaseVerifier]:
    """Decorator that registers a strategy class by its FINDING_TYPE."""
    if not cls.FINDING_TYPE:
        raise ValueError(f"{cls.__name__} must define FINDING_TYPE")
    _REGISTRY[cls.FINDING_TYPE] = cls
    return cls


def get_strategy(finding_type: str) -> type[BaseVerifier] | None:
    return _REGISTRY.get(finding_type)


def list_supported_types() -> list[str]:
    return sorted(_REGISTRY.keys())


# ── Verdict logic ─────────────────────────────────────────────────────────────

def _compute_verdict(results: list[TestResult]) -> str:
    """
    Finalization logic:
    - Any FAIL → REMEDIATION_FAILED
    - All ERROR (no conclusive results) → INCONCLUSIVE
    - All PASS → REMEDIATION_VERIFIED
    Inconsistency handling: a test that FAILs in 1/3 retries is flagged
    via its anomaly list by the retry engine, but still counts as FAIL here.
    """
    if not results:
        return "INCONCLUSIVE"
    statuses = {r.result for r in results}
    if "FAIL" in statuses:
        return "REMEDIATION_FAILED"
    if statuses == {"ERROR"}:
        return "INCONCLUSIVE"
    return "REMEDIATION_VERIFIED"


# ── Report builder ────────────────────────────────────────────────────────────

def build_report(finding: dict, results: list[TestResult], ai_analysis: dict | None = None) -> EvidenceReport:
    total   = len(results)
    passed  = sum(1 for r in results if r.result == "PASS")
    failed  = sum(1 for r in results if r.result == "FAIL")
    inconc  = sum(1 for r in results if r.result == "ERROR")

    verdict = _compute_verdict(results)

    report = EvidenceReport(
        report_id       = str(uuid.uuid4()),
        finding_id      = finding["finding_id"],
        generated_at    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        engine_version  = ENGINE_VERSION,
        verdict         = verdict,
        test_results    = results,
        summary         = {"total": total, "passed": passed, "failed": failed, "inconclusive": inconc},
        ai_analysis     = ai_analysis,
    )

    # Compute tamper-evident hash AFTER populating all fields (excluding hash itself)
    d = report.to_dict()
    d.pop("report_hash", None)
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    report.report_hash = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

    return report
