"""
src/strategies/sql_injection.py — SQL Injection verification strategy
Supports mysql, postgres, mssql, sqlite engine hints from metadata.
"""

from __future__ import annotations

import time
import requests

from src.engine import BaseVerifier, TestResult, register


@register
class SQLInjectionVerifier(BaseVerifier):

    FINDING_TYPE = "sql_injection"

    # ── Payload library ───────────────────────────────────────────────────────

    CLASSIC_PAYLOADS = [
        ("TC-01", "classic_injection",    "' OR '1'='1"),
        ("TC-02", "union_based",          "' UNION SELECT NULL,NULL,NULL--"),
        ("TC-03", "boolean_blind_true",   "' AND '1'='1"),
        ("TC-04", "boolean_blind_false",  "' AND '1'='2"),
        ("TC-06", "encoding_bypass",      "%27%20OR%20%271%27%3D%271"),
        ("TC-07", "second_order",         "admin'--"),
        ("TC-08", "error_based",          "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--"),
    ]

    TIME_PAYLOADS_BY_ENGINE = {
        "mysql":    "' AND SLEEP(3)--",
        "postgres": "'; SELECT pg_sleep(3)--",
        "mssql":    "'; WAITFOR DELAY '0:0:3'--",
        "sqlite":   "' AND randomblob(100000000)--",
    }

    CANARY = "remcheck_sqli_canary_7x9z"

    def build_test_cases(self) -> list[dict]:
        engine = self.metadata.get("db_engine", "mysql").lower()
        time_payload = self.TIME_PAYLOADS_BY_ENGINE.get(engine, self.TIME_PAYLOADS_BY_ENGINE["mysql"])

        tcs = []
        for tc_id, category, payload in self.CLASSIC_PAYLOADS:
            tcs.append({
                "test_id":    tc_id,
                "category":   category,
                "payload":    payload,
                "inject_in":  "body",
            })

        # Time-based blind (TC-05) — engine-specific
        tcs.insert(4, {
            "test_id":   "TC-05",
            "category":  "time_based_blind",
            "payload":   time_payload,
            "inject_in": "body",
        })

        return tcs

    def execute_test(self, tc: dict) -> TestResult:
        method, path = self.endpoint.split(" ", 1)
        url = self.base_url + path
        headers = self._build_headers()

        body_data = {self.parameter: tc["payload"]}

        start = time.monotonic()
        status_code = None
        body = ""
        error = None

        try:
            resp = requests.request(
                method,
                url,
                json=body_data,
                headers=headers,
                timeout=10,
                allow_redirects=False,
            )
            elapsed = time.monotonic() - start
            status_code = resp.status_code
            body = resp.text[:2000]

        except requests.exceptions.Timeout:
            elapsed = time.monotonic() - start
            error = "TIMEOUT"
            body = ""
        except requests.exceptions.RequestException as exc:
            elapsed = time.monotonic() - start
            error = str(exc)
            body = ""

        response_hash = self._hash_body(body)

        # Finding-specific checks
        # For SQL injection: error messages in body signal the fix may be incomplete
        error_patterns = [
            "sql syntax", "mysql_fetch", "ora-", "pg_query",
            "sqlite_", "unclosed quotation", "sqlexception",
        ]
        sql_error_found = any(p in body.lower() for p in error_patterns)

        # Time-based: if elapsed >= 2.5s and payload was time-based → anomaly
        is_time_based = tc["category"] == "time_based_blind"
        time_triggered = is_time_based and elapsed >= 2.5

        extra = [
            ("CONTENT: SQL error message detected in response body", sql_error_found),
            ("BEHAVIORAL: time-based blind injection delay triggered", time_triggered),
        ]

        if error:
            anomalies = [f"NETWORK: {error}"]
            result = "ERROR"
        else:
            anomalies = self._detect_anomalies(
                status_code, elapsed, response_hash, body,
                canary=self.CANARY, extra_checks=extra,
            )
            result = "PASS" if not anomalies else "FAIL"

        return TestResult(
            test_id          = tc["test_id"],
            category         = tc["category"],
            payload          = tc["payload"],
            status_code      = status_code,
            response_time    = round(elapsed, 3),
            response_hash    = response_hash,
            anomalies        = anomalies,
            result           = result,
            raw_body_preview = body[:200],
        )
