#!/usr/bin/env python3
"""Unit tests for dot_snyk_result and rego_result."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import find_expiring_vulns  # noqa: E402

NOW_TS = 1748736000.0   # 2025-06-01 00:00:00 UTC
PROD_MAX_DAYS = {"critical": 0, "high": 2, "medium": 4, "low": 6}
BETA_MAX_DAYS = {"critical": 1, "high": 2, "medium": 4, "low": 6}


def _high_vuln_no_ignore(first_seen_ts=None):
    """Return a minimal attestation_data dict for a high-severity vuln with no ignore."""
    return {
        "trail_name": "creator-high-SNYK-GOLANG-NETHTTP-3321444",
        "full_id": "SNYK-GOLANG-NETHTTP-3321444",
        "severity": "high",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
        "ignore_expires_exists": False,
        "ignore_forever": False,
        "ignore_expires_ts": 0,
        "ignore_expires": "",
        "first_seen_ts": first_seen_ts if first_seen_ts is not None else NOW_TS - 1 * 86400,
    }


class TestDotSnykResult(unittest.TestCase):

    def test_c7f2a301(self):
        """Returns a result dict when a future .snyk ignore entry exists."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS + 3 * 86400,
                "ignore_expires": "2025-06-04 00:00:00+00:00"}
        result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "dot_snyk_expiry")
        self.assertAlmostEqual(result["days_remaining"], 3.0, places=5)
        self.assertEqual(result["env"], "aws-prod")
        self.assertEqual(result["artifact"], "creator")
        self.assertIsNone(result["age_days"])
        self.assertIsNone(result["limit_days"])

    def test_c7f2a302(self):
        """Returns None when ignore_expires_exists is False."""
        result = find_expiring_vulns.dot_snyk_result(_high_vuln_no_ignore(), "aws-prod", NOW_TS)
        self.assertIsNone(result)

    def test_c7f2a303(self):
        """Returns a result with negative days_remaining when the .snyk ignore has already expired."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS - 2 * 86400,
                "ignore_expires": "2025-05-30 00:00:00+00:00"}
        result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "dot_snyk_expiry")
        self.assertAlmostEqual(result["days_remaining"], -2.0, places=5)

    def test_c7f2a308(self):
        """Returns None when the .snyk ignore entry has no expiry (suppressed forever)."""
        data = {**_high_vuln_no_ignore(),
                "ignore_expires_exists": True,
                "ignore_forever": True,
                "ignore_expires_ts": 0,
                "ignore_expires": ""}
        result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
        self.assertIsNone(result)


class TestRegoResult(unittest.TestCase):

    def test_c7f2a304(self):
        """Returns a result dict when age is within the severity limit."""
        data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400)
        result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "rego_limit")
        self.assertAlmostEqual(result["days_remaining"], 1.0, places=5)
        self.assertAlmostEqual(result["age_days"], 1.0, places=5)
        self.assertEqual(result["limit_days"], 2)
        self.assertEqual(result["artifact"], "creator")
        self.assertIsNone(result["ignore_expires"])

    def test_c7f2a305(self):
        """Returns None when a .snyk ignore entry exists (dot_snyk_result handles it)."""
        data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400),
                "ignore_expires_exists": True,
                "ignore_expires_ts": NOW_TS + 3 * 86400}
        result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
        self.assertIsNone(result)

    def test_c7f2a306(self):
        """Returns a result with negative days_remaining for a zero-limit severity (critical in aws-prod)."""
        data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 3 * 86400),
                "severity": "critical",
                "trail_name": "creator-critical-SNYK-GOLANG-NETHTTP-3321444"}
        result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "rego_limit")
        self.assertAlmostEqual(result["days_remaining"], -3.0, places=5)
        self.assertEqual(result["limit_days"], 0)

    def test_c7f2a307(self):
        """Returns a result with negative days_remaining when the vuln age has exceeded the severity limit."""
        data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 3 * 86400)
        result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
        self.assertIsNotNone(result)
        self.assertEqual(result["mechanism"], "rego_limit")
        self.assertAlmostEqual(result["days_remaining"], -1.0, places=5)
        self.assertAlmostEqual(result["age_days"], 3.0, places=5)
        self.assertEqual(result["limit_days"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
