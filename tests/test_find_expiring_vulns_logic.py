#!/usr/bin/env python3
"""Unit tests for dot_snyk_result and rego_result."""

import os
import sys

import pytest

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


def test_c7f2a301():
    """dot_snyk_result returns a result dict when a future .snyk ignore entry exists."""
    data = {**_high_vuln_no_ignore(),
            "ignore_expires_exists": True,
            "ignore_expires_ts": NOW_TS + 3 * 86400,
            "ignore_expires": "2025-06-04 00:00:00+00:00"}
    result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
    assert result is not None
    assert result["mechanism"] == "dot_snyk_expiry"
    assert result["days_remaining"] == pytest.approx(3.0)
    assert result["env"] == "aws-prod"
    assert result["artifact"] == "creator"
    assert result["age_days"] is None
    assert result["limit_days"] is None


def test_c7f2a302():
    """dot_snyk_result returns None when ignore_expires_exists is False."""
    result = find_expiring_vulns.dot_snyk_result(_high_vuln_no_ignore(), "aws-prod", NOW_TS)
    assert result is None


def test_c7f2a303():
    """dot_snyk_result returns negative days_remaining when the .snyk ignore has already expired."""
    data = {**_high_vuln_no_ignore(),
            "ignore_expires_exists": True,
            "ignore_expires_ts": NOW_TS - 2 * 86400,
            "ignore_expires": "2025-05-30 00:00:00+00:00"}
    result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
    assert result is not None
    assert result["mechanism"] == "dot_snyk_expiry"
    assert result["days_remaining"] == pytest.approx(-2.0)


def test_c7f2a308():
    """dot_snyk_result returns None when the .snyk ignore entry has no expiry (suppressed forever)."""
    data = {**_high_vuln_no_ignore(),
            "ignore_expires_exists": True,
            "ignore_forever": True,
            "ignore_expires_ts": 0,
            "ignore_expires": ""}
    result = find_expiring_vulns.dot_snyk_result(data, "aws-prod", NOW_TS)
    assert result is None


def test_c7f2a304():
    """rego_result returns a result dict when age is within the severity limit."""
    data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400)
    result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
    assert result is not None
    assert result["mechanism"] == "rego_limit"
    assert result["days_remaining"] == pytest.approx(1.0)
    assert result["age_days"] == pytest.approx(1.0)
    assert result["limit_days"] == 2
    assert result["artifact"] == "creator"
    assert result["ignore_expires"] is None


def test_c7f2a305():
    """rego_result returns None when a .snyk ignore entry exists (dot_snyk_result handles it)."""
    data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400),
            "ignore_expires_exists": True,
            "ignore_expires_ts": NOW_TS + 3 * 86400}
    result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
    assert result is None


def test_c7f2a306():
    """rego_result returns negative days_remaining for a zero-limit severity (critical in aws-prod)."""
    data = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 3 * 86400),
            "severity": "critical",
            "trail_name": "creator-critical-SNYK-GOLANG-NETHTTP-3321444"}
    result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
    assert result is not None
    assert result["mechanism"] == "rego_limit"
    assert result["days_remaining"] == pytest.approx(-3.0)
    assert result["limit_days"] == 0


def test_c7f2a307():
    """rego_result returns negative days_remaining when the vuln age has exceeded the severity limit."""
    data = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 3 * 86400)
    result = find_expiring_vulns.rego_result(data, "aws-prod", NOW_TS, PROD_MAX_DAYS)
    assert result is not None
    assert result["mechanism"] == "rego_limit"
    assert result["days_remaining"] == pytest.approx(-1.0)
    assert result["age_days"] == pytest.approx(3.0)
    assert result["limit_days"] == 2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
