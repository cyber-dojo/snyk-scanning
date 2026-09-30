#!/usr/bin/env python3
"""Unit tests for sort_key, vuln_result and artifact_results."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import find_expiring_vulns  # noqa: E402

NOW_TS = 1748736000.0   # 2025-06-01 00:00:00 UTC


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


def _suppressed_vuln(trail_name, severity, secs_remaining):
    """Return an expiry row for a vuln held by a .snyk ignore entry."""
    full_id = trail_name.split("-", 2)[2]
    return {
        "env": "aws-prod",
        "trail_name": trail_name,
        "full_id": full_id,
        "severity": severity,
        "vuln_url": f"https://security.snyk.io/vuln/{full_id}",
        "mechanism": "dot_snyk_expiry",
        "days_remaining": secs_remaining / 86400,
        "ignore_expires": "2026-09-21 00:00:00+00:00",
        "age_days": None,
        "limit_days": None,
        "artifact": "runner",
    }


# The five runner vulns in the aws-prod scan of 2026-08-23. All are held by .snyk
# ignore entries sharing one expiry, so they fall due on the same day; the spread
# in seconds is the order their matrix jobs stamped now_ts.
PROD_RUNNER_VULNS = [
    ("runner-medium-SNYK-GOLANG-GOOPENTELEMETRYIOOTELPROPAGATION-17054905", "medium", 2495281),
    ("runner-high-SNYK-GOLANG-GOOGLEGOLANGORGGRPCINTERNALTRANSPORT-18172578", "high", 2495282),
    ("runner-medium-SNYK-GOLANG-GITHUBCOMCILIUMEBPFBTF-17810931", "medium", 2495285),
    ("runner-high-SNYK-GOLANG-GITHUBCOMAWSAWSSDKGOV2SERVICECLOUDWATCHLOGS-16316406", "high", 2495286),
    ("runner-medium-SNYK-GOLANG-GOOPENTELEMETRYIOOTELBAGGAGE-17054906", "medium", 2495288),
]


def test_c7f2a309():
    """sort_key orders vulns sharing a whole-day deadline by severity, then by trail_name."""
    vulns = [_suppressed_vuln(trail_name, severity, secs)
             for trail_name, severity, secs in PROD_RUNNER_VULNS]
    vulns.sort(key=find_expiring_vulns.sort_key)
    assert [v["trail_name"] for v in vulns] == [
        "runner-high-SNYK-GOLANG-GITHUBCOMAWSAWSSDKGOV2SERVICECLOUDWATCHLOGS-16316406",
        "runner-high-SNYK-GOLANG-GOOGLEGOLANGORGGRPCINTERNALTRANSPORT-18172578",
        "runner-medium-SNYK-GOLANG-GITHUBCOMCILIUMEBPFBTF-17810931",
        "runner-medium-SNYK-GOLANG-GOOPENTELEMETRYIOOTELBAGGAGE-17054906",
        "runner-medium-SNYK-GOLANG-GOOPENTELEMETRYIOOTELPROPAGATION-17054905",
    ]


def test_c7f2a30a():
    """sort_key keeps a sooner medium ahead of a later high, so severity only breaks ties."""
    later_high = _suppressed_vuln(
        "runner-high-SNYK-GOLANG-GITHUBCOMAWSAWSSDKGOV2SERVICECLOUDWATCHLOGS-16316406",
        "high", 29 * 86400)
    sooner_medium = _suppressed_vuln(
        "runner-medium-SNYK-GOLANG-GOOPENTELEMETRYIOOTELPROPAGATION-17054905",
        "medium", 1 * 86400)
    vulns = [later_high, sooner_medium]
    vulns.sort(key=find_expiring_vulns.sort_key)
    assert [v["severity"] for v in vulns] == ["medium", "high"]


def test_c7f2a30c():
    """vuln_result joins a rego_limit report onto its vuln to give the expiry row."""
    vuln = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400)
    report = {"mechanism": "rego_limit", "age_days": 1, "limit_days": 2, "days_remaining": 1}
    assert find_expiring_vulns.vuln_result(vuln, report, "aws-prod") == {
        "env": "aws-prod",
        "trail_name": "creator-high-SNYK-GOLANG-NETHTTP-3321444",
        "full_id": "SNYK-GOLANG-NETHTTP-3321444",
        "severity": "high",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
        "mechanism": "rego_limit",
        "days_remaining": 1,
        "ignore_expires": None,
        "age_days": 1,
        "limit_days": 2,
        "artifact": "creator",
    }


def test_c7f2a30d():
    """vuln_result joins a dot_snyk_expiry report onto its vuln, with no age or limit."""
    vuln = {**_high_vuln_no_ignore(),
            "ignore_expires_exists": True,
            "ignore_expires_ts": NOW_TS + 3 * 86400,
            "ignore_expires": "2025-06-04 00:00:00+00:00"}
    report = {"mechanism": "dot_snyk_expiry",
              "ignore_expires": "2025-06-04 00:00:00+00:00",
              "days_remaining": 3}
    assert find_expiring_vulns.vuln_result(vuln, report, "aws-prod") == {
        "env": "aws-prod",
        "trail_name": "creator-high-SNYK-GOLANG-NETHTTP-3321444",
        "full_id": "SNYK-GOLANG-NETHTTP-3321444",
        "severity": "high",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
        "mechanism": "dot_snyk_expiry",
        "days_remaining": 3,
        "ignore_expires": "2025-06-04 00:00:00+00:00",
        "age_days": None,
        "limit_days": None,
        "artifact": "creator",
    }


def test_c7f2a30e():
    """artifact_results gives each vuln of a vuln-reports file the report keyed by its own full_id."""
    high = _high_vuln_no_ignore(first_seen_ts=NOW_TS - 1 * 86400)
    medium = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 3 * 86400),
              "trail_name": "creator-medium-SNYK-ALPINE321-OPENSSL-13939001",
              "full_id": "SNYK-ALPINE321-OPENSSL-13939001",
              "severity": "medium",
              "vuln_url": "https://security.snyk.io/vuln/SNYK-ALPINE321-OPENSSL-13939001"}
    reports = {
        "vulns": [high, medium],
        "vuln_reports": {
            "SNYK-ALPINE321-OPENSSL-13939001":
                {"mechanism": "rego_limit", "age_days": 3, "limit_days": 4, "days_remaining": 1},
            "SNYK-GOLANG-NETHTTP-3321444":
                {"mechanism": "rego_limit", "age_days": 1, "limit_days": 2, "days_remaining": 1},
        },
    }
    results = find_expiring_vulns.artifact_results(reports, "aws-prod")
    assert [(r["full_id"], r["age_days"], r["limit_days"]) for r in results] == [
        ("SNYK-GOLANG-NETHTTP-3321444", 1, 2),
        ("SNYK-ALPINE321-OPENSSL-13939001", 3, 4),
    ]


def test_c7f2a30f():
    """artifact_results leaves out a vuln ignored forever, since it has no deadline."""
    forever = {**_high_vuln_no_ignore(first_seen_ts=NOW_TS - 30 * 86400),
               "ignore_expires_exists": True,
               "ignore_forever": True}
    reports = {
        "vulns": [forever],
        "vuln_reports": {"SNYK-GOLANG-NETHTTP-3321444": {"mechanism": "dot_snyk_forever"}},
    }
    assert find_expiring_vulns.artifact_results(reports, "aws-prod") == []


def test_c7f2a310():
    """artifact_results refuses a vuln the rego gave no report, naming it.

    The rego reports every vuln whose deadline it can measure, so a missing
    report is an age no clock measured; a deadline for it would be invented.
    """
    ahead = _high_vuln_no_ignore(first_seen_ts=NOW_TS + 76)
    reports = {"vulns": [ahead], "vuln_reports": {}}
    with pytest.raises(ValueError, match="^SNYK-GOLANG-NETHTTP-3321444: no vuln_reports entry"):
        find_expiring_vulns.artifact_results(reports, "aws-prod")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
