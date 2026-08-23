#!/usr/bin/env python3
"""Unit tests for stamp_vuln_times, which adds the two instants a vuln's age is measured between."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import stamp_vuln_times  # noqa: E402

# Timestamps and their rendered strings are taken from vuln files the workflow
# actually produced, so the formatting is pinned to observed output rather than
# to a restatement of the implementation. test_schema_matches_attested_data.py
# names the same four keys as the ones the workflow adds.
FIRST_SEEN_TS = 1787193945.8263896
FIRST_SEEN = "2026-08-20 02:45:45.826390+00:00"
NOW_TS = 1787323545
NOW = "2026-08-21 14:45:45+00:00"


def _vuln():
    """Return an attestation_data dict as the find-snyk-vulns job emits it, before stamping."""
    return {
        "full_id": "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
        "severity": "high",
        "trail_name": "runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
        "artifact_fingerprint": "f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096",
        "ignore_expires_exists": False,
    }


def test_b4e1d701():
    """stamp adds the four time keys and leaves the vuln's own fields untouched."""
    stamped = stamp_vuln_times.stamp(_vuln(), FIRST_SEEN_TS, NOW_TS)
    assert stamped["first_seen_ts"] == FIRST_SEEN_TS
    assert stamped["first_seen"] == FIRST_SEEN
    assert stamped["now_ts"] == NOW_TS
    assert stamped["now"] == NOW
    assert stamped["full_id"] == "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"
    assert stamped["severity"] == "high"
    assert stamped["ignore_expires_exists"] is False


def test_b4e1d702():
    """stamp renders a fractional trail created_at to microseconds, as the trail reports it."""
    stamped = stamp_vuln_times.stamp(_vuln(), FIRST_SEEN_TS, NOW_TS)
    assert stamped["first_seen"] == "2026-08-20 02:45:45.826390+00:00"


def test_b4e1d703():
    """stamp renders a whole-second timestamp with no fractional part."""
    stamped = stamp_vuln_times.stamp(_vuln(), 1787193945, NOW_TS)
    assert stamped["first_seen"] == "2026-08-20 02:45:45+00:00"


def test_b4e1d704():
    """stamp does not mutate the vuln it is given, so the caller's data survives."""
    vuln = _vuln()
    stamp_vuln_times.stamp(vuln, FIRST_SEEN_TS, NOW_TS)
    assert "first_seen_ts" not in vuln
    assert "now_ts" not in vuln


def test_b4e1d705():
    """first_seen_ts is read from the trail's created_at field."""
    assert stamp_vuln_times.first_seen_ts({"created_at": FIRST_SEEN_TS}) == FIRST_SEEN_TS


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
