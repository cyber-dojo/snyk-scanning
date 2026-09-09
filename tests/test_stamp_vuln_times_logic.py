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
# names the same keys as the ones the workflow adds.
FIRST_SEEN_TS = 1787193945.8263896
FIRST_SEEN = "2026-08-20 02:45:45.826390+00:00"
NOW_TS = 1787323545
NOW = "2026-08-21 14:45:45+00:00"

HIGH_LIMIT = 2
PARAMS = {"max_days_by_severity": {"critical": 0, "high": HIGH_LIMIT, "medium": 4, "low": 10}}


def _vuln():
    """Return an attestation_data dict as the find-snyk-vulns job emits it, before stamping."""
    return {
        "full_id": "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
        "severity": "high",
        "trail_name": "runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
        "artifact_fingerprint": "f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096",
        "ignore_expires_exists": False,
    }


def _stamped(first_seen=FIRST_SEEN_TS, now=NOW_TS, limit=HIGH_LIMIT):
    """Return a stamped copy of the fixture vuln."""
    return stamp_vuln_times.stamp(_vuln(), first_seen, now, limit)


def test_b4e1d701():
    """stamp adds the four time keys and leaves the vuln's own fields untouched."""
    stamped = _stamped()
    assert stamped["first_seen_ts"] == FIRST_SEEN_TS
    assert stamped["first_seen"] == FIRST_SEEN
    assert stamped["now_ts"] == NOW_TS
    assert stamped["now"] == NOW
    assert stamped["full_id"] == "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"
    assert stamped["severity"] == "high"
    assert stamped["ignore_expires_exists"] is False


def test_b4e1d702():
    """stamp renders a fractional trail created_at to microseconds, as the trail reports it."""
    assert _stamped()["first_seen"] == "2026-08-20 02:45:45.826390+00:00"


def test_b4e1d703():
    """stamp renders a whole-second timestamp with no fractional part."""
    assert _stamped(first_seen=1787193945)["first_seen"] == "2026-08-20 02:45:45+00:00"


def test_b4e1d704():
    """stamp does not mutate the vuln it is given, so the caller's data survives."""
    vuln = _vuln()
    stamp_vuln_times.stamp(vuln, FIRST_SEEN_TS, NOW_TS, HIGH_LIMIT)
    assert "first_seen_ts" not in vuln
    assert "now_ts" not in vuln
    assert "age_days" not in vuln
    assert "limit_days" not in vuln


def test_b4e1d705():
    """first_seen_ts is read from the trail's created_at field."""
    assert stamp_vuln_times.first_seen_ts({"created_at": FIRST_SEEN_TS}) == FIRST_SEEN_TS


def test_b4e1d706():
    """stamp records the age between the two instants it carries, and the limit it is judged against."""
    stamped = _stamped()
    assert stamped["age_days"] == (NOW_TS - FIRST_SEEN_TS) / 86400
    assert stamped["limit_days"] == HIGH_LIMIT


def test_b4e1d70f():
    """now_ts is read from the trail's last_modified_at, so both instants come from one clock.

    `kosli begin trail` touches the trail before it is read back, so
    last_modified_at is the server's instant for this run. The database
    invariant last_modified_at >= created_at is what makes a negative age
    impossible rather than merely unlikely.
    """
    trail = {"created_at": FIRST_SEEN_TS, "last_modified_at": NOW_TS}
    assert stamp_vuln_times.now_ts(trail) == NOW_TS


def test_b4e1d707():
    """stamp raises TrailTimesOutOfOrder when first_seen is ahead of now, rather than stamping an age."""
    with pytest.raises(stamp_vuln_times.TrailTimesOutOfOrder, match="cannot be measured"):
        _stamped(now=int(FIRST_SEEN_TS) - 76)


def test_b4e1d70a():
    """The message names both instants and the size of the discrepancy."""
    with pytest.raises(stamp_vuln_times.TrailTimesOutOfOrder) as raised:
        _stamped(now=int(FIRST_SEEN_TS) - 76)
    assert str(raised.value).startswith(
        f"first_seen {FIRST_SEEN_TS} is ahead of now {int(FIRST_SEEN_TS) - 76} by ")


def test_b4e1d70b():
    """An age of exactly zero is measurable, so the boundary is on skew and not on a zero age."""
    assert _stamped(now=FIRST_SEEN_TS)["age_days"] == 0


def test_b4e1d708():
    """limit_days comes from the params profile, by severity."""
    assert stamp_vuln_times.limit_days(PARAMS, "high") == HIGH_LIMIT
    assert stamp_vuln_times.limit_days(PARAMS, "critical") == 0
    assert stamp_vuln_times.limit_days(PARAMS, "low") == 10


def test_b4e1d709():
    """A severity absent from the params carries no allowance."""
    assert stamp_vuln_times.limit_days({"max_days_by_severity": {}}, "high") == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
