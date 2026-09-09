#!/usr/bin/env python3
"""Unit tests for vuln_verdicts, which says why each vuln of an artifact failed."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import vuln_verdicts  # noqa: E402

PROFILE = "aws-beta"
PARAMS = {"max_days_by_severity": {"critical": 1, "high": 2, "medium": 4, "low": 10}}

FAILING_ID = "SNYK-ALPINE324-UTILLINUX-19533434"
PASSING_ID = "SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157"

FAILING_REASON = "high severity vuln age 2.000007091046297 days exceeds 2 day limit"
FAILING_MESSAGE = f"{FAILING_ID}: {FAILING_REASON}"


def _vuln(full_id, severity="high", age_days=2.000007091046297, limit_days=2):
    """Return a stamped vuln as the per-vuln matrix job attests it."""
    return {
        "full_id": full_id,
        "severity": severity,
        "age_days": age_days,
        "limit_days": limit_days,
        "first_seen": "2026-09-06 01:54:39.387334+00:00",
        "now": "2026-09-08 01:54:40+00:00",
        "ignore_expires": "",
        "attestation_url": f"https://app.kosli.com/attestation/{full_id}",
    }


def _record(vulns, evaluation):
    """Build the artifact's verdict record from the given vulns and evaluation."""
    return vuln_verdicts.verdicts(vulns, evaluation, PROFILE, PARAMS)


def test_c7f4a201():
    """A violation message splits into the vuln it names and the reason it gives."""
    assert vuln_verdicts.reasons_by_id({"violations": [FAILING_MESSAGE]}) == {
        FAILING_ID: [FAILING_REASON]
    }


def test_c7f4a202():
    """A compliant evaluation carries violations as null, which names no vuln."""
    assert vuln_verdicts.reasons_by_id({"allow": True, "violations": None}) == {}
    assert vuln_verdicts.failing_ids({"allow": True, "violations": None}) == set()


def test_c7f4a203():
    """Two messages about one vuln are both kept, rather than one overwriting the other."""
    reasons = vuln_verdicts.reasons_by_id({"violations": [
        f"{FAILING_ID}: snyk ignore entry expired at 2026-09-01 00:00:00+00:00",
        FAILING_MESSAGE,
    ]})
    assert reasons == {FAILING_ID: [
        "snyk ignore entry expired at 2026-09-01 00:00:00+00:00",
        FAILING_REASON,
    ]}


def test_c7f4a204():
    """A reason carrying colons of its own survives, so the split is on the first only."""
    message = f"{FAILING_ID}: snyk ignore entry expired at 2026-09-01 10:53:10+00:00"
    assert vuln_verdicts.reasons_by_id({"violations": [message]}) == {
        FAILING_ID: ["snyk ignore entry expired at 2026-09-01 10:53:10+00:00"]
    }


def test_c7f4a215():
    """A licence vuln id, which carries colons of its own, is recovered whole."""
    licence_id = "snyk:lic:pip:astroid:LGPL-2.1"
    reason = "low severity vuln age 20 days exceeds 10 day limit"
    assert vuln_verdicts.reasons_by_id({"violations": [f"{licence_id}: {reason}"]}) == {
        licence_id: [reason]
    }


def test_c7f4a216():
    """A licence vuln is labelled from its own reason rather than refused as unknown."""
    licence_id = "snyk:lic:pip:astroid:LGPL-2.1"
    vuln = _vuln(licence_id, severity="low", age_days=20.0, limit_days=10)
    record = _record([vuln], {
        "allow": False,
        "violations": [f"{licence_id}: low severity vuln age 20 days exceeds 10 day limit"],
    })
    assert record["vulns"][0]["status"] == "fail"
    assert record["failing_count"] == 1


def test_c7f4a205():
    """Each vuln is labelled fail or pass, and a failing one carries its reason."""
    record = _record([_vuln(FAILING_ID), _vuln(PASSING_ID)],
                     {"allow": False, "violations": [FAILING_MESSAGE]})
    by_id = {one["full_id"]: one for one in record["vulns"]}
    assert by_id[FAILING_ID]["status"] == "fail"
    assert by_id[FAILING_ID]["reasons"] == [FAILING_REASON]
    assert by_id[PASSING_ID]["status"] == "pass"
    assert by_id[PASSING_ID]["reasons"] == []


def test_c7f4a206():
    """The record names the profile and the limits the vulns were judged against."""
    record = _record([_vuln(FAILING_ID)], {"allow": False, "violations": [FAILING_MESSAGE]})
    assert record["params_profile"] == PROFILE
    assert record["max_days_by_severity"] == PARAMS["max_days_by_severity"]


def test_c7f4a207():
    """The verdict carries the age and limit from the vuln, not a recomputation of them."""
    vuln = _vuln(FAILING_ID, age_days=1.25, limit_days=5)
    record = _record([vuln], {"allow": True, "violations": None})
    assert record["vulns"][0]["age_days"] == 1.25
    assert record["vulns"][0]["limit_days"] == 5


def test_c7f4a208():
    """The counts and the compliant flag come from the evaluation and the labelling."""
    record = _record([_vuln(FAILING_ID), _vuln(PASSING_ID)],
                     {"allow": False, "violations": [FAILING_MESSAGE]})
    assert record["compliant"] is False
    assert record["vuln_count"] == 2
    assert record["failing_count"] == 1


def test_c7f4a209():
    """The summary names the failing vuln and gives its reason, for the one line that shows."""
    record = _record([_vuln(FAILING_ID), _vuln(PASSING_ID)],
                     {"allow": False, "violations": [FAILING_MESSAGE]})
    assert record["summary"] == (
        f"1 of 2 vulns failing: {FAILING_ID} (high) -- {FAILING_REASON}")


def test_c7f4a210():
    """A compliant artifact still gets a summary, so the decision records that a scan ran."""
    record = _record([_vuln(PASSING_ID)], {"allow": True, "violations": None})
    assert record["summary"] == "1 vulns, all compliant"
    assert record["failing_count"] == 0


def test_c7f4a211():
    """An artifact with no vulns at all is compliant and says so."""
    record = _record([], {"allow": True, "violations": None})
    assert record["summary"] == "0 vulns, all compliant"
    assert record["vuln_count"] == 0


def test_c7f4a212():
    """A denied evaluation naming no vuln is refused rather than recorded without a reason."""
    with pytest.raises(ValueError, match="denied but named no vuln"):
        _record([_vuln(FAILING_ID)], {"allow": False, "violations": None})


def test_c7f4a213():
    """A violation naming a vuln that is not in the list is refused."""
    with pytest.raises(ValueError, match="not in the vuln list"):
        _record([_vuln(PASSING_ID)], {"allow": False, "violations": [FAILING_MESSAGE]})


def test_c7f4a214():
    """A vuln decided by its ignore entry has no age or limit, and is reported without them."""
    vuln = {
        "full_id": FAILING_ID,
        "severity": "high",
        "ignore_expires": "2026-09-01 00:00:00+00:00",
        "attestation_url": "https://app.kosli.com/attestation/x",
    }
    record = _record([vuln], {
        "allow": False,
        "violations": [f"{FAILING_ID}: snyk ignore entry expired at 2026-09-01 00:00:00+00:00"],
    })
    assert record["vulns"][0]["age_days"] is None
    assert record["vulns"][0]["limit_days"] is None
    assert record["vulns"][0]["ignore_expires"] == "2026-09-01 00:00:00+00:00"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
