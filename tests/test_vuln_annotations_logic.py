#!/usr/bin/env python3
"""Unit tests for turning one rego evaluation into a pass/fail annotation per vuln."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bin'))
import vuln_annotations  # noqa: E402

FLOW_URL = "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails"

GOLANG_ID = "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"
OPENSSL_ID = "SNYK-ALPINE321-OPENSSL-13939001"


def _vuln(full_id, severity):
    """Return one vuln dict shaped as the workflow writes it into vulns.json."""
    return {
        "full_id": full_id,
        "severity": severity,
        "artifact_name": "244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:c0fa195",
        "trail_name": f"runner-{severity}-{full_id}",
        "attestation_url": f"{FLOW_URL}/runner-{severity}-{full_id}/attestations/snyk-fd8c68c615",
    }


def _age_violation(full_id, severity, age_days, limit_days):
    """Return a violation message in the form the rego emits for an over-age vuln."""
    return (f"{full_id}: {severity} severity vuln age {age_days} days "
            f"exceeds {limit_days} day limit")


def test_9c4e1a01():
    """failing_ids takes the id from the first colon-delimited field of each violation."""
    evaluation = {"allow": False,
                  "violations": [_age_violation(GOLANG_ID, "high", 9, 2),
                                 f"{OPENSSL_ID}: snyk ignore entry expired at 2026-08-20 00:00:00+00:00"]}
    assert vuln_annotations.failing_ids(evaluation) == {GOLANG_ID, OPENSSL_ID}


def test_9c4e1a02():
    """failing_ids is empty when a compliant evaluation carries a null violations field."""
    assert vuln_annotations.failing_ids({"allow": True, "violations": None}) == set()


def test_9c4e1a03():
    """Every vuln is labelled pass when the evaluation allows."""
    vulns = [_vuln(GOLANG_ID, "high"), _vuln(OPENSSL_ID, "medium")]
    evaluation = {"allow": True, "violations": None}
    assert vuln_annotations.annotations(vulns, evaluation) == [
        f"pass_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666="
        f"{FLOW_URL}/runner-high-{GOLANG_ID}/attestations/snyk-fd8c68c615",
        f"pass_medium_SNYK_ALPINE321_OPENSSL_13939001="
        f"{FLOW_URL}/runner-medium-{OPENSSL_ID}/attestations/snyk-fd8c68c615",
    ]


def test_9c4e1a04():
    """Only the vuln named in violations is labelled fail; the other stays pass."""
    vulns = [_vuln(GOLANG_ID, "high"), _vuln(OPENSSL_ID, "medium")]
    evaluation = {"allow": False,
                  "violations": [_age_violation(OPENSSL_ID, "medium", 9, 4)]}
    keys = [line.split("=")[0] for line in vuln_annotations.annotations(vulns, evaluation)]
    assert keys == ["pass_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666",
                    "fail_medium_SNYK_ALPINE321_OPENSSL_13939001"]


def test_9c4e1a05():
    """Every vuln is labelled fail when violations name them all."""
    vulns = [_vuln(GOLANG_ID, "high"), _vuln(OPENSSL_ID, "medium")]
    evaluation = {"allow": False,
                  "violations": [_age_violation(GOLANG_ID, "high", 9, 2),
                                 _age_violation(OPENSSL_ID, "medium", 9, 4)]}
    keys = [line.split("=")[0] for line in vuln_annotations.annotations(vulns, evaluation)]
    assert keys == ["fail_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666",
                    "fail_medium_SNYK_ALPINE321_OPENSSL_13939001"]


def test_9c4e1a06():
    """The key holds only the characters the CLI accepts, so every other one becomes an underscore."""
    vuln = _vuln("SNYK-JS-BABELTRAVERSE-5962462", "critical")
    evaluation = {"allow": True, "violations": None}
    key = vuln_annotations.annotations([vuln], evaluation)[0].split("=")[0]
    assert key == "pass_critical_SNYK_JS_BABELTRAVERSE_5962462"


def test_9c4e1a07():
    """An artifact with no vulns produces no annotations."""
    assert vuln_annotations.annotations([], {"allow": True, "violations": None}) == []


def test_9c4e1a08():
    """A denial that names no vuln is an error, so no vuln is ever mislabelled pass."""
    vulns = [_vuln(GOLANG_ID, "high")]
    evaluation = {"allow": False, "violations": None}
    with pytest.raises(ValueError, match="denied but named no vuln"):
        vuln_annotations.annotations(vulns, evaluation)


def test_9c4e1a09():
    """A violation naming a vuln that is not in vulns.json is an error."""
    vulns = [_vuln(GOLANG_ID, "high")]
    evaluation = {"allow": False,
                  "violations": [_age_violation(OPENSSL_ID, "medium", 9, 4)]}
    with pytest.raises(ValueError, match="not in the vuln list"):
        vuln_annotations.annotations(vulns, evaluation)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
