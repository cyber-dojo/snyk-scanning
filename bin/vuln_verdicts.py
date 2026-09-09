#!/usr/bin/env python3
"""Turn one rego evaluation of an artifact's vulns into a verdict record naming why each vuln failed."""

import argparse
import json
import sys

# A vuln id can hold colons (a licence finding is
# "snyk:lic:pip:astroid:LGPL-2.1") but never a colon followed by a space.
_ID_REASON_SEPARATOR = ": "


def reasons_by_id(evaluation):
    """Return a dict of vuln full_id to the reasons the evaluation gave for failing it.

    A compliant evaluation carries violations as null.
    """
    reasons = {}
    for message in evaluation.get("violations") or []:
        full_id, _, reason = message.partition(_ID_REASON_SEPARATOR)
        reasons.setdefault(full_id, []).append(reason)
    return reasons


def failing_ids(evaluation):
    """Return the set of vuln ids named by the evaluation's violations."""
    return set(reasons_by_id(evaluation))


def verdict(vuln, reasons):
    """Return one vuln's verdict: its identity, the arithmetic behind it, and why it failed.

    age_days and limit_days are read rather than recomputed, so this cannot
    disagree with the per-vuln attestation.
    """
    return {
        "full_id": vuln["full_id"],
        "severity": vuln["severity"],
        "status": "fail" if reasons else "pass",
        "reasons": reasons,
        "age_days": vuln.get("age_days"),
        "limit_days": vuln.get("limit_days"),
        "first_seen": vuln.get("first_seen"),
        "now": vuln.get("now"),
        "ignore_expires": vuln.get("ignore_expires"),
        "attestation_url": vuln.get("attestation_url"),
    }


def verdicts(vulns, evaluation, params_profile, params):
    """Return the whole artifact's verdict record, or raise ValueError if it cannot be built."""
    reasons = reasons_by_id(evaluation)
    if not evaluation["allow"] and not reasons:
        raise ValueError("evaluation denied but named no vuln")
    unknown = set(reasons) - {vuln["full_id"] for vuln in vulns}
    if unknown:
        raise ValueError(f"violations name {sorted(unknown)}, not in the vuln list")

    judged = [verdict(vuln, reasons.get(vuln["full_id"], [])) for vuln in vulns]
    failing = [one for one in judged if one["status"] == "fail"]
    return {
        "compliant": evaluation["allow"],
        "params_profile": params_profile,
        "max_days_by_severity": params["max_days_by_severity"],
        "vuln_count": len(judged),
        "failing_count": len(failing),
        "summary": summary(judged, failing),
        "vulns": judged,
    }


def summary(judged, failing):
    """Return the one-line summary of the artifact's verdict."""
    if not failing:
        return f"{len(judged)} vulns, all compliant"
    named = ", ".join(f'{one["full_id"]} ({one["severity"]})' for one in failing)
    return (f"{len(failing)} of {len(judged)} vulns failing: {named}"
            f' -- {failing[0]["reasons"][0]}')


_EXAMPLE = """
example:

  bin/vuln_verdicts.py vulns.json evaluation.json \\
    --params-profile aws-prod \\
    --params-file rego.params.aws-prod.json > verdicts.json

The output goes on the decision attestation as --user-data.
"""


def main(argv):
    """Print the artifact's verdict record as JSON, or say on stderr why it cannot be built."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("vulns_file",
                        help="JSON array of the artifact's vulns, each with a full_id, severity and attestation_url")
    parser.add_argument("evaluation_file",
                        help="JSON verdict from one `kosli evaluate input` of those vulns")
    parser.add_argument("--params-profile", required=True,
                        help="Name of the params profile the vulns were judged against, e.g. aws-prod")
    parser.add_argument("--params-file", required=True,
                        help="The rego.params.<profile>.json named by --params-profile")
    args = parser.parse_args(argv)

    with open(args.vulns_file) as vulns_file:
        vulns = json.load(vulns_file)
    with open(args.evaluation_file) as evaluation_file:
        evaluation = json.load(evaluation_file)
    with open(args.params_file) as params_file:
        params = json.load(params_file)

    try:
        record = verdicts(vulns, evaluation, args.params_profile, params)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
