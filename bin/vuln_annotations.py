#!/usr/bin/env python3
"""Turn one rego evaluation of an artifact's vulns into a pass or fail annotation per vuln."""

import argparse
import json
import re
import sys

# The Kosli CLI restricts annotation keys to [A-Za-z0-9_], so every other
# character of a vuln id becomes an underscore. The UI's humanize filter renders
# each underscore as a space. The key is the only place a readable vuln
# identifier can go, because the UI renders an annotation value that is a URL as
# a link whose visible text is the URL itself.
DISALLOWED_IN_KEY = re.compile(r'[^A-Za-z0-9_]')


def failing_ids(evaluation):
    """Return the set of vuln ids named by the evaluation's violations.

    Every violation message begins with its vuln's full_id followed by a colon,
    and a compliant evaluation carries violations as null.
    """
    return {message.split(":")[0] for message in evaluation.get("violations") or []}


def annotation_key(status, vuln):
    """Return the annotation key carrying one vuln's status, severity and id."""
    label = DISALLOWED_IN_KEY.sub("_", f'{vuln["severity"]}-{vuln["full_id"]}')
    return f"{status}_{label}"


def annotations(vulns, evaluation):
    """Return one key=url annotation per vuln, labelling each one pass or fail.

    Raises ValueError when the failing ids cannot be reconciled against the vuln
    list, which is what keeps a vuln from being labelled pass on the strength of
    a diagnostic that went missing.
    """
    failing = failing_ids(evaluation)
    if not evaluation["allow"] and not failing:
        raise ValueError("evaluation denied but named no vuln")
    unknown = failing - {vuln["full_id"] for vuln in vulns}
    if unknown:
        raise ValueError(f"violations name {sorted(unknown)}, not in the vuln list")
    return [f'{annotation_key("fail" if vuln["full_id"] in failing else "pass", vuln)}'
            f'={vuln["attestation_url"]}'
            for vuln in vulns]


def main(argv):
    """Print one annotation per vuln, or say on stderr why the vulns cannot be labelled."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="""Example, for an artifact carrying five vulns (URLs shortened here):

  bin/vuln_annotations.py vulns.json evaluation.json

  fail_critical_SNYK_ALPINE321_OPENSSL_13939001=https://app.kosli.com/...
  fail_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666=https://app.kosli.com/...
  fail_high_SNYK_ALPINE321_LIBXML2_14098711=https://app.kosli.com/...
  pass_medium_SNYK_GOLANG_GOOPENTELEMETRYIOOTELPROPAGATION_17054905=https://app.kosli.com/...
  pass_low_SNYK_ALPINE321_BUSYBOX_13939021=https://app.kosli.com/...""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("vulns_file",
                        help="JSON array of the artifact's vulns, each with a full_id, severity and attestation_url")
    parser.add_argument("evaluation_file",
                        help="JSON verdict from one `kosli evaluate input` of those vulns")
    args = parser.parse_args(argv)

    with open(args.vulns_file) as vulns_file:
        vulns = json.load(vulns_file)
    with open(args.evaluation_file) as evaluation_file:
        evaluation = json.load(evaluation_file)

    # Every annotation is built before any is printed, so a partial labelling
    # never reaches the caller.
    try:
        lines = annotations(vulns, evaluation)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
