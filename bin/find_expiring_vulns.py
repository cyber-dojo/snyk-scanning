#!/usr/bin/env python3
"""Read *-vuln-reports.json files and print their vulns as JSON sorted by days_remaining ascending, including vulns already non-compliant (zero or negative days_remaining)."""

import argparse
import glob
import json
import math
import os
import re
import sys


def extract_artifact_name(trail_name):
    """Extract artifact name by taking the trail_name segment before the first -severity- part."""
    match = re.search(r'-(critical|high|medium|low)-', trail_name)
    if match:
        return trail_name[:match.start()]
    return trail_name


def vuln_result(vuln, report, env):
    """Return the expiry row for one vuln, its deadline taken from the rego's vuln_reports entry for it."""
    return {
        "env": env,
        "trail_name": vuln["trail_name"],
        "full_id": vuln["full_id"],
        "severity": vuln["severity"],
        "vuln_url": vuln["vuln_url"],
        "mechanism": report["mechanism"],
        "days_remaining": report["days_remaining"],
        "ignore_expires": report.get("ignore_expires"),
        "age_days": report.get("age_days"),
        "limit_days": report.get("limit_days"),
        "artifact": extract_artifact_name(vuln["trail_name"]),
    }


def artifact_results(reports, env):
    """Return the expiry rows for one artifact's vuln-reports file, in the file's vuln order.

    A vuln ignored forever has no deadline, so it gets no row.

    Raises ValueError for a vuln with no vuln_reports entry. The rego reports
    every vuln whose deadline it can measure, so a missing entry is an age it
    could not measure, and a row for it would put a number on nothing.
    """
    results = []
    for vuln in reports["vulns"]:
        report = reports["vuln_reports"].get(vuln["full_id"])
        if report is None:
            raise ValueError(f'{vuln["full_id"]}: no vuln_reports entry, so its deadline cannot be known')
        if report["mechanism"] != "dot_snyk_forever":
            results.append(vuln_result(vuln, report, env))
    return results


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def sort_key(vuln):
    """Return the ordering key for a vuln: whole-day deadline, then severity, then trail_name.

    days_remaining is quantised with ceil, the same rounding the Slack message
    displays, so vulns falling due on the same day compare equal and severity
    decides between them. Each vuln carries its own now_ts, stamped by its own
    matrix job, so two vulns sharing a deadline differ by seconds; without the
    quantising those seconds of job-start jitter would fix the order. trail_name
    last keeps the result independent of the order the files are read in.

    A severity outside the four Snyk reports raises KeyError. combine_snyk.py
    asserts the same four when it builds a vuln, so reaching here with anything
    else means that guard has gone, which is worth a crash rather than a silent
    ranking.
    """
    return (math.ceil(vuln["days_remaining"]),
            _SEVERITY_RANK[vuln["severity"]],
            vuln["trail_name"])


_EXAMPLE = """
example output (2 vulns, sorted by days_remaining ascending):

  {
    "vulns": [
      {
        "env": "aws-beta",
        "trail_name": "creator-low-SNYK-ALPINE322-NGHTTP2-16426989",
        "full_id": "SNYK-ALPINE322-NGHTTP2-16426989",
        "severity": "low",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-ALPINE322-NGHTTP2-16426989",
        "mechanism": "rego_limit",
        "days_remaining": 4.84,
        "ignore_expires": null,
        "age_days": 5.16,
        "limit_days": 10,
        "artifact": "creator"
      },
      {
        "env": "aws-beta",
        "trail_name": "runner-high-SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157",
        "full_id": "SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157",
        "severity": "high",
        "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157",
        "mechanism": "dot_snyk_expiry",
        "days_remaining": 19.80,
        "ignore_expires": "2026-06-01 10:53:10.182000+00:00",
        "age_days": null,
        "limit_days": null,
        "artifact": "runner"
      }
    ]
  }
"""


def main():
    """Parse args, read the vuln-reports files from this run, print sorted JSON to stdout, or exit 45 naming a vuln with no report."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--env", required=True,
                        help="Environment name, e.g. aws-beta")
    parser.add_argument("--vuln-dir", required=True,
                        help="Directory to read *-vuln-reports.json files from")
    args = parser.parse_args()

    vulns = []

    for path in sorted(glob.glob(os.path.join(args.vuln_dir, "*-vuln-reports.json"))):
        with open(path) as f:
            reports = json.load(f)
        try:
            vulns.extend(artifact_results(reports, args.env))
        except ValueError as error:
            print(error, file=sys.stderr)
            sys.exit(45)

    vulns.sort(key=sort_key)
    print(json.dumps({"vulns": vulns}))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
