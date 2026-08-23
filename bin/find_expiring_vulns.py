#!/usr/bin/env python3
"""Read vuln-*.json files and print them as JSON sorted by days_remaining ascending, including vulns already non-compliant (zero or negative days_remaining)."""

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


def dot_snyk_result(data, env, now_ts):
    """Return a result dict for a vuln whose .snyk ignore entry has an expiry date, else None.

    days_remaining is the days until the ignore expires: positive while the ignore
    is still active, zero or negative once it has already expired (non-compliant).
    """
    if not data.get("ignore_expires_exists"):
        return None
    if data.get("ignore_forever"):
        # No expiry date -- suppressed forever, so it never appears in an expiry report.
        return None
    secs_remaining = data["ignore_expires_ts"] - now_ts
    return {
        "env": env,
        "trail_name": data["trail_name"],
        "full_id": data["full_id"],
        "severity": data["severity"],
        "vuln_url": data["vuln_url"],
        "mechanism": "dot_snyk_expiry",
        "days_remaining": secs_remaining / 86400,
        "ignore_expires": data["ignore_expires"],
        "age_days": None,
        "limit_days": None,
        "artifact": extract_artifact_name(data["trail_name"]),
    }


# days_remaining for a vuln whose age cannot be measured. Every consumer treats
# days_remaining as a number -- print_expiring_vulns_summary.py sorts on it and
# rounds it, and check-expiry-and-notify.yml pipes it through jq's ceil -- so the
# unmeasurable case needs a numeric stand-in rather than null. This one sorts
# above every measurable vuln and is conspicuous enough to read as "not a real
# deadline" wherever it surfaces.
_CLOCK_SKEW_DAYS_REMAINING = -99999


def rego_result(data, env, now_ts, max_days):
    """Return a result dict for a vuln tracked by the rego age limit (no .snyk ignore), else None.

    days_remaining is limit - age_days: positive while still within the age limit,
    zero or negative once the age has reached or exceeded the limit (non-compliant).

    now_ts is stamped on the GitHub runner and first_seen_ts is the trail
    created_at from the Kosli server, so skew between the two clocks can put
    first_seen_ts ahead of now_ts and leave the age unmeasurable. Such a vuln
    reports mechanism clock_skew with no age_days, matching the rego, which holds
    it non-compliant rather than granting it the grace a zero age would.
    """
    if data.get("ignore_expires_exists"):
        return None
    severity = data["severity"]
    limit = max_days.get(severity, 0)
    age_secs = now_ts - data["first_seen_ts"]
    if age_secs < 0:
        mechanism = "clock_skew"
        age_days = None
        days_remaining = _CLOCK_SKEW_DAYS_REMAINING
    else:
        mechanism = "rego_limit"
        age_days = age_secs / 86400
        days_remaining = limit - age_days
    return {
        "env": env,
        "trail_name": data["trail_name"],
        "full_id": data["full_id"],
        "severity": data["severity"],
        "vuln_url": data["vuln_url"],
        "mechanism": mechanism,
        "days_remaining": days_remaining,
        "ignore_expires": None,
        "age_days": age_days,
        "limit_days": limit,
        "artifact": extract_artifact_name(data["trail_name"]),
    }


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
    """Parse args, read vuln JSON files from this run, print sorted JSON to stdout."""
    parser = argparse.ArgumentParser(
        description="Read vuln-*.json files and print them as JSON sorted by days_remaining ascending, including vulns already non-compliant (zero or negative days_remaining).",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--env", required=True,
                        help="Environment name, e.g. aws-beta")
    parser.add_argument("--vuln-dir", required=True,
                        help="Directory to read vuln-*.json files from")
    args = parser.parse_args()

    params_file = f"rego.params.{args.env}.json"
    with open(params_file) as f:
        params = json.load(f)
    max_days = params["max_days_by_severity"]

    vulns = []

    for path in sorted(glob.glob(os.path.join(args.vuln_dir, "vuln-*.json"))):
        with open(path) as f:
            data = json.load(f)
        # Age is measured against the now_ts stamped into the attested data, the
        # same instant the rego divides by, so this report and the per-vuln
        # attestation reach the same verdict from the same vuln file.
        now_ts = data["now_ts"]
        result = dot_snyk_result(data, args.env, now_ts)
        if result:
            vulns.append(result)
        result = rego_result(data, args.env, now_ts, max_days)
        if result:
            vulns.append(result)

    vulns.sort(key=sort_key)
    print(json.dumps({"vulns": vulns}))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
