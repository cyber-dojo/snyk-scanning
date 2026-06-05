#!/usr/bin/env python3
"""Read vuln-*.json files and print them as JSON sorted by days_remaining ascending, including vulns already non-compliant (zero or negative days_remaining)."""

import argparse
import glob
import json
import os
import re
import sys
import time


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


def rego_result(data, env, now_ts, max_days):
    """Return a result dict for a vuln tracked by the rego age limit (no .snyk ignore), else None.

    days_remaining is limit - age_days: positive while still within the age limit,
    zero or negative once the age has reached or exceeded the limit (non-compliant).
    """
    if data.get("ignore_expires_exists"):
        return None
    severity = data["severity"]
    limit = max_days.get(severity, 0)
    age_days = (now_ts - data["first_seen_ts"]) / 86400
    days_remaining = limit - age_days
    return {
        "env": env,
        "trail_name": data["trail_name"],
        "full_id": data["full_id"],
        "severity": data["severity"],
        "vuln_url": data["vuln_url"],
        "mechanism": "rego_limit",
        "days_remaining": days_remaining,
        "ignore_expires": None,
        "age_days": age_days,
        "limit_days": limit,
        "artifact": extract_artifact_name(data["trail_name"]),
    }


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

    now_ts = time.time()
    vulns = []

    for path in sorted(glob.glob(os.path.join(args.vuln_dir, "vuln-*.json"))):
        with open(path) as f:
            data = json.load(f)
        result = dot_snyk_result(data, args.env, now_ts)
        if result:
            vulns.append(result)
        result = rego_result(data, args.env, now_ts, max_days)
        if result:
            vulns.append(result)

    vulns.sort(key=lambda v: v["days_remaining"])
    print(json.dumps({"vulns": vulns}))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
