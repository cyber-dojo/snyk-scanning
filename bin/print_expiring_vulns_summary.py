#!/usr/bin/env python3
"""Read a JSON array of vulns and print a Markdown step summary with one table per Snyk severity level, sorted by days_remaining ascending."""

import argparse
import json
import sys


SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def mechanism_label(mechanism):
    """Return a short display label for the mechanism."""
    return "rego" if mechanism == "rego_limit" else ".snyk"


def format_severity_table(severity, vulns):
    """Return a list of Markdown lines for one severity's table, sorted by days_remaining."""
    sev_vulns = sorted(
        [v for v in vulns if v["severity"] == severity],
        key=lambda v: v["days_remaining"],
    )
    lines = [f"### {severity.capitalize()} (Count={len(sev_vulns)})", ""]
    if not sev_vulns:
        lines.append("No vulnerabilities.")
    else:
        lines.append("| Artifact | Days remaining | Mechanism | Vuln ID |")
        lines.append("|----------|----------------|-----------|---------|")
        for v in sev_vulns:
            days = int(round(v["days_remaining"]))
            mech = mechanism_label(v["mechanism"])
            link = f"[{v['full_id']}]({v['vuln_url']})"
            lines.append(f"| {v['artifact']} | {days} | {mech} | {link} |")
    lines.append("")
    return lines


def format_env_section(env_label, vulns):
    """Return a list of Markdown lines for one environment's section."""
    lines = [f"## {env_label} (Snyk vulns tracked: Count={len(vulns)})", ""]
    for severity in SEVERITY_ORDER:
        lines.extend(format_severity_table(severity, vulns))
    return lines


_EXAMPLE = """
example output:

  ## aws-beta (Snyk vulns tracked: Count=2)

  ### Critical (Count=0)

  No vulnerabilities.

  ### High (Count=1)

  | Artifact | Days remaining | Mechanism | Vuln ID |
  |----------|----------------|-----------|---------|
  | runner | 20 | .snyk | [SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157](https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXNETHTTP2-16535157) |

  ### Medium (Count=0)

  No vulnerabilities.

  ### Low (Count=1)

  | Artifact | Days remaining | Mechanism | Vuln ID |
  |----------|----------------|-----------|---------|
  | creator | 5 | rego | [SNYK-ALPINE322-NGHTTP2-16426989](https://security.snyk.io/vuln/SNYK-ALPINE322-NGHTTP2-16426989) |
"""


def main():
    """Parse --env and --vulns JSON array and print a Markdown step summary to stdout."""
    parser = argparse.ArgumentParser(
        description="Read a JSON array of vulns and print a Markdown step summary with one table per Snyk severity level, sorted by days_remaining ascending.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--env",   required=True, help="Environment name, e.g. aws-beta")
    parser.add_argument("--vulns", required=True, help="JSON array of vuln objects as output by find_expiring_vulns.py")
    args = parser.parse_args()

    vulns = json.loads(args.vulns)
    lines = format_env_section(args.env, vulns)
    print("\n".join(lines).rstrip("\n"))


if __name__ == "__main__":  # pragma: no cover
    main()
