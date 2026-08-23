#!/usr/bin/env python3
"""Read a JSON array of vulns and print the Slack message body for the most urgent one."""

import argparse
import json
import math
import sys


def days_line(vuln):
    """Return the deadline line for a vuln, counting days of grace left or days already overdue.

    days_remaining is rounded up, so a vuln with 2.3 days of grace reads as 3:
    a reader acting on the message has until the end of that day.

    A clock_skew vuln has no measurable age, so its days_remaining is a sentinel
    that sorts it above every real deadline rather than a count of days. Printing
    it would claim tens of thousands of days of non-compliance, so the line says
    the count is unknown and names the cause instead.
    """
    if vuln["mechanism"] == "clock_skew":
        return "Days non-compliant: unknown (clock skew)"
    days = math.ceil(vuln["days_remaining"])
    if days > 0:
        return f"Days till non-compliant: {days}"
    return f"Days non-compliant: {0 - days}"


def slack_message(vulns):
    """Return the Slack message body describing the first vuln, or the all-clear when there are none.

    find_expiring_vulns.py has already sorted the vulns by urgency, so the most
    urgent one is the first.
    """
    if not vulns:
        return "No Snyk vulnerabilities :-)"
    vuln = vulns[0]
    return "\n".join([
        days_line(vuln),
        f"Vuln: {vuln['full_id']}",
        f"Severity: {vuln['severity']}",
        f"Repo: {vuln['artifact']}",
        f"Mechanism: {vuln['mechanism']}",
    ])


_EXAMPLE = """
example:

  bin/print_slack_vuln_message.py --vulns '[{"full_id":"SNYK-GOLANG-NETHTTP-3321444",
    "severity":"high","artifact":"creator","mechanism":"rego_limit","days_remaining":2.3}]'

example output:

  Days till non-compliant: 3
  Vuln: SNYK-GOLANG-NETHTTP-3321444
  Severity: high
  Repo: creator
  Mechanism: rego_limit
"""


def main():
    """Parse --vulns JSON array and print the Slack message body to stdout."""
    parser = argparse.ArgumentParser(
        description="Read a JSON array of vulns and print the Slack message body for the most urgent one.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--vulns", required=True,
                        help="JSON array of vuln objects as output by find_expiring_vulns.py")
    args = parser.parse_args()

    print(slack_message(json.loads(args.vulns)))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
