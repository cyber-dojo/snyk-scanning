#!/usr/bin/env python3
"""Read a JSON array of vulns and print the Slack symbol saying whether the run is compliant."""

import argparse
import json
import sys

COMPLIANT = ":white_check_mark:"
NOT_COMPLIANT = ":x:"


def status_symbol(vulns):
    """Return the symbol for the run: not-compliant when the most urgent vuln has reached its boundary.

    find_expiring_vulns.py has already sorted the vulns by urgency, so only the
    first can be the one at its boundary.

    days_remaining is tested unrounded, and zero counts as reached: zero is the
    limit day itself, which the rego denies. Rounding here would let the symbol
    contradict the attestation for a whole day.
    """
    if not vulns:
        return COMPLIANT
    elif vulns[0]["days_remaining"] <= 0:
        return NOT_COMPLIANT
    else:
        return COMPLIANT


_EXAMPLE = """
example:

  bin/print_slack_status_symbol.py --vulns '[{"days_remaining":-1.0}]'

example output:

  :x:
"""


def main():
    """Parse --vulns JSON array and print the run's Slack status symbol to stdout."""
    parser = argparse.ArgumentParser(
        description="Read a JSON array of vulns and print the Slack symbol saying whether the run is compliant.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--vulns", required=True,
                        help="JSON array of vuln objects as output by find_expiring_vulns.py")
    args = parser.parse_args()

    print(status_symbol(json.loads(args.vulns)))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
