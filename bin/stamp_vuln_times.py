#!/usr/bin/env python3
"""Add the two instants a vuln's age is measured between to its attestation data."""

import argparse
import json
import sys
import time
from datetime import datetime, timezone


def as_utc_string(ts):
    """Return a UTC timestamp rendered the way the attested vuln files carry it.

    A fractional timestamp keeps its microseconds, a whole-second one has no
    fractional part, which is what the trail created_at and the wall clock
    respectively produce.
    """
    return str(datetime.fromtimestamp(ts, tz=timezone.utc))


def first_seen_ts(trail):
    """Return the trail's created_at, which is when this vuln was first seen.

    The trail is created once per vuln, by the first run that finds it, so its
    created_at is the age's origin for every later run.
    """
    return trail["created_at"]


def stamp(vuln, first_seen, now):
    """Return a copy of vuln carrying first_seen_ts, first_seen, now_ts and now.

    Both instants travel with the vuln so that every later reader measures its
    age between the same two points: the rego inside kosli evaluate, and
    find_expiring_vulns.py locally. Nothing downstream consults a clock of its
    own.
    """
    return {
        **vuln,
        "first_seen_ts": first_seen,
        "first_seen": as_utc_string(first_seen),
        "now_ts": now,
        "now": as_utc_string(now),
    }


_EXAMPLE = """
example:

  kosli get trail "${KOSLI_TRAIL}" --output=json > trail.json
  bin/stamp_vuln_times.py trail.json "${VULN_JSON}" > "${VULN_FILENAME}"

The trail is created before this runs, so its created_at is never later than the
instant stamped here, and a vuln's age is never measured against an origin that
comes after it.
"""


def main():
    """Parse the trail file and vuln JSON, print the vuln with both instants added."""
    parser = argparse.ArgumentParser(
        description="Add the two instants a vuln's age is measured between to its attestation data.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("trail_json",
                        help="File holding the vuln's Kosli trail as JSON, whose created_at is when the vuln was first seen")
    parser.add_argument("vuln_json",
                        help="The vuln's attestation data as JSON, as the find-snyk-vulns job emits it")
    parser.add_argument("--now-ts", type=int, default=None,
                        help="The instant to measure the age at, as epoch seconds (default: now)")
    args = parser.parse_args()

    with open(args.trail_json) as f:
        trail = json.load(f)
    now = args.now_ts if args.now_ts is not None else int(time.time())

    print(json.dumps(stamp(json.loads(args.vuln_json), first_seen_ts(trail), now)))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
