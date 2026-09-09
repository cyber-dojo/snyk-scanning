#!/usr/bin/env python3
"""Add the two instants a vuln's age is measured between, and the limit it is measured against, to its attestation data."""

import argparse
import json
import sys
from datetime import datetime, timezone

SECONDS_PER_DAY = 60 * 60 * 24


def as_utc_string(ts):
    """Return a UTC timestamp rendered the way the attested vuln files carry it.

    A fractional timestamp keeps its microseconds, a whole-second one has no
    fractional part. Both instants come off the Kosli server, which reports
    microseconds.
    """
    return str(datetime.fromtimestamp(ts, tz=timezone.utc))


class TrailFieldMissing(Exception):
    """Raised when the trail lacks one of the two instants the age is measured between."""


def _trail_instant(trail, field):
    """Return one server instant from the trail, raising TrailFieldMissing if it is absent."""
    if field not in trail:
        raise TrailFieldMissing(
            f"trail has no {field}, so the vuln age cannot be measured")
    return trail[field]


def first_seen_ts(trail):
    """Return the trail's created_at, which is when this vuln was first seen.

    The trail is created once per vuln, by the first run that finds it, so its
    created_at is the age's origin for every later run.
    """
    return _trail_instant(trail, "created_at")


def now_ts(trail):
    """Return the trail's last_modified_at, the instant to measure the vuln's age at.

    `kosli begin trail` touches the trail immediately before it is read back, so
    last_modified_at is the Kosli server's instant for this run. Taking it from
    the same object as created_at puts both ends of the age on one clock, so no
    runner clock enters the measurement and last_modified_at >= created_at holds
    by construction.
    """
    return _trail_instant(trail, "last_modified_at")


class TrailTimesOutOfOrder(Exception):
    """Raised when the trail's last_modified_at is earlier than its created_at, so no age can be measured."""


def age_days(first_seen, now):
    """Return the vuln's age in days, raising TrailTimesOutOfOrder if first_seen is ahead of now.

    Both instants come from one read of one trail, so this ordering means the
    server reported a last_modified_at earlier than the created_at of the same
    object. That is a fault in the machinery rather than a fact about the vuln,
    so it stops the scan instead of being recorded as a verdict. The rego
    divides the same two instants and can differ in the last few digits, and
    decides the boundary itself.
    """
    seconds = now - first_seen
    if seconds < 0:
        raise TrailTimesOutOfOrder(
            f"first_seen {first_seen} is ahead of now {now} by {-seconds} seconds, "
            "so the trail reported a last_modified_at earlier than its own "
            "created_at and the vuln age cannot be measured")
    return seconds / SECONDS_PER_DAY


def limit_days(params, severity):
    """Return the max_days limit the given severity is judged against, 0 if the params omit it."""
    return params["max_days_by_severity"].get(severity, 0)


def stamp(vuln, first_seen, now, limit):
    """Return a copy of vuln carrying both instants, its age and the limit that age is judged against.

    Both instants travel with the vuln so that every later reader measures its
    age between the same two points: the rego inside kosli evaluate, and
    find_expiring_vulns.py locally. Nothing downstream consults a clock of its
    own. The age and its limit travel with it so that one per-vuln record shows
    its own arithmetic.

    Raises TrailTimesOutOfOrder when the age cannot be measured.
    """
    return {
        **vuln,
        "first_seen_ts": first_seen,
        "first_seen": as_utc_string(first_seen),
        "now_ts": now,
        "now": as_utc_string(now),
        "age_days": age_days(first_seen, now),
        "limit_days": limit,
    }


_EXAMPLE = """
example:

  kosli get trail "${KOSLI_TRAIL}" --output=json > trail.json
  bin/stamp_vuln_times.py trail.json "${VULN_JSON}" \\
    --params-file rego.params.aws-prod.json > "${VULN_FILENAME}"

`kosli begin trail` runs before the read, so the trail's last_modified_at is
this run's instant and its created_at is when the vuln was first seen. Both ends
of the age come off the Kosli server, so no runner clock enters the measurement.
"""


def main():
    """Parse the trail file, vuln JSON and params, print the vuln with both instants, its age and its limit added."""
    parser = argparse.ArgumentParser(
        description="Add the two instants a vuln's age is measured between, and the limit it is measured against, to its attestation data.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("trail_json",
                        help="File holding the vuln's Kosli trail as JSON, whose created_at is when the vuln was first seen and whose last_modified_at is the instant to measure at")
    parser.add_argument("vuln_json",
                        help="The vuln's attestation data as JSON, as the find-snyk-vulns job emits it")
    parser.add_argument("--params-file", required=True,
                        help="The rego.params.<env>.json the vuln's age is judged against")
    args = parser.parse_args()

    with open(args.trail_json) as f:
        trail = json.load(f)
    with open(args.params_file) as f:
        params = json.load(f)

    vuln = json.loads(args.vuln_json)
    try:
        stamped = stamp(vuln,
                        first_seen_ts(trail),
                        now_ts(trail),
                        limit_days(params, vuln["severity"]))
    except (TrailTimesOutOfOrder, TrailFieldMissing) as error:
        print(f'{vuln["full_id"]}: {error}', file=sys.stderr)
        sys.exit(44)

    print(json.dumps(stamped))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
