#!/usr/bin/env python3
"""Read stale .snyk entry ids and print a Markdown step summary table naming them."""

import argparse
import json
import sys


def summary_lines(stale_ids, artifact_name, fingerprint, snyk_version):
    """Return the table's lines, or no lines at all when nothing is stale.

    An empty result adds nothing to the job summary, so a scan with every .snyk
    entry still matching a reported vuln says nothing rather than showing an
    empty table.

    The table is HTML rather than Markdown because Markdown requires a header
    row, which renders as a visible blank row when the headers are empty.
    """
    if not stale_ids:
        return []
    return [
        "<table>",
        f"<tr><td><b>Stale .snyk entries</b></td><td>{len(stale_ids)} found</td></tr>",
        f"<tr><td><b>Artifact name</b></td><td>{artifact_name}</td></tr>",
        f"<tr><td><b>Artifact fingerprint</b></td><td>{fingerprint}</td></tr>",
        f"<tr><td><b>Snyk version</b></td><td>{snyk_version}</td></tr>",
        *[f"<tr><td></td><td>{stale_id}</td></tr>" for stale_id in stale_ids],
        "</table>",
    ]


_EXAMPLE = """
example:

  bin/print_stale_snyk_entries_summary.py stale_vulns.json \\
    --artifact-name "${ARTIFACT_NAME}" \\
    --fingerprint   "${FINGERPRINT}" \\
    --snyk-version  "${SNYK_VERSION}" \\
    >> "${GITHUB_STEP_SUMMARY}"

example output:

  <table>
  <tr><td><b>Stale .snyk entries</b></td><td>1 found</td></tr>
  <tr><td><b>Artifact name</b></td><td>runner:85cac88</td></tr>
  <tr><td><b>Artifact fingerprint</b></td><td>f3cdc22a59</td></tr>
  <tr><td><b>Snyk version</b></td><td>v1.1300.2</td></tr>
  <tr><td></td><td>SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804</td></tr>
  </table>
"""


def main():
    """Parse the stale ids file and scan details, print the summary table to stdout."""
    parser = argparse.ArgumentParser(
        description="Read stale .snyk entry ids and print a Markdown step summary table naming them.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("stale_ids_json",
                        help="File holding the stale .snyk entry ids as a JSON array, as combine_snyk.py writes it")
    parser.add_argument("--artifact-name", required=True,
                        help="Name of the scanned artifact")
    parser.add_argument("--fingerprint", required=True,
                        help="Fingerprint of the scanned artifact")
    parser.add_argument("--snyk-version", required=True,
                        help="Version of Snyk that produced the scan")
    args = parser.parse_args()

    with open(args.stale_ids_json) as f:
        stale_ids = json.load(f)

    lines = summary_lines(stale_ids, args.artifact_name, args.fingerprint, args.snyk_version)
    if lines:
        print("\n".join(lines))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
