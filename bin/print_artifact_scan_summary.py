#!/usr/bin/env python3
"""Read one artifact's vulns and attestation and print its Snyk scan step summary header."""

import argparse
import json
import sys

# The tick and cross the step summary shows. Named by code point so this file
# stays plain ASCII while emitting the characters a reader sees.
COMPLIANT_STATUS = chr(0x2705)      # WHITE HEAVY CHECK MARK
NOT_COMPLIANT_STATUS = chr(0x274C)  # CROSS MARK

LOGO = "https://app.kosli.com/static/images/nav-kosli-logo-new-collapsed.svg"


def status_mark(compliant):
    """Return the tick or the cross, according to whether the artifact is compliant."""
    if compliant:
        return COMPLIANT_STATUS
    else:
        return NOT_COMPLIANT_STATUS


def attestation_url(attestation):
    """Return the html_url of the first attestation returned by kosli get attestation.

    kosli reports a list, and the artifact has one attestation in this slot, so
    the first entry is the one to link to.
    """
    return attestation[0]["html_url"]


def summary_lines(vulns, url, compliant, repo_name, artifact_name, fingerprint, snyk_version):
    """Return the header's lines: the verdict and count, what was scanned, and the attestation link.

    A clean artifact still gets a header, so the summary records that a scan ran
    rather than saying nothing at all.

    The table is HTML rather than Markdown because Markdown requires a header
    row, which renders as a visible blank row when the headers are empty.
    """
    return [
        f'## <img src="{LOGO}" height="20"> {repo_name} - Snyk container vulnerabilities by Kosli',
        "<table>",
        f"<tr><td><b>Status</b></td><td>{status_mark(compliant)} {len(vulns)} found</td></tr>",
        f"<tr><td><b>Artifact</b></td><td>{artifact_name}</td></tr>",
        f"<tr><td><b>Fingerprint</b></td><td>{fingerprint}</td></tr>",
        f"<tr><td><b>Snyk</b></td><td>{snyk_version}</td></tr>",
        f'<tr><td><b>Attestation</b></td><td><a href="{url}">{url}</a></td></tr>',
        "</table>",
    ]


_EXAMPLE = """
example:

  bin/print_artifact_scan_summary.py vulns.json attestation.json \\
    --compliant     "${COMPLIANT}" \\
    --repo-name     "${REPO_NAME}" \\
    --artifact-name "${ARTIFACT_NAME}" \\
    --fingerprint   "${KOSLI_FINGERPRINT}" \\
    --snyk-version  "${SNYK_VERSION}" \\
    >> "${GITHUB_STEP_SUMMARY}"
"""


def main():
    """Parse the vulns and attestation files plus the scan details, print the header to stdout."""
    parser = argparse.ArgumentParser(
        description="Read one artifact's vulns and attestation and print its Snyk scan step summary header.",
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("vulns_json",
                        help="File holding the artifact's vulns as a JSON array")
    parser.add_argument("attestation_json",
                        help="File holding the output of kosli get attestation as JSON")
    parser.add_argument("--compliant", required=True, choices=["true", "false"],
                        help="Whether the policy evaluation allowed the artifact")
    parser.add_argument("--repo-name", required=True,
                        help="Name of the repository that was scanned")
    parser.add_argument("--artifact-name", required=True,
                        help="Name of the scanned artifact")
    parser.add_argument("--fingerprint", required=True,
                        help="Fingerprint of the scanned artifact")
    parser.add_argument("--snyk-version", required=True,
                        help="Version of Snyk that produced the scan")
    args = parser.parse_args()

    with open(args.vulns_json) as f:
        vulns = json.load(f)
    with open(args.attestation_json) as f:
        attestation = json.load(f)

    print("\n".join(summary_lines(
        vulns,
        attestation_url(attestation),
        args.compliant == "true",
        args.repo_name,
        args.artifact_name,
        args.fingerprint,
        args.snyk_version,
    )))
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    main()
