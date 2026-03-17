#!/usr/bin/env python3

import sys
import json

# Finds Snyk vulnerabilities present in current JSON file
# that are NOT present in previous JSON file, for Artifacts
# with identical fingerprint/digests.
# Artifacts in the current JSON file whose fingerprint was
# NOT present in the previous JSON file do NOT count as new vulns.
# The assumption is that each workflow that deploys an Artifact
# to a given Environment has its own controls. In other words,
# finds Snyk vulnerabilities that are new, for a given Artifact,
# AFTER they have been deployed to a given Environment.

if __name__ == "__main__":
    previous_filename = sys.argv[1]
    current_filename = sys.argv[2]

    with open(previous_filename) as previous_file:
        previous_data = json.load(previous_file)

    with open(current_filename) as current_file:
        current_data = json.load(current_file)

    vulns = []

    for fingerprint, current_vulns in current_data.items():
        if fingerprint in previous_data:
            # The artifact is the previous-trail and the current-trail
            for current_vuln_id, current_vuln in current_vulns.items():
                if current_vuln_id == 'none':
                    vulns.append(current_vuln)
                elif current_vuln_id not in previous_data[fingerprint]:
                    vulns.append(current_vuln)

    print(json.dumps(vulns, default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
