#!/usr/bin/env python3

import sys
import json

# Extracts the name and severity of all vulnerabilities 
# in a SARIF file created from `snyk container test`.

if __name__ == "__main__":
    sarif_filename = sys.argv[1]

    # Extract ids and severities of each vulnerability in sarif file
    with open(sarif_filename) as sarif_file:
        sarif_data = json.load(sarif_file)

    vulns = []
    for run in sarif_data['runs']:
        for rule in run['tool']['driver']['rules']:
            full_id = rule['id'] # SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804
            short_id = full_id.split('-')[-1] # 14059804
            vuln_url = f"https://security.snyk.io/vuln/{full_id}"
            short_text = rule['shortDescription']['text']
            # cvssv3_base_score = rule['properties']['cvssv3_baseScore'] # eg 6.8 can be None
            # security_severity = rule['properties']['security-severity'] # eg 6.8 can be None
            severity = short_text.split(' ')[0].lower()  # eg "medium"
            assert severity in ["critical", "high", "medium", "low"]

            vulns.append({
                'snyk_full_id': full_id,
                'snyk_short_id': short_id,
                'snyk_severity': severity,
                'snyk_vuln_url': vuln_url
            })

    print(json.dumps(vulns, default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
