#!/usr/bin/env python3

import sys
import json
import yaml


if __name__ == "__main__":  # pragma: no cover
    snyk_version = sys.argv[1]
    repo_name = sys.argv[2]
    sarif_filename = sys.argv[3]
    snyk_policy_filename = sys.argv[4]

    # Extract ids and severities of each vulnerability in sarif file
    with open(sarif_filename) as sarif_file:
        sarif_data = json.load(sarif_file)

    vulns = {}
    for run in sarif_data['runs']:
        for rule in run['tool']['driver']['rules']:
            full_id = rule['id'] # SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804
            vuln_url = f"https://security.snyk.io/vuln/{full_id}"
            short_text = rule['shortDescription']['text']
            # cvssv3_base_score = rule['properties']['cvssv3_baseScore'] # eg 6.8 can be None
            # security_severity = rule['properties']['security-severity'] # eg 6.8 can be None
            severity = short_text.split(' ')[0].lower()  # eg "medium"
            assert severity in ["critical", "high", "medium", "low"]
            
            trail_name = f"{repo_name}-{severity}-{full_id}"

            vulns[full_id] = {
                'version': snyk_version,
                'full_id': full_id,
                'severity': severity,
                'vuln_url': vuln_url,
                'ignore_expires': '',
                'ignore_expires_ts': 0,
                "ignore_expires_exists": False,
                'trail_name': trail_name,
            }

    # Overwrite specific vulnerability expiry dates if found in snyk policy file (yaml)
    with open(snyk_policy_filename) as snyk_file:
        snyk_data = yaml.safe_load(snyk_file)

    if snyk_data:
        ignore = snyk_data.get('ignore', {})
        for id in ignore:
            if id in vulns:
                vuln = vulns[id]
                expires = ignore[id][0]['*']['expires']
                vuln['ignore_expires'] = expires
                vuln['ignore_expires_ts'] = expires.timestamp()
                vuln['ignore_expires_exists'] = True
            # else:
            #   .snyk has ignore entry for vuln that artifact does not have

    print(json.dumps(list(vulns.values()), default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
