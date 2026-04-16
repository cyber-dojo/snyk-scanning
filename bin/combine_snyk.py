#!/usr/bin/env python3

import sys
import json
import yaml


if __name__ == "__main__":  # pragma: no cover
    sarif_filename = sys.argv[1]
    snyk_policy_filename = sys.argv[2]

    # Extract ids and severities of each vulnerability in sarif file
    with open(sarif_filename) as sarif_file:
        sarif_data = json.load(sarif_file)

    vulns = {}
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

            vulns[full_id] = {
                'full_id': full_id,
                'short_id': short_id,
                'severity': severity,
                'vuln_url': vuln_url,
                'ignore_expires': '',
                'ignore_expires_ts': 0,
                "ignore_expires_exists": False
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

    flat = []
    for id, values in vulns.items():
        flat.append({
            'snyk_full_id': id,
            'snyk_short_id': values['short_id'],
            'snyk_severity': values['severity'],
            'snyk_vuln_url': values['vuln_url'],
            'snyk_ignore_expires': values['ignore_expires'],
            'snyk_ignore_expires_ts': values['ignore_expires_ts'],
            'snyk_ignore_expires_exists': values['ignore_expires_exists']
        })

    print(json.dumps(flat, default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
