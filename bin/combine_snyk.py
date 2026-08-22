#!/usr/bin/env python3

import sys
import json
import yaml


# now_ts and now are stamped later, by the job that begins the per-vuln trail,
# so that the instant a vuln's age is measured from is never earlier than the
# trail created_at it is measured against.
if __name__ == "__main__":  # pragma: no cover
    snyk_version = sys.argv[1]
    repo_name = sys.argv[2]
    sarif_filename = sys.argv[3]
    snyk_policy_filename = sys.argv[4]
    stale_filename = sys.argv[5]
    artifact_name = sys.argv[6]
    artifact_fingerprint = sys.argv[7]

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
                'artifact_name': artifact_name,
                'artifact_fingerprint': artifact_fingerprint,
                'full_id': full_id,
                'severity': severity,
                'vuln_url': vuln_url,
                'ignore_expires': '',
                'ignore_expires_ts': 0,
                "ignore_expires_exists": False,
                'ignore_forever': False,
                'trail_name': trail_name,
            }

    # Overwrite specific vulnerability expiry dates if found in snyk policy file (yaml)
    with open(snyk_policy_filename) as snyk_file:
        snyk_data = yaml.safe_load(snyk_file)

    stale_ids = []
    if snyk_data:
        ignore = snyk_data.get('ignore', {})
        for id in ignore:
            if id in vulns:
                vuln = vulns[id]
                entry = ignore[id][0]['*']
                vuln['ignore_expires_exists'] = True
                if 'expires' in entry:
                    expires = entry['expires']
                    vuln['ignore_expires'] = expires
                    vuln['ignore_expires_ts'] = expires.timestamp()
                else:
                    # A .snyk entry with no expiry date means suppress that warning forever.
                    # The rego treats this as compliant regardless of age, so there is no
                    # concrete expiry date to record.
                    vuln['ignore_forever'] = True
            else:
                stale_ids.append(id)

    with open(stale_filename, 'w') as stale_file:
        stale_file.write(json.dumps(stale_ids))

    print(json.dumps(list(vulns.values()), default=str))


#   Severity. CVSS v3 Rating
#   ------------------------
#   Critical. 9.0 - 10.0
#   High	  7.0 -  8.9
#   Medium	  4.0 -  6.9
#   Low	      0.1 -  3.9
