package policy

import rego.v1

max_days_by_severity := data.params.max_days_by_severity

default allow = false

# rule-1: vulnerability age exceeds the threshold for its severity
violations contains msg if {
    some trail in input.trails
    vuln := trail.compliance_status.attestations_statuses["snyk"].attestation_data
    seconds_per_day := 60 * 60 * 24
    age_days := (vuln.now_ts - vuln.first_seen_ts) / seconds_per_day
    max := max_days_by_severity[vuln.severity]
    # Use >= so that critical (max=0) is non-compliant on day zero
    age_days >= max  
    msg := sprintf(
        "trail '%v': %v severity vuln age %d days exceeds %d day limit for severity %v",
        [trail.name, vuln.full_id, age_days, max, vuln.severity],
    )
}

# rule-2: vulnerability has an ignore entry whose expiry is in the past
violations contains msg if {
    some trail in input.trails
    vuln := trail.compliance_status.attestations_statuses["snyk"].attestation_data
    vuln.ignore_expires_exists == true
    vuln.ignore_expires_ts < vuln.now_ts
    msg := sprintf(
        "trail '%v': %v snyk ignore entry expired at %v",
        [trail.name, vuln.full_id, vuln.ignore_expires],
    )
}

allow if {
    count(violations) == 0
}
