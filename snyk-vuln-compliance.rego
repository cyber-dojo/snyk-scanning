package policy

import rego.v1

max_days_by_severity := data.params.max_days_by_severity

default allow = false

ignore_has_expired(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_expires_ts < vuln.now_ts
}

# allow is driven by a positive assertion (every trail must be compliant) rather
# than by the absence of violations. This ensures that if some error occurs while
# generating a diagnostic string, it can only lose a message -- it cannot silently
# produce a compliant result. See https://github.com/open-policy-agent/opa/issues/1857
trail_is_compliant(trail) if {
    vuln := trail.compliance_status.attestations_statuses["snyk"].attestation_data
    seconds_per_day := 60 * 60 * 24
    age_days := (vuln.now_ts - vuln.first_seen_ts) / seconds_per_day
    # Use < so that critical (max=0) is non-compliant on day zero
    age_days < max_days_by_severity[vuln.severity]
    not ignore_has_expired(vuln)
}

allow if {
    every trail in input.trails {
        trail_is_compliant(trail)
    }
}

# Violations provide diagnostics only -- they do not drive the allow decision.

# rule-1: vulnerability age exceeds the threshold for its severity
violations contains msg if {
    some trail in input.trails
    vuln := trail.compliance_status.attestations_statuses["snyk"].attestation_data
    seconds_per_day := 60 * 60 * 24
    age_days := (vuln.now_ts - vuln.first_seen_ts) / seconds_per_day
    max := max_days_by_severity[vuln.severity]
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
    ignore_has_expired(vuln)
    msg := sprintf(
        "trail '%v': %v snyk ignore entry expired at %v",
        [trail.name, vuln.full_id, vuln.ignore_expires],
    )
}
