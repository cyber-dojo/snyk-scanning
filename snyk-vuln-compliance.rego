package policy

import rego.v1

max_days_by_severity := data.params.max_days_by_severity

default allow := false

vuln_of(trail) := trail.compliance_status.attestations_statuses["snyk"].attestation_data

seconds_per_day := 60 * 60 * 24

age_days(vuln) := (vuln.now_ts - vuln.first_seen_ts) / seconds_per_day

ignore_has_expired(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_expires_ts < vuln.now_ts
}

ignore_is_active(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_expires_ts >= vuln.now_ts
}

# allow is driven by a positive assertion (every trail must be compliant) rather
# than by the absence of violations. This ensures that if some error occurs while
# generating a diagnostic string, it can only lose a message -- it cannot silently
# produce a compliant result. See https://github.com/open-policy-agent/opa/issues/1857

# Case 1: no ignore entry -- age determines compliance
# Use < so that critical (max=0) is non-compliant on day zero
age_within_limit(vuln) if {
    vuln.ignore_expires_exists == false
    age_days(vuln) < max_days_by_severity[vuln.severity]
}

trail_is_compliant(trail) if age_within_limit(vuln_of(trail))

# Case 2: active (not yet expired) ignore entry -- compliant regardless of age
trail_is_compliant(trail) if ignore_is_active(vuln_of(trail))

allow if trail_is_compliant(input.trail)

# Violations provide diagnostics only -- they do not drive the allow decision.

# rule-1: no ignore entry and vulnerability age exceeds the threshold for its severity
violations contains msg if {
    vuln := vuln_of(input.trail)
    vuln.ignore_expires_exists == false
    not age_within_limit(vuln)
    msg := sprintf(
        "trail '%v': %v severity vuln age %d days exceeds %d day limit for severity %v",
        [input.trail.name, vuln.full_id, age_days(vuln), max_days_by_severity[vuln.severity], vuln.severity],
    )
}

# rule-2: vulnerability has an ignore entry whose expiry is in the past
violations contains msg if {
    vuln := vuln_of(input.trail)
    ignore_has_expired(vuln)
    msg := sprintf(
        "trail '%v': %v snyk ignore entry expired at %v",
        [input.trail.name, vuln.full_id, vuln.ignore_expires],
    )
}
