package policy

import rego.v1

max_days_by_severity    := data.params.max_days_by_severity

default allow := false

seconds_per_day := 60 * 60 * 24

# first_seen_ts is the per-vuln trail created_at, set by `kosli begin trail`
# before now_ts is stamped, so job ordering cannot put first_seen_ts ahead of
# now_ts. The two readings come from different clocks (the GitHub runner and
# the Kosli server), so skew between them can. age_days is undefined for such a
# vuln, which stops age_within_limit firing and leaves the vuln non-compliant:
# an age that cannot be measured must not satisfy a severity limit.
age_days(vuln) := days if {
    days := (vuln.now_ts - vuln.first_seen_ts) / seconds_per_day
    days >= 0
}

# Use < so that critical (max=0) is non-compliant on day zero
age_within_limit(vuln) if {
    vuln.ignore_expires_exists == false
    age_days(vuln) < max_days_by_severity[vuln.severity]
}

ignore_has_expired(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_forever == false
    vuln.ignore_expires_ts < vuln.now_ts
}

ignore_is_active(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_forever == false
    vuln.ignore_expires_ts >= vuln.now_ts
}

# A .snyk ignore entry with no expiry date suppresses the vuln forever.
ignore_is_forever(vuln) if {
    vuln.ignore_expires_exists == true
    vuln.ignore_forever == true
}

# allow is driven by a positive assertion (every vuln must be compliant) rather
# than by the absence of violations. This ensures that if some error occurs while
# generating a diagnostic string, it can only lose a message -- it cannot silently
# produce a compliant result. See https://github.com/open-policy-agent/opa/issues/1857

# Case 1: no .snyk ignore entry -- age determines compliance
vuln_is_compliant(vuln) if age_within_limit(vuln)

# Case 2: .snyk ignore entry exists and is active (not expired) -- compliant regardless of age
vuln_is_compliant(vuln) if ignore_is_active(vuln)

# Case 3: .snyk ignore entry exists with no expiry date -- suppressed forever, compliant regardless of age
vuln_is_compliant(vuln) if ignore_is_forever(vuln)

# The artifact is compliant when every vuln found in it is compliant, so an
# artifact with no vulns is compliant. An input carrying no vulns key at all
# leaves this body undefined, so allow falls back to its false default.
allow if {
    every vuln in input.vulns {
        vuln_is_compliant(vuln)
    }
}

# Violations provide diagnostics only -- they do not drive the allow decision.
#
# Every message begins with its vuln's full_id followed by a colon. full_id
# holds no colon, so the caller recovers the set of failing vuln ids by taking
# the first colon-delimited field of each message. That is what lets a single
# evaluation label each vuln of an artifact pass or fail.

# Case 1 violation: no ignore entry and vulnerability age exceeds the threshold for its severity
violations contains msg if {
    some vuln in input.vulns
    vuln.ignore_expires_exists == false
    not age_within_limit(vuln)
    msg := sprintf(
        "%v: %v severity vuln age %d days exceeds %d day limit",
        [vuln.full_id, vuln.severity, floor(age_days(vuln)), max_days_by_severity[vuln.severity]],
    )
}

# Case 2 violation: ignore entry exists (with an expiry date) but has expired
violations contains msg if {
    some vuln in input.vulns
    ignore_has_expired(vuln)
    msg := sprintf(
        "%v: snyk ignore entry expired at %v",
        [vuln.full_id, vuln.ignore_expires],
    )
}

# Case 3 violation: no ignore entry and first_seen_ts is ahead of now_ts. That
# ordering is only reachable through skew between the two clocks the timestamps
# come from, so the message names it as the thing to go and fix. age_days is
# undefined for such a vuln, which is what makes it non-compliant and is also
# why the Case 1 message cannot be built, so this rule carries the diagnostic
# for that deny. Both timestamps are named to show the size of the skew.
violations contains msg if {
    some vuln in input.vulns
    vuln.ignore_expires_exists == false
    vuln.first_seen_ts > vuln.now_ts
    msg := sprintf(
        "%v: first_seen_ts %d is ahead of now_ts %d, indicating clock skew between the GitHub runner and the Kosli server, so the vuln age cannot be measured",
        [vuln.full_id, vuln.first_seen_ts, vuln.now_ts],
    )
}
