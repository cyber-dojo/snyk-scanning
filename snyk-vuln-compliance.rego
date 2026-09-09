package policy

import rego.v1

max_days_by_severity    := data.params.max_days_by_severity

default allow := false

seconds_per_day := 60 * 60 * 24

# stamp_vuln_times.py fails the scan when first_seen_ts is ahead of now_ts, so
# that ordering does not reach here. The guard is the backstop if it ever does:
# age_days stays undefined, which stops age_within_limit firing and denies the
# vuln with no violation naming it, and both vuln_annotations.py and
# vuln_verdicts.py refuse a denial they cannot attribute. An age that cannot be
# measured must not satisfy a severity limit.
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
# Every message begins with its vuln's full_id followed by a colon and a space.
# A vuln id can hold colons (a licence finding is
# "snyk:lic:pip:astroid:LGPL-2.1") but never a colon followed by a space, so the
# caller recovers each failing vuln id by partitioning a message on the first
# ": ". That is what lets a single evaluation label each vuln of an artifact
# pass or fail.

# Case 1 violation: no ignore entry and vulnerability age exceeds the threshold for its severity
#
# The age is unrounded: the daily scans measure it at close to the same
# wall-clock time each run, so a vuln crosses its limit within a second of a
# whole number of days and a rounded age hides the margin entirely.
#
# %v because the age is an int for a whole-day age and a float otherwise, and
# each fixed-type verb errors on the other: %d renders %!d(float64=...), %.6f
# renders %!f(int=...).
violations contains msg if {
    some vuln in input.vulns
    vuln.ignore_expires_exists == false
    not age_within_limit(vuln)
    msg := sprintf(
        "%v: %v severity vuln age %v days exceeds %d day limit",
        [vuln.full_id, vuln.severity, age_days(vuln), max_days_by_severity[vuln.severity]],
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
