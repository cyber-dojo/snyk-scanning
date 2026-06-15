# OPA/Rego: undefined field in a violations rule silently fails to fire

## The Rego footgun

In a Rego `violations contains msg if { ... }` rule, if any expression in the
rule body evaluates to `undefined`, the entire rule body silently fails to fire
and contributes nothing to the `violations` set. The most common trigger is
referencing an object field that does not exist in the input data: if the
attestation data has `full_id` but the rego references `vuln.id`, then `vuln.id`
is undefined, the `sprintf(...)` is undefined, `msg` is undefined, and the rule
produces no violation.

The danger arises only when `allow` is *derived from the absence of violations*
(`allow if count(violations) == 0`). Under that design an undefined field empties
the violations set, so `allow` becomes `true` even when the intent was to deny.

## The bug this once caused here

Both violation rules in `snyk-vuln-compliance.rego` used `vuln.id` in their
`sprintf` calls, but `combine_snyk.py` outputs `full_id`. Combined with an
`allow if count(violations) == 0` design, every vulnerability was evaluated as
compliant regardless of age or expired ignore entries.

## Current design: allow does not depend on violations

`snyk-vuln-compliance.rego` no longer derives `allow` from the violations set.
It uses `default allow := false` (line 13) and proves compliance with a positive
assertion, `allow if trail_is_compliant(input.trail)` (line 61). The `violations`
rules exist only to produce human-readable diagnostic strings (line 63: "Violations
provide diagnostics only -- they do not drive the allow decision").

So an undefined field in a violations rule can now only lose a diagnostic message;
it cannot flip the verdict to compliant. The violation rules reference
`vuln.full_id` (lines 70, 81), matching `combine_snyk.py`. A regression test
(`tests/test_rego_rules.sh`, `test_deny_vuln_over_age_limit_but_with_wrong_field_name_in_input`)
asserts that even with a wrong field name the result is still `deny` with a null
violations set.

## Confirmed by experiment (the unsafe `count(violations)` design)

This is the design the project moved away from. Minimal reproducing rego:

```rego
violations contains msg if {
    some trail in input.trails
    vuln := trail.attestation_data
    vuln.value > 5
    msg := sprintf("value %d exceeds limit (id=%v)", [vuln.value, vuln.nonexistent_field])
}

allow if { count(violations) == 0 }
```

| Input | Expected | Actual |
|---|---|---|
| value=10, nonexistent_field absent | DENIED | ALLOWED |
| value=3, nonexistent_field absent | ALLOWED | ALLOWED |
| value=10, nonexistent_field present | DENIED | DENIED |

## Known OPA issue

This is a documented design consequence of Rego's closed-world assumption:
undefined anywhere in a rule body causes the body to not fire, with no error or
warning. It is widely acknowledged as a footgun.

Relevant OPA GitHub issues:
- #1857: "Missing input causes policy to return without error with Sprintf"
  (documents this exact scenario)
- #2345: "Improve support for handling undefined inside of queries"
  (long-standing request; proposes a jq-style `//` fallback operator, not yet
  implemented as of 2025)
- #5211: "Allow undefined to be passed to function as value"

## Safer alternatives

**1. Fix the field name mismatch (best for our case)**

If the mismatch is simply a typo or rename, align the field names between the
data producer and the rego consumer. This is the simplest fix and leaves no
room for silent failure.

**2. `object.get` with a fallback**

```rego
vuln_id := object.get(vuln, ["full_id"], "unknown")
msg := sprintf("trail '%v': %v ...", [trail.name, vuln_id, ...])
```

Returns the fallback string instead of undefined, so `sprintf` always
evaluates. The downside is that a typo produces a misleading "unknown" in
the violation message rather than a test failure.

**3. Explicit existence guard**

```rego
violations contains msg if {
    ...
    age_days >= max
    vuln.full_id  # body fails here if field is absent
    msg := sprintf("...", [trail.name, vuln.full_id, ...])
}
```

Still silently skips when the field is absent, but placing the guard
immediately before the `sprintf` makes the dependency visible to a reader and
ensures tests catch any future rename.

## Linting

Regal (the official OPA linter) does not catch this class of problem. It flags
references to undefined *variables*, but it cannot know at lint time which
*keys* a runtime object will contain. The only reliable safety net is a test
suite that exercises deny cases with realistic input data.
