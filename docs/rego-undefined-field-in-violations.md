# OPA/Rego: undefined field in violations rule silently produces compliant

## The problem

In a Rego `violations contains msg if { ... }` rule, if any expression in the
rule body evaluates to `undefined`, the entire rule body silently fails to fire.
The violations set stays empty, `count(violations) == 0` is true, and `allow`
defaults to `true` -- even when the intent was to deny.

The most common trigger is referencing an object field that does not exist in
the input data. For example, if the attestation data has `full_id` but the rego
references `vuln.id`, then `vuln.id` is undefined, `sprintf(...)` is undefined,
`msg` is undefined, and the rule body does not contribute to `violations`.

This was the bug in `snyk-vuln-compliance.rego`: both violation rules used
`vuln.id` in their `sprintf` calls, but `combine_snyk.py` outputs `full_id`.
Result: every vulnerability was evaluated as compliant regardless of age or
expired ignore entries.

## Confirmed by experiment

Minimal reproducing rego:

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
