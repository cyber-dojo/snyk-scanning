# Rego: default allow = false is the safe default

## The principle

`default allow = false` means compliance must be proved, not assumed.
A bug that prevents the allow rule from firing produces a denial -- loud,
visible, and safe. The same bug with `default allow = true` produces a
silent approval -- dangerous and invisible.

## Validated by a real bug (2026-04)

The rego used `input.trails` (plural array) throughout, but `kosli evaluate
trail` passes the trail as `input.trail` (singular object). Because
`input.trails` was undefined, every rule body that referenced it failed
silently.

With `default allow = false` (the actual code):
- The `allow` rule body failed to fire.
- `allow` stayed at its default `false`.
- Every trail was denied, including genuinely compliant ones.
- The bug was immediately visible: "why are compliant vulns being denied?"

With `default allow = true` (the unsafe alternative):
- The `allow` rule body would have failed in exactly the same way.
- `allow` would have stayed at its default `true`.
- Every trail would have been approved, including genuinely non-compliant ones.
- Vulnerabilities with expired ignores or ages over the limit would have
  silently passed. The bug would have gone unnoticed.

## Key asymmetry

The failure mode of `default allow = false` is a false denial: things that
should pass get blocked. This is noisy and forces investigation.

The failure mode of `default allow = true` is a false approval: things that
should be blocked pass silently. This is the dangerous direction for a
compliance policy.

Always prove compliance; never assume it.
