# Scoping environment policies by env: `!=` needs an `exists()` guard to fail closed

Status: design note (2026-06-06). Companion to
[per-artifact-attestation-crosses-environments.md](per-artifact-attestation-crosses-environments.md).

## Why this matters

A snyk attestation is attached to an artifact's fingerprint, not to an
environment. The same fingerprint can run in more than one environment, so if
one artifact is in both aws-beta and aws-prod, any snyk attestations it makes
for that artifact in aws-beta will also be seen by a simple `trail-compliance`
policy attached to aws-prod. An unscoped `required` trail-compliance policy
spans every trail on the fingerprint, so a red trail from one environment makes
the artifact non-compliant in the others too.

The fix is to split the unscoped `trail-compliance` policy into per-environment
copies, so each environment only requires its own trails. This note records a
compliance-asymmetry trap in how that per-env scoping is written, so the same
mistake is not repeated.

## Two ways to write the exception

Scoping uses the policy's `exceptions` list. Each exception is `{ if: <expr> }`,
and the requirement is WAIVED for a trail when its flow makes the expression
true. Flows are tagged `env=<target-env>`, so a per-env policy requires its own
env's trails and waives the others.

For the aws-beta policy:

1. Name the other env: `if: ${{ flow.tags.env == "aws-prod" }}`
2. Anything-but-this-env: `if: ${{ flow.tags.env != "aws-beta" }}`

Scalability favours form 2: with N environments, form 1 needs N-1 OR-terms and
an edit every time an environment is added; form 2 is a single term that needs
no edit.

## The trap: `!=` fails open on a MISSING tag

The forms differ in how they treat a flow whose `env` tag is absent, and for
`!=` that difference is in the dangerous direction.

- Form 2 (`!= "aws-beta"`): a missing tag is `!= X` for every X, so the trail is
  WAIVED in every environment's policy. A flow added without an `env` tag is
  silently dropped from `trail-compliance` everywhere. That is fail-OPEN:
  compliance waived by omission.
- Form 1 (`== "aws-prod"`): a missing tag makes the expression false, so the
  trail is still required. Fail-CLOSED.

Under Kosli compliance asymmetry (never report compliant when actually
non-compliant; when in doubt, fail toward non-compliance), waiving by omission
is exactly what must not happen. The Kosli docs also do not define how a bare
comparison behaves when the referenced tag is absent, which is a second reason
not to rely on it.

## The resolution: guard the comparison with `exists()`

Kosli expressions provide `exists(arg)` ("returns true if arg is not null").
Guarding the comparison keeps the `!=` scalability AND restores fail-closed:

    exceptions:
      - if: ${{ exists(flow.tags.env) and flow.tags.env != "aws-beta" }}

A trail is waived only when its flow HAS an `env` tag AND that tag is some other
environment:

| flow's `env` tag | `exists()` | `!= "aws-beta"` | waived? | result |
|---|---|---|---|---|
| `aws-beta`              | true  | false | no  | required (fail closed) |
| `aws-prod` / other env  | true  | true  | yes | waived |
| missing                 | false | n/a   | no  | required (fail closed) |
