# Scoping environment policies by env: `!=` needs an `exists()` guard to fail closed

Status: design note (2026-06-06). Companion to
[per-artifact-attestation-crosses-environments.md](per-artifact-attestation-crosses-environments.md).

## Context

The unscoped `trail-compliance` Kosli environment policy is being split into
per-environment copies so that a red trail produced by one environment's scan
stops failing the other environments (the cross-environment leak documented in
the companion file). The policy itself lives in the `kosli-environment-policies`
repo; this note records a compliance-asymmetry trap in how the per-env scoping
is written, so the same mistake is not repeated elsewhere.

Scoping uses the policy's `exceptions` list. Each exception is `{ if: <expr> }`,
and the requirement is WAIVED for a trail when its flow makes the expression
true. Flows are tagged `env=<target-env>`. So the per-env `trail-compliance`
policy wants to require its own env's trails and waive the others.

## Two ways to write the exception

For the aws-beta policy:

1. Name the other env: `if: ${{ flow.tags.env == "aws-prod" }}`
2. Anything-but-this-env: `if: ${{ flow.tags.env != "aws-beta" }}`

Scalability favours form 2. With N environments, form 1 needs N-1 OR-terms per
policy and an edit every time an environment is added; form 2 is a single term
per policy and needs no edit when environments are added.

## The trap: the two forms disagree on a MISSING tag, and `!=` fails open

The forms differ in how they treat a flow whose `env` tag is absent, and for
`!=` that difference is in the dangerous direction.

- Form 2 (`!= "aws-beta"`): if a missing tag evaluates as "not equal to
  aws-beta", the expression is true, so the trail is WAIVED. The same holds for
  every environment's policy (a missing tag is `!= X` for all X). So a flow
  added without an `env` tag is silently dropped from `trail-compliance` in
  every environment. That is fail-OPEN: compliance waived by omission.
- Form 1 (`== "aws-prod"`): a missing tag makes the expression false, so the
  trail is NOT waived, i.e. still required. Fail-CLOSED.

Under Kosli compliance asymmetry (never report compliant when actually
non-compliant; when in doubt, fail toward non-compliance), waiving by omission
is exactly what must not happen. So the scalable `!=` form, written naively,
trades away the safe default. The Kosli docs also do not define how a bare
comparison behaves when the referenced tag is absent (false, error, or
null-not-equal), which is a second reason not to rely on it.

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

## Recommended pattern

- Tag every flow with `env=<target-env>`.
- Each per-env `trail-compliance` policy carries the single exception
  `exists(flow.tags.env) and flow.tags.env != "<this-env>"`.

This scales to any number of environments (one exception per policy, no edits
when an environment is added) and fails closed on any missing tag.

## Rollout safety

The `exists()` guard makes incremental tagging safe. Until a flow is tagged it
stays required in every environment (possibly over-strict, but safe), so flows
can be tagged one at a time without ever opening a silent compliance hole.

## General principle

When scoping a `required` policy via `exceptions` (which WAIVE the requirement),
write the condition so that MISSING or unrecognised inputs do NOT match it. An
exception that matches on absence waives compliance by omission. Prefer a
positive existence check (`exists(...) and ...`) over a bare inequality, so the
safe default stays "required".

## References

- [per-artifact-attestation-crosses-environments.md](per-artifact-attestation-crosses-environments.md)
- Kosli policy reference: https://docs.kosli.com/policy-reference/environment_policy
- Kosli environment policies: https://docs.kosli.com/getting_started/policies/
