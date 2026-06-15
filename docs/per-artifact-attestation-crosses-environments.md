# Per-artifact snyk attestation is fingerprint-scoped and crosses environments

Status: confirmed (investigated 2026-06-06). See also
[shared-per-vuln-trail-race.md](shared-per-vuln-trail-race.md).

## Summary

The `snyk-container-scan` attestation that drives environment compliance is
attached to the artifact fingerprint, not to an environment. The same artifact
fingerprint runs in more than one environment (for example aws-beta and
aws-prod), so a failing scan produced by one environment's flow can make that
artifact appear non-compliant in another environment. Re-running the live scan
for the second environment does not necessarily clear it, because that scan
attests into a different flow.

## Mechanism (confirmed from code)

In `artifact_snyk_test.yml`, the `attest-snyk-vulns` job sets the fingerprint in
its own `env:` block and attests a generic attestation:

    env:
      KOSLI_FINGERPRINT:      ${{needs.find-snyk-vulns.outputs.fingerprint}}
      KOSLI_ATTESTATION_NAME: ${{inputs.kosli_attestation_name}}
    ...
    kosli attest generic --name "${KOSLI_ATTESTATION_NAME}"

`KOSLI_FLOW` (`${{inputs.kosli_flow}}`, i.e. `snyk-<env>-per-artifact`) is set
once at the workflow level and inherited by this job.

Because `KOSLI_FINGERPRINT` is set, the attestation attaches to the artifact
fingerprint. The flow differs per environment: the aws-prod scan attests into
`snyk-aws-prod-per-artifact`, the aws-beta scan into `snyk-aws-beta-per-artifact`.
But both are attestations on the same artifact fingerprint.

A single image fingerprint is one artifact regardless of how many environments
it runs in. So `runner:bc5fbc1` (fingerprint `bdc8eb7f...`) is the same artifact
in aws-beta and aws-prod, and an attestation's compliance follows the artifact
into every environment it runs in.

## Symptom observed

- The daily aws-prod live scan produced a `snyk-container-scan` attestation with
  `is_compliant: false` (the 5 x/net/html vulns, see the per-vuln race doc).
  That attestation lives in the `snyk-aws-prod-per-artifact` flow but is pinned
  to fingerprint `bdc8eb7f...`.
- `runner:bc5fbc1` then showed as non-compliant in aws-beta as well, even though
  aws-beta has its own scanning path.
- Re-running the aws-beta live scan did not make aws-beta compliant. That scan
  attests into `snyk-aws-beta-per-artifact`, a different trail.

## Verified cause: a generic trail-compliance policy, not the snyk policy

Reading the aws-beta snapshot (`applied_policies` plus the artifact's
`policy_decisions`) shows aws-beta applies four policies to runner. Two facts
settle the cause:

1. The environment-specific snyk policy passed. `snyk-scan-aws-beta` is scoped
   with `if flow.name == "snyk-aws-beta-per-artifact"` and evaluates
   `rule_satisfied`. The aws-beta rerun worked for this policy.
2. A separate generic policy fails. `trail-compliance` has `required: true`
   and no flow scoping, so it requires the artifact to be compliant in EVERY
   trail it appears in. Its resolutions list four trails and one is red:

       runner-ci / bc5fbc14...                        -> rule_satisfied (COMPLIANT)
       production-promotion / promotion-one-63         -> rule_satisfied (COMPLIANT)
       snyk-aws-prod-per-artifact / runner-bdc8eb7f... -> non_compliant_in_trail (NON-COMPLIANT)
       snyk-aws-beta-per-artifact / runner-bdc8eb7f... -> rule_satisfied (COMPLIANT)

So the leak path is the `trail-compliance` policy, which spans every flow and
trail attached to the fingerprint. Because the `snyk-aws-prod-per-artifact`
trail is red (the per-vuln race), the fingerprint is non-compliant in any
environment that applies a `required` trail-compliance policy, including
aws-beta. This is also why re-running the aws-beta scan cannot fix aws-beta on
its own: `trail-compliance` is still evaluating the prod trail.

The earlier assumption that the aws-beta snyk policy was reading the prod-flow
attestation was wrong. The aws-beta snyk policy is correctly flow-scoped and
green; the cross-environment effect comes entirely from the unscoped
`trail-compliance` policy.

## Why this matters

This is a distinct issue from the per-vuln trail race. The per-vuln race
explains how a stale verdict gets computed; this finding explains how that
verdict, once attached to a fingerprint and surfaced as a red per-artifact
trail, leaks across environment boundaries through a `required`
trail-compliance policy.

The dangerous direction for compliance is the same: a red trail produced by one
environment's scan can distort the compliance picture of the same artifact in
another environment. Practical consequences:

- To clear aws-beta you must make the `snyk-aws-prod-per-artifact` trail for
  that fingerprint compliant (fix or re-run the prod scan), not just re-run the
  aws-beta scan.
- If per-environment isolation is desired, the `trail-compliance` policy would
  need flow scoping (similar to how `snyk-scan-aws-beta` scopes by flow name),
  so that an aws-beta environment only requires aws-beta trails to be compliant.
