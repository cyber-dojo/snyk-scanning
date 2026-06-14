# Refactoring is_build_flow() to use the type=build annotation

Status: proposed (investigated 2026-06-14).

## Summary

`bin/artifacts.py` decides which of an artifact's flows is the "build flow"
(the CI flow that built the image) so it can emit one scanning matrix entry
per artifact. Today that decision is a hardcoded allow-list. This document
proposes replacing it with a data-driven check: a flow is a build flow when
the artifact's attestation in that flow carries the annotation `type=build`,
set by the `kosli attest artifact --annotate type=build` call that the CI
pipeline runs.

## Current implementation

`is_build_flow()` matches the flow name against a hardcoded list:

    BUILD_FLOWS = [
        "dashboard-ci",
        "differ-ci",
        "custom-start-points-ci",
        "languages-start-points-ci",
        "exercises-start-points-ci",
        "saver-ci",
        "web-ci",
        "creator-ci",
        "runner-ci",
        "nginx-ci"
    ]

    def is_build_flow(flow_name):
        return flow_name in BUILD_FLOWS

The docstring records that an earlier attempt called `kosli get flow
--output=json` and inspected its tags, but that was "very slow", so the list
was hardcoded instead.

### Problems with the hardcoded list

- It must be edited by hand whenever a service is added, removed, or renamed.
  A new build flow that is not in the list is silently skipped, so its artifact
  never gets a scanning matrix entry. That is the dangerous direction: an
  unscanned artifact can run in an environment without ever being checked.
- It couples the scanning tool to a fixed roster of cyber-dojo services rather
  than to a property of the flow itself.
- The `[:-3]` repo-name derivation (stripping the `-ci` suffix) assumes every
  build flow name ends in `-ci`, which the hardcoded list happens to guarantee
  but the convention does not enforce.

## Proposed approach: detect the type=build annotation

The CI pipeline that builds each artifact attests it with
`kosli attest artifact --annotate type=build`. That annotation is stored on the
artifact-in-flow record and is returned by `kosli get artifact` under the
`annotations` field. A non-build flow such as `snyk-aws-beta-per-artifact`
attests the same fingerprint without that annotation, so its `annotations`
field is empty.

So the build flow is the one whose artifact record has `annotations` containing
`type == "build"`.

### Verified from the aws-beta snapshot (2026-06-14)

The saver artifact (fingerprint `f5909cc8...`) appears in two flows:
`saver-ci` and `snyk-aws-beta-per-artifact`. Querying each flow:

    kosli get artifact saver-ci@f5909cc8...                 --output json
        -> annotations: {"type": "build"}

    kosli get artifact snyk-aws-beta-per-artifact@f5909cc8... --output json
        -> annotations: {}

Only `saver-ci`, the build flow, carries `type=build`. This matches the
hardcoded list (`saver-ci` is in `BUILD_FLOWS`, `snyk-aws-beta-per-artifact`
is not), confirming the annotation reproduces the existing classification.

## Cost: the snapshot JSON does not carry annotations

This is the key tradeoff to weigh before adopting the change.

`artifacts()` iterates over `artifact["flows"]` from the snapshot JSON that is
piped in on stdin. The per-flow objects in the snapshot do **not** include an
`annotations` field (confirmed against the aws-beta snapshot: the flow object
keys are `flow_name`, `trail_name`, `template_reference_name`, `git_commit`,
`commit_url`, `git_commit_info`, `html_url`, `flow_html_url`,
`deployment_diff`, `commit_lead_time`, `artifact_compliance_in_flow`,
`flow_reasons_for_non_compliance` -- no `annotations`).

The annotation is only visible through `kosli get artifact <flow>@<fingerprint>
--output json`. So the refactored `is_build_flow()` can no longer be a pure
in-memory string check; it must make one `kosli get artifact` API call per
(flow, fingerprint) pair to read `annotations`. This is the same class of cost
that pushed the original implementation away from `kosli get flow`, so the
performance impact must be measured, and mitigations considered:

- Memoize per (flow_name, fingerprint) within a run so repeated flows are not
  re-fetched.
- Each artifact in the snapshot typically has two flows, so the call count is
  bounded by roughly 2 x number-of-artifacts.

## Compliance direction

The safe failure mode follows the project rule that we must never report a
non-compliant artifact as compliant. Here, treating a build flow as a non-build
flow drops its scanning matrix entry, which can leave an artifact unscanned.
Therefore, if the `kosli get artifact` call fails, times out, or returns an
artifact whose `annotations` cannot be read, the refactored function must NOT
silently exclude the flow. It should either fail loudly (non-zero exit, as
`raw_snyk_policy_url` already does for an unknown CI system) or fall back to
including the flow, never silently skip it.

## Sketch of the change

    def is_build_flow(flow_name, fingerprint):
        """
        A flow is a build flow when the artifact's attestation in that flow
        carries the annotation type=build, set by the CI pipeline's
        'kosli attest artifact --annotate type=build' call.
        Requires a 'kosli get artifact <flow>@<fingerprint>' call because the
        snapshot JSON does not include per-flow annotations.
        """
        annotations = get_artifact_annotations(flow_name, fingerprint)
        return annotations.get("type") == "build"

The caller in `artifacts()` would pass the fingerprint it already has in scope.
The `repo_name = flow_name[:-3]` derivation can stay for now, but once flows are
identified by annotation rather than by an `-ci` name, consider sourcing the
repo name from a flow field (for example `template_reference_name` or the
commit URL) instead of stripping a suffix.
