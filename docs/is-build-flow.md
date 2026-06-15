# Detecting a build flow via the type=build annotation

## Summary

`bin/artifacts.py` decides which of an artifact's flows is the "build flow"
(the CI flow that built the image) so it can emit one scanning matrix entry
per artifact. A flow is a build flow when the artifact's attestation in that
flow carries the annotation `type=build`, set by the
`kosli attest artifact --annotate type=build` call that the CI pipeline runs.

`is_build_flow(flow_name, fingerprint, fetch)` returns true when the artifact's
`annotations` in that flow contain `type == "build"`.

### Example, from an aws-beta snapshot

An artifact appears in several flows. Querying each flow:

    kosli get artifact runner-ci@<fingerprint>                  --output json
        -> annotations: {"type": "build"}

    kosli get artifact snyk-aws-beta-per-artifact@<fingerprint> --output json
        -> annotations: {}

    kosli get artifact production-promotion@<fingerprint>       --output json
        -> annotations: {}

Only the build flow (`runner-ci`) carries `type=build`.

## The snapshot JSON does not carry annotations

`artifacts()` iterates over `artifact["flows"]` from the snapshot JSON piped in
on stdin. The per-flow objects in that snapshot do NOT include an `annotations`
field. The annotation is only visible through
`kosli get artifact <flow>@<fingerprint> --output json`.

So `is_build_flow()` is not a pure in-memory check; it makes one
`kosli get artifact` call per (flow, fingerprint) pair via the `fetch` argument.
Each (flow, fingerprint) pair is visited exactly once in a run (each artifact has
a unique fingerprint, and an artifact's `flows` list has distinct flow names), so
there is nothing to memoize.

`fetch_annotations` runs the `kosli get artifact` call with a restricted
environment containing only `PATH` (so the `kosli` executable can be located).
The host, org, and API token are passed explicitly as `--host`, `--org`, and
`--api-token` flags, read from the `KOSLI_HOST`, `KOSLI_ORG`, and
`KOSLI_API_TOKEN` environment variables, so nothing else in the ambient
environment can influence the call.

## Testability

The single impure operation is isolated in `fetch_annotations(flow_name,
fingerprint)`, which shells out to `kosli get artifact`. `artifacts()` and
`is_build_flow()` take that fetcher as an injected `fetch` argument, defaulting to
the real `fetch_annotations`. Unit tests in `tests/test_artifacts_logic.py` pass a
dict-backed fake fetcher, so they supply the annotation JSON directly and never
make a live kosli call. The failure path is tested by monkeypatching
`subprocess.run` to raise.

## Compliance direction

Treating a build flow as a non-build flow drops its scanning matrix entry, which
can leave an artifact unscanned. That must never happen silently. So if the
`kosli get artifact` call fails or returns JSON that cannot be parsed,
`fetch_annotations` exits non-zero (exit code 43) rather than guess. Likewise an
unset `KOSLI_HOST`, `KOSLI_ORG`, or `KOSLI_API_TOKEN` exits 44, and an
unrecognised CI system in a commit_url exits 42.

For the same reason, a non-exited artifact whose flows contain no build flow is
never silently dropped (which would leave it unscanned): `artifacts()` exits 45,
naming the fingerprint, rather than omit it from the matrix.

## repo_name is derived from the commit_url

`parse_commit_url(commit_url)` returns `repo_name` as the last path segment of the
repository in the artifact's `commit_url` (the same URL used to build the raw
`.snyk` policy URL), so the repo name does not depend on the flow naming
convention.
