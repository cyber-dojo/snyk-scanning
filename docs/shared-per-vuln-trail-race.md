# Race condition: shared per-vuln trails clobbered during a deploy swap

Status: confirmed bug, fixed 2026-06-06 (see "Fix (implemented)" below).

## Summary

The live environment snyk scan (`env_snyk_test.yml`) can write two conflicting
`snyk` attestations to the same per-vuln trail within a single workflow run.
The trail is keyed only by `repo-severity-vulnid`, so when an environment
snapshot transiently contains two builds of the same repo (the normal state
during a rolling deploy), both builds get their own matrix job and both write
the same trail. There is no ordering guarantee, so the stale verdict can land
last and win. The per-artifact attestation, and therefore environment
compliance, then reflects the loser of the race.

## How pass/fail is actually decided (background)

The `.snyk` ignore file does NOT suppress vulns from the scan. `snyk container
test` always runs with an empty `.snyk` policy, so it reports every vuln. The
real `.snyk` is fetched separately and `combine_snyk.py` records, per vuln,
whether an ignore entry matched (`ignore_expires_exists`, `ignore_expires_ts`).
Compliance is then decided by `snyk-vuln-compliance.rego`:

- Case 1 (no ignore entry): compliant only while the vuln age is under the
  severity limit in `rego.params.<env>.json`.
- Case 2 (active ignore entry): compliant regardless of age.
- Case 3 (ignore entry with no expiry): compliant forever.

The per-artifact `snyk-container-scan` attestation carries no verdict of its
own. It builds its pass/fail annotations by reading the per-vuln trails via
`kosli evaluate trail`.

## The bug

Three design facts combine:

1. Per-vuln trails are shared, keyed only by `repo-severity-vulnid`
   (`combine_snyk.py` builds `trail_name = f"{repo}-{severity}-{full_id}"`;
   `env_snyk_test.yml` uses it as `KOSLI_TRAIL`). There is no artifact
   fingerprint and no commit in the key.
2. `env_snyk_test.yml` fans out one matrix job per artifact found in the
   environment snapshot.
3. During a rolling deploy the snapshot transiently holds two builds of the
   same repo: the outgoing build (call it R1) and the incoming build (R2).

So both runner artifacts in that transient snapshot get their own matrix job,
and both `attest-individual-snyk-vulns` jobs write the SAME per-vuln trail.
Each job derived its `raw_snyk_policy_url` from its own artifact's build
commit, so R1 fetched an older `.snyk` and R2 fetched the newer one. The two
jobs therefore computed different `ignore_expires_exists` values for the same
vuln id, and wrote them to the same trail. Last write wins. The per-artifact
attestation reads whichever landed last.

## The proof

Observed on the prod per-vuln trail
`snyk-aws-prod-per-vuln / runner-medium-SNYK-GOLANG-GOLANGORGXNETHTML-16873672`.
Three most recent `snyk` attestations:

| created (UTC) | ignore_expires_exists | ignore_expires_ts | origin run |
|---|---|---|---|
| 05:20:46 | true  | 1782039190 (2026-06-21) | aws-prod-co-promotion run 27053598411 |
| 05:37:12 | true  | 1782039190 (2026-06-21) | snyk-scanning run 27053914972 |
| 05:37:26 | false | 0                       | snyk-scanning run 27053914972 |

The last two are from the SAME GitHub Actions run (27053914972), 14 seconds
apart, with opposite results, and different `now_ts` values (two separate
`combine_snyk.py` invocations, i.e. two matrix jobs). The `false` write landed
last, so it became the live value, and the per-artifact attestation reported
the 5 x/net/html vulns as failing.

For context: the vulns were first seen on 2026-05-27 and the `.snyk` ignore
entries for them were added to runner on 2026-06-05. The 05:20 co-promotion
scan of the new build correctly recorded `true`; the env scan 17 minutes later
raced and clobbered it back to `false`.

### The transient two-artifact snapshot, captured

The racing run (27053914972) read aws-prod snapshot `#4701` (live at 05:34 UTC,
the snapshot immediately before the scan). `artifacts.py` against that exact
snapshot produces two runner rows:

| fingerprint | build commit | annotation | instances (was -> now) | instances started | `.snyk` entries | computed |
|---|---|---|---|---|---|---|
| `bdc8eb7f` | `bc5fbc14` (06-05, incoming) | `started-compliant` | 0 -> 3 | 05:34 today | 32 (has the 5) | true |
| `9db5a998` | `bc8fb513` (older, outgoing) | `unchanged` | 3 -> 3 | 06-01 | 27 (lacks the 5) | false |

This is the deploy swap frozen in one snapshot: the incoming build had just
started (`was=0 now=3`), the outgoing build was still running. Both rows are
non-exited, so both became matrix jobs, each fetching its own build commit's
`.snyk` (verified: `bc8fb513/.snyk` has zero x/net/html entries,
`bc5fbc14/.snyk` has all 5). Both wrote the shared per-vuln trail; the outgoing
build's `false` landed last and won. The very next snapshot `#4702`, one minute
later, was back to a single runner row.

## What the trail surfaces (why last write wins)

Each scan attests an attestation named `snyk` to the per-vuln trail, so over
time the trail accumulates a history of `snyk` attestations (18 of them on this
trail). But `compliance_status.attestations_statuses` surfaces only one status
per attestation name. The rego reads exactly that one
(`trail.compliance_status.attestations_statuses["snyk"]`). So no matter how many
builds wrote `snyk`, the rego sees a single latest verdict. That collapse to one
status per name is the mechanism behind last-writer-wins, and it is why
recording the fingerprint inside the attestation data alone would not help: the
older build's instance is not surfaced to the rego at all, only the latest.

## What threw the investigation off

The `.snyk` file attached to the per-artifact attestation correctly showed the
new build's `.snyk` (all entries present). The file association is fine. The
corruption is purely in the shared, last-writer-wins per-vuln trail, written by
the older build's matrix job. Running the current `combine_snyk.py` against the
attached evidence reproduces `true`, which is why the stored `false` initially
looked impossible.

## Severity

The race can flip a result in either direction:

- A compliant vuln on the new build can be marked non-compliant (the observed,
  noisy case).
- A genuinely non-compliant vuln on the new build can be masked by an older
  build's compliant verdict. This is a false approval, the dangerous direction
  for a compliance policy.

Because the trigger is "two builds of the same repo in one snapshot", the race
is latent on every rolling deploy, not specific to these 5 vulns or to the
`.snyk` timing that made it visible.

## The stable trail key is required, do not key by fingerprint

It is tempting to "fix" the race by adding the artifact fingerprint (or commit)
to the per-vuln trail key so two builds cannot collide. That would break age
tracking and must not be done.

Vuln age is not measured from the scan time. The rego computes
`age_days = (now_ts - first_seen_ts) / seconds_per_day`, and `first_seen_ts`
is the per-vuln trail's `created_at`. The step in `artifact_snyk_test.yml` is
named "Add time vuln first seen in the repo" and reads it back:

    kosli begin trail ${KOSLI_TRAIL}
    kosli get trail ${KOSLI_TRAIL} --output=json > trail.json
    FIRST_SEEN_TS="$(jq '.created_at' trail.json)"

`begin trail` is idempotent: the first scan that begins a given trail name sets
`created_at`, and every later scan that re-begins the same name reads back that
original timestamp. The severity SLA (`max_days_by_severity`) is measured
against it.

For that to be meaningful the key must be stable across builds and across daily
scans, and must identify the vulnerability, not the artifact. `repo-...-vulnid`
does exactly that: the same CVE keeps the same trail across every rebuild, so
its age accumulates correctly. Adding the fingerprint would create a brand-new
trail with a fresh `created_at` on every deploy, resetting the age clock to
zero. The severity SLA would then never trigger, because no vuln would ever
appear older than the interval between deploys. That is a silent false
approval, the dangerous direction for a compliance policy.

(Aside: `severity` in the key is not load-bearing. The rego reads
`vuln.severity` from the attestation data, and the snyk id is already unique,
so `severity` in the trail name is only for readability and grouping. Only
`repo` and `vulnid` are required for identity and age.)

## The bug, stated precisely

The stable `repo-severity-vulnid` key is a feature, not the bug. The bug is
narrower: a shared, mutable, last-writer-wins field (`ignore_expires_exists`
and the current verdict) living on that long-lived trail, written by whichever
build's matrix job happens to run last. The verdict is per artifact (each build
has its own `.snyk`, hence its own answer), but it is stored in a single slot
shared by all builds of the repo. A fix must keep the trail identity stable for
age while letting each build's verdict coexist without overwriting another's.

## Fix (implemented): per-fingerprint attestation identity

Status: implemented 2026-06-06.

Both artifacts are still scanned, but each build's per-vuln verdict gets its own
identity on the shared trail, and the rego evaluates only the verdict for the
artifact being evaluated. Because `compliance_status` surfaces one status per
attestation name (see "What the trail surfaces" above), giving the verdicts
distinct names is what keeps them from collapsing.

What was changed:

1. Per-fingerprint attestation name. `artifact_snyk_test.yml` attests the
   per-vuln verdict as `snyk-<fingerprint>` (job env var `VULN_ATTESTATION_NAME`)
   instead of the fixed `snyk`, and reads it back under the same name. Two builds
   in one snapshot now write two distinct statuses on the trail, so neither
   clobbers the other.
2. Name-parameterised rego. `snyk-vuln-compliance.rego` selects
   `attestations_statuses[data.params.attestation_name]` instead of the
   hard-coded `["snyk"]`. The workflow builds the per-fingerprint name
   `snyk-<fingerprint>` once (the `VULN_ATTESTATION_NAME` env var used for the
   attest and read steps) and merges it into the `evaluate trail --params` object
   alongside `max_days_by_severity`, so the `snyk-` prefix lives in exactly one
   place rather than being rebuilt inside the rego. If the name is ever absent,
   `vuln_of` is undefined and `allow` defaults to `false` (the safe,
   non-compliant direction).
3. Fingerprint in the attested data. `combine_snyk.py` emits `artifact_name`
   and `artifact_fingerprint` on every vuln (fed from the workflow), and
   `single-snyk-vuln.schema.json` documents and requires them. Not strictly
   needed for name-based selection, but it aids traceability and is guarded by a
   contract test.

Why this approach:

- Age is untouched. `first_seen_ts` stays `trail.created_at`, shared across all
  fingerprints, which is exactly what the severity SLA needs.
- The transient two-artifact snapshot stops mattering. Each per-artifact
  evaluation reads only its own fingerprint's verdict, so deploy intent never has
  to be inferred from the snapshot.
- It does not drop scans (unlike abort-on-ambiguity below).

Tests:

- `tests/test_rego_rules.sh` keys its inputs as `snyk-<fingerprint>` and passes
  the fingerprint via params. A new test,
  `test_selects_only_the_matching_fingerprints_verdict`, puts two builds'
  verdicts on one trail (the real `bc5fbc14` and `bc8fb513` runner fingerprints
  from snapshot #4701) and asserts each fingerprint gets its own verdict.
- `tests/test_combine_snyk.sh` and `tests/test_schema_matches_attested_data.py`
  cover the new data fields and the schema contract.

Verification done: `kosli evaluate trail` feeds the rego an `input.trail` whose
`compliance_status.attestations_statuses` is an object keyed by attestation name
(the array shape seen via `kosli get trail` is only that command's
representation). So distinct names become distinct keys and the rego selects by
name. `kosli evaluate trail --show-input` dumps the exact policy input.

Remaining caveat: this was confirmed with a single name present on the trail.
That two per-fingerprint names coexist as two keys in one
`attestations_statuses` object is inferred from the object-keyed-by-name
structure, not yet observed with two names live. The next real deploy-swap scan
will confirm it.

## Rejected approach: ordering artifacts from the snapshot

An earlier idea was to de-duplicate the matrix to one artifact per repo by
picking the most recently started, using `creationTimestamp` (the array of
instance start times). It was rejected: `creationTimestamp` is an instance
lifecycle event, not a build or deploy event, so it cannot reliably order
builds. If the outgoing build is flaky and a task restarts after the incoming
build's tasks start, the outgoing (older) build gets the more recent
`creationTimestamp` and would be wrongly chosen, re-introducing the race. No
single-snapshot heuristic is robust here: instance timestamps reflect churn,
commit recency inverts on rollback, and the snapshot reports what is running,
not what is intended.

If a non-scanning fallback is ever wanted (for example while the
per-fingerprint fix is not yet in place), the safe option is to abort: when a
snapshot holds more than one non-exited artifact for the same repo, skip that
repo for the run. Skipping writes nothing, so it cannot assert a wrong verdict,
and a brand-new artifact with no scan yet stays non-compliant (missing
attestation), which is the safe direction. The next snapshot, typically a minute
later, is back to a single artifact and scans cleanly.
