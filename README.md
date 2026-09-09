A repo holding CI workflows to run Snyk container tests on the Docker images running in, or being deployed to, cyber-dojo's
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/) runtime environments.

## The main problems
1. A snyk container scan produces a sarif output file, with ignored vulnerabilities from the .snyk policy file already filtered out. We'd prefer a complete picture of all the vulnerabilities.
2. The `kosli attest snyk` command creates a non-compliant attestation for _any_ new attestation not in the .snyk file. There are fairly frequent bursts of new low-severity vulnerabilities and we would like to control whether these block the main development workflow.

## TL;DR of the solution

The Snyk scan runs _without_ the `.snyk` policy file, so _all_ vulnerabilities are visible
regardless of any `.snyk` file ignore entries. The `.snyk` file is only applied during compliance evaluation.

Each individual vulnerability found in a running artifact is evaluated as follows:

- If it has an `ignore` entry in the artifact's `.snyk` file, it is honoured and treated as
  compliant. The exception is an ignore entry whose expiry date has passed, in which case it
  becomes non-compliant immediately.
- If it has no `ignore` entry, compliance depends on how long that vulnerability has been
  present in the artifact running in the given environment. The allowed number of days before
  non-compliance is set per severity in `rego.params.{env}.json`. See below.

The top-level generic artifact-level attestation is controlled by the `attest_to_kosli` input, which defaults to `true` when the caller's workflow is on `main`.

The inner trail-level attestations (one per Snyk vulnerability) _always_ take place. A single
`kosli evaluate input` call then judges every vulnerability found in the artifact at once. The
artifact-level attestation carries that verdict, plus one annotation per vulnerability whose key
says `pass` or `fail` and whose value links to that vulnerability's own attestation.

### Why a control is red

A `decision` attestation's payload is only its `is_compliant`, so the reason the Rego gave
travels beside it:

- **`description`**: the one line that shows without opening anything, for example
  `1 of 10 vulns failing: SNYK-ALPINE324-UTILLINUX-19533434 (high) -- high severity vuln age
  2.000007091046297 days exceeds 2 day limit`.
- **`user_data`**: the verdict record from `bin/vuln_verdicts.py`, holding the profile and limits
  judged against, the counts, and per vulnerability its status, the reasons the Rego named, its
  age, its limit, both instants and a link to its own attestation. Queryable through the API.
- **`attachments`**: the Rego policy, the params profile, the sarif, the `.snyk` file, the JSON
  handed to the policy, the raw evaluation and the verdict record, in the evidence vault.

Each per-vulnerability attestation also carries `age_days` and `limit_days`, so one per-vuln
record shows the arithmetic behind its own verdict.

Ages are unrounded. The daily scans measure at close to the same wall-clock time each run, so a
vulnerability crosses its limit within a second of a whole number of days, and a rounded age
hides the margin.

Both ends of the age come off one clock, the Kosli server's. `kosli begin trail` touches the
vulnerability's trail, and the read that follows yields both `created_at` (when the vulnerability
was first seen) and `last_modified_at` (this run's instant). No runner clock enters the
measurement, so there is no skew to absorb and a negative age is impossible rather than merely
unlikely.

If the server ever did report a `last_modified_at` earlier than the `created_at` of the same
object, `stamp_vuln_times.py` raises `TrailTimesOutOfOrder` and exits non-zero rather than record
an unmeasurable age as a verdict. That is a backstop against a broken invariant, not an expected
case.

What a failed scan does and does not do: the artifact-level decision is attested in the same job
as the artifact slot it hangs off, so a failed scan writes neither. The per-artifact trail is
named `{repo_name}-{artifact_fingerprint}` and persists across runs, so a fingerprint an earlier
run already scanned keeps that run's verdict, and the environment's compliance does not change.
Only a fingerprint never scanned before leaves no verdict for `kosli-aws-policy`'s
SDLC-CTRL-0022 rule to miss. The signal is therefore the workflow failure and its Slack alert,
which reads `Snyk scan FAILED for <env>` with the failing step's message on the job's stderr, not the
environment going red.

## Workflows

### `aws-beta.yml` / `aws-prod.yml`

Triggered daily, manually via `workflow_dispatch`, or on a push
to `main` that changes `snyk-vuln-compliance.rego` or the relevant
`rego.params.{env}.json`. Calls `repo_test.yml` first, so a policy change that
fails this repo's own tests never reaches a live compliance decision. Then calls
`env_snyk_test.yml` for the target environment, and finally
`check-expiry-and-notify.yml` to report on upcoming compliance expirations via
Slack.

| Workflow | Kosli flow (per-artifact) | Kosli flow (per-vuln) |
|---|---|---|
| `aws-beta.yml` | `snyk-aws-beta-per-artifact` | `snyk-aws-beta-per-vuln` |
| `aws-prod.yml` | `snyk-aws-prod-per-artifact` | `snyk-aws-prod-per-vuln` |

The per-artifact flow holds one trail per artifact currently running in the environment. Trail
names have the form `{repo_name}-{artifact_fingerprint}`. Each trail contains one `decision`
artifact-level attestation named `{repo_name}.snyk-container-scan` with the sarif output, Rego
policy file, Rego params file, `.snyk` policy file, the JSON handed to the policy, the
policy's verdict and the verdict record attached.

The per-vuln flow holds one trail per vulnerability found across all scanned artifacts. Trail
names have the form `{repo_name}-{severity}-{snyk_id}`, where `snyk_id` is the Snyk rule id
(for example `SNYK-ALPINE322-ZLIB-16078399`), not a CVE id. Each trail contains one custom
attestation of type `single-snyk-vuln`, named `snyk-{first 10 characters of the artifact
fingerprint}`. That attestation holds the data the compliance decision is made from, including
the vuln's `age_days` and the `limit_days` it was judged against, and its URL is what the
matching annotation on the per-artifact attestation links to.

## Rego compliance params

Each environment has a `rego.params.{env}.json` file setting the maximum number of days a
vulnerability may exist in that environment before it is non-compliant, by severity:

| Profile | critical | high | medium | low |
|---|---|---|---|---|
| `aws-beta` | 1 | 2 | 4 | 10 |
| `aws-prod` | 1 | 5 | 10 | 30 |

When a new low severity vulnerability appears in aws-prod you have 30 days to either fix it or
add an entry to the relevant `.snyk` file.

aws-prod is the more lenient of the two on high, medium and low. `kosli_env` defaults to
`aws-beta`, so the server build judges against the aws-beta profile: a vulnerability that will
eventually breach an aws-prod limit therefore fails the build first, days before the day it
could turn aws-prod non-compliant. `tests/test_rego_params.sh` holds `beta <= prod` for every
severity, so that ordering cannot be lost to an edit of a params file.


### `env_snyk_test.yml` (reusable)

Called by `aws-beta.yml` and `aws-prod.yml`. Queries Kosli for the artifacts currently running in the environment and fans out to `artifact_snyk_test.yml` via a matrix strategy.

**Inputs**

| Name | Required | Description |
|---|---|---|
| `kosli_env` | yes | Name of the Kosli environment to scan |
| `kosli_flow` | yes | Name of the Kosli flow to attest evidence in |

### `check-expiry-and-notify.yml` (reusable)

Called by `aws-beta.yml` and `aws-prod.yml` after the environment scan completes.
Downloads all per-vulnerability artifact files produced during the current run,
identifies the soonest-expiring vulnerability, and sends a Slack message
summarising it. Also writes a step summary to the GitHub Actions run page.

**Inputs**

| Name | Required | Description |
|---|---|---|
| `kosli_env` | yes | Name of the Kosli environment that was scanned |

**Secrets**

| Name | Required | Description |
|---|---|---|
| `SLACK_WEBHOOK_URL` | yes | Slack incoming webhook URL |

### `artifact_snyk_test.yml` (reusable)

Called by `env_snyk_test.yml` to scan artifacts running in an environment.

Also called by deployment workflows in the `cyber-dojo/aws-prod-co-promotion` repo.
For example, [aws-prod-co-promotion/.github/workflows/promote_one.yml](https://github.com/cyber-dojo/aws-prod-co-promotion/blob/1a3f516ca3da64bb329c5447dddc8c58751ec82b/.github/workflows/promote_one.yml#L115):

Also called directly by build workflows in other repos to scan a newly built artifact.
For example, [nginx/.github/workflows/main.yml](https://github.com/cyber-dojo/nginx/blob/b1ce55beb190397c80d3ba0536f6b97bb5f468f6/.github/workflows/main.yml#L102):

**Example use**

```yaml
jobs:
  ...
  snyk-container-scan:
    needs: [build-image]
    uses: cyber-dojo/snyk-scanning/.github/workflows/artifact_snyk_test.yml@main
    with:
      artifact_name: ${{ needs.build-image.outputs.tagged_image_name }}
      kosli_flow: ${{ vars.KOSLI_FLOW }}
      kosli_trail: ${{ github.sha }}
      kosli_attestation_name: nginx.snyk-container-scan
    secrets:
      snyk_token: ${{ secrets.SNYK_TOKEN }}
      kosli_api_token: ${{ secrets.KOSLI_API_TOKEN }}
```

Runs a Snyk container test against a single artifact, evaluates the results against a Rego
compliance policy, and makes an artifact-level attestation in Kosli. Attaches the sarif output, the Rego policy file, the Rego params file, the `.snyk` policy file, the JSON handed to the policy, and the policy's verdict to the attestation.

**Inputs**

| Name | Required | Default | Description |
|---|---|---|---|
| `aws_rolename` | no | `gh_actions_services` | IAM role for ECR login |
| `artifact_name` | yes | | OCI artifact to scan (image name with tag) |
| `kosli_flow` | yes | | Kosli flow to attest to |
| `kosli_trail` | no | `${{ github.sha }}` | Kosli trail to attest to |
| `kosli_attestation_name` | yes | | Kosli attestation name |
| `kosli_env` | no | `aws-beta` | Environment the artifact is deployed-in/deploying-to |
| `repo_name` | no | repository name | Repo the artifact was built in |
| `snyk_version` | no | `v1.1300.2` | Version of Snyk CLI to use |
| `raw_snyk_policy_url` | no | `.snyk` at `${{ github.sha }}` | URL of the `.snyk` policy file for the artifact's commit |
| `attest_to_kosli` | no | `true` on main | Whether to record the generic artifact-level attestation |

**Secrets**

| Name | Required | Description |
|---|---|---|
| `snyk_token` | yes | Snyk API token |
| `kosli_api_token` | yes | Kosli API token |

**Outputs**

| Name | Description |
|---|---|
| `vulns_json` | JSON array of vulnerability objects found for the artifact |

### `repo_test.yml` (reusable)

Tests this repo's own code: the Rego policy, the `bin/` scripts, and the
`single-snyk-vuln` attestation-type schema. It scans nothing; the Snyk Test
workflows above scan artifacts.

Runs on every pull request and on pushes to `main`, and is also called as a
gating job by `aws-beta.yml` and `aws-prod.yml`. Every service repo calls
`artifact_snyk_test.yml@main`, so `main` is the live deploy target for all of
them at once, which makes green-before-merge the only real gate.

Takes no inputs and needs no secrets: `kosli evaluate input`, which
`test_rego_rules.sh` shells out to, evaluates a policy locally, so the workflow
also runs on pull requests from forks.

