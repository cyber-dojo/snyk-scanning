A repo holding CI workflows to run Snyk container tests on the Docker images running in, or being deployed to, cyber-dojo's
[aws-beta](https://app.kosli.com/cyber-dojo/environments/aws-beta/events/) and
[aws-prod](https://app.kosli.com/cyber-dojo/environments/aws-prod/events/) runtime environments.

## The main problems
1. A snyk container scan produces a sarif output file, with ignored vulnreabilities from the .snyk policy file already filtered out. We'd prefer a complete picture of all the vulnerabilities.
2. The `kosli attest snyk` command creates a non-compliant attestation for _any_ new attestation not in the .snyk file. There are fairly frequent bursts of new low-severity vulnerabilities and we would like to control whether these block the main development workflow.

## TL;DR of the solution

The Snyk scan runs _without_ the `.snyk` policy file, so _all_ vulnerabilities are visible
regardless of any `.snyk` file ignore entries. The `.snyk` file is only applied during compliance evaluation.

Each individual vulnerability found in a running artifact is evaluated as follows:

- If it has an `ignore` entry in the artifact's `.snyk` file, it is honoured and treated as
  compliant — unless that ignore entry has an expiry date which has passed, in which case it
  becomes non-compliant immediately.
- If it has no `ignore` entry, compliance depends on how long that vulnerability has been
  present in the artifact running in the given environment. The allowed number of days before
  non-compliance is set per severity in `rego.params.{env}.json`. See below.

The top-level generic artifact-level attestation is controlled by the `attest_to_kosli` input, which defaults to `true` when the caller's workflow is on `main`.

The inner trail-level attestations (one per Snyk vulnerability) _always_ take place and are the inputs to the `kosli evaluate trail` calls used to determine the overall compliance.

## Workflows

### `aws-beta.yml` / `aws-prod.yml`

Triggered daily at 06:00 UTC or manually via `workflow_dispatch`. Calls
`env_snyk_test.yml` for the target environment.

| Workflow | Kosli flow |
|---|---|
| `aws-beta.yml` | `snyk-vulns-aws-beta` |
| `aws-prod.yml` | `snyk-vulns-aws-prod` |

Each flow holds one trail per artifact currently running in the environment. Trail names have
the form `{repo_name}-{artifact_fingerprint}`. Each trail contains one `generic` artifact-level attestation named `{repo_name}.snyk-container-scan` with the sarif output, Rego policy file, Rego params file, and `.snyk` policy file attached.

## Rego compliance params

Each environment has a `rego.params.{env}.json` file that sets the maximum number of days a
vulnerability may exist in that environment before it is considered non-compliant, by severity. aws-prod has a stricter limit for critical vulnerabilities (0 days — any critical vuln is immediately non-compliant), reflecting the higher risk of a production environment.

Example — `rego.params.aws-prod.json`:

```json
{
    "max_days_by_severity":
    {
        "critical": 0,
        "high":     7,
        "medium":   30,
        "low":      90
    }
}
```

### `env_snyk_test.yml` (reusable)

Called by `aws-beta.yml` and `aws-prod.yml`. Queries Kosli for the artifacts currently running in the environment and fans out to `artifact_snyk_test.yml` via a matrix strategy.

**Inputs**

| Name | Required | Description |
|---|---|---|
| `kosli_env` | yes | Name of the Kosli environment to scan |
| `kosli_flow` | yes | Name of the Kosli flow to attest evidence in |

### `artifact_snyk_test.yml` (reusable)

Called by `env_snyk_test.yml` to scan artifacts running in an environment.


Also called directly by build workflows in other repos to scan a newly built artifact.
For example, [nginx/.github/workflows/main.yml](https://github.com/cyber-dojo/nginx/blob/b1ce55beb190397c80d3ba0536f6b97bb5f468f6/.github/workflows/main.yml#L102):

**Example usage**

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
compliance policy, and makes an artifact-level attestations in Kosli. Attaches the sarif output, the Rego policy file, the Rego params file, and the `.snyk` policy file to the attestation.

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

