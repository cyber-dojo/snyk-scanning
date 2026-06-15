Snyk expiry alert response guide
=================================

When you receive a Slack alert from the check-expiry-and-notify workflow,
check the GitHub step summary (linked in the message) to see which vulns
are approaching expiry and which mechanism applies.

After fixing, you can re-run the live env-scan to verify:
- [Live Snyk Test aws-beta](https://github.com/cyber-dojo/snyk-scanning/actions/workflows/aws-beta.yml)
- [Live Snyk Test aws-prod](https://github.com/cyber-dojo/snyk-scanning/actions/workflows/aws-prod.yml)


Mechanism: rego_limit
----------------------
The vuln has been open long enough to approach the policy age limit
defined in the rego params for that environment.

Example step summary entry (the summary groups vulns under a per-severity
heading, and shows this mechanism as `rego`):

<pre>
### Medium (Count=1)

| Artifact | Days remaining | Mechanism | Vuln ID |
|----------|----------------|-----------|---------|
| creator  | 1              | rego      | SNYK-GOLANG-GITHUBCOMSIGSTORETIMESTAMPAUTHORITYV2PKGVERIFICATION-16134930 |
</pre>

This means there is no .snyk ignore entry. The vuln has been open for 3 days
against a 4-day limit for medium severity in aws-beta (4 - 3 = 1
day remaining).

The rego expiry days cannot be extended. The countdown is based on
when the vuln first appeared in the environment for the relevant repo,
not on any configurable date.

Options:
- Fix the underlying dependency and deploy (removes the vuln entirely)
- Add an explicit .snyk ignore entry (shifts it to dot_snyk_expiry
  and buys more time)

Relevant files:
  [rego.params.aws-beta.json](../rego.params.aws-beta.json)
  [rego.params.aws-prod.json](../rego.params.aws-prod.json)


Mechanism: dot_snyk_expiry
--------------------------
The .snyk ignore entry for this vuln is about to expire.
Note: a .snyk entry without an expiry date means ignore forever. Such an entry is
compliant regardless of the vuln's age and never appears in an expiry report, so
it will never trigger this alert.

Example step summary entry (shown under the High heading, with this mechanism
displayed as `.snyk`):

<pre>
### High (Count=1)

| Artifact | Days remaining | Mechanism | Vuln ID |
|----------|----------------|-----------|---------|
| runner   | 3              | .snyk     | SNYK-ALPINE322-ZLIB-16078399 |
</pre>

This means the .snyk file contains an ignore entry for this vuln whose expiry
date is 3 days away.

Options:
- Fix the underlying dependency and deploy (removes the vuln entirely)
- Extend the expiry date in .snyk (if fixing is not yet feasible). Omitting the expiry date ignores the vuln indefinitely.

Relevant file: .snyk (in the relevant repo)
