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

Example step summary entry:

<pre>
| Level  | Days remaining | Mechanism  | Vuln ID |
|--------|----------------|------------|---------|
| medium | 1              | rego_limit | SNYK-GOLANG-GITHUBCOMSIGSTORETIMESTAMPAUTHORITYV2PKGVERIFICATION-16134930 |
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

Example step summary entry:

<pre>
| Level | Days remaining | Mechanism       | Vuln ID |
|-------|----------------|-----------------|---------|
| high  | 3              | dot_snyk_expiry | SNYK-ALPINE322-ZLIB-16078399 |
</pre>

This means the .snyk file contains an ignore entry for this vuln whose expiry
date is 3 days away.

Options:
- Fix the underlying dependency and deploy (removes the vuln entirely)
- Extend the expiry date in .snyk (if fixing is not yet feasible). You can extend by at most 30 days, as set by max_ignore_expiry_days in the rego params files above.

Relevant file: .snyk (in the relevant repo)
