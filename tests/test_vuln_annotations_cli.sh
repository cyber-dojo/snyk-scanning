#!/usr/bin/env bash

# Tests bin/vuln_annotations.py as the workflow calls it: two JSON files in, one
# key=url line per vuln out, and a refusal when the ids named by a denial cannot
# be reconciled against the vuln list.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/vuln_annotations.py"

readonly GOLANG_ID="SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"
readonly OPENSSL_ID="SNYK-ALPINE321-OPENSSL-13939001"
readonly TRAILS_URL="https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails"

readonly GOLANG_URL="${TRAILS_URL}/runner-high-${GOLANG_ID}?attestation_id=85d13fe9-b33b-49b1-8a03-8a99d4ad35c1"
readonly OPENSSL_URL="${TRAILS_URL}/runner-medium-${OPENSSL_ID}?attestation_id=1f4b2c07-9d61-4a3e-8c55-71b0ee9c2a44"

# The two vulns Snyk finds in the runner image, as the workflow writes them into
# vulns.json after the per-vuln attestations have been made.
readonly TWO_VULNS='[
  {
    "artifact_fingerprint": "f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096",
    "artifact_name": "244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88",
    "first_seen": "2026-08-20 02:45:45+00:00",
    "first_seen_ts": 1787193945,
    "full_id": "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
    "ignore_expires": "",
    "ignore_expires_exists": false,
    "ignore_expires_ts": 0,
    "ignore_forever": false,
    "now": "2026-08-21 14:45:45+00:00",
    "now_ts": 1787323545,
    "severity": "high",
    "trail_name": "runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
    "version": "v1.1300.2",
    "vuln_url": "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
    "attestation_url": "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails/runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666?attestation_id=85d13fe9-b33b-49b1-8a03-8a99d4ad35c1"
  },
  {
    "artifact_fingerprint": "f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096",
    "artifact_name": "244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88",
    "first_seen": "2026-08-12 02:45:45+00:00",
    "first_seen_ts": 1786502745,
    "full_id": "SNYK-ALPINE321-OPENSSL-13939001",
    "ignore_expires": "",
    "ignore_expires_exists": false,
    "ignore_expires_ts": 0,
    "ignore_forever": false,
    "now": "2026-08-21 14:45:45+00:00",
    "now_ts": 1787323545,
    "severity": "medium",
    "trail_name": "runner-medium-SNYK-ALPINE321-OPENSSL-13939001",
    "version": "v1.1300.2",
    "vuln_url": "https://security.snyk.io/vuln/SNYK-ALPINE321-OPENSSL-13939001",
    "attestation_url": "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails/runner-medium-SNYK-ALPINE321-OPENSSL-13939001?attestation_id=1f4b2c07-9d61-4a3e-8c55-71b0ee9c2a44"
  }
]'

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# One evaluation labels every vuln: the one it names fails, the rest pass.

test_the_named_vuln_fails_and_the_unnamed_one_passes()
{
  local -r violation="${OPENSSL_ID}: medium severity vuln age 9 days exceeds 4 day limit"
  run_annotations "${TWO_VULNS}" "$(make_evaluation false "${violation}")"
  assert_status_equals 0
  assert_stdout_equals "$(printf '%s\n%s' \
    "pass_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666=${GOLANG_URL}" \
    "fail_medium_SNYK_ALPINE321_OPENSSL_13939001=${OPENSSL_URL}")"
  assert_stderr_equals ""
}

test_every_vuln_passes_when_the_evaluation_allows()
{
  run_annotations "${TWO_VULNS}" '{"allow": true, "violations": null}'
  assert_status_equals 0
  assert_stdout_equals "$(printf '%s\n%s' \
    "pass_high_SNYK_GOLANG_GITHUBCOMMOBYGOARCHIVE_18958666=${GOLANG_URL}" \
    "pass_medium_SNYK_ALPINE321_OPENSSL_13939001=${OPENSSL_URL}")"
  assert_stderr_equals ""
}

test_an_artifact_with_no_vulns_prints_nothing()
{
  run_annotations '[]' '{"allow": true, "violations": null}'
  assert_status_equals 0
  assert_stdout_empty
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# A denial whose vuln ids cannot be recovered must label nothing at all, so that
# a lost diagnostic can never present a failing vuln as passing.

test_denial_naming_no_vuln_prints_nothing_and_exits_non_zero()
{
  run_annotations "${TWO_VULNS}" '{"allow": false, "violations": null}'
  assert_status_equals 1
  assert_stdout_empty
  assert_stderr_includes "denied but named no vuln"
}

test_denial_naming_a_vuln_outside_the_list_prints_nothing_and_exits_non_zero()
{
  local -r violation="SNYK-ALPINE321-BUSYBOX-13939999: low severity vuln age 20 days exceeds 10 day limit"
  run_annotations "${TWO_VULNS}" "$(make_evaluation false "${violation}")"
  assert_status_equals 1
  assert_stdout_empty
  assert_stderr_includes "not in the vuln list"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_h_prints_help_with_an_example()
{
  "${script}" -h >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_includes "usage:"
  assert_stdout_includes "bin/vuln_annotations.py vulns.json evaluation.json"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_annotations()
{
  local -r vulns_json="${1}"
  local -r evaluation_json="${2}"
  local -r vulns_file="${SHUNIT_TMPDIR}/vulns.json"
  local -r evaluation_file="${SHUNIT_TMPDIR}/evaluation.json"
  echo "${vulns_json}" > "${vulns_file}"
  echo "${evaluation_json}" > "${evaluation_file}"
  "${script}" "${vulns_file}" "${evaluation_file}" >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

make_evaluation()
{
  local -r allow="${1}"
  shift
  printf '%s\n' "$@" | jq --raw-input --slurp --argjson allow "${allow}" \
    '{allow: $allow, violations: (split("\n") | map(select(length > 0)))}'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
