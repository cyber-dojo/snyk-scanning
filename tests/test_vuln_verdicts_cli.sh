#!/usr/bin/env bash

# Tests bin/vuln_verdicts.py as the workflow calls it: vulns, evaluation and
# params in, the record that becomes the decision's --user-data out.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/vuln_verdicts.py"
readonly params="${my_dir}/../rego.params.aws-beta.json"

readonly GOLANG_ID="SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"
readonly OPENSSL_ID="SNYK-ALPINE321-OPENSSL-13939001"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_the_failing_vuln_carries_its_reason_and_the_other_does_not()
{
  local -r reason="medium severity vuln age 9.5 days exceeds 4 day limit"
  run_verdicts "${TWO_VULNS}" "$(make_evaluation false "${OPENSSL_ID}: ${reason}")"
  assert_status_equals 0
  assert_stderr_equals ""
  assert_verdict_equals "${OPENSSL_ID}" '.status' '"fail"'
  assert_verdict_equals "${OPENSSL_ID}" '.reasons' "[\"${reason}\"]"
  assert_verdict_equals "${GOLANG_ID}" '.status' '"pass"'
  assert_verdict_equals "${GOLANG_ID}" '.reasons' '[]'
}

test_the_summary_names_the_failing_vuln_and_its_reason()
{
  local -r reason="medium severity vuln age 9.5 days exceeds 4 day limit"
  run_verdicts "${TWO_VULNS}" "$(make_evaluation false "${OPENSSL_ID}: ${reason}")"
  assert_status_equals 0
  assert_stdout_json_equals '.summary' \
    "\"1 of 2 vulns failing: ${OPENSSL_ID} (medium) -- ${reason}\""
}

test_the_record_names_the_profile_and_the_limits_used()
{
  run_verdicts "${TWO_VULNS}" '{"allow": true, "violations": null}'
  assert_status_equals 0
  assert_stdout_json_equals '.params_profile' '"aws-beta"'
  assert_stdout_json_equals '.max_days_by_severity' "$(jq --compact-output '.max_days_by_severity' "${params}")"
}

test_a_compliant_artifact_still_gets_a_record()
{
  run_verdicts "${TWO_VULNS}" '{"allow": true, "violations": null}'
  assert_status_equals 0
  assert_stdout_json_equals '.compliant' 'true'
  assert_stdout_json_equals '.failing_count' '0'
  assert_stdout_json_equals '.summary' '"2 vulns, all compliant"'
}

test_an_artifact_with_no_vulns_gets_a_record_too()
{
  run_verdicts '[]' '{"allow": true, "violations": null}'
  assert_status_equals 0
  assert_stdout_json_equals '.vuln_count' '0'
  assert_stdout_json_equals '.summary' '"0 vulns, all compliant"'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# A record that cannot place the failure it reports is worse than none: it is
# attested as the reason a control is red.

test_denial_naming_no_vuln_prints_nothing_and_exits_non_zero()
{
  run_verdicts "${TWO_VULNS}" '{"allow": false, "violations": null}'
  assert_status_equals 1
  assert_stdout_empty
  assert_stderr_includes "denied but named no vuln"
}

test_denial_naming_a_vuln_outside_the_list_prints_nothing_and_exits_non_zero()
{
  local -r violation="SNYK-ALPINE321-BUSYBOX-13939999: low severity vuln age 20 days exceeds 10 day limit"
  run_verdicts "${TWO_VULNS}" "$(make_evaluation false "${violation}")"
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
  assert_stdout_includes "bin/vuln_verdicts.py vulns.json evaluation.json"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_verdicts()
{
  local -r vulns_json="${1}"
  local -r evaluation_json="${2}"
  local -r vulns_file="${SHUNIT_TMPDIR}/vulns.json"
  local -r evaluation_file="${SHUNIT_TMPDIR}/evaluation.json"
  echo "${vulns_json}" > "${vulns_file}"
  echo "${evaluation_json}" > "${evaluation_file}"
  "${script}" "${vulns_file}" "${evaluation_file}" \
    --params-profile aws-beta \
    --params-file "${params}" >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

assert_stdout_json_equals()
{
  local -r jq_filter="${1}"
  local -r expected="${2}"
  local -r actual="$(jq --compact-output "${jq_filter}" <${stdoutF})"
  assertEquals "${jq_filter}" "${expected}" "${actual}"
}

assert_verdict_equals()
{
  local -r full_id="${1}"
  local -r jq_filter="${2}"
  local -r expected="${3}"
  assert_stdout_json_equals \
    "(.vulns[] | select(.full_id == \"${full_id}\")) | ${jq_filter}" \
    "${expected}"
}

make_evaluation()
{
  local -r allow="${1}"
  shift
  printf '%s\n' "$@" | jq --raw-input --slurp --argjson allow "${allow}" \
    '{allow: $allow, violations: (split("\n") | map(select(length > 0)))}'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

readonly TWO_VULNS='[
  {
    "full_id": "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
    "severity": "high",
    "age_days": 1.5,
    "limit_days": 2,
    "first_seen": "2026-08-20 02:45:45+00:00",
    "now": "2026-08-21 14:45:45+00:00",
    "ignore_expires": "",
    "attestation_url": "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails/runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666?attestation_id=85d13fe9"
  },
  {
    "full_id": "SNYK-ALPINE321-OPENSSL-13939001",
    "severity": "medium",
    "age_days": 9.5,
    "limit_days": 4,
    "first_seen": "2026-08-12 02:45:45+00:00",
    "now": "2026-08-21 14:45:45+00:00",
    "ignore_expires": "",
    "attestation_url": "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta-per-vuln/trails/runner-medium-SNYK-ALPINE321-OPENSSL-13939001?attestation_id=1f4b2c07"
  }
]'

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
