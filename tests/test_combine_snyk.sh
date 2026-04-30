#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

# Fixed point in time for all tests: 2025-06-01 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SNYK_VERSION="1.0.0"
readonly REPO_NAME="test-repo"

setUp()
{
  staleF="${outputDir}/stale.json"
  rm -f "${staleF}"
}

test_no_vulns()
{
  run_combine_snyk "no-vulns.sarif.json" "no-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/no-vulns.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-empty.json")"
}

test_one_medium_vuln_no_ignore()
{
  run_combine_snyk "one-medium.sarif.json" "no-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/one-medium-no-ignore.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-empty.json")"
}

test_one_medium_vuln_with_active_ignore()
{
  run_combine_snyk "one-medium.sarif.json" "active-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/one-medium-active-ignore.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-empty.json")"
}

test_two_vulns_no_ignore()
{
  run_combine_snyk "two-vulns.sarif.json" "no-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/two-vulns-no-ignore.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-empty.json")"
}

test_two_vulns_one_with_active_ignore()
{
  run_combine_snyk "two-vulns.sarif.json" "active-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/two-vulns-one-active-ignore.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-empty.json")"
}

test_one_stale_snyk_entry()
{
  # .snyk ignores a vuln that does not appear in the SARIF output
  run_combine_snyk "no-vulns.sarif.json" "active-ignore.snyk.yaml"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/combine-snyk/expected/no-vulns.json")"
  assert_stderr_equals ""
  assert_stale_equals "$(cat "${my_dir}/combine-snyk/expected/stale-one-entry.json")"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

assert_stale_equals()
{
  local -r message="stale:$(dump_sss)"
  local -r expected="${1}"
  local -r actual="$(jq . "${staleF}")"
  assertEquals "${message}" "${expected}" "${actual}"
}

run_combine_snyk()
{
  local -r sarif_filename="${1}"
  local -r snyk_policy_filename="${2}"
  python3 "${my_dir}/../bin/combine_snyk.py" \
    "${NOW_TS}" \
    "${SNYK_VERSION}" \
    "${REPO_NAME}" \
    "${my_dir}/combine-snyk/${sarif_filename}" \
    "${my_dir}/combine-snyk/${snyk_policy_filename}" \
    "${staleF}" \
    | jq . >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
