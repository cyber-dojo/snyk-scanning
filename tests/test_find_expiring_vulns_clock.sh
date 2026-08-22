#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly repo_dir="${my_dir}/.."
readonly fixture_dir="${my_dir}/find-expiring-vulns"

# The fixture vuln is 1.5 days old measured between its own now_ts and
# first_seen_ts, so it sits inside the 2 day aws-prod limit for high severity.
# Wall clock cannot produce that age, which is what pins the clock the report
# reads. The vuln is the one that exposed this: on 2026-08-22 the aws-prod
# attestation for runner passed it at an age of 1.99693 days while the Slack
# alert called the same vuln file non-compliant.

test_age_is_measured_from_the_attested_now_ts()
{
  run_find_expiring_vulns aws-prod vulns-runner-high-within-limit
  assert_status_equals 0
  assert_stdout_equals "$(cat "${fixture_dir}/expected/runner-high-within-limit.json")"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_find_expiring_vulns()
{
  local -r kosli_env="${1}"
  local -r vuln_dirname="${2}"
  # find_expiring_vulns.py reads rego.params.<env>.json from the current
  # directory, so run it from the repo root. That makes limit_days in the
  # expected file the real aws-prod limit, which test_rego_params.sh pins.
  (cd "${repo_dir}" && python3 ./bin/find_expiring_vulns.py \
    --env "${kosli_env}" \
    --vuln-dir "${fixture_dir}/${vuln_dirname}" \
    | jq . >${stdoutF} 2>${stderrF})
  echo $? >${statusF}
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
