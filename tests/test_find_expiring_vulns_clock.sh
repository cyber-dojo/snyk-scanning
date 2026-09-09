#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly repo_dir="${my_dir}/.."
readonly fixture_dir="${my_dir}/find-expiring-vulns"

# The fixture vuln is 1.5 days old measured between its own now_ts and
# first_seen_ts, so it sits inside the aws-prod limit for high severity.
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

# The same vuln in the aws-prod run of 2026-08-20, where first_seen_ts landed
# 75.8 seconds ahead of now_ts. stamp_vuln_times.py fails the scan on that
# ordering, so no vuln file can carry it. Reporting a deadline for it would put
# a number on an age no clock measured, so the report refuses it too.

test_first_seen_ahead_of_now_is_refused()
{
  run_find_expiring_vulns aws-prod vulns-runner-high-first-seen-ahead
  assert_status_equals 45
  assert_stdout_equals ""
  assert_stderr_includes "is ahead of now_ts"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_find_expiring_vulns()
{
  local -r kosli_env="${1}"
  local -r vuln_dirname="${2}"
  local -r raw="${SHUNIT_TMPDIR}/raw.json"
  # find_expiring_vulns.py reads rego.params.<env>.json from the current
  # directory, so run it from the repo root. That makes limit_days in the
  # expected file the real aws-prod limit, which test_rego_params.sh pins.
  #
  # Captured before jq rather than piped into it, so the status and stderr are
  # the script's own and a refusal is not read as a success.
  (cd "${repo_dir}" && python3 ./bin/find_expiring_vulns.py \
    --env "${kosli_env}" \
    --vuln-dir "${fixture_dir}/${vuln_dirname}" \
    >"${raw}" 2>${stderrF})
  echo $? >${statusF}
  if [ -s "${raw}" ]; then
    jq . <"${raw}" >${stdoutF}
  else
    : >${stdoutF}
  fi
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
