#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly repo_dir="${my_dir}/.."
readonly fixture_dir="${my_dir}/find-expiring-vulns"

# The fixture vuln is 1.5 days old measured between its own now_ts and
# first_seen_ts, so it sits inside the aws-prod limit for high severity. Its
# vuln_reports entry is the output of kosli evaluate input --output-rule
# vuln_reports on that vuln, so the row carries the rego's own arithmetic. The
# vuln is the one where, on 2026-08-22, the aws-prod attestation for runner
# passed it at an age of 1.99693 days while the Slack alert called it
# non-compliant.

test_the_deadline_is_the_one_the_rego_reported()
{
  run_find_expiring_vulns aws-prod reports-runner-high-within-limit
  assert_status_equals 0
  assert_stdout_equals "$(cat "${fixture_dir}/expected/runner-high-within-limit.json")"
  assert_stderr_equals ""
}

# The same vuln in the aws-prod run of 2026-08-20, where first_seen_ts landed
# 75.8 seconds ahead of now_ts. The rego measures no age for it, so gives it no
# vuln_reports entry. Reporting a deadline for it would put a number on an age
# no clock measured, so the report refuses it.

test_a_vuln_with_no_report_is_refused()
{
  run_find_expiring_vulns aws-prod reports-runner-high-first-seen-ahead
  assert_status_equals 45
  assert_stdout_equals ""
  assert_stderr_includes "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666: no vuln_reports entry"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_find_expiring_vulns()
{
  local -r kosli_env="${1}"
  local -r vuln_dirname="${2}"
  local -r raw="${SHUNIT_TMPDIR}/raw.json"
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
