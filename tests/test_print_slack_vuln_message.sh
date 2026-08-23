#!/usr/bin/env bash

# Tests for print_slack_vuln_message.py, which renders the Slack message body for
# the most urgent vuln of a run. find_expiring_vulns.py has already sorted the
# vulns, so the message always describes vulns[0].

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

test_no_vulns_reports_none_found()
{
  run_message '[]'
  assert_status_equals 0
  assert_stdout_equals "No Snyk vulnerabilities :-)"
  assert_stderr_equals ""
}

# days_remaining is rounded up, so 2.3 days of grace reads as 3 days. A reader
# acting on the message has until the end of that day.

test_vuln_inside_its_limit_counts_the_days_of_grace_left()
{
  run_message "${ONE_CREATOR_HIGH_INSIDE_LIMIT}"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_INSIDE_LIMIT}"
  assert_stderr_equals ""
}

test_vuln_past_its_limit_counts_the_days_it_has_been_non_compliant()
{
  run_message "${ONE_CREATOR_HIGH_PAST_LIMIT}"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_PAST_LIMIT}"
  assert_stderr_equals ""
}

# A clock_skew vuln carries the sentinel days_remaining that sorts it above every
# real deadline. Printing that number would claim tens of thousands of days of
# non-compliance, so the message says the count is unknown and names the cause.

test_clock_skew_vuln_reports_unknown_days_and_names_the_cause()
{
  run_message "${ONE_RUNNER_HIGH_CLOCK_SKEW}"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_CLOCK_SKEW}"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_message()
{
  python3 "${my_dir}/../bin/print_slack_vuln_message.py" \
    --vulns "${1}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

readonly EXPECTED_INSIDE_LIMIT='Days till non-compliant: 3
Vuln: SNYK-GOLANG-NETHTTP-3321444
Severity: high
Repo: creator
Mechanism: rego_limit'

readonly EXPECTED_PAST_LIMIT='Days non-compliant: 1
Vuln: SNYK-GOLANG-NETHTTP-3321444
Severity: high
Repo: creator
Mechanism: rego_limit'

readonly EXPECTED_CLOCK_SKEW='Days non-compliant: unknown (clock skew)
Vuln: SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666
Severity: high
Repo: runner
Mechanism: clock_skew'

# Every fixture is built through jq so that the fields each test turns on can be
# marked with # <<<: jq programs take comments, JSON does not.

readonly ONE_CREATOR_HIGH_INSIDE_LIMIT="$(jq --null-input '
  [
    {
      env: "aws-beta",
      trail_name: "creator-high-SNYK-GOLANG-NETHTTP-3321444",
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",           # <<< printed on the Severity line
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
      mechanism: "rego_limit",    # <<< printed raw on the Mechanism line
      days_remaining: 2.3,        # <<< rounds UP to 3, which is what pins ceil
      ignore_expires: null,
      age_days: 4.7,
      limit_days: 7,
      artifact: "creator"         # <<< printed on the Repo line
    }
  ]')"

readonly ONE_CREATOR_HIGH_PAST_LIMIT="$(jq --null-input '
  [
    {
      env: "aws-beta",
      trail_name: "creator-high-SNYK-GOLANG-NETHTTP-3321444",
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
      mechanism: "rego_limit",
      days_remaining: -1.0,       # <<< negative, so the line counts days overdue
      ignore_expires: null,
      age_days: 8.0,
      limit_days: 7,
      artifact: "creator"
    }
  ]')"

readonly ONE_RUNNER_HIGH_CLOCK_SKEW="$(jq --null-input '
  [
    {
      env: "aws-prod",
      trail_name: "runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      full_id: "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      mechanism: "clock_skew",   # <<< selects the unknown-days line
      days_remaining: -99999,    # <<< the sentinel that must not be counted
      ignore_expires: null,
      age_days: null,
      limit_days: 2,
      artifact: "runner"
    }
  ]')"

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
