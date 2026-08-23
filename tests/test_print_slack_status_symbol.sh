#!/usr/bin/env bash

# Tests print_slack_status_symbol.py, which picks the symbol heading the Slack
# message for a run. find_expiring_vulns.py has already sorted the vulns, so the
# most urgent one is the first, and the symbol reports whether that one has
# reached its boundary.
#
# The symbol is the compliance claim a reader sees first, so it uses the same
# days_remaining <= 0 test the rego's verdict is held to in
# tests/test_rego_report_verdict_parity.sh. Rounding is deliberately absent: the
# rendered day counts round, this decision does not.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

test_no_vulns_is_compliant()
{
  run_symbol '[]'
  assert_status_equals 0
  assert_stdout_equals ":white_check_mark:"
  assert_stderr_equals ""
}

test_most_urgent_vuln_inside_its_boundary_is_compliant()
{
  run_symbol "${INSIDE_BOUNDARY}"
  assert_status_equals 0
  assert_stdout_equals ":white_check_mark:"
  assert_stderr_equals ""
}

test_most_urgent_vuln_past_its_boundary_is_not_compliant()
{
  run_symbol "${PAST_BOUNDARY}"
  assert_status_equals 0
  assert_stdout_equals ":x:"
  assert_stderr_equals ""
}

# Zero is the limit day itself, which the rego treats as non-compliant. The
# symbol has to agree, or Slack contradicts the attestation on that one day.

test_most_urgent_vuln_exactly_on_its_boundary_is_not_compliant()
{
  run_symbol "${ON_BOUNDARY}"
  assert_status_equals 0
  assert_stdout_equals ":x:"
  assert_stderr_equals ""
}

test_clock_skew_vuln_is_not_compliant()
{
  run_symbol "${CLOCK_SKEW}"
  assert_status_equals 0
  assert_stdout_equals ":x:"
  assert_stderr_equals ""
}

# Only the first vuln decides. A later vuln past its boundary cannot be first,
# because the report sorts by urgency, so a trailing compliant vuln must not
# drag the symbol down.

test_only_the_first_vuln_decides_the_symbol()
{
  run_symbol "${FIRST_INSIDE_SECOND_LATER}"
  assert_status_equals 0
  assert_stdout_equals ":white_check_mark:"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_symbol()
{
  python3 "${my_dir}/../bin/print_slack_status_symbol.py" \
    --vulns "${1}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

# Every fixture is built through jq so that the field each test turns on can be
# marked with # <<<: jq programs take comments, JSON does not. The fields are
# those the Slack path reads; days_remaining is the only one the symbol consults.

readonly INSIDE_BOUNDARY="$(jq --null-input '
  [
    {
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      artifact: "creator",
      mechanism: "rego_limit",
      days_remaining: 2.3          # <<< above zero, so still inside the limit
    }
  ]')"

readonly PAST_BOUNDARY="$(jq --null-input '
  [
    {
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      artifact: "creator",
      mechanism: "rego_limit",
      days_remaining: -1.0         # <<< below zero, so already overdue
    }
  ]')"

readonly ON_BOUNDARY="$(jq --null-input '
  [
    {
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      artifact: "creator",
      mechanism: "rego_limit",
      days_remaining: 0            # <<< the limit day, which the rego denies
    }
  ]')"

readonly CLOCK_SKEW="$(jq --null-input '
  [
    {
      full_id: "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      severity: "high",
      artifact: "runner",
      mechanism: "clock_skew",     # <<< age unmeasurable, so never compliant
      days_remaining: -99999       # <<< the sentinel, which is below zero
    }
  ]')"

readonly FIRST_INSIDE_SECOND_LATER="$(jq --null-input '
  [
    {
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      artifact: "creator",
      mechanism: "rego_limit",
      days_remaining: 2.3          # <<< first, and the only one consulted
    },
    {
      full_id: "SNYK-ALPINE321-OPENSSL-13939001",
      severity: "medium",
      artifact: "runner",
      mechanism: "rego_limit",
      days_remaining: 9.0
    }
  ]')"

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
