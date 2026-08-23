#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

test_no_vulns()
{
  run_summary aws-beta '[]'
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/print-expiring-vulns-summary/expected/env-empty.txt")"
  assert_stderr_equals ""
}

test_one_beta_vuln()
{
  run_summary aws-beta "${ONE_CREATOR_HIGH_BETA}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/print-expiring-vulns-summary/expected/one-beta-vuln.txt")"
  assert_stderr_equals ""
}

test_one_prod_vuln()
{
  run_summary aws-prod "${ONE_CREATOR_HIGH_PROD}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/print-expiring-vulns-summary/expected/one-prod-vuln.txt")"
  assert_stderr_equals ""
}

test_sorted_by_severity_then_days_remaining()
{
  run_summary aws-beta "${CREATOR_MIXED_BETA}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/print-expiring-vulns-summary/expected/sorted-by-severity-and-days.txt")"
  assert_stderr_equals ""
}

# A clock_skew vuln carries no measurable age, so its days_remaining is the
# sentinel find_expiring_vulns.py uses to sort it above every real deadline. The
# table shows "?" in place of that number, because the sentinel is a sort device
# and not a count of days anyone can act on, and labels the mechanism "skew" so
# the row is not read as a .snyk expiry.

test_clock_skew_vuln_shows_no_day_count_and_its_own_mechanism_label()
{
  run_summary aws-prod "${ONE_RUNNER_HIGH_PROD_CLOCK_SKEW}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/print-expiring-vulns-summary/expected/clock-skew-vuln.txt")"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_summary()
{
  python3 "${my_dir}/../bin/print_expiring_vulns_summary.py" \
    --env   "${1}" \
    --vulns "${2}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

# Every fixture is built through jq so that the fields each test turns on can be
# marked with # <<<: jq programs take comments, JSON does not.

readonly ONE_CREATOR_HIGH_BETA="$(jq --null-input '
  [
    {
      env: "aws-beta",            # <<< names the section heading
      trail_name: "creator-high-SNYK-GOLANG-NETHTTP-3321444",
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",           # <<< picks the table the row lands in
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
      mechanism: "rego_limit",    # <<< renders as the "rego" label
      days_remaining: 2.3,        # <<< rounds to nearest, so the table shows 2
      ignore_expires: null,
      age_days: 4.7,
      limit_days: 7,
      artifact: "creator"
    }
  ]')"

# Identical to ONE_CREATOR_HIGH_BETA but for env, which is the whole point: the
# section heading is the only thing that differs between the two environments.
readonly ONE_CREATOR_HIGH_PROD="$(jq --null-input '
  [
    {
      env: "aws-prod",            # <<< the only field that differs
      trail_name: "creator-high-SNYK-GOLANG-NETHTTP-3321444",
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
      mechanism: "rego_limit",
      days_remaining: 2.3,
      ignore_expires: null,
      age_days: 4.7,
      limit_days: 7,
      artifact: "creator"
    }
  ]')"

# Three vulns whose severity and days_remaining decide the order they render in.
readonly CREATOR_MIXED_BETA="$(jq --null-input '
  [
    {
      env: "aws-beta",
      trail_name: "creator-medium-SNYK-GOLANG-GOLANGORGJWTV4-3180456",
      full_id: "SNYK-GOLANG-GOLANGORGJWTV4-3180456",
      severity: "medium",              # <<< lands in the medium table, below both highs
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGJWTV4-3180456",
      mechanism: "rego_limit",
      days_remaining: 6.0,
      ignore_expires: null,
      age_days: 24.0,
      limit_days: 30,
      artifact: "creator"
    },
    {
      env: "aws-beta",
      trail_name: "creator-high-SNYK-GOLANG-NETHTTP-3321444",
      full_id: "SNYK-GOLANG-NETHTTP-3321444",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444",
      mechanism: "rego_limit",
      days_remaining: 5.0,             # <<< the larger of the two highs, so it renders second
      ignore_expires: null,
      age_days: 2.0,
      limit_days: 7,
      artifact: "creator"
    },
    {
      env: "aws-beta",
      trail_name: "creator-high-SNYK-GOLANG-GOLANG-3208976",
      full_id: "SNYK-GOLANG-GOLANG-3208976",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-GOLANG-3208976",
      mechanism: "dot_snyk_expiry",    # <<< the one row labelled .snyk
      days_remaining: 1.0,             # <<< the smallest, so it renders first
      ignore_expires: "2026-05-09 00:00:00+00:00",
      age_days: null,
      limit_days: null,
      artifact: "creator"
    }
  ]')"

readonly ONE_RUNNER_HIGH_PROD_CLOCK_SKEW="$(jq --null-input '
  [
    {
      env: "aws-prod",
      trail_name: "runner-high-SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      full_id: "SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      severity: "high",
      vuln_url: "https://security.snyk.io/vuln/SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666",
      mechanism: "clock_skew",   # <<< selects the skew label and the "?" day count
      days_remaining: -99999,    # <<< the sentinel that must not reach the table
      ignore_expires: null,
      age_days: null,            # <<< no age can be stated for this vuln
      limit_days: 2,
      artifact: "runner"
    }
  ]')"

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
