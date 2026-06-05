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

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_summary()
{
  python3 "${my_dir}/../bin/print_expiring_vulns_summary.py" \
    --env   "${1}" \
    --vulns "${2}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

ONE_CREATOR_HIGH_BETA='[{"env":"aws-beta","trail_name":"creator-high-SNYK-GOLANG-NETHTTP-3321444","full_id":"SNYK-GOLANG-NETHTTP-3321444","severity":"high","vuln_url":"https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444","mechanism":"rego_limit","days_remaining":2.3,"ignore_expires":null,"age_days":4.7,"limit_days":7,"artifact":"creator"}]'

ONE_CREATOR_HIGH_PROD='[{"env":"aws-prod","trail_name":"creator-high-SNYK-GOLANG-NETHTTP-3321444","full_id":"SNYK-GOLANG-NETHTTP-3321444","severity":"high","vuln_url":"https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444","mechanism":"rego_limit","days_remaining":2.3,"ignore_expires":null,"age_days":4.7,"limit_days":7,"artifact":"creator"}]'

CREATOR_MIXED_BETA='[{"env":"aws-beta","trail_name":"creator-medium-SNYK-GOLANG-GOLANGORGJWTV4-3180456","full_id":"SNYK-GOLANG-GOLANGORGJWTV4-3180456","severity":"medium","vuln_url":"https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGJWTV4-3180456","mechanism":"rego_limit","days_remaining":6.0,"ignore_expires":null,"age_days":24.0,"limit_days":30,"artifact":"creator"},{"env":"aws-beta","trail_name":"creator-high-SNYK-GOLANG-NETHTTP-3321444","full_id":"SNYK-GOLANG-NETHTTP-3321444","severity":"high","vuln_url":"https://security.snyk.io/vuln/SNYK-GOLANG-NETHTTP-3321444","mechanism":"rego_limit","days_remaining":5.0,"ignore_expires":null,"age_days":2.0,"limit_days":7,"artifact":"creator"},{"env":"aws-beta","trail_name":"creator-high-SNYK-GOLANG-GOLANG-3208976","full_id":"SNYK-GOLANG-GOLANG-3208976","severity":"high","vuln_url":"https://security.snyk.io/vuln/SNYK-GOLANG-GOLANG-3208976","mechanism":"dot_snyk_expiry","days_remaining":1.0,"ignore_expires":"2026-05-09 00:00:00+00:00","age_days":null,"limit_days":null,"artifact":"creator"}]'

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
