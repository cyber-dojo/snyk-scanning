#!/usr/bin/env bash

# Tests that aws-prod param limits are <= the equivalent aws-beta limits.
# A lower max_days value means stricter enforcement, so prod <= beta means
# prod is always at least as strict as beta.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly rego_dir="$(cd "${my_dir}/.." && pwd)"

readonly PARAMS_BETA="${rego_dir}/rego.params.aws-beta.json"
readonly PARAMS_PROD="${rego_dir}/rego.params.aws-prod.json"

test_prod_critical_limit_le_beta_critical_limit()
{
  assert_prod_le_beta "critical limit" '.max_days_by_severity.critical'
}

test_prod_high_limit_le_beta_high_limit()
{
  assert_prod_le_beta "high limit" '.max_days_by_severity.high'
}

test_prod_medium_limit_le_beta_medium_limit()
{
  assert_prod_le_beta "medium limit" '.max_days_by_severity.medium'
}

test_prod_low_limit_le_beta_low_limit()
{
  assert_prod_le_beta "low limit" '.max_days_by_severity.low'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

assert_prod_le_beta()
{
  local -r label="${1}"
  local -r jq_filter="${2}"
  local -r prod_val="$(jq "${jq_filter}" "${PARAMS_PROD}")"
  local -r beta_val="$(jq "${jq_filter}" "${PARAMS_BETA}")"
  assertTrue "prod ${label} (${prod_val}) should be <= beta ${label} (${beta_val})" \
    "[ ${prod_val} -le ${beta_val} ]"
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
