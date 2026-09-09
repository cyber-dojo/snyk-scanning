#!/usr/bin/env bash

# A lower max_days value is stricter, so beta <= prod holds aws-beta at least as
# strict as aws-prod for every severity. kosli_env defaults to aws-beta, so the
# server build judges against the beta profile: that ordering is what makes the
# build gate fail a vuln before the day it could turn aws-prod non-compliant.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly rego_dir="$(cd "${my_dir}/.." && pwd)"

readonly PARAMS_BETA="${rego_dir}/rego.params.aws-beta.json"
readonly PARAMS_PROD="${rego_dir}/rego.params.aws-prod.json"

readonly SEVERITIES="critical high medium low"

test_beta_limits_le_prod_limits()
{
  local severity
  for severity in ${SEVERITIES}; do
    assert_beta_le_prod "${severity}"
  done
}

# A severity missing from a params file reads as zero in stamp_vuln_times.py and
# find_expiring_vulns.py, which fails every vuln of that severity rather than
# erroring.
test_every_profile_covers_every_severity()
{
  local params severity value
  for params in "${PARAMS_BETA}" "${PARAMS_PROD}"; do
    for severity in ${SEVERITIES}; do
      value="$(jq ".max_days_by_severity.${severity}" "${params}")"
      assertNotEquals "${params##*/} should name a ${severity} limit" "null" "${value}"
    done
  done
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

assert_beta_le_prod()
{
  local -r severity="${1}"
  local -r jq_filter=".max_days_by_severity.${severity}"
  local -r beta_val="$(jq "${jq_filter}" "${PARAMS_BETA}")"
  local -r prod_val="$(jq "${jq_filter}" "${PARAMS_PROD}")"
  assertTrue "beta ${severity} limit (${beta_val}) should be <= prod ${severity} limit (${prod_val})" \
    "[ ${beta_val} -le ${prod_val} ]"
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
