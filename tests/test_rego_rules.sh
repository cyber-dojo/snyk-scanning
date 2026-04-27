#!/usr/bin/env bash

# Tests for snyk-vuln-compliance.rego covering the four compliance cases:
#   Active ignore => compliant regardless of age
#   No ignore => age within limit => compliant
#   Expired ignore => non-compliant regardless of age
#   No ignore, age exceeded => non-compliant

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly rego_dir="$(cd "${my_dir}/.." && pwd)"

readonly PARAMS_BETA="${rego_dir}/rego.params.aws-beta.json"
readonly PARAMS_PROD="${rego_dir}/rego.params.aws-prod.json"

# Fixed point in time for all tests: 2025-05-31 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SECONDS_PER_DAY=86400

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Active ignore => compliant regardless of age

test_allow_vuln_with_active_ignore()
{
  # 35 days old (over the 30-day medium limit) but has an active ignore -- age does not matter
  local -r first_seen_ts=$((NOW_TS - 35 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-01 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore => age within limit => compliant

test_allow_medium_vuln_within_age_limit()
{
  # 29 days old: below the 30-day medium threshold
  local -r first_seen_ts=$((NOW_TS - 29 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

test_allow_critical_vuln_within_age_limit_on_beta()
{
  # 2 days old: below the 3-day critical threshold on aws-beta
  local -r first_seen_ts=$((NOW_TS - 2 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Expired ignore => non-compliant regardless of age

test_deny_vuln_with_expired_ignore()
{
  # 5 days old (within the 30-day medium limit) but ignore has expired -- age does not matter
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS - SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-05-30 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 snyk ignore entry expired at 2025-05-30 00:00:00+00:00"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore, age exceeded => non-compliant

test_deny_medium_vuln_at_age_limit()
{
  # 30 days old: at the 30-day medium threshold (>= means non-compliant)
  local -r first_seen_ts=$((NOW_TS - 30 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age 30 days exceeds 30 day limit for severity medium"
}

test_deny_critical_vuln_at_age_limit_on_beta()
{
  # 3 days old: at the 3-day critical threshold on aws-beta
  local -r first_seen_ts=$((NOW_TS - 3 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age 3 days exceeds 3 day limit for severity critical"
}

test_deny_critical_vuln_on_prod_day_zero()
{
  # 0 days old: critical on aws-prod has max=0, so even day zero is non-compliant
  local input
  input=$(make_input "test-trail" "critical" "${NOW_TS}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_PROD}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age 0 days exceeds 0 day limit for severity critical"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Demonstrate OPA undefined-field footgun: wrong field name in input silently
# makes a violation rule body fail, producing compliant when it should be denied.
# See docs/rego-undefined-field-in-violations.md

test_deny_vuln_over_age_limit_but_with_wrong_field_name_in_input()
{
  # 30 days old: should be denied, but not_full_id instead of full_id in the
  # input means vuln.full_id is undefined in the rego, violations stays null
  # (no diagnostic). allow is still correctly false because trail_is_compliant
  # does not reference full_id.
  local -r first_seen_ts=$((NOW_TS - 30 * SECONDS_PER_DAY))
  local input
  input=$(jq -n \
    --argjson now_ts        "${NOW_TS}" \
    --argjson first_seen_ts "${first_seen_ts}" \
    '{
      trail: {
        name: "test-trail",
        compliance_status: {
          attestations_statuses: {
            snyk: {
              attestation_data: {
                not_full_id:           "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
                now_ts:                $now_ts,
                first_seen_ts:         $first_seen_ts,
                severity:              "medium",
                ignore_expires_exists: false,
                ignore_expires_ts:     0,
                ignore_expires:        ""
              }
            }
          }
        }
      }
    }')
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violations_null
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

evaluate_rego()
{
  local -r input_json="${1}"
  local -r params_file="${2}"
  echo "${input_json}" | kosli evaluate input \
    --policy "${rego_dir}/snyk-vuln-compliance.rego" \
    --params "@${params_file}" \
    --output json \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

make_input()
{
  local -r trail_name="${1}"
  local -r severity="${2}"
  local -r first_seen_ts="${3}"
  local -r ignore_expires_exists="${4}"
  local -r ignore_expires_ts="${5}"
  local -r ignore_expires="${6}"
  jq -n \
    --arg     trail_name            "${trail_name}" \
    --arg     severity              "${severity}" \
    --argjson now_ts                "${NOW_TS}" \
    --argjson first_seen_ts         "${first_seen_ts}" \
    --argjson ignore_expires_exists "${ignore_expires_exists}" \
    --argjson ignore_expires_ts     "${ignore_expires_ts}" \
    --arg     ignore_expires        "${ignore_expires}" \
    '{
      trail: {
        name: $trail_name,
        compliance_status: {
          attestations_statuses: {
            snyk: {
              attestation_data: {
                full_id:               "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
                now_ts:                $now_ts,
                first_seen_ts:         $first_seen_ts,
                severity:              $severity,
                ignore_expires_exists: $ignore_expires_exists,
                ignore_expires_ts:     $ignore_expires_ts,
                ignore_expires:        $ignore_expires
              }
            }
          }
        }
      }
    }'
}

assert_allow()
{
  local -r allow="$(jq '.allow' "${stdoutF}")"
  assertEquals "allow:$(dump_sss)" "true" "${allow}"
  local -r violations="$(jq '.violations' "${stdoutF}")"
  assertEquals "violations:$(dump_sss)" "null" "${violations}"
}

assert_deny()
{
  local -r allow="$(jq '.allow' "${stdoutF}")"
  assertEquals "allow:$(dump_sss)" "false" "${allow}"
}

assert_violations_null()
{
  local -r violations="$(jq '.violations' "${stdoutF}")"
  assertEquals "violations:$(dump_sss)" "null" "${violations}"
}

assert_violation_message()
{
  local -r expected="${1}"
  local found
  found="$(jq --arg s "${expected}" '.violations[] | select(. == $s)' "${stdoutF}")"
  if [ -z "${found}" ]; then
    dump_sss
    fail "expected violations to include '${expected}'"
  fi
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
