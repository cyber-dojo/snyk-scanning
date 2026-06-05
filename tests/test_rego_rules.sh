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
readonly PARAMS_MISSING_IGNORE_EXPIRY="${my_dir}/rego.params.missing-ignore-expiry-days.json"

readonly MEDIUM_LIMIT_BETA="$(jq '.max_days_by_severity.medium' "${PARAMS_BETA}")"
readonly CRITICAL_LIMIT_BETA="$(jq '.max_days_by_severity.critical' "${PARAMS_BETA}")"
readonly CRITICAL_LIMIT_PROD="$(jq '.max_days_by_severity.critical' "${PARAMS_PROD}")"
readonly MAX_IGNORE_EXPIRY_DAYS="$(jq '.max_ignore_expiry_days' "${PARAMS_BETA}")"

# Fixed point in time for all tests: 2025-05-31 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SECONDS_PER_DAY=86400

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Active ignore => compliant regardless of age

test_allow_vuln_with_active_ignore()
{
  # over the medium limit but has an active ignore -- age does not matter
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-01 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Forever ignore (.snyk entry with no expiry) => compliant regardless of age

test_allow_vuln_with_forever_ignore()
{
  # well over the medium age limit, but ignored forever (.snyk entry has no expiry) -- age does not matter
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true 0 "" true)
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore => age within limit => compliant

test_allow_medium_vuln_within_age_limit()
{
  # one day below the medium limit: within threshold
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA - 1) * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

test_allow_critical_vuln_within_age_limit_on_beta()
{
  # one day below the critical limit on aws-beta: within threshold
  local -r first_seen_ts=$((NOW_TS - (CRITICAL_LIMIT_BETA - 1) * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Expired ignore => non-compliant regardless of age

test_deny_vuln_with_expired_ignore()
{
  # 5 days old but ignore has expired -- age does not matter
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS - SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-05-30 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 snyk ignore entry expired at 2025-05-30 00:00:00+00:00"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Ignore expiry too far ahead => non-compliant regardless of age

test_deny_vuln_with_ignore_expiry_too_far_ahead()
{
  # 5 days old but ignore expires one day beyond the max_ignore_expiry_days limit
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + (MAX_IGNORE_EXPIRY_DAYS + 1) * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2026-07-01 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 snyk ignore entry expiry 2026-07-01 00:00:00+00:00 is more than ${MAX_IGNORE_EXPIRY_DAYS} days ahead"
}

test_allow_vuln_with_ignore_expiry_at_limit()
{
  # 5 days old, ignore expires exactly at the max_ignore_expiry_days limit -- compliant
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + MAX_IGNORE_EXPIRY_DAYS * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-30 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Missing max_ignore_expiry_days param => non-compliant (fail-safe)

test_deny_active_ignore_when_max_ignore_expiry_days_param_is_missing()
{
  # A missing max_ignore_expiry_days param must produce deny, not silent
  # compliance. This guards against using not ignore_too_far_ahead(vuln)
  # in the policy, which would be vacuously true when the param is absent.
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-01 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_MISSING_IGNORE_EXPIRY}"
  assert_deny
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore, age exceeded => non-compliant

test_deny_medium_vuln_at_age_limit()
{
  # at the medium age limit: non-compliant
  local -r first_seen_ts=$((NOW_TS - MEDIUM_LIMIT_BETA * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age ${MEDIUM_LIMIT_BETA} days exceeds ${MEDIUM_LIMIT_BETA} day limit for severity medium"
}

test_deny_critical_vuln_at_age_limit_on_beta()
{
  # at the critical age limit on aws-beta: non-compliant
  local -r first_seen_ts=$((NOW_TS - CRITICAL_LIMIT_BETA * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age ${CRITICAL_LIMIT_BETA} days exceeds ${CRITICAL_LIMIT_BETA} day limit for severity critical"
}

test_deny_critical_vuln_on_prod_day_zero()
{
  # 0 days old: critical on aws-prod has max=0, so even day zero is non-compliant
  local input
  input=$(make_input "test-trail" "critical" "${NOW_TS}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_PROD}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age 0 days exceeds ${CRITICAL_LIMIT_PROD} day limit for severity critical"
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
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 1) * SECONDS_PER_DAY))
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
  local -r ignore_forever="${7:-false}"
  jq -n \
    --arg     trail_name            "${trail_name}" \
    --arg     severity              "${severity}" \
    --argjson now_ts                "${NOW_TS}" \
    --argjson first_seen_ts         "${first_seen_ts}" \
    --argjson ignore_expires_exists "${ignore_expires_exists}" \
    --argjson ignore_expires_ts     "${ignore_expires_ts}" \
    --arg     ignore_expires        "${ignore_expires}" \
    --argjson ignore_forever        "${ignore_forever}" \
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
                ignore_expires:        $ignore_expires,
                ignore_forever:        $ignore_forever
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
