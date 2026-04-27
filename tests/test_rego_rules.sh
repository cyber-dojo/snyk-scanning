#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly rego_dir="$(cd "${my_dir}/.." && pwd)"

readonly PARAMS_BETA="${rego_dir}/rego.params.aws-beta.json"
readonly PARAMS_PROD="${rego_dir}/rego.params.aws-prod.json"

# Fixed point in time for all tests: 2025-05-31 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SECONDS_PER_DAY=86400

evaluate_rego()
{
  local -r input_json="${1}"
  local -r params_file="${2}"
  echo "${input_json}" | kosli evaluate input \
    --policy "${rego_dir}/snyk-vuln-compliance.rego" \
    --params "@${params_file}" \
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
      trails: [{
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
      }]
    }'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_allow_no_trails()
{
  evaluate_rego '{"trails":[]}' "${PARAMS_BETA}"
  assert_status_equals 0
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Rule-1: age check

test_allow_medium_vuln_within_age_limit()
{
  # 29 days old: below the 30-day medium threshold
  local -r first_seen_ts=$((NOW_TS - 29 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 0
}

test_deny_medium_vuln_at_age_limit()
{
  # 30 days old: at the 30-day medium threshold (>= means non-compliant)
  local -r first_seen_ts=$((NOW_TS - 30 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 1
}

test_allow_critical_vuln_within_age_limit_on_beta()
{
  # 2 days old: below the 3-day critical threshold on aws-beta
  local -r first_seen_ts=$((NOW_TS - 2 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 0
}

test_deny_critical_vuln_at_age_limit_on_beta()
{
  # 3 days old: at the 3-day critical threshold on aws-beta
  local -r first_seen_ts=$((NOW_TS - 3 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "critical" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 1
}

test_deny_critical_vuln_on_prod_day_zero()
{
  # 0 days old: critical on aws-prod has max=0, so even day zero is non-compliant
  local input
  input=$(make_input "test-trail" "critical" "${NOW_TS}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_PROD}"
  assert_status_equals 1
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Rule-2: expired ignore check

test_allow_vuln_with_active_ignore()
{
  # Ignore entry exists but has not yet expired
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-01 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 0
}

test_deny_vuln_with_expired_ignore()
{
  # Ignore entry exists and has expired
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS - SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-05-30 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_status_equals 1
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
