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

readonly MEDIUM_LIMIT_BETA="$(jq '.max_days_by_severity.medium' "${PARAMS_BETA}")"
readonly CRITICAL_LIMIT_BETA="$(jq '.max_days_by_severity.critical' "${PARAMS_BETA}")"
readonly CRITICAL_LIMIT_PROD="$(jq '.max_days_by_severity.critical' "${PARAMS_PROD}")"

# Fixed point in time for all tests: 2025-05-31 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SECONDS_PER_DAY=86400

# Per-vuln attestations are named snyk-<fingerprint>; the rego selects the entry
# matching data.params.attestation_name. Tests key their input and params to this.
readonly TEST_FINGERPRINT="1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a"

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
# Ignore with a far-future expiry => compliant (there is no cap on how far ahead)

test_allow_vuln_with_far_future_ignore()
{
  # 5 days old, ignore expiry is a year ahead -- compliant, there is no expiry cap
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + 365 * SECONDS_PER_DAY))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2026-05-31 00:00:00+00:00")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
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

test_deny_vuln_age_message_uses_whole_days_for_fractional_age()
{
  # 9.5 days old (fractional) over the 4-day medium limit -- the violation message
  # must report a whole number of days, not a Go %d-on-float error token.
  local -r first_seen_ts=$((NOW_TS - 9 * SECONDS_PER_DAY - SECONDS_PER_DAY / 2))
  local input
  input=$(make_input "test-trail" "medium" "${first_seen_ts}" false 0 "")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "trail 'test-trail': SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804 severity vuln age 9 days exceeds ${MEDIUM_LIMIT_BETA} day limit for severity medium"
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
    --arg     fingerprint   "${TEST_FINGERPRINT}" \
    --argjson now_ts        "${NOW_TS}" \
    --argjson first_seen_ts "${first_seen_ts}" \
    '{
      trail: {
        name: "test-trail",
        compliance_status: {
          attestations_statuses: {
            ("snyk-" + $fingerprint): {
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
# Per-fingerprint selection: one shared trail can carry two builds' verdicts.
# The rego must return the verdict for the fingerprint being evaluated, never
# the other build's. This is what stops a deploy-swap race from clobbering.

test_selects_only_the_matching_fingerprints_verdict()
{
  # The two real runner builds from the aws-prod deploy swap that triggered this:
  # incoming bc5fbc14 and outgoing bc8fb513.
  local -r fingerprintA="bdc8eb7fd4717d25b74f5bae58316e66c24283f17a03ce0256ea04fe7eee72b1"
  local -r fingerprintB="9db5a9987ba83419bec8ded2cc7bc5c9db814c8f0f275b5fe7228957ceed5ac2"
  # Both builds are well over the medium age limit. fingerprintA has an active ignore
  # (compliant); fingerprintB has no ignore (non-compliant on age).
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local -r future_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(jq -n \
    --arg     fingerprintA       "${fingerprintA}" \
    --arg     fingerprintB       "${fingerprintB}" \
    --argjson now_ts    "${NOW_TS}" \
    --argjson old_ts    "${old_ts}" \
    --argjson future_ts "${future_ts}" \
    '{
      trail: {
        name: "test-trail",
        compliance_status: {
          attestations_statuses: {
            ("snyk-" + $fingerprintA): {
              attestation_data: {
                full_id:               "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
                artifact_fingerprint:  $fingerprintA,
                now_ts:                $now_ts,
                first_seen_ts:         $old_ts,
                severity:              "medium",
                ignore_expires_exists: true,
                ignore_expires_ts:     $future_ts,
                ignore_expires:        "2025-06-01 00:00:00+00:00",
                ignore_forever:        false
              }
            },
            ("snyk-" + $fingerprintB): {
              attestation_data: {
                full_id:               "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
                artifact_fingerprint:  $fingerprintB,
                now_ts:                $now_ts,
                first_seen_ts:         $old_ts,
                severity:              "medium",
                ignore_expires_exists: false,
                ignore_expires_ts:     0,
                ignore_expires:        "",
                ignore_forever:        false
              }
            }
          }
        }
      }
    }')
  # fingerprintA: active ignore => compliant
  evaluate_rego "${input}" "${PARAMS_BETA}" "${fingerprintA}"
  assert_allow
  # fingerprintB: same trail, but no ignore and age over the limit => non-compliant
  evaluate_rego "${input}" "${PARAMS_BETA}" "${fingerprintB}"
  assert_deny
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

evaluate_rego()
{
  local -r input_json="${1}"
  local -r params_file="${2}"
  local -r fingerprint="${3:-${TEST_FINGERPRINT}}"
  # The rego needs both the severity limits (from the params file) and the
  # attestation name of the artifact being evaluated. The workflow builds that
  # name as snyk-<fingerprint>; mirror it here. --params takes a single value, so
  # merge them into one inline JSON object.
  local -r params="$(jq -c --arg name "snyk-${fingerprint}" '. + {attestation_name: $name}' "${params_file}")"
  echo "${input_json}" | kosli evaluate input \
    --policy "${rego_dir}/snyk-vuln-compliance.rego" \
    --params "${params}" \
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
    --arg     fingerprint           "${TEST_FINGERPRINT}" \
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
            ("snyk-" + $fingerprint): {
              attestation_data: {
                full_id:               "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
                artifact_fingerprint:  $fingerprint,
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
