#!/usr/bin/env bash

# Tests for snyk-vuln-compliance.rego, which judges every vuln found in one
# artifact in a single evaluation, covering the four compliance cases:
#   Active ignore => compliant regardless of age
#   No ignore => age within limit => compliant
#   Expired ignore => non-compliant regardless of age
#   No ignore, age exceeded => non-compliant
# Also pins the two properties the caller relies on to label each vuln pass or
# fail from one evaluation: every violation message names its vuln, and an
# artifact is compliant only when every one of its vulns is.

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

readonly TEST_FINGERPRINT="1d7fc67092bee8492e5019ca0175edf5189e4fc71a4b3a21976c64070def810a"

readonly VULN_ID="SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804"
readonly VULN_ID_OPENSSL="SNYK-ALPINE321-OPENSSL-13939001"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Active ignore => compliant regardless of age

test_allow_vuln_with_active_ignore()
{
  # over the medium limit but has an active ignore -- age does not matter
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-06-01 00:00:00+00:00")")
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
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" true 0 "" true)")
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
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

test_allow_critical_vuln_within_age_limit_on_beta()
{
  # one day below the critical limit on aws-beta: within threshold
  local -r first_seen_ts=$((NOW_TS - (CRITICAL_LIMIT_BETA - 1) * SECONDS_PER_DAY))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "critical" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# An artifact with no vulns at all is compliant

test_allow_artifact_with_no_vulns()
{
  evaluate_rego '{"vulns": []}' "${PARAMS_PROD}"
  assert_allow
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Compliance must be proved. An input that does not carry the vulns key at all
# leaves the allow rule body undefined, so allow falls back to its false default.

test_deny_input_with_no_vulns_key()
{
  evaluate_rego '{}' "${PARAMS_BETA}"
  assert_deny
  assert_violations_null
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Expired ignore => non-compliant regardless of age

test_deny_vuln_with_expired_ignore()
{
  # 5 days old but ignore has expired -- age does not matter
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS - SECONDS_PER_DAY))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2025-05-30 00:00:00+00:00")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "${VULN_ID}: snyk ignore entry expired at 2025-05-30 00:00:00+00:00"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Ignore with a far-future expiry => compliant (there is no cap on how far ahead)

test_allow_vuln_with_far_future_ignore()
{
  # 5 days old, ignore expiry is a year ahead -- compliant, there is no expiry cap
  local -r first_seen_ts=$((NOW_TS - 5 * SECONDS_PER_DAY))
  local -r ignore_expires_ts=$((NOW_TS + 365 * SECONDS_PER_DAY))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" true "${ignore_expires_ts}" "2026-05-31 00:00:00+00:00")")
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
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "${VULN_ID}: medium severity vuln age ${MEDIUM_LIMIT_BETA} days exceeds ${MEDIUM_LIMIT_BETA} day limit"
}

test_deny_vuln_age_message_uses_whole_days_for_fractional_age()
{
  # 9.5 days old (fractional) over the 4-day medium limit -- the violation message
  # must report a whole number of days, not a Go %d-on-float error token.
  local -r first_seen_ts=$((NOW_TS - 9 * SECONDS_PER_DAY - SECONDS_PER_DAY / 2))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "medium" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "${VULN_ID}: medium severity vuln age 9 days exceeds ${MEDIUM_LIMIT_BETA} day limit"
}

test_deny_critical_vuln_at_age_limit_on_beta()
{
  # at the critical age limit on aws-beta: non-compliant
  local -r first_seen_ts=$((NOW_TS - CRITICAL_LIMIT_BETA * SECONDS_PER_DAY))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "critical" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_message "${VULN_ID}: critical severity vuln age ${CRITICAL_LIMIT_BETA} days exceeds ${CRITICAL_LIMIT_BETA} day limit"
}

test_deny_critical_vuln_on_prod_day_zero()
{
  # 0 days old: critical on aws-prod has max=0, so even day zero is non-compliant
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "critical" "${NOW_TS}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_PROD}"
  assert_deny
  assert_violation_message "${VULN_ID}: critical severity vuln age 0 days exceeds ${CRITICAL_LIMIT_PROD} day limit"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore, first_seen_ts ahead of now_ts => non-compliant
# now_ts is stamped in the find-snyk-vulns job; first_seen_ts is the trail
# created_at set by `kosli begin trail` in the job after it. On a vuln's first
# sighting first_seen_ts is therefore ahead of now_ts, by 76 seconds in the
# aws-prod run of 2026-08-20. A negative age must not satisfy a severity limit.

test_deny_critical_vuln_on_prod_when_first_seen_is_ahead_of_now()
{
  local -r first_seen_ts=$((NOW_TS + 76))
  local input
  input=$(make_input "$(make_vuln "${VULN_ID}" "critical" "${first_seen_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_PROD}"
  assert_deny
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Demonstrate OPA undefined-field footgun: wrong field name in input silently
# makes a violation rule body fail, producing no diagnostic where one is due.
# See docs/rego-undefined-field-in-violations.md

test_deny_vuln_over_age_limit_but_with_wrong_field_name_in_input()
{
  # 30 days old: denied, but not_full_id instead of full_id in the input means
  # vuln.full_id is undefined in the rego, so violations stays null (no
  # diagnostic). allow is still correctly false because vuln_is_compliant does
  # not reference full_id.
  local -r first_seen_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 1) * SECONDS_PER_DAY))
  local vuln
  vuln=$(jq -n \
    --argjson now_ts        "${NOW_TS}" \
    --argjson first_seen_ts "${first_seen_ts}" \
    '{
       not_full_id:           "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804",
       now_ts:                $now_ts,
       first_seen_ts:         $first_seen_ts,
       severity:              "medium",
       ignore_expires_exists: false,
       ignore_expires_ts:     0,
       ignore_expires:        ""
     }')
  evaluate_rego "$(make_input "${vuln}")" "${PARAMS_BETA}"
  assert_deny
  assert_violations_null
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# One evaluation covers every vuln in the artifact. The caller labels each vuln
# pass or fail by whether a violation names it, so a mixed artifact must deny
# and must name the failing vuln only.

test_deny_names_the_failing_vuln_only_when_one_of_two_is_over_the_limit()
{
  # Both are well over the medium age limit. VULN_ID has an active ignore
  # (compliant); VULN_ID_OPENSSL has no ignore (non-compliant on age).
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local -r future_ts=$((NOW_TS + SECONDS_PER_DAY))
  local input
  input=$(make_input \
    "$(make_vuln "${VULN_ID}" "medium" "${old_ts}" true "${future_ts}" "2025-06-01 00:00:00+00:00")" \
    "$(make_vuln "${VULN_ID_OPENSSL}" "medium" "${old_ts}" false 0 "")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_count 1
  assert_violation_message "${VULN_ID_OPENSSL}: medium severity vuln age $((MEDIUM_LIMIT_BETA + 5)) days exceeds ${MEDIUM_LIMIT_BETA} day limit"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Every violation message starts with its vuln's full_id followed by a colon.
# That is the contract the caller splits on to recover the set of failing ids.

test_every_violation_message_starts_with_its_vuln_id()
{
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT_BETA + 5) * SECONDS_PER_DAY))
  local -r expired_ts=$((NOW_TS - SECONDS_PER_DAY))
  local input
  input=$(make_input \
    "$(make_vuln "${VULN_ID}" "medium" "${old_ts}" false 0 "")" \
    "$(make_vuln "${VULN_ID_OPENSSL}" "medium" "${old_ts}" true "${expired_ts}" "2025-05-30 00:00:00+00:00")")
  evaluate_rego "${input}" "${PARAMS_BETA}"
  assert_deny
  assert_violation_count 2
  local -r ids="$(jq --raw-output '[.violations[] | split(":")[0]] | sort | join(",")' "${stdoutF}")"
  assertEquals "violation ids:$(dump_sss)" "${VULN_ID_OPENSSL},${VULN_ID}" "${ids}"
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
  # Each argument is one vuln JSON object, as built by make_vuln.
  printf '%s\n' "$@" | jq --slurp '{vulns: .}'
}

make_vuln()
{
  local -r full_id="${1}"
  local -r severity="${2}"
  local -r first_seen_ts="${3}"
  local -r ignore_expires_exists="${4}"
  local -r ignore_expires_ts="${5}"
  local -r ignore_expires="${6}"
  local -r ignore_forever="${7:-false}"
  jq -n \
    --arg     full_id               "${full_id}" \
    --arg     severity              "${severity}" \
    --arg     fingerprint           "${TEST_FINGERPRINT}" \
    --argjson now_ts                "${NOW_TS}" \
    --argjson first_seen_ts         "${first_seen_ts}" \
    --argjson ignore_expires_exists "${ignore_expires_exists}" \
    --argjson ignore_expires_ts     "${ignore_expires_ts}" \
    --arg     ignore_expires        "${ignore_expires}" \
    --argjson ignore_forever        "${ignore_forever}" \
    '{
       full_id:               $full_id,
       artifact_fingerprint:  $fingerprint,
       now_ts:                $now_ts,
       first_seen_ts:         $first_seen_ts,
       severity:              $severity,
       ignore_expires_exists: $ignore_expires_exists,
       ignore_expires_ts:     $ignore_expires_ts,
       ignore_expires:        $ignore_expires,
       ignore_forever:        $ignore_forever
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

assert_violation_count()
{
  local -r expected="${1}"
  local -r count="$(jq '.violations | length' "${stdoutF}")"
  assertEquals "violations count:$(dump_sss)" "${expected}" "${count}"
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
