#!/usr/bin/env bash

# Pins the two implementations of the compliance taxonomy against each other.
#
# snyk-vuln-compliance.rego decides compliance inside kosli evaluate, server
# side. bin/find_expiring_vulns.py decides it again locally, because it answers a
# question the policy output cannot: how many days remain before the boundary.
# Neither can call the other, so the arithmetic exists twice and nothing forces
# the two to agree. They have disagreed before: see the incident recorded in
# tests/test_find_expiring_vulns_clock.sh.
#
# A vuln fails on the rego side when a violation names its full_id, which is the
# contract bin/vuln_annotations.py already splits on. It fails on the report side
# when it appears with days_remaining <= 0, which is the test
# .github/workflows/check-expiry-and-notify.yml applies to pick the Slack symbol.
#
# Each scenario states the ids it expects to fail and both sides are held to it,
# so a case where the two agree on a wrong answer fails here rather than passing
# quietly.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly repo_dir="$(cd "${my_dir}/.." && pwd)"

readonly KOSLI_ENV="aws-beta"
readonly PARAMS="${repo_dir}/rego.params.${KOSLI_ENV}.json"
readonly MEDIUM_LIMIT="$(jq '.max_days_by_severity.medium' "${PARAMS}")"

# Fixed point in time for all scenarios: 2025-05-31 00:00:00 UTC
readonly NOW_TS=1748736000
readonly SECONDS_PER_DAY=86400

# Sorted order matters where a scenario expects both: ALPINE sorts before GOLANG.
readonly GOLANG_ID="SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804"
readonly OPENSSL_ID="SNYK-ALPINE321-OPENSSL-13939001"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# No ignore entry: age alone decides, and the boundary convention differs between
# the two sides. The rego asks age < limit; the report subtracts to get
# days_remaining and its callers ask days_remaining <= 0. Those agree only if the
# limit day itself is non-compliant on both sides, which is what the exactly-at
# scenario pins.

test_agree_no_ignore_and_age_inside_the_limit()
{
  assert_verdicts_agree "" \
    "$(make_vuln "${GOLANG_ID}" medium $((NOW_TS - (MEDIUM_LIMIT - 1) * SECONDS_PER_DAY)) false 0 "" false)"
}

test_agree_no_ignore_and_age_exactly_at_the_limit()
{
  assert_verdicts_agree "${GOLANG_ID}" \
    "$(make_vuln "${GOLANG_ID}" medium $((NOW_TS - MEDIUM_LIMIT * SECONDS_PER_DAY)) false 0 "" false)"
}

test_agree_no_ignore_and_age_past_the_limit()
{
  assert_verdicts_agree "${GOLANG_ID}" \
    "$(make_vuln "${GOLANG_ID}" medium $((NOW_TS - (MEDIUM_LIMIT + 5) * SECONDS_PER_DAY)) false 0 "" false)"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# A .snyk ignore entry displaces the age entirely. The report reaches that verdict
# by a different route: an active ignore yields positive days_remaining, while a
# forever ignore is dropped from the report altogether, so absence has to read as
# compliant for the two sides to agree.

test_agree_active_ignore_holds_a_vuln_past_its_age_limit()
{
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT + 5) * SECONDS_PER_DAY))
  assert_verdicts_agree "" \
    "$(make_vuln "${GOLANG_ID}" medium "${old_ts}" true $((NOW_TS + SECONDS_PER_DAY)) "2025-06-01 00:00:00+00:00" false)"
}

test_agree_forever_ignore_holds_a_vuln_past_its_age_limit()
{
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT + 5) * SECONDS_PER_DAY))
  assert_verdicts_agree "" \
    "$(make_vuln "${GOLANG_ID}" medium "${old_ts}" true 0 "" true)"
}

test_agree_expired_ignore_fails_a_vuln_inside_its_age_limit()
{
  local -r young_ts=$((NOW_TS - SECONDS_PER_DAY))
  assert_verdicts_agree "${GOLANG_ID}" \
    "$(make_vuln "${GOLANG_ID}" medium "${young_ts}" true $((NOW_TS - SECONDS_PER_DAY)) "2025-05-30 00:00:00+00:00" false)"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Clock skew puts first_seen_ts ahead of now_ts and leaves the age unmeasurable.
# The rego has no age_days to compare, the report has no age to subtract, and
# both must land on non-compliant rather than on a day zero that a limit above
# zero would forgive.

test_agree_clock_skew_fails_a_vuln_whose_age_cannot_be_measured()
{
  assert_verdicts_agree "${GOLANG_ID}" \
    "$(make_vuln "${GOLANG_ID}" medium $((NOW_TS + 76)) false 0 "" false)"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# One artifact, two vulns, one verdict each. Both sides must name the failing
# vuln and only the failing vuln, which is what lets a single evaluation label
# every vuln of an artifact.

test_agree_naming_only_the_failing_vuln_of_two()
{
  local -r old_ts=$((NOW_TS - (MEDIUM_LIMIT + 5) * SECONDS_PER_DAY))
  assert_verdicts_agree "${OPENSSL_ID}" \
    "$(make_vuln "${GOLANG_ID}" medium "${old_ts}" true $((NOW_TS + SECONDS_PER_DAY)) "2025-06-01 00:00:00+00:00" false)" \
    "$(make_vuln "${OPENSSL_ID}" medium "${old_ts}" false 0 "" false)"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

# Assert that both implementations fail exactly the given comma-separated ids.
# Every remaining argument is one vuln object, as built by make_vuln.
assert_verdicts_agree()
{
  local -r expected_failing_ids="${1}"
  shift

  local -r vuln_dir="${SHUNIT_TMPDIR}/parity-vulns"
  local -r evaluation_file="${outputDir}/evaluation.json"
  local -r report_file="${outputDir}/report.json"

  rm -rf "${vuln_dir}"
  mkdir -p "${vuln_dir}"
  local index=0
  local vuln
  for vuln in "$@"; do
    index=$((index + 1))
    echo "${vuln}" > "${vuln_dir}/vuln-${index}.json"
  done

  # The policy input is built from the vuln files the same way the workflow
  # builds it, so both sides are reading one set of facts.
  jq --slurp '{vulns: .}' "${vuln_dir}"/vuln-*.json | kosli evaluate input \
    --policy "${repo_dir}/snyk-vuln-compliance.rego" \
    --params "@${PARAMS}" \
    --output json \
    >"${evaluation_file}" 2>"${stderrF}"

  # find_expiring_vulns.py reads rego.params.<env>.json from the current
  # directory, so run it from the repo root, against the same params file the
  # policy was given.
  (cd "${repo_dir}" && ./bin/find_expiring_vulns.py \
    --env "${KOSLI_ENV}" \
    --vuln-dir "${vuln_dir}" \
    >"${report_file}" 2>>"${stderrF}")

  local -r rego_failing_ids="$(jq --raw-output \
    '[.violations[]? | split(":")[0]] | unique | join(",")' "${evaluation_file}")"
  local -r report_failing_ids="$(jq --raw-output \
    '[.vulns[] | select(.days_remaining <= 0) | .full_id] | unique | join(",")' "${report_file}")"

  assertEquals "rego failing ids$(dump_parity "${evaluation_file}" "${report_file}")" \
    "${expected_failing_ids}" "${rego_failing_ids}"
  assertEquals "report failing ids$(dump_parity "${evaluation_file}" "${report_file}")" \
    "${expected_failing_ids}" "${report_failing_ids}"
}

# Show both verdicts side by side, so a disagreement says which side moved.
dump_parity()
{
  echo
  echo '<evaluation>'
  cat "${1}"
  echo '</evaluation>'
  echo '<report>'
  cat "${2}"
  echo '</report>'
  dump_stderr
}

make_vuln()
{
  local -r full_id="${1}"
  local -r severity="${2}"
  local -r first_seen_ts="${3}"
  local -r ignore_expires_exists="${4}"
  local -r ignore_expires_ts="${5}"
  local -r ignore_expires="${6}"
  local -r ignore_forever="${7}"
  # Carries the union of the fields the two sides read: the rego wants the
  # ignore fields and the timestamps, the report also wants trail_name and
  # vuln_url for its output rows.
  jq --null-input \
    --arg     full_id               "${full_id}" \
    --arg     severity              "${severity}" \
    --argjson now_ts                "${NOW_TS}" \
    --argjson first_seen_ts         "${first_seen_ts}" \
    --argjson ignore_expires_exists "${ignore_expires_exists}" \
    --argjson ignore_expires_ts     "${ignore_expires_ts}" \
    --arg     ignore_expires        "${ignore_expires}" \
    --argjson ignore_forever        "${ignore_forever}" \
    '{
       full_id:               $full_id,
       severity:              $severity,
       trail_name:            "runner-\($severity)-\($full_id)",
       vuln_url:              "https://security.snyk.io/vuln/\($full_id)",
       now_ts:                $now_ts,
       first_seen_ts:         $first_seen_ts,
       ignore_expires_exists: $ignore_expires_exists,
       ignore_expires_ts:     $ignore_expires_ts,
       ignore_expires:        $ignore_expires,
       ignore_forever:        $ignore_forever
     }'
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
