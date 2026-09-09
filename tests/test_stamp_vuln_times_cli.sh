#!/usr/bin/env bash

# Tests bin/stamp_vuln_times.py as the workflow calls it: a trail file and the
# matrix vuln in, the attestation data out. The trail file is the contract this
# pins, because both ends of the age are read from it and nothing else.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/stamp_vuln_times.py"
readonly params="${my_dir}/../rego.params.aws-beta.json"

# Taken from the real aws-beta trail for this vuln, so the origin has the
# microseconds the Kosli server actually reports. NOW_TS is exactly 1.5 days
# later, which makes age_days assertable to the digit.
readonly FIRST_SEEN_TS=1787194041.4591043
readonly NOW_TS=1787323641.4591043
readonly HIGH_LIMIT_BETA=2

readonly VULN_ID="SNYK-GOLANG-GITHUBCOMMOBYGOARCHIVE-18958666"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_both_instants_come_from_the_one_trail_read()
{
  run_stamp "$(make_trail "${FIRST_SEEN_TS}" "${NOW_TS}")"
  assert_status_equals 0
  assert_stderr_equals ""
  assert_stdout_json_equals '.first_seen_ts' "${FIRST_SEEN_TS}"
  assert_stdout_json_equals '.now_ts' "${NOW_TS}"
}

test_now_ts_is_last_modified_at_and_not_created_at()
{
  run_stamp "$(make_trail "${FIRST_SEEN_TS}" "${NOW_TS}")"
  assert_status_equals 0
  assert_stdout_json_equals '.now_ts != .first_seen_ts' 'true'
}

test_the_age_is_measured_between_those_two_instants()
{
  run_stamp "$(make_trail "${FIRST_SEEN_TS}" "${NOW_TS}")"
  assert_status_equals 0
  assert_stdout_json_equals '.age_days' '1.5'
  assert_stdout_json_equals '.limit_days' "${HIGH_LIMIT_BETA}"
}

test_the_rendered_strings_match_the_stamped_instants()
{
  run_stamp "$(make_trail "${FIRST_SEEN_TS}" "${NOW_TS}")"
  assert_status_equals 0
  assert_stdout_json_equals '.first_seen' '"2026-08-20 02:47:21.459104+00:00"'
  assert_stdout_json_equals '.now' '"2026-08-21 14:47:21.459104+00:00"'
}

test_the_vulns_own_fields_survive_the_stamping()
{
  run_stamp "$(make_trail "${FIRST_SEEN_TS}" "${NOW_TS}")"
  assert_status_equals 0
  assert_stdout_json_equals '.full_id' "\"${VULN_ID}\""
  assert_stdout_json_equals '.severity' '"high"'
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# A trail that cannot supply both instants must stop the scan. Stamping an age
# from a half-read trail would put a number on a measurement never made.

test_a_trail_with_no_last_modified_at_is_refused()
{
  run_stamp "$(jq --null-input --argjson c "${FIRST_SEEN_TS}" '{created_at: $c}')"
  assert_status_equals 44
  assert_stdout_empty
  assert_stderr_line_count_equals 1
  assert_stderr_includes "trail has no last_modified_at"
}

test_a_trail_with_no_created_at_is_refused()
{
  run_stamp "$(jq --null-input --argjson m "${NOW_TS}" '{last_modified_at: $m}')"
  assert_status_equals 44
  assert_stdout_empty
  assert_stderr_line_count_equals 1
  assert_stderr_includes "trail has no created_at"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# last_modified_at earlier than the created_at of the same object is a broken
# server invariant, not a fact about the vuln, so it exits 44 and writes nothing.

test_last_modified_at_before_created_at_exits_44()
{
  run_stamp "$(make_trail "${NOW_TS}" "${FIRST_SEEN_TS}")"
  assert_status_equals 44
  assert_stdout_empty
  assert_stderr_includes "the vuln age cannot be measured"
}

test_the_refusal_names_the_vuln_and_both_instants()
{
  run_stamp "$(make_trail "${NOW_TS}" "${FIRST_SEEN_TS}")"
  assert_status_equals 44
  assert_stderr_includes "${VULN_ID}"
  assert_stderr_includes "first_seen ${NOW_TS} is ahead of now ${FIRST_SEEN_TS}"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

test_h_prints_help_with_an_example()
{
  "${script}" -h >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_includes "usage:"
  assert_stdout_includes "bin/stamp_vuln_times.py trail.json"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_stamp()
{
  local -r trail_json="${1}"
  local -r trail_file="${SHUNIT_TMPDIR}/trail.json"
  echo "${trail_json}" > "${trail_file}"
  "${script}" "${trail_file}" "$(make_vuln)" \
    --params-file "${params}" >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

assert_stdout_json_equals()
{
  local -r jq_filter="${1}"
  local -r expected="${2}"
  local -r actual="$(jq --compact-output "${jq_filter}" <${stdoutF})"
  assertEquals "${jq_filter}" "${expected}" "${actual}"
}

make_trail()
{
  local -r created_at="${1}"
  local -r last_modified_at="${2}"
  jq --null-input \
    --argjson created_at "${created_at}" \
    --argjson last_modified_at "${last_modified_at}" \
    '{created_at: $created_at, last_modified_at: $last_modified_at}'
}

# The matrix data for one vuln, as find-snyk-vulns emits it, before stamping.
make_vuln()
{
  jq --null-input --compact-output --arg full_id "${VULN_ID}" '
    {
      full_id: $full_id,
      severity: "high",
      trail_name: ("runner-high-" + $full_id),
      artifact_fingerprint: "f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096",
      ignore_expires_exists: false
    }'
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
