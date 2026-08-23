#!/usr/bin/env bash

# Tests print_stale_snyk_entries_summary.py, which renders the step-summary table
# naming .snyk ignore entries that no longer match any vuln Snyk reports.
#
# combine_snyk.py writes the ids as a JSON array of strings. An empty array
# renders nothing at all, so a scan with nothing stale adds no table to the job
# summary.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/print_stale_snyk_entries_summary.py"

readonly ARTIFACT_NAME="244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88"
readonly FINGERPRINT="f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096"
readonly SNYK_VERSION="v1.1300.2"

readonly GOLANG_ID="SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804"
readonly OPENSSL_ID="SNYK-ALPINE321-OPENSSL-13939001"

# Nothing stale means nothing to say, so the job summary gains no empty table.

test_no_stale_entries_renders_nothing()
{
  run_summary '[]'
  assert_status_equals 0
  assert_stdout_empty
  assert_stderr_equals ""
}

test_one_stale_entry_names_it_under_the_scan_details()
{
  run_summary "[\"${GOLANG_ID}\"]"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_ONE_ENTRY}"
  assert_stderr_equals ""
}

# The count in the heading row and the number of id rows are separate pieces of
# output, so two entries pins that they move together.

test_two_stale_entries_are_counted_and_both_named()
{
  run_summary "[\"${GOLANG_ID}\",\"${OPENSSL_ID}\"]"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_TWO_ENTRIES}"
  assert_stderr_equals ""
}

test_h_prints_help_with_an_example()
{
  "${script}" -h >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_includes "usage:"
  assert_stdout_includes "bin/print_stale_snyk_entries_summary.py"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_summary()
{
  local -r stale_ids_json="${1}"
  local -r stale_file="${SHUNIT_TMPDIR}/stale_vulns.json"
  echo "${stale_ids_json}" > "${stale_file}"
  "${script}" "${stale_file}" \
    --artifact-name  "${ARTIFACT_NAME}" \
    --fingerprint    "${FINGERPRINT}" \
    --snyk-version   "${SNYK_VERSION}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

readonly EXPECTED_ONE_ENTRY='<table>
<tr><td><b>Stale .snyk entries</b></td><td>1 found</td></tr>
<tr><td><b>Artifact name</b></td><td>244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88</td></tr>
<tr><td><b>Artifact fingerprint</b></td><td>f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096</td></tr>
<tr><td><b>Snyk version</b></td><td>v1.1300.2</td></tr>
<tr><td></td><td>SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804</td></tr>
</table>'

readonly EXPECTED_TWO_ENTRIES='<table>
<tr><td><b>Stale .snyk entries</b></td><td>2 found</td></tr>
<tr><td><b>Artifact name</b></td><td>244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88</td></tr>
<tr><td><b>Artifact fingerprint</b></td><td>f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096</td></tr>
<tr><td><b>Snyk version</b></td><td>v1.1300.2</td></tr>
<tr><td></td><td>SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804</td></tr>
<tr><td></td><td>SNYK-ALPINE321-OPENSSL-13939001</td></tr>
</table>'

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
