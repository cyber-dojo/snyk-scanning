#!/usr/bin/env bash

# Tests print_artifact_scan_summary.py, which renders the step-summary header for
# one artifact's Snyk scan: the compliance verdict, how many vulns were found,
# what was scanned, and a link to the attestation.
#
# The expected output carries the tick and cross literally, copied from the
# workflow this replaced. The script writes them as escapes, so these
# assertions are what proves the escapes name the same characters.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/print_artifact_scan_summary.py"

readonly REPO_NAME="snyk-scanning"
readonly ARTIFACT_NAME="244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:85cac88"
readonly FINGERPRINT="f3cdc22a599ddb789e7791389a5a58b43fd9c30d3af079aec392d5962d181096"
readonly SNYK_VERSION="v1.1300.2"
readonly ATTESTATION_URL="https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta/trails/85cac88"

readonly HEADING='## <img src="https://app.kosli.com/static/images/nav-kosli-logo-new-collapsed.svg" height="20"> snyk-scanning - Snyk container vulnerabilities by Kosli'

# The verdict characters, held here as literals so they can be checked against
# the code points the script names. The two are easy to confuse by eye, which is
# why the code point is written down rather than left to the reader.
readonly TICK="✅"   # WHITE HEAVY CHECK MARK  (U+2705)
readonly CROSS="❌"  # CROSS MARK              (U+274C)

test_compliant_scan_with_vulns_shows_a_tick_and_the_count()
{
  run_summary true "${TWO_VULNS}"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_COMPLIANT_TWO}"
  assert_stderr_equals ""
}

test_non_compliant_scan_shows_a_cross_and_the_same_count()
{
  run_summary false "${TWO_VULNS}"
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_NOT_COMPLIANT_TWO}"
  assert_stderr_equals ""
}

# A clean artifact still gets its header, so the summary says a scan happened
# rather than saying nothing.

test_compliant_scan_with_no_vulns_still_renders_the_header()
{
  run_summary true '[]'
  assert_status_equals 0
  assert_stdout_equals "${EXPECTED_COMPLIANT_NONE}"
  assert_stderr_equals ""
}

test_h_prints_help_with_an_example()
{
  "${script}" -h >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_includes "usage:"
  assert_stdout_includes "bin/print_artifact_scan_summary.py"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

run_summary()
{
  local -r compliant="${1}"
  local -r vulns_json="${2}"
  local -r vulns_file="${SHUNIT_TMPDIR}/vulns.json"
  local -r attestation_file="${SHUNIT_TMPDIR}/attestation.json"
  echo "${vulns_json}" > "${vulns_file}"
  echo "${ATTESTATION_JSON}" > "${attestation_file}"
  "${script}" "${vulns_file}" "${attestation_file}" \
    --compliant      "${compliant}" \
    --repo-name      "${REPO_NAME}" \
    --artifact-name  "${ARTIFACT_NAME}" \
    --fingerprint    "${FINGERPRINT}" \
    --snyk-version   "${SNYK_VERSION}" \
    >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

# kosli get attestation returns a list, and the workflow reads the first entry's
# html_url, so the fixture keeps that shape.
readonly ATTESTATION_JSON="$(jq --null-input \
  --arg url "https://app.kosli.com/cyber-dojo/flows/snyk-aws-beta/trails/85cac88" '
  [
    {
      html_url: $url                 # <<< the only field read
    }
  ]')"

# Only the count of these matters to the header, so they carry just enough to be
# recognisable as the vulns file the scan produced.
readonly TWO_VULNS="$(jq --null-input '
  [
    { full_id: "SNYK-GOLANG-GOLANGORGXCRYPTOSSHAGENT-14059804", severity: "medium" },
    { full_id: "SNYK-ALPINE321-OPENSSL-13939001",               severity: "high"   }
  ]')"

readonly EXPECTED_COMPLIANT_TWO="${HEADING}
<table>
<tr><td><b>Status</b></td><td>${TICK} 2 found</td></tr>
<tr><td><b>Artifact</b></td><td>${ARTIFACT_NAME}</td></tr>
<tr><td><b>Fingerprint</b></td><td>${FINGERPRINT}</td></tr>
<tr><td><b>Snyk</b></td><td>${SNYK_VERSION}</td></tr>
<tr><td><b>Attestation</b></td><td><a href=\"${ATTESTATION_URL}\">${ATTESTATION_URL}</a></td></tr>
</table>"

readonly EXPECTED_NOT_COMPLIANT_TWO="${HEADING}
<table>
<tr><td><b>Status</b></td><td>${CROSS} 2 found</td></tr>
<tr><td><b>Artifact</b></td><td>${ARTIFACT_NAME}</td></tr>
<tr><td><b>Fingerprint</b></td><td>${FINGERPRINT}</td></tr>
<tr><td><b>Snyk</b></td><td>${SNYK_VERSION}</td></tr>
<tr><td><b>Attestation</b></td><td><a href=\"${ATTESTATION_URL}\">${ATTESTATION_URL}</a></td></tr>
</table>"

readonly EXPECTED_COMPLIANT_NONE="${HEADING}
<table>
<tr><td><b>Status</b></td><td>${TICK} 0 found</td></tr>
<tr><td><b>Artifact</b></td><td>${ARTIFACT_NAME}</td></tr>
<tr><td><b>Fingerprint</b></td><td>${FINGERPRINT}</td></tr>
<tr><td><b>Snyk</b></td><td>${SNYK_VERSION}</td></tr>
<tr><td><b>Attestation</b></td><td><a href=\"${ATTESTATION_URL}\">${ATTESTATION_URL}</a></td></tr>
</table>"

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
