#!/usr/bin/env bash

# Tests print_component_name.py, which artifact_snyk_test.yml runs to name the
# artifact it scans. Build workflows pass the image name without a digest, so
# that is the form tested here; the snapshot form, with a digest, is covered
# by test_artifacts_logic.py.

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly script="${my_dir}/../bin/print_component_name.py"

# web's main-creator.yml builds creator from the web repo.
readonly ARTIFACT_NAME="244531986313.dkr.ecr.eu-central-1.amazonaws.com/creator:9c517d0"

test_the_component_name_is_the_image_name()
{
  "${script}" "${ARTIFACT_NAME}" >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_equals "creator"
  assert_stderr_equals ""
}

test_h_prints_help_with_an_example()
{
  "${script}" -h >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
  assert_status_equals 0
  assert_stdout_includes "usage:"
  assert_stdout_includes "bin/print_component_name.py"
  assert_stderr_equals ""
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
