#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

export KOSLI_HOST=https://app.kosli.com
export KOSLI_ORG=cyber-dojo
export KOSLI_API_TOKEN=dummy-read-only

test_SUCCESS_json_artifacts_written_to_stdout() { :; }

xtest___SUCCESS_no_artifacts()
{
  local -r filename="0.json"
  get_artifacts "${filename}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/expected/${filename}")"
  assert_stderr_equals ""
}

test___SUCCESS_aws_beta()
{
  local -r filename="aws-beta.json"
  get_artifacts "${filename}"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/expected/${filename}")"
  assert_stderr_equals ""
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

xtest_FAILURE_with_diagnostic_on_stderr() { :; }

xtest___FAILURE_unknown_ci_system()
{
  local -r filename="unknown-ci-system"
  get_artifacts "${filename}.json"
  assert_status_not_equals 0
  assert_stdout_equals ""
  assert_stderr_equals "$(cat "${my_dir}/expected/${filename}.txt")"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

get_artifacts()
{
  local -r filename="${1}"
  cat ${my_dir}/get-snapshot/${filename} | python3 ${my_dir}/../bin/artifacts.py >${stdoutF} 2>${stderrF}
  status=$?
  echo ${status} >${statusF}
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2

