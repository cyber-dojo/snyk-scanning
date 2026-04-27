#!/usr/bin/env bash

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"

test_github_commit_url_gives_raw_githubusercontent_snyk_policy_url()
{
  get_artifacts "github-artifact.snapshot.json"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/artifacts/expected/github-artifact.json")"
  assert_stderr_equals ""
}

test_gitlab_commit_url_gives_gitlab_raw_snyk_policy_url()
{
  get_artifacts "gitlab-artifact.snapshot.json"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/artifacts/expected/gitlab-artifact.json")"
  assert_stderr_equals ""
}

test_exited_artifact_is_excluded()
{
  get_artifacts "exited-artifact.snapshot.json"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/artifacts/expected/exited-artifact.json")"
  assert_stderr_equals ""
}

test_non_build_flow_is_excluded()
{
  get_artifacts "non-build-flow.snapshot.json"
  assert_status_equals 0
  assert_stdout_equals "$(cat "${my_dir}/artifacts/expected/non-build-flow.json")"
  assert_stderr_equals ""
}

test_unknown_ci_system()
{
  get_artifacts "unknown-ci-system.snapshot.json"
  assert_status_not_equals 0
  assert_stdout_equals ""
  assert_stderr_equals "$(cat "${my_dir}/artifacts/expected/unknown-ci-system.txt")"
}

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

get_artifacts()
{
  local -r filename="${1}"
  cat "${my_dir}/artifacts/${filename}" \
    | python3 "${my_dir}/../bin/artifacts.py" >${stdoutF} 2>${stderrF}
  echo $? >${statusF}
}

echo "::${0##*/}"
. ${my_dir}/shunit2_helpers.sh
. ${my_dir}/shunit2
