#!/usr/bin/env bash
set -Eeu

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly tmp_dir=$(mktemp -d "/tmp/artifacts.XXX")
remove_tmp_dir() { rm -rf "${tmp_dir}" > /dev/null; }
trap remove_tmp_dir INT EXIT

# Echo the first directory on PATH whose python3 can import pytest and yaml,
# or nothing if there is none.
python3_dir_with_required_modules()
{
  local -r saved_ifs="${IFS}"
  local dir found=''
  IFS=':'
  for dir in ${PATH}; do
    if [ -x "${dir}/python3" ] && "${dir}/python3" -c 'import pytest, yaml' > /dev/null 2>&1; then
      found="${dir}"
      break
    fi
  done
  IFS="${saved_ifs}"
  printf '%s' "${found}"
}

# The test_*.py files import pytest, and combine_snyk.py imports yaml to read
# the .snyk policy file. Both come from whichever python3 is found first on
# PATH, including through the test files' own #!/usr/bin/env python3 shebangs,
# so put an interpreter that has them at the front rather than trusting the
# default. A machine with several python3 installations usually has the modules
# in only one of them.
readonly python3_dir="$(python3_dir_with_required_modules)"
if [ -z "${python3_dir}" ]; then
  echo "ERROR: no python3 on PATH can import both pytest and yaml"
  echo "       pytest runs the test_*.py files"
  echo "       PyYAML lets bin/combine_snyk.py read the .snyk policy file"
  exit 1
fi
export PATH="${python3_dir}:${PATH}"

echo
for test_file in ${my_dir}/test_*; do
  ${test_file}
done
