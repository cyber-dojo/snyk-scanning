#!/usr/bin/env bash
set -Eeu

readonly my_dir="$(cd "$(dirname "${0}")" && pwd)"
readonly tmp_dir=$(mktemp -d "/tmp/artifacts.XXX")
remove_tmp_dir() { rm -rf "${tmp_dir}" > /dev/null; }
trap remove_tmp_dir INT EXIT

# The test_*.py files import pytest, and bin/combine_snyk.py imports yaml to read
# the .snyk policy file, which is YAML. The test_*.sh files use the vendored
# tests/shunit2 and need nothing installed.
readonly required_modules='pytest yaml'

# Echo each directory on PATH, one per line.
path_dirs()
{
  local -r saved_ifs="${IFS}"
  local dir
  IFS=':'
  for dir in ${PATH}; do
    printf '%s\n' "${dir}"
  done
  IFS="${saved_ifs}"
}

# Succeed only if the given python3 can import every required module.
python3_has_required_modules()
{
  local -r python3_path="${1}"
  local module
  for module in ${required_modules}; do
    "${python3_path}" -c "import ${module}" > /dev/null 2>&1 || return 1
  done
  return 0
}

# Echo the first directory on PATH whose python3 has every required module,
# or nothing if there is none.
python3_dir_with_required_modules()
{
  local dir
  while IFS= read -r dir; do
    if [ -x "${dir}/python3" ] && python3_has_required_modules "${dir}/python3"; then
      printf '%s' "${dir}"
      break
    fi
  done < <(path_dirs)
  return 0
}

# Echo one line per python3 on PATH giving its version and which required
# modules it can import, so a failure says which module is missing where.
report_python3_modules()
{
  local dir module state
  while IFS= read -r dir; do
    [ -x "${dir}/python3" ] || continue
    printf '       %s (%s)' \
      "${dir}/python3" \
      "$("${dir}/python3" -c 'import platform; print(platform.python_version())' 2>&1)"
    for module in ${required_modules}; do
      if "${dir}/python3" -c "import ${module}" > /dev/null 2>&1; then
        state='yes'
      else
        state='no'
      fi
      printf ' %s=%s' "${module}" "${state}"
    done
    printf '\n'
  done < <(path_dirs)
  return 0
}

# Whichever python3 comes first on PATH is the one the test files get, including
# through their own #!/usr/bin/env python3 shebangs, so put one that has the
# modules at the front rather than trusting the default. A machine with several
# python3 installations usually has the modules in only one of them.
readonly python3_dir="$(python3_dir_with_required_modules)"
if [ -z "${python3_dir}" ]; then
  echo "ERROR: no python3 on PATH can import all of: ${required_modules}"
  echo "       pytest runs the test_*.py files"
  echo "       PyYAML lets bin/combine_snyk.py read the .snyk policy file"
  report_python3_modules
  exit 1
fi
export PATH="${python3_dir}:${PATH}"

echo
for test_file in ${my_dir}/test_*; do
  ${test_file}
done
