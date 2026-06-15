#!/usr/bin/env bash
set -Eeu

export ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/bin/lib.sh"

# No defaults: require each variable to be set explicitly so we never silently
# query the wrong host/org, use a dummy token, or default to the wrong environment.
: "${KOSLI_HOST:?KOSLI_HOST must be set}"
: "${KOSLI_ORG:?KOSLI_ORG must be set}"
: "${KOSLI_API_TOKEN:?KOSLI_API_TOKEN must be set}"
: "${KOSLI_ENV:?KOSLI_ENV must be set}"

# NOTE: in a Github Action, stdout and stderr are multiplexed together.
# This multiplexing is standard behaviour inside a docker container with a tty.
# This means that the output of the $(subshell) is not just stdout, it is stdout+stderr!
# To ensure the Kosli CLI does not print to stderr, we set the --debug=false flag explicitly.

exit_non_zero_unless_installed kosli jq

kosli get snapshot "${KOSLI_ENV}" \
    --host="${KOSLI_HOST}" \
    --org="${KOSLI_ORG}" \
    --api-token="${KOSLI_API_TOKEN}" \
    --debug=false \
    --output=json
