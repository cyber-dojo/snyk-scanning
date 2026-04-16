#!/usr/bin/env bash
set -Eeu

export ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/bin/lib.sh"

KOSLI_HOST="${KOSLI_HOST:-https://app.kosli.com}"
KOSLI_ORG="${KOSLI_ORG:-cyber-dojo}"
KOSLI_API_TOKEN="${KOSLI_API_TOKEN:-read-only-dummy}"
KOSLI_FLOW="${KOSLI_FLOW}"
KOSLI_TRAIL="${KOSLI_TRAIL}"

# NOTE: in a Github Action, stdout and stderr are multiplexed together.
# This multiplexing is standard behaviour inside a docker container with a tty.
# This means that the output of the $(subshell) is not just stdout, it is stdout+stderr!
# To ensure the Kosli CLI does not print to stderr, we set the --debug=false flag explicitly.

exit_non_zero_unless_installed kosli jq

kosli get trail "${KOSLI_TRAIL}" \
    --host="${KOSLI_HOST}" \
    --org="${KOSLI_ORG}" \
    --api-token="${KOSLI_API_TOKEN}" \
    --debug=false \
    --flow="${KOSLI_FLOW}" \
    --output=json
