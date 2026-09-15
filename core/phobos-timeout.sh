#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# A generic layer: it does its work and execs the rest of the chain, whatever phobos.sh put
# after the "--". phobos.sh includes this layer only when the timeout is enabled, so there is
# no enable flag to read; --debug is accepted for symmetry with the layers that print.
if [[ "${1:-}" == "--debug" ]]; then shift; fi
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-timeout.sh [--debug] <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created if this layer ends before it hands over.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

# The effective timeout travels to the filesystem layer, which applies it coupled to
# phobos-landlock so the kill escalation still reaches a command that ignores SIGTERM. An
# empty timeout.sec, or none, means no timeout.
if [[ -s "${SPEC_DIR}/timeout.sec" ]]; then
  PHB_TIMEOUT_SEC="$(<"${SPEC_DIR}/timeout.sec")"
else
  PHB_TIMEOUT_SEC=""
fi
export PHB_TIMEOUT_SEC

exec "$@"
