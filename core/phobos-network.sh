#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# A generic layer: it does its work and execs the rest of the chain. phobos.sh includes this
# layer only when the network filter is enabled, so there is no enable flag to read.
NETBLOCKER_SO_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) shift ;;
    --netblocker-so) shift; NETBLOCKER_SO_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-network.sh [--debug] [--netblocker-so <path>] <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created if this layer ends before it hands over,
# for instance because the library cannot be used.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

RULES="${SPEC_DIR}/net.rules"
NETBLOCKER_SO="${NETBLOCKER_SO_OPT:-${HERE}/libnetblocker.so}"
NETBLOCKER_SO="$(realpath --canonicalize-missing -- "${NETBLOCKER_SO}")"

# The loader skips a preload library it cannot use with only a warning, so either way the
# command would run with no network filtering. Refuse instead.
refuse_unusable_netblocker "${NETBLOCKER_SO}"

# Remember the path so the filesystem layer can bind it into the sandbox.
export PHB_NETBLOCKER_SO="${NETBLOCKER_SO}"

case ":${LD_PRELOAD:-}:" in
  *":${NETBLOCKER_SO}:"*) ;; # already there
  *) export LD_PRELOAD="${NETBLOCKER_SO}${LD_PRELOAD:+:${LD_PRELOAD}}";;
esac

# Use the spec's net.rules file as config, whether or not it is empty; ensure it exists.
if [[ -f "$RULES" ]]; then
  export NETBLOCKER_CONF="$RULES"
else
  : > "$RULES"
  export NETBLOCKER_CONF="$RULES"
fi

exec "$@"
