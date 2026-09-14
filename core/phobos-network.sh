#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-network.sh <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2
CMD=("$@")

# Removes the specification phobos.sh created if this layer ends before it hands over,
# for instance because the library cannot be used.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

enable_network="${PHB_ENABLE_NETWORK:-1}"

# If network layer is disabled, just pass through to the resource layer.
if [[ "$enable_network" != "1" ]]; then
  exec "${HERE}/phobos-resources.sh" "${SPEC_DIR}" -- "${CMD[@]}"
fi

RULES="${SPEC_DIR}/net.rules"
: "${NETBLOCKER_SO:=${HERE}/libnetblocker.so}"
NETBLOCKER_SO="$(realpath --canonicalize-missing -- "${NETBLOCKER_SO}")"

# A missing library used to be skipped here, and the loader skips one it cannot use
# with only a warning, so either way the command ran with no network filtering. Such
# a run ends instead.
refuse_unusable_netblocker "${NETBLOCKER_SO}"

# Always define env vars for clarity
export LD_PRELOAD="${LD_PRELOAD:-}"
export NETBLOCKER_CONF="${NETBLOCKER_CONF:-}"

# Remember the path so the filesystem layer can bind it into the sandbox
export PHB_NETBLOCKER_SO="${NETBLOCKER_SO}"

case ":${LD_PRELOAD}:" in
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

exec "${HERE}/phobos-resources.sh" "${SPEC_DIR}" -- "${CMD[@]}"
