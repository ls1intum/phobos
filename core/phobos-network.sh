#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# A generic layer: it does its work and execs the rest of the chain. phobos.sh includes this
# layer only when the network filter is enabled, so there is no enable flag to read.
NETBLOCKER_SO_OPT=""
GUARD_BIN_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; shift ;;
    --netblocker-so) shift; NETBLOCKER_SO_OPT="${1:-}"; shift ;;
    --connect-guard-bin) shift; GUARD_BIN_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-network.sh [--debug] [--netblocker-so <path>] [--connect-guard-bin <path>] <SPEC_DIR> -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
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

# Remember the path so the filesystem layer can grant it read and execute under Landlock.
export PHB_NETBLOCKER_SO="${NETBLOCKER_SO}"

case ":${LD_PRELOAD:-}:" in
  *":${NETBLOCKER_SO}:"*) ;; # already there
  *) export LD_PRELOAD="${NETBLOCKER_SO}${LD_PRELOAD:+:${LD_PRELOAD}}";;
esac

# Use the spec's net.rules file as config, whether or not it is empty; ensure it exists.
[[ -f "$RULES" ]] || : > "$RULES"
export NETBLOCKER_CONF="$RULES"

# The spec's bind.rules gives libnetblocker the local-bind allow-list, whether or not it is
# empty; an empty file leaves binding unrestricted, matching the absence of a Landlock
# bind-port rule.
BIND_RULES="${SPEC_DIR}/bind.rules"
[[ -f "$BIND_RULES" ]] || : > "$BIND_RULES"
export NETBLOCKER_BIND_CONF="$BIND_RULES"

# The connect guard supervises every connect the command makes and enforces the [connect]
# allow-list by host and port from a place a raw syscall cannot step around, unlike the
# preload library above, which stays as the softer in-process filter beside it. It forks a
# supervisor and execs the rest of the chain, so it goes on the front of what this layer hands
# over. It is refused when missing rather than skipped, so a run cannot lose connect
# supervision unnoticed.
GUARD_BIN="${GUARD_BIN_OPT:-${HERE}/phobos-connect-guard}"
if [[ ! -x "$GUARD_BIN" ]]; then
  report "The connect guard '${GUARD_BIN}' is missing or not executable; refusing to run without connect supervision. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
fi
guard_command=( "$GUARD_BIN" )
if (( PHB_DEBUG_ENABLED )); then guard_command+=( --verbose ); fi
guard_command+=( --rules "$RULES" -- )
debug_log network "preload ${LD_PRELOAD} with NETBLOCKER_CONF=${NETBLOCKER_CONF} NETBLOCKER_BIND_CONF=${NETBLOCKER_BIND_CONF}"
debug_log network "run" "${guard_command[@]}" "$@"
exec "${guard_command[@]}" "$@"
