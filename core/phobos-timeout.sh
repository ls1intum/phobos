#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# A self-contained layer: it reads the timeout from the specification and, when one is set,
# runs the rest of the chain under GNU timeout itself, rather than passing a value down for a
# deeper layer to apply. So phobos-timeout.sh -- CMD is a usable timeout on its own. phobos.sh
# includes this layer only when the timeout is enabled, so there is no enable flag to read.
DEBUG=0
TIMEOUT_BIN_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) DEBUG=1; shift ;;
    --timeout-bin) shift; TIMEOUT_BIN_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-timeout.sh [--debug] [--timeout-bin <path>] <SPEC_DIR> -- <cmd...>" >&2; exit 2; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created. When a timeout is set this layer waits, so this
# trap is what removes the specification, including after the timeout has just group-killed
# everything below it. When no timeout is set the layer hands over with exec below, which does
# not fire an EXIT trap, so the layer that does wait removes it instead.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

TIMEOUT_BIN="${TIMEOUT_BIN_OPT:-timeout}"

# An empty timeout.sec, or none, means no timeout: hand the chain straight on.
if [[ ! -s "${SPEC_DIR}/timeout.sec" ]]; then
  exec "$@"
fi
timeout_sec="$(<"${SPEC_DIR}/timeout.sec")"

if (( DEBUG )); then
  >&2 printf '[phobos] %s --kill-after=5s %ss ' "${TIMEOUT_BIN}" "${timeout_sec}"
  >&2 printf '%q ' "$@"
  echo >&2
fi

# No --foreground: GNU timeout puts the command in a new process group and signals the whole
# group, so the kill reaches the command's children too. --kill-after escalates to SIGKILL for
# a command that ignores SIGTERM. That escalation only fires while GNU timeout's own child is
# still alive, so the layers below keep themselves alive across SIGTERM (they set the command
# itself back to the default disposition), and it is the SIGKILL that stops such a command.
start_microseconds="$(epoch_realtime_microseconds "$EPOCHREALTIME")"
set +e
"${TIMEOUT_BIN}" "--kill-after=5s" "${timeout_sec}s" "$@"
rc=$?
set -e
elapsed_microseconds=$(( $(epoch_realtime_microseconds "$EPOCHREALTIME") - start_microseconds ))

# A timeout only when GNU timeout's status says so and the run lasted at least the timeout;
# any other status, a 124 or 137 of the command's own included, passes through unchanged.
if run_reached_timeout "$rc" "$elapsed_microseconds" "$timeout_sec"; then
  report "Timed out after ${timeout_sec}s. (PHB-ETIMEOUT)"
  exit "${PHB_ETIMEOUT}"
fi
exit "$rc"
