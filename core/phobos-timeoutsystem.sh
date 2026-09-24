#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"

# A self-contained layer: it reads the timeout from the specification and, when one is set,
# runs the rest of the chain under GNU timeout itself, rather than passing a value down for a
# deeper layer to apply. So phobos-timeoutsystem.sh SPEC -- CMD is a usable timeout on its own, and with
# one or more --config files instead of a specification directory it builds its own through
# phobos-policysystem.sh. phobos.sh includes this layer only when the timeout is enabled, so there is no
# enable flag to read.
TIMEOUT_BIN_OPT=""
PGROUP_LOCK_BIN_OPT=""
CONFIGS=()
SPEC_PARENT="/var/tmp"
TAIL_FLAGS_FILE_OPT=""
LAYER_FLAGS=()
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; LAYER_FLAGS+=( --debug ); shift ;;
    --timeout-bin) shift; TIMEOUT_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --timeout-bin "${1:-}" ); shift ;;
    --pgroup-lock-bin) shift; PGROUP_LOCK_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --pgroup-lock-bin "${1:-}" ); shift ;;
    --config) shift; CONFIGS+=( "${1:-}" ); shift ;;
    --spec-parent) shift; SPEC_PARENT="${1:-}"; shift ;;
    --tail-flags-file) shift; TAIL_FLAGS_FILE_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done

# Standalone mode: given one or more --config files instead of a specification directory, build a
# specification of this layer's own through the one parser, then run this layer over it in
# specification-directory mode as a child, so the directory is owned and removed by this outer
# shell rather than leaked when the layer execs the command on the no-timeout path.
if (( ${#CONFIGS[@]} > 0 )); then
  [[ "${1:-}" == "--" && $# -ge 2 ]] || { echo "Usage: phobos-timeoutsystem.sh [flags] --config <file> [--config <file>]... [--spec-parent <dir>] [--tail-flags-file <file>] -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
  shift
  build_owned_spec_from_configs "$HERE" "$SPEC_PARENT" "$TAIL_FLAGS_FILE_OPT" "${CONFIGS[@]}"
  set +e
  bash "${BASH_SOURCE[0]}" "${LAYER_FLAGS[@]}" "$BUILT_SPEC_DIR" -- "$@"
  rc=$?
  set -e
  exit "$rc"
fi

[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-timeoutsystem.sh [--debug] [--timeout-bin <path>] [--pgroup-lock-bin <path>] (<SPEC_DIR> | --config <file>...) -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created. When a timeout is set this layer waits, so this
# trap is what removes the specification, including after the timeout has just group-killed
# everything below it. When no timeout is set the layer hands over with exec below, which does
# not fire an EXIT trap, so the layer that does wait removes it instead.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

TIMEOUT_BIN="${TIMEOUT_BIN_OPT:-timeout}"
PGROUP_LOCK_BIN="${PGROUP_LOCK_BIN_OPT:-${HERE}/phobos-seccomp-timeoutsystem}"

# An empty timeout.sec, or none, means no timeout: hand the chain straight on. Without a timeout
# there is no group-kill to escape, so the group lock is not applied either.
if [[ ! -s "${SPEC_DIR}/timeout.sec" ]]; then
  debug_log timeout "no timeout is set; hand on" "$@"
  exec "$@"
fi
timeout_sec="$(<"${SPEC_DIR}/timeout.sec")"

# The group lock refuses setsid and setpgid, so nothing under the timeout can start a new session
# or process group and step out of the group GNU timeout kills. It is refused when missing rather
# than skipped, so a timed run cannot lose the lock unnoticed and outlive its timeout through a
# detached child. The connect guard refuses the same two calls for the command it supervises, but
# that is the network layer's; this keeps the timeout safe on its own and with the network off.
if [[ ! -x "$PGROUP_LOCK_BIN" ]]; then
  report "The group lock '${PGROUP_LOCK_BIN}' is missing or not executable; refusing to run a timed command that could escape the timeout with setsid. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
fi

debug_log timeout "run" "${TIMEOUT_BIN}" "--kill-after=${PHB_KILL_AFTER_SECONDS}s" "${timeout_sec}s" "${PGROUP_LOCK_BIN}" -- "$@"

# No --foreground: GNU timeout puts the command in a new process group and signals the whole
# group, so the kill reaches the command's children too. --kill-after escalates to SIGKILL for
# a command that ignores SIGTERM. That escalation only fires while GNU timeout's own child is
# still alive, so the layers below keep themselves alive across SIGTERM (they set the command
# itself back to the default disposition), and it is the SIGKILL that stops such a command. The
# group lock is the first process under GNU timeout, so its seccomp filter is inherited by the
# whole group and nothing in it can leave the group with setsid or setpgid.
start_microseconds="$(epoch_realtime_microseconds "$EPOCHREALTIME")"
set +e
"${TIMEOUT_BIN}" "--kill-after=${PHB_KILL_AFTER_SECONDS}s" "${timeout_sec}s" "${PGROUP_LOCK_BIN}" -- "$@"
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
