#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"

# A generic layer: it sets the resource limits and execs the rest of the chain. phobos.sh has
# the filesystem layer start it, and only when the resource limits are enabled, so there is no
# enable flag to read. On its own, phobos-resourcesystem.sh SPEC -- CMD limits CMD, or, with one or
# more --config files instead of a specification directory, it builds its own through
# phobos-policysystem.sh and applies only the resource limits.
CONFIGS=()
SPEC_PARENT="/var/tmp"
TAIL_FLAGS_FILE_OPT=""
LAYER_FLAGS=()
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; LAYER_FLAGS+=( --debug ); shift ;;
    --config) shift; CONFIGS+=( "${1:-}" ); shift ;;
    --spec-parent) shift; SPEC_PARENT="${1:-}"; shift ;;
    --tail-flags-file) shift; TAIL_FLAGS_FILE_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done

# Standalone mode: given one or more --config files instead of a specification directory, build a
# specification of this layer's own through the one parser, then run this layer over it in
# specification-directory mode as a child, so the directory is owned and removed by this outer
# shell rather than leaked when the layer execs the command.
if (( ${#CONFIGS[@]} > 0 )); then
  [[ "${1:-}" == "--" && $# -ge 2 ]] || { echo "Usage: phobos-resourcesystem.sh [flags] --config <file> [--config <file>]... [--spec-parent <dir>] [--tail-flags-file <file>] -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
  shift
  build_owned_spec_from_configs "$HERE" "$SPEC_PARENT" "$TAIL_FLAGS_FILE_OPT" "${CONFIGS[@]}"
  set +e
  bash "${BASH_SOURCE[0]}" "${LAYER_FLAGS[@]}" "$BUILT_SPEC_DIR" -- "$@"
  rc=$?
  set -e
  exit "$rc"
fi

[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-resourcesystem.sh [--debug] (<SPEC_DIR> | --config <file>...) -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created if this layer ends before it hands over. The
# filesystem layer starts this one right before phobos-landlock-filesystem-and-networksystem, so the trap only fires when a
# limit cannot be set, or when a SIGTERM arrives in the short moment before the exec below: the
# run is ending then anyway, and the filesystem layer's own trap finds the directory gone,
# which remove_owned_spec_dir treats as done.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

# The limits phobos-policysystem.sh wrote into the specification, re-validated at this boundary
# rather than trusted, one entry per key; an absent file or key leaves that limit unset.
declare -A limits
read_limits_conf "${SPEC_DIR}/limits.conf" limits

# Set the limits in this shell, then exec on, so phobos-landlock-filesystem-and-networksystem and the command it finally
# runs inherit them, and nothing else does: the filesystem layer starts this layer as the last
# step before phobos-landlock-filesystem-and-networksystem, so the helpers around the command (the layer shell, the stderr
# pass-through and the denial counter, the connect guard's supervisor) never run under the
# command's limits. rlimits are self-imposed and unprivileged, exactly as Landlock is, so they
# hold inside the ordinary container an exercise runs in. The hard caps a machine needs against
# a determined submission (a fork bomb filling the process table, a run filling the disk) are
# cgroups the container is started with; these rlimits are the in-process line beside them.
apply_resource_limits "${limits[mem_mb]}" "${limits[nproc]}" "${limits[nofile]}" "${limits[fsize_mb]}" "${limits[cpu]}"

debug_log resources "limits mem_mb=${limits[mem_mb]:-none} nproc=${limits[nproc]:-none} nofile=${limits[nofile]:-none} fsize_mb=${limits[fsize_mb]:-none} cpu=${limits[cpu]:-none}; run" "$@"
exec "$@"
