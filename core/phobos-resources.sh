#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# A generic layer: it sets the resource limits and execs the rest of the chain. phobos.sh has
# the filesystem layer start it, and only when the resource limits are enabled, so there is no
# enable flag to read. On its own, phobos-resources.sh SPEC -- CMD limits CMD.
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-resources.sh [--debug] <SPEC_DIR> -- <cmd...>" >&2; exit 2; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created if this layer ends before it hands over. The
# filesystem layer starts this one right before phobos-landlock, so the trap only fires when a
# limit cannot be set, or when a SIGTERM arrives in the short moment before the exec below: the
# run is ending then anyway, and the filesystem layer's own trap finds the directory gone,
# which remove_owned_spec_dir treats as done.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

# The limits phobos-policy.sh wrote into the specification, re-validated at this boundary
# rather than trusted, one entry per key; an absent file or key leaves that limit unset.
declare -A limits
read_limits_conf "${SPEC_DIR}/limits.conf" limits

# Set the limits in this shell, then exec on, so phobos-landlock and the command it finally
# runs inherit them, and nothing else does: the filesystem layer starts this layer as the last
# step before phobos-landlock, so the helpers around the command (the layer shell, the stderr
# pass-through and the denial counter, the connect guard's supervisor) never run under the
# command's limits. rlimits are self-imposed and unprivileged, exactly as Landlock is, so they
# hold inside the ordinary container an exercise runs in. The hard caps a machine needs against
# a determined submission (a fork bomb filling the process table, a run filling the disk) are
# cgroups the container is started with; these rlimits are the in-process line beside them.
apply_resource_limits "${limits[mem_mb]}" "${limits[nproc]}" "${limits[nofile]}" "${limits[fsize_mb]}" "${limits[cpu]}"

debug_log resources "limits mem_mb=${limits[mem_mb]:-none} nproc=${limits[nproc]:-none} nofile=${limits[nofile]:-none} fsize_mb=${limits[fsize_mb]:-none} cpu=${limits[cpu]:-none}; run" "$@"
exec "$@"
