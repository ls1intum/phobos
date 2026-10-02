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

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the call is refused because it was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos-resourcesystem.sh - the resource layer: set the run's rlimits, then hand on.

It reads the limits from the specification, sets them in its own shell and execs the rest of
the chain, so the command and everything it starts inherit them and nothing else does.
phobos.sh does not put this layer in the chain itself: the filesystem layer starts it as the
very last step before the Landlock enforcer, so none of the helpers around the command runs
under the command's limits and no helper dying at one can cut the command's output short.

USAGE
  phobos-resourcesystem.sh [options] <SPEC_DIR> -- <command> [args...]
  phobos-resourcesystem.sh [options] --config <file> [--config <file>]... -- <command> [args...]
  phobos-resourcesystem.sh --help

  Two modes. Given a specification directory it applies what is written there. Given one or
  more --config files instead it builds a specification of its own through
  phobos-policysystem.sh, applies only the resource limits and removes that specification
  again. Everything after -- is the command.

OPTIONS
  --config <file>, -c <file>  Standalone mode: an exercise configuration to build a
                              specification from. May be given repeatedly.
  --spec-parent <dir>         Standalone mode only: where that specification directory is
                              made (default: /var/tmp).
  --tail-flags-file <file>    Standalone mode only: the tail flags to build it with.
  --debug, -d                 Report on stderr which limits were set and what is run.
  --help, -h                  Print this manual and end with status 0.

WHAT IT READS FROM THE SPECIFICATION DIRECTORY
  limits.conf   one "key=value" line per limit. An absent file or an absent key leaves that
                limit unset. Every value is re-validated here rather than trusted.

THE LIMITS AND WHAT EACH ONE REALLY BOUNDS
  mem_mb    ulimit -v, the virtual address space rather than the resident set. A 64-bit JVM
            reserves far more address space than it makes resident, so a value near the real
            memory of the machine stops it before main().
  cpu       ulimit -t, cumulative CPU seconds across every thread, so a parallel build
            spends it several times faster than wall-clock time passes.
  nproc     ulimit -u, which the kernel counts per real user id rather than per process
            tree, so it bounds the whole grading user rather than this command alone.
  nofile    ulimit -n, the open file descriptors.
  fsize_mb  ulimit -f, which truncates any single file the command writes, build output
            included, rather than bounding the total written.

  These are self-imposed and unprivileged, exactly as Landlock is, so they hold inside an
  ordinary container. They are the in-process line beside the container's cgroup caps, not a
  replacement for them: a fork bomb filling the process table and a run filling the disk are
  what the cgroups are for.

EXIT STATUS
  0 to 255  the command's own status, passed through unchanged
  2         phobos-resourcesystem.sh was called the wrong way (PHB_EXIT_USAGE)
  11        a limit in the specification is malformed (PHB-EPOLICY)
  15        a limit could not be set (PHB-ERUNTIME)

EXAMPLE
  phobos-resourcesystem.sh --config exercise.cfg -- bash -c 'ulimit -v'
        Apply only the resource limits and show the memory bound that resulted.
PHOBOS_HELP
}

# Prints the manual on stdout and ends successfully, for an explicit --help.
show_help() {
  help_text 1
  exit 0
}

# Prints the manual on stderr and ends with PHB_EXIT_USAGE, for a call that was wrong.
usage() {
  help_text 2
  exit "${PHB_EXIT_USAGE}"
}

CONFIGS=()
SPEC_PARENT="/var/tmp"
TAIL_FLAGS_FILE_OPT=""
LAYER_FLAGS=()
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --help|-h) show_help ;;
    --debug|-d) enable_debug_log; LAYER_FLAGS+=( --debug ); shift ;;
    --config|-c) shift; CONFIGS+=( "${1:-}" ); shift ;;
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
  [[ "${1:-}" == "--" && $# -ge 2 ]] || usage
  shift
  build_owned_spec_from_configs "$HERE" "$SPEC_PARENT" "$TAIL_FLAGS_FILE_OPT" "${CONFIGS[@]}"
  set +e
  bash "${BASH_SOURCE[0]}" "${LAYER_FLAGS[@]}" "$BUILT_SPEC_DIR" -- "$@"
  rc=$?
  set -e
  exit "$rc"
fi

[[ $# -ge 3 && "$2" == "--" ]] || usage
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
