#!/bin/bash
# shellcheck shell=bash
set -euo pipefail
# This script's directory, found in bash alone so that PATH and CDPATH are cleaned before any
# program is looked up or any cd made, and made absolute once they are: phobos-environment.sh.
case "${BASH_SOURCE[0]}" in */*) HERE="${BASH_SOURCE[0]%/*}/" ;; *) HERE="./" ;; esac
# shellcheck source=phobos-tools-common/phobos-environment.sh
source "${HERE}phobos-tools-common/phobos-environment.sh"
clean_startup_environment
HERE="$(cd -- "$HERE" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"

# The filesystem layer: it applies the Landlock policy and runs the command. phobos.sh hands it a
# specification directory; run on its own with one or more --config files instead, it builds its
# own through phobos-policysystem.sh and enforces only the filesystem.

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the call is refused because it was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos-filesystem.sh - the filesystem layer: apply the Landlock policy and run the command.

This is the last layer of a Phobos run and the one that actually starts the command. It
turns the specification's path sets into one Landlock rule per path, applies them, runs the
command as its child. The reporter in front of it words each action Landlock refuses.

USAGE
  phobos-filesystem.sh [options] <SPEC_DIR> -- <command> [args...]
  phobos-filesystem.sh [options] --config <file> [--config <file>]... -- <command> [args...]
  phobos-filesystem.sh --help

  Two modes. Given a specification directory, it enforces what is already written there,
  which is how phobos.sh calls it. Given one or more --config files instead, it builds a
  specification of its own through phobos-policysystem.sh, enforces only the filesystem and
  removes that specification again when the command ends. Everything after -- is the command.

OPTIONS
  --no-landlock               Run the command without applying Landlock at all. The layer
                              still runs the command, and still words a resource limit it hit.
  --landlock-bin <path>       The Landlock enforcer
                              (default: "${HERE}/phobos-landlock-filesystem-and-networksystem").
  --resources-layer <path>    Apply the specification's resource limits by starting that
                              layer as the very last step before the enforcer, so the limits
                              bind the command and none of the helpers around it. Without
                              this option no rlimit is set.
  --reporter-bin <path>       The report-only supervisor that reports each blocked action
                              (default: "${HERE}/phobos-seccomp-filesystem").
  --no-own-reporter           Start no reporter of this layer's own. phobos.sh passes it when
                              the network layer is on, whose connect guard is then the run's
                              one supervisor.
  --group-lock-above          The timeout layer's group lock is above this layer, so the
                              reporter answers and reports the calls it refuses outright
                              (setsid, setpgid, a foreign ABI), once the lock's signature
                              confirms it. phobos.sh passes it exactly when it applies the lock.
  --config <file>, -c <file>  Standalone mode: an exercise configuration to build a
                              specification from. May be given repeatedly.
  --spec-parent <dir>         Standalone mode only: where that specification directory is
                              made (default: /var/tmp).
  --tail-flags-file <file>    Standalone mode only: the tail flags to build it with.
  --debug, -d                 Report on stderr what this layer runs, and have the enforcer
                              report verbosely too.
  --help, -h                  Print this manual and end with status 0.

WHAT IT READS FROM THE SPECIFICATION DIRECTORY
  read.paths execute.paths write.paths create.paths delete.paths ipc.paths symlink.paths
  refer.paths ioctl.paths   one Landlock rule per line, the rights being exactly the sections a path
                appears in
  tail.flags    flags handed to the enforcer last
  limits.conf   only with --resources-layer

  A path named in no section at all is simply not listed and stays denied by Landlock's own
  default. Creating device nodes is never granted.

WHAT IT REPORTS
  Unless --no-own-reporter is given, the reporter prints a line on stderr for each distinct
  action it can attribute with certainty to Landlock, such as "Phobos Security Error: the
  program tried to illegally read the File '/etc/shadow' but was blocked by Phobos.", at
  most 100 per run, and, with --group-lock-above, one for each distinct call the group lock
  refuses outright. Every doubt ends in silence, so a run without such a line may still have
  been refused something. While it runs, no refused call succeeds and no permitted one
  fails, the group lock's refusals failing with EACCES rather than ENOSYS; should it die, the
  calls it watches fail with ENOSYS, so nothing is granted. When the reporter is missing, or
  the kernel cannot support it, a notice names what goes unreported and why, and the run is
  enforced all the same.

  When the command ends with the status of a file size limit it was given (153 for SIGXFSZ), or
  with 137 or 152 after the processes it started used the CPU time limit it was given, the layer
  prints the matching line, "... exceed the File Size Limit of N MB ..." or "... exceed the CPU
  Time Limit of N seconds ...". The CPU limit ends a command with SIGKILL, 137, which a shell
  cannot tell from an outside kill; the CPU time used decides, and a tree of processes that
  together used the limit and was stopped some other way gets the line wrongly. A command that
  ends with 153 by itself gets the file size line, which a shell cannot tell from the signal. At
  the end of a run that blocked anything, the reporter prints one "Phobos Security Summary"
  line that counts per layer what it decided, never the words in the command's own output.
  None of this is a status: the command's own exit status is passed through unchanged, unless
  it could not be read at all (16, below).

EXIT STATUS
  0 to 255  the command's own status, passed through unchanged
  2         phobos-filesystem.sh was called the wrong way (PHB_EXIT_USAGE)
  11        the policy is invalid (PHB-EPOLICY)
  16        the command ran but the reporter could not read its exit status (PHB-ESTATUS)

EXAMPLES
  phobos-filesystem.sh --config exercise.cfg -- ./gradlew test
        Enforce only the filesystem, building the policy from one configuration.
  phobos-filesystem.sh -d /var/tmp/phobos-spec.ab12cd -- /bin/ls /etc
        Enforce a specification another program has already written.
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

NO_LANDLOCK=0
LANDLOCK_BIN_OPT=""
RESOURCES_LAYER_OPT=""
REPORTER_BIN_OPT=""
NO_OWN_REPORTER=0
GROUP_LOCK_ABOVE=0
CONFIGS=()
SPEC_PARENT="/var/tmp"
TAIL_FLAGS_FILE_OPT=""
LAYER_FLAGS=()
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --help|-h) show_help ;;
    --debug|-d) enable_debug_log; LAYER_FLAGS+=( --debug ); shift ;;
    --no-landlock) NO_LANDLOCK=1; LAYER_FLAGS+=( --no-landlock ); shift ;;
    --landlock-bin) shift; LANDLOCK_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --landlock-bin "${1:-}" ); shift ;;
    --resources-layer) shift; RESOURCES_LAYER_OPT="${1:-}"; LAYER_FLAGS+=( --resources-layer "${1:-}" ); shift ;;
    --reporter-bin) shift; REPORTER_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --reporter-bin "${1:-}" ); shift ;;
    --no-own-reporter) NO_OWN_REPORTER=1; LAYER_FLAGS+=( --no-own-reporter ); shift ;;
    --group-lock-above) GROUP_LOCK_ABOVE=1; LAYER_FLAGS+=( --group-lock-above ); shift ;;
    --config|-c) shift; CONFIGS+=( "${1:-}" ); shift ;;
    --spec-parent) shift; SPEC_PARENT="${1:-}"; shift ;;
    --tail-flags-file) shift; TAIL_FLAGS_FILE_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done

# Standalone mode: given one or more --config files instead of a specification directory, build a
# specification of this layer's own through the one parser, then run this layer over it in
# specification-directory mode as a child. This layer waits on the command and removes the
# directory through its own trap, so the outer shell's trap then finds it already gone; the outer
# owner still matters for the layers that exec, and is kept here for one contract across them all.
if (( ${#CONFIGS[@]} > 0 )); then
  [[ "${1:-}" == "--" && $# -ge 2 ]] || usage
  shift
  build_owned_spec_from_configs "$HERE" "$SPEC_PARENT" "$TAIL_FLAGS_FILE_OPT" "${CONFIGS[@]}"
  set +e
  run_forwarding_signals /bin/bash "${BASH_SOURCE[0]}" "${LAYER_FLAGS[@]}" "$BUILT_SPEC_DIR" -- "$@"
  rc=$?
  set -e
  exit "$rc"
fi

[[ $# -ge 3 && "$2" == "--" ]] || usage
SPEC_DIR="$1"; shift 2
CMD=("$@")

# Canonicalising a path is how this layer decides which rules name one tree, so the tool it
# needs for that is established before any rule is built.
refuse_missing_realpath

# The temporary files this layer makes go under the specification directory, which the trap
# below removes whole. A refusal exits before the rm that follows each use, so a policy error
# would otherwise leave them in /tmp, which the policy itself usually makes writable.
PHOBOS_SCRATCH="${SPEC_DIR}/${PHB_SPEC_SCRATCH}"
mkdir -p "$PHOBOS_SCRATCH"

# Removes the specification phobos.sh created. This layer always runs the command as a child
# and waits on it, then exits, so this trap always runs, except when the command's timeout
# group-kills this layer, where the timeout layer removes the specification instead.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

# This layer runs the command as a child and waits on it, so it can word the limit that ended it
# afterwards. An outer timeout (phobos-timeoutsystem.sh) group-kills on expiry and escalates to SIGKILL
# only while GNU timeout's own child is still alive, so this layer ignores SIGTERM and stays
# until the command it waits on is gone. While it waits, run_forwarding_signals passes a SIGTERM,
# SIGHUP, SIGINT or SIGQUIT it receives on to the command, which has the default disposition, so a
# caller that cancels the run reaches the command and the layer still stays to clean up.
trap '' TERM

READ="${SPEC_DIR}/read.paths"
EXECUTE="${SPEC_DIR}/execute.paths"
WRITE="${SPEC_DIR}/write.paths"
CREATE="${SPEC_DIR}/create.paths"
DELETE="${SPEC_DIR}/delete.paths"
IPC="${SPEC_DIR}/ipc.paths"
SYMLINK="${SPEC_DIR}/symlink.paths"
REFER="${SPEC_DIR}/refer.paths"
IOCTL="${SPEC_DIR}/ioctl.paths"
TAIL="${SPEC_DIR}/tail.flags"
LANDLOCK="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock-filesystem-and-networksystem}"

# With --resources-layer the command's resource limits are set by that layer, started as the
# very last step before phobos-landlock-filesystem-and-networksystem (or the command), so they reach phobos-landlock-filesystem-and-networksystem and the
# command and nothing else: this layer's shell runs without them. A limit set any earlier would also bind those helpers, and a helper
# that dies of the command's file-size, memory or CPU limit takes the command's output with it.
# The limits are validated here, before any write path is materialised, so a malformed one is
# refused before this layer changes anything; the resource layer checks them again.
limit_prefix=()
# read_limits_conf fills the array by name. This layer needs its refusal, and, after the command,
# the CPU and file size limits to word a command that hit one; the resource layer reads the
# values again when it applies them. The array stays empty when there is no resource layer.
declare -A validated_limits=()
if [[ -n "$RESOURCES_LAYER_OPT" ]]; then
  read_limits_conf "${SPEC_DIR}/limits.conf" validated_limits
  limit_prefix=( "$RESOURCES_LAYER_OPT" )
  if (( PHB_DEBUG_ENABLED )); then limit_prefix+=( --debug ); fi
  limit_prefix+=( "$SPEC_DIR" -- )
fi

# The report-only supervisor reports what Landlock and the timeout layer's group lock refuse, and
# changes the outcome of no call. It is started in front of the resource layer and the enforcer,
# so it forks before the rlimits and the Landlock domain exist and its supervising half runs under
# neither. With the network layer on, the connect guard is the run's one supervisor, because only
# one seccomp listener may exist per filter tree, and phobos.sh says so with --no-own-reporter. It
# is started with --no-landlock too, where it may still answer the group lock's refusals, and
# execs the command without forking when it has nothing to watch. A reporter that is missing is
# said once, never refused: reporting is a diagnostic, and the run is enforced all the same.
reporter_prefix=()
if (( ! NO_OWN_REPORTER )); then
  REPORTER="${REPORTER_BIN_OPT:-${HERE}/phobos-seccomp-filesystem}"
  if [[ -f "$REPORTER" && -x "$REPORTER" ]]; then
    reporter_prefix=( "$REPORTER" )
    if (( PHB_DEBUG_ENABLED )); then reporter_prefix+=( --verbose ); fi
    if (( NO_LANDLOCK )); then reporter_prefix+=( --no-landlock ); fi
    if (( GROUP_LOCK_ABOVE )); then reporter_prefix+=( --group-lock-above ); fi
    reporter_prefix+=( --landlock-bin "$LANDLOCK" -- )
  elif (( ! NO_LANDLOCK || GROUP_LOCK_ABOVE )); then
    _log "NOTICE: the denial reporter '${REPORTER}' is missing, so blocked actions are enforced but not reported in this run."
  fi
fi

# With --no-landlock the filesystem restriction is off, so run the command without Landlock.
# Run it as this layer's child with the default signal dispositions, so an outer timeout's kill
# escalation and the signals this layer passes on reach it, while this layer keeps ignoring
# SIGTERM between them and stays to remove the specification directory.
if (( NO_LANDLOCK )); then
  debug_log filesystem "filesystem layer disabled; run" "${reporter_prefix[@]}" "${limit_prefix[@]}" "${CMD[@]}"

  set +e
  run_forwarding_signals "${reporter_prefix[@]}" "${limit_prefix[@]}" "${CMD[@]}"
  rc=$?
  set -e
  report_resource_limit_hit "$rc" "${validated_limits[cpu]:-}" "${validated_limits[fsize_mb]:-}"
  exit "$rc"
fi

# --mark-reported-domain has the enforcer install, right after the restriction, a seccomp filter
# that allows everything, so a supervisor tells the tasks of this Landlock domain from the layers'
# helpers beside it by their filter count. It changes no outcome, and it is passed whoever reports,
# since the connect guard is the reporter when the network layer is on.
args=( --mark-reported-domain )
if (( PHB_DEBUG_ENABLED )); then args+=( --verbose ); fi

# One --rights=LETTERS rule per allow-listed path, the letters being exactly the sections the
# path appears in: [read] grants r, [execute] x, [write] w, [create] m (regular files and
# directories), [delete] d, [create-ipc] p (sockets and named pipes), [create-symlink] l, [ioctl] i (ioctl
# on a character or block device, and nothing else), and [restructure] m+d+f (create, delete and REFER, so the
# path may be renamed and moved within).
# Creating device nodes is never granted, since a device node reaches hardware the policy never
# named. A path that names no right at all is simply not listed and stays denied by Landlock's
# default. The Landlock TCP-port rules are no longer built here: they
# are the network boundary's kernel half and the network layer applies them on its own
# network-only ruleset, which composes with this filesystem-only one. The specification directory
# is kept out of every write path by phobos-policysystem.sh, where the write union is known and which
# runs whichever layers are in the chain.
build_path_args args "${READ}" "${EXECUTE}" "${WRITE}" "${CREATE}" "${DELETE}" "${IPC}" "${SYMLINK}" "${REFER}" "${IOCTL}"
if [[ -s "${TAIL}" ]]; then
  # Splitting is intended: tail.flags holds whitespace-separated arguments.
  # Read line by line so a multi-line file works too.
  while IFS= read -r tail_line || [[ -n "$tail_line" ]]; do
    [[ -z "$tail_line" ]] && continue
    read -ra tail_parts <<< "$tail_line"
    args+=( "${tail_parts[@]}" )
  done < "${TAIL}"
fi

debug_log filesystem "run" "${reporter_prefix[@]}" "${limit_prefix[@]}" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"

# The command runs as this layer's child, started through the reporter, when there is one, then the
# resource layer, when there is one, and phobos-landlock-filesystem-and-networksystem, which exec's
# it, so the last two and the command are one process that an outer timeout's kill escalation and
# the signals passed on reach directly, while this layer ignores SIGTERM between them and waits so
# it can word a limit the command hit. The reporter comes first and forks: its supervising half is
# this layer's child, passes every signal it receives on to that process and ends with its status,
# and the kill escalation reaches both, since they share the run's process group. The command's
# standard error is this layer's own; the reporter words what it decided on that stream, once, at
# the end. The timeout itself, when set, is phobos-timeoutsystem.sh's.
set +e
run_forwarding_signals "${reporter_prefix[@]}" "${limit_prefix[@]}" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"
rc=$?
set -e
report_resource_limit_hit "$rc" "${validated_limits[cpu]:-}" "${validated_limits[fsize_mb]:-}"
exit "$rc"
