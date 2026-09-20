#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

NO_LANDLOCK=0
NO_NETWORK_PORTS=0
LANDLOCK_BIN_OPT=""
RESOURCES_LAYER_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; shift ;;
    --no-landlock) NO_LANDLOCK=1; shift ;;
    --no-network-ports) NO_NETWORK_PORTS=1; shift ;;
    --landlock-bin) shift; LANDLOCK_BIN_OPT="${1:-}"; shift ;;
    --resources-layer) shift; RESOURCES_LAYER_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-filesystem.sh [--debug] [--no-landlock] [--no-network-ports] [--landlock-bin <path>] [--resources-layer <path>] <SPEC_DIR> -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
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

# This layer runs the command as a child and waits on it, so its stderr can be watched for
# denials. An outer timeout (phobos-timeout.sh) group-kills on expiry and escalates to SIGKILL
# only while GNU timeout's own child is still alive, so this layer ignores SIGTERM and stays
# until the command it waits on is gone. The command is put back to the default disposition
# just before it runs, so the graceful SIGTERM still reaches the command itself.
trap '' TERM

READ="${SPEC_DIR}/read.paths"
EXECUTE="${SPEC_DIR}/execute.paths"
WRITE="${SPEC_DIR}/write.paths"
CREATE="${SPEC_DIR}/create.paths"
DELETE="${SPEC_DIR}/delete.paths"
TAIL="${SPEC_DIR}/tail.flags"
LANDLOCK="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock}"

# With --resources-layer the command's resource limits are set by that layer, started as the
# very last step before phobos-landlock (or the command), so they reach phobos-landlock and the
# command and nothing else: this layer's shell, the stderr pass-through and the denial counter
# below run without them. A limit set any earlier would also bind those helpers, and a helper
# that dies of the command's file-size, memory or CPU limit takes the command's output with it.
# The limits are validated here, before any write path is materialised, so a malformed one is
# refused before this layer changes anything; the resource layer checks them again.
limit_prefix=()
if [[ -n "$RESOURCES_LAYER_OPT" ]]; then
  # read_limits_conf fills the array by name; this layer only needs its refusal, the resource
  # layer reads the values again when it applies them.
  # shellcheck disable=SC2034
  declare -A validated_limits
  read_limits_conf "${SPEC_DIR}/limits.conf" validated_limits
  limit_prefix=( "$RESOURCES_LAYER_OPT" )
  if (( PHB_DEBUG_ENABLED )); then limit_prefix+=( --debug ); fi
  limit_prefix+=( "$SPEC_DIR" -- )
fi

# With --no-landlock the filesystem restriction is off, so run the command without Landlock.
# Run it in a subshell that restores the default SIGTERM disposition and exec's it, so the
# command stands in as this layer's child: an outer timeout's kill escalation reaches it, while
# this layer keeps ignoring SIGTERM and stays to remove the specification directory.
if (( NO_LANDLOCK )); then
  debug_log filesystem "filesystem layer disabled; run" "${limit_prefix[@]}" "${CMD[@]}"

  set +e
  ( trap - TERM; exec "${limit_prefix[@]}" "${CMD[@]}" )
  rc=$?
  set -e
  exit "$rc"
fi

args=()
if (( PHB_DEBUG_ENABLED )); then args+=( --verbose ); fi

# The paths a submission can change: the union of the write, create and delete sections. The
# preload library and its rules file must stay out of this set, or a submission could rewrite
# its own network policy before starting another process.
WRITABLE="$(new_scratch_file phobos-writable.XXXXXX)"
cat "${WRITE}" "${CREATE}" "${DELETE}" 2>/dev/null > "${WRITABLE}" || :

# Keep the LD_PRELOAD library and its rules file reachable, and out of reach of
# change: Landlock must allow reading and mapping the library, or the loader skips
# it, and reading the rules file, which every process the command starts opens.
# PHB_NETBLOCKER_SO and NETBLOCKER_CONF are set by phobos-network.sh.
if [[ -n "${PHB_NETBLOCKER_SO:-}" && -f "${PHB_NETBLOCKER_SO}" && -n "${NETBLOCKER_CONF:-}" ]]; then
  append_netblocker_rules args "${WRITABLE}" "$PHB_NETBLOCKER_SO" "$NETBLOCKER_CONF" "${NETBLOCKER_BIND_CONF:-}"
fi
rm -f "${WRITABLE}"

# One --rights=LETTERS rule per allow-listed path, the letters being exactly the sections the
# path appears in: [read] grants r, [execute] x, [write] w, [create] m, [delete] d. Creating
# device nodes and symbolic links is never granted, since those are the two ways to reach
# something the policy never named. A path that names no right at all is simply not listed and
# stays denied by Landlock's default.
build_path_args args "${READ}" "${EXECUTE}" "${WRITE}" "${CREATE}" "${DELETE}"
# The Landlock TCP-port rules are the kernel-enforced half of the network boundary, built
# here rather than in the network layer. With --no-network-ports the network restriction is
# off as a whole, so they are skipped too, not only the preload filter.
if (( ! NO_NETWORK_PORTS )); then
  build_network_args args "${SPEC_DIR}/net.rules"
  build_bind_args args "${SPEC_DIR}/bind.rules"
fi
if [[ -s "${TAIL}" ]]; then
  # Splitting is intended: tail.flags holds whitespace-separated arguments.
  # Read line by line so a multi-line file works too.
  while IFS= read -r tail_line || [[ -n "$tail_line" ]]; do
    [[ -z "$tail_line" ]] && continue
    read -ra tail_parts <<< "$tail_line"
    args+=( "${tail_parts[@]}" )
  done < "${TAIL}"
fi

debug_log filesystem "run" "${limit_prefix[@]}" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"

# The command's stderr passes through tee to this layer's stderr unchanged, and a copy goes to
# count_denials, whose counts come back over an anonymous pipe. Nothing is written to a file, so
# the counts cannot be tampered with from inside the sandbox and no helper fills a disk. The
# command inherits neither descriptor, so it sees only its standard three and can neither feed
# the counter directly nor keep it alive through a hidden descriptor. tee -p keeps passing the
# output through should the counter die at its own limits, which only means no counts.
exec {denial_counts}<> <(:)
exec {filtered_stderr}> >(tee -p >(count_denials >&"$denial_counts") >&2)

# The command runs in a subshell that restores the default SIGTERM disposition and exec's the
# resource layer, when there is one, and phobos-landlock, so phobos-landlock and the command it
# runs are one process an outer timeout's kill escalation reaches directly, while this layer
# ignores SIGTERM and waits so it can report the denials. The timeout itself, when set, is
# phobos-timeout.sh's.
set +e
(
  trap - TERM
  exec "${limit_prefix[@]}" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"
) 2>&"$filtered_stderr" {filtered_stderr}>&- {denial_counts}>&-
rc=$?
set -e
exec {filtered_stderr}>&-

# The counts arrive once every writer of the command's stderr has gone. A process the command
# left behind can hold it open indefinitely, so the wait is bounded, and a run whose counts do
# not arrive in time, or whose counter died, reports none. Neither ever changes the exit status.
net_denials=0
fs_denials=0
if read -r -t "$PHB_DENIAL_COUNT_GRACE_SECONDS" -u "$denial_counts" net_denials fs_denials; then
  if (( net_denials > 0 || fs_denials > 0 )); then
    report "Sandbox denials: network=${net_denials}, filesystem=${fs_denials}. (PHB-EDENY)"
  fi
else
  debug_log filesystem "no denial counts within ${PHB_DENIAL_COUNT_GRACE_SECONDS}s; a process the command left behind may still hold its stderr"
fi
exec {denial_counts}<&-

exit "$rc"
