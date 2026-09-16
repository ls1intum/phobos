#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

usage() {
  cat <<USAGE
Usage:
  phobos.sh [layer options] [--config <file>]... -- <build_command> [args...]
  phobos.sh [layer options] [--config <file>]... <build_command> [args...]

Restriction options (every restriction is applied by default):
  --no-runtime-restriction, -ntr     Disable the timeout (phobos-timeout.sh).
  --no-networksystem-restriction, -nnr
                                     Disable the whole network restriction: the
                                     libnetblocker preload filter and the Landlock
                                     TCP-port rules.
  --no-resources-restriction, -nrr   Disable the resource limits (rlimits /
                                     phobos-resources.sh).
  --no-filesystem-restriction, -nfr  Disable the filesystem sandbox (Landlock). This
                                     turns off ALL of Landlock, the TCP-port rules
                                     included, since they are one kernel ruleset.
  --allow-unsandboxed                Debug switch: run the command raw, with every
                                     layer disabled, EVEN when a base policy is
                                     present. For deliberate unconfined runs only.
  --debug                            Print the exact command each layer runs.

Override options (taken only from the command line, never from the environment):
  --landlock-bin <path>              The phobos-landlock binary (default: beside this script).
  --timeout-bin <path>              The timeout tool (default: timeout).
  --netblocker-so <path>            The libnetblocker library (default: beside this script).
  --connect-guard-bin <path>        The connect guard (default: beside this script).
  --tail-flags-file <path>          The tail flags file (default: TailPhobos.cfg beside this script).
  --spec-parent <path>              Where the run's specification directory is made (default: /var/tmp).

Notes:
- Base config: any "${HERE}/Base*.cfg" (INI-like) is applied first (sorted).
- Exercise configs: only files passed via --config/-c are applied in order;
  per-path FS merge, NET union, and for the timeout and each resource limit the
  largest value any cfg names, where a zero switches that limit off and wins.
- Tail config: "${HERE}/TailPhobos.cfg" (flags only) is applied last.
- If no Base*.cfg is present, Phobos refuses to run (PHB-EPOLICY) rather than run
  the command unconfined. --allow-unsandboxed opts into a raw run on purpose.
- An unknown option is refused rather than treated as the command. The first
  non-option word is the command; everything after it is its arguments.
- The run's policy is written to a directory under --spec-parent (default
  /var/tmp), which must lie outside every write path, and removed when the run
  ends, together with the scratch subdirectory this script keeps inside it. The layer that
  waits for the command removes it: the timeout layer when a timeout bounds the run, since the
  filesystem layer is then group-killed with the command, and the filesystem layer otherwise.
USAGE
  exit 2
}

[[ $# -lt 1 ]] && usage

# Layer toggles (default: all enabled)
enable_timeout=1
enable_network=1
enable_resources=1
enable_filesystem=1
enable_debug=0
# Refusing to run without a base policy is the default; this is the explicit opt-out.
allow_unsandboxed=0

# Which enforcement tools and locations a run uses. Taken only from these flags, never from
# the environment, so a value left in the environment cannot change which binary applies the
# sandbox, which timeout tool bounds it, which library filters the network, where the tail
# flags come from, or where the specification is written. Empty means the built-in default.
opt_landlock_bin=""
opt_timeout_bin=""
opt_netblocker_so=""
opt_connect_guard_bin=""
opt_tail_flags_file=""
opt_spec_parent=""

cfgs=()
cmd=()
while (( "$#" )); do
  case "$1" in
    --config|-c)
      shift
      [[ $# -gt 0 ]] || usage
      cfgs+=("$1"); shift;;
    --no-runtime-restriction|-ntr)
      enable_timeout=0; shift;;
    --no-networksystem-restriction|-nnr)
      enable_network=0; shift;;
    --no-resources-restriction|-nrr)
      enable_resources=0; shift;;
    --no-filesystem-restriction|-nfr)
      enable_filesystem=0; shift;;
    --allow-unsandboxed)
      allow_unsandboxed=1; shift;;
    --debug)
      enable_debug=1; shift;;
    --landlock-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_landlock_bin="$1"; shift;;
    --timeout-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_timeout_bin="$1"; shift;;
    --netblocker-so)
      shift; [[ $# -gt 0 ]] || usage; opt_netblocker_so="$1"; shift;;
    --connect-guard-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_connect_guard_bin="$1"; shift;;
    --tail-flags-file)
      shift; [[ $# -gt 0 ]] || usage; opt_tail_flags_file="$1"; shift;;
    --spec-parent)
      shift; [[ $# -gt 0 ]] || usage; opt_spec_parent="$1"; shift;;
    --)
      shift
      while (( "$#" )); do cmd+=("$1"); shift; done
      break;;
    -*)
      # An unknown option is refused rather than silently run as the command, so an
      # obsolete or mistyped flag fails clearly instead of ending up as argv.
      echo "Unknown option: $1" >&2; usage;;
    *)
      # The first non-option word is the command; everything after it, options
      # included, is its arguments.
      while (( "$#" )); do cmd+=("$1"); shift; done
      break;;
  esac
done
[[ ${#cmd[@]} -eq 0 ]] && usage

# --allow-unsandboxed is a debug switch: it runs the command with no layer at all, even
# when a base policy is present. Handled here, before any specification directory is
# created, so a raw run leaves nothing behind, and before the configs are read, since
# there is no sandbox to build from them.
if (( allow_unsandboxed )); then
  _log "WARNING: --allow-unsandboxed given; running the command RAW, with NO sandbox."
  _log "runtime restriction (timeout) DISABLED"
  _log "network-system restriction (libnetblocker) DISABLED"
  _log "resources restriction (rlimits) DISABLED"
  _log "filesystem restriction (Landlock) DISABLED"
  (( ${#cfgs[@]} )) && _log "--allow-unsandboxed ignores the ${#cfgs[@]} --config file(s) given: there is no sandbox to apply them to."
  exec "${cmd[@]}"
fi

# Loudly record every restriction the caller switched off, so a run with a layer
# disabled cannot look like an ordinary one in a log.
(( enable_timeout ))    || _log "runtime restriction (timeout) DISABLED by --no-runtime-restriction"
(( enable_network ))    || _log "network-system restriction (libnetblocker) DISABLED by --no-networksystem-restriction"
(( enable_resources ))  || _log "resources restriction (rlimits) DISABLED by --no-resources-restriction"
(( enable_filesystem )) || _log "filesystem restriction (Landlock) DISABLED by --no-filesystem-restriction"

# Clear the internal channels a layer would otherwise inherit, so a value left in the
# environment cannot make a layer act that the flags left out of the chain. Each layer that
# is in the chain sets its own.
unset PHB_NETBLOCKER_SO NETBLOCKER_CONF NETBLOCKER_BIND_CONF

# Resolve the startup overrides from the flags, with the built-in defaults. The environment
# is deliberately not consulted for any of them.
tail_flags_file="${opt_tail_flags_file:-${HERE}/TailPhobos.cfg}"
landlock_bin="${opt_landlock_bin:-${HERE}/phobos-landlock}"
timeout_bin="${opt_timeout_bin:-timeout}"
netblocker_so="${opt_netblocker_so:-${HERE}/libnetblocker.so}"
connect_guard_bin="${opt_connect_guard_bin:-${HERE}/phobos-connect-guard}"

# The specification directory is created before any scratch file, so every temporary file
# this script makes lives under it and is removed with it. phobos.sh ends with exec, so its
# own EXIT trap never runs; the layer that finally ends the run removes the specification
# directory, and with it the scratch subdirectory, in one place. It has to lie outside every
# write path, where Landlock keeps the rules file it holds unchangeable. /tmp is a write path
# in both shipped policies; /var/tmp is in neither.
spec_parent="${opt_spec_parent:-/var/tmp}"
refuse_unusable_spec_parent "$spec_parent"
SPEC_DIR="$(mktemp -d "${spec_parent%/}/phobos-spec.XXXXXX")"
mark_owned_spec_dir "$SPEC_DIR"
PHOBOS_SCRATCH="${SPEC_DIR}/${PHB_SPEC_SCRATCH}"
mkdir -p "$PHOBOS_SCRATCH"
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

# Build the run's specification: base discovery, parse, merge and every spec file, all in
# the one policy program, over the directory this script owns and the chain below reads.
policy_flags=( --spec-dir "$SPEC_DIR" --tail-flags-file "$tail_flags_file" )
for c in "${cfgs[@]}"; do policy_flags+=( --config "$c" ); done
"${HERE}/phobos-policy.sh" "${policy_flags[@]}"

# Assemble the layer chain from the flags: a disabled layer is left out of the chain rather
# than entered and skipped, so no PHB_ENABLE_* has to travel with the run. Each wrapper does
# its work and hands on the rest of the chain; the timeout layer, when a timeout is set, runs
# the rest under GNU timeout and waits on it, and the filesystem layer is always last and runs
# the command, applying Landlock unless --no-landlock tells it not to.
dbg=(); (( enable_debug )) && dbg=(--debug)
chain=()
if (( enable_timeout ));   then chain+=( "${HERE}/phobos-timeout.sh"   "${dbg[@]}" --timeout-bin "$timeout_bin" "$SPEC_DIR" -- ); fi
if (( enable_network ));   then chain+=( "${HERE}/phobos-network.sh"   "${dbg[@]}" --netblocker-so "$netblocker_so" --connect-guard-bin "$connect_guard_bin" "$SPEC_DIR" -- ); fi
if (( enable_resources )); then chain+=( "${HERE}/phobos-resources.sh" "${dbg[@]}" "$SPEC_DIR" -- ); fi
fs_flags=( "${dbg[@]}" --landlock-bin "$landlock_bin" )
if (( ! enable_filesystem )); then fs_flags+=( --no-landlock ); fi
# The network restriction spans two layers: the preload filter in phobos-network.sh, left
# out of the chain above, and the kernel-enforced Landlock TCP-port rules built in the
# filesystem layer. Disabling the network restriction has to cover both, so tell the
# filesystem layer to skip the port rules too.
if (( ! enable_network )); then fs_flags+=( --no-network-ports ); fi
chain+=( "${HERE}/phobos-filesystem.sh" "${fs_flags[@]}" "$SPEC_DIR" -- )
exec "${chain[@]}" "${cmd[@]}"
