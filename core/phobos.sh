#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the run is refused because the call was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos.sh - run a command under the Phobos sandbox.

Phobos confines a command to the files, the network and the resources its policy names.
Everything the policy does not name is denied. The policy is built once, from the shipped
base configuration plus any exercise configuration given, and is then applied by four
layers: the timeout, the network, the resources and the filesystem.

USAGE
  phobos.sh [options] [--config <file>]... -- <command> [args...]
  phobos.sh [options] [--config <file>]... <command> [args...]
  phobos.sh --help

  Everything after -- is the command and its arguments. Without --, the first word that is
  not an option starts the command, and every word after it belongs to the command, its own
  options included. An option phobos.sh does not know is refused rather than run as the
  command, so a mistyped flag fails clearly instead of ending up as argv.

POLICY
  Base configuration      every "${HERE}/Base*.cfg", applied first, in sorted order. With
                          none present Phobos refuses to run (PHB-EPOLICY) rather than run
                          the command unconfined.
  Exercise configuration  only the files given with --config, applied in that order.
  Tail configuration      "${HERE}/TailPhobos.cfg", flags only, applied last.

  The model is additive: filesystem paths and network rules are unioned, and for the timeout
  and for each resource limit the largest value any configuration names wins, where a zero
  switches that limit off and beats every finite value.

  WITHOUT --config the run takes its most restrictive shape. Every [connect], [bind] and
  [accept] rule the base granted is dropped, so the command reaches no network at all, not
  even loopback. The base still grants the filesystem, because a command whose own binary
  and libraries were denied could not start at all. A bare run is therefore a containment
  posture rather than a working grading run: anything that talks over loopback, a Gradle
  daemon among it, fails. Give the exercise's own policy with --config for a real run.

DEFAULTS WHEN NO CONFIGURATION NAMES A VALUE
    timeout   600 s wall-clock        mem_mb    8192  (ulimit -v, address space)
    cpu       600 s CPU time          nofile    1024
    nproc     256                     fsize_mb  256
  A configuration naming a larger value wins over the default, and one naming 0 switches
  that limit off and wins over it too.

RESTRICTION OPTIONS (every restriction is applied by default)
  --no-timeoutsystem-restriction, -ntr
        Disable the timeout (phobos-timeoutsystem.sh). The command may then run forever.
  --no-networksystem-restriction, -nnr
        Disable the whole network restriction: the connect guard and the Landlock port
        rules. An [accept] rule then starts no inbound filter either and the listener's
        port is not locked, so the listener runs fully exposed.
  --no-resourcesystem-restriction, -nrr
        Disable the resource limits (rlimits, phobos-resourcesystem.sh).
  --no-filesystem-restriction, -nfr
        Disable the filesystem sandbox (Landlock). The port rules are unaffected: they are
        a separate network-only ruleset the network layer applies.
  --no-restriction, -nr
        DANGER: runs the command COMPLETELY UNCONFINED, even when a base policy is present.
        Not one layer is applied: no Landlock, no connect guard, no timeout, no rlimits.
        A debugging switch, never a grading mode. It is refused together with --config,
        because giving a policy says a confined run was meant, and that refusal is what
        catches -nr typed where -nrr was meant. Note how close the two are:
          -nrr  disables ONLY the resource limits
          -nr   disables THE ENTIRE SANDBOX

OTHER OPTIONS
  --config <file>, -c <file>
        An exercise configuration, applied on top of the base. May be given repeatedly.
  --debug, -d
        Report on stderr what each layer does and runs, and have the enforcers report
        verbosely too. It prints the whole effective policy, so it is meant for diagnosis
        rather than for a grading log.
  --help, -h
        Print this manual and end with status 0.

OVERRIDE OPTIONS (read from the command line only, never from the environment, so a value
left in the environment cannot change which binary applies the sandbox)
  --landlock-bin <path>       the Landlock enforcer            (default: beside this script)
  --connect-guard-bin <path>  the connect guard                (default: beside this script)
  --pgroup-lock-bin <path>    the timeout's group lock         (default: beside this script)
  --timeout-bin <path>        the timeout tool                 (default: timeout)
  --haproxy-bin <path>        the egress broker and the inbound filter  (default: haproxy)
  --resolver <ip[:port]>      the DNS resolver the egress broker resolves an exact [connect]
                              host name through, the default DNS port being used when none
                              is given. The broker starts by itself whenever a [connect]
                              rule names a host, and an exact-name rule is refused when no
                              resolver was given.
  --tail-flags-file <path>    the tail flags   (default: TailPhobos.cfg beside this script)
  --spec-parent <path>        where the run's specification directory is made (default:
                              /var/tmp). It must lie outside every write path, and it is
                              removed together with its scratch subdirectory when the run
                              ends. The layer that waits for the command removes it: the
                              timeout layer when a timeout bounds the run, since the
                              filesystem layer is then group-killed with the command, and
                              the filesystem layer otherwise.

EXIT STATUS
  0 to 255  the command's own status, passed through unchanged
  2         phobos.sh was called the wrong way (PHB_EXIT_USAGE)
  11        the policy is invalid or missing (PHB-EPOLICY)
  14        the command ran past its timeout (PHB-ETIMEOUT)
  15        something the run needs could not be started (PHB-ERUNTIME)

EXAMPLES
  phobos.sh --config exercise.cfg -- ./gradlew test
        Grade an exercise under its own policy.
  phobos.sh -d --config exercise.cfg -- ./gradlew test
        The same, reporting what each layer does and what the effective policy is.
  phobos.sh -nnr --config exercise.cfg -- ./gradlew test
        The same with the network restriction off, to find out which layer a failure
        belongs to.
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
opt_pgroup_lock_bin=""
opt_connect_guard_bin=""
opt_tail_flags_file=""
opt_spec_parent=""
opt_haproxy_bin=""
opt_resolver=""

cfgs=()
cmd=()
while (( "$#" )); do
  case "$1" in
    --config|-c)
      shift
      [[ $# -gt 0 ]] || usage
      cfgs+=("$1"); shift;;
    --no-timeoutsystem-restriction|-ntr)
      enable_timeout=0; shift;;
    --no-networksystem-restriction|-nnr)
      enable_network=0; shift;;
    --no-resourcesystem-restriction|-nrr)
      enable_resources=0; shift;;
    --no-filesystem-restriction|-nfr)
      enable_filesystem=0; shift;;
    --no-restriction|-nr)
      allow_unsandboxed=1; shift;;
    --help|-h)
      show_help;;
    --haproxy-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_haproxy_bin="$1"; shift;;
    --resolver)
      shift; [[ $# -gt 0 ]] || usage; opt_resolver="$1"; shift;;
    --debug|-d)
      enable_debug=1; enable_debug_log; shift;;
    --landlock-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_landlock_bin="$1"; shift;;
    --timeout-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_timeout_bin="$1"; shift;;
    --pgroup-lock-bin)
      shift; [[ $# -gt 0 ]] || usage; opt_pgroup_lock_bin="$1"; shift;;
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

# --no-restriction is a debug switch: it runs the command with no layer at all, even when a
# base policy is present. Handled here, before any specification directory is created, so a
# raw run leaves nothing behind, and before the configs are read, since there is no sandbox
# to build from them. A --config beside it is refused rather than ignored: giving a policy
# says a confined run was meant, which is what catches -nr typed where -nrr was meant, the
# two being one character apart and worlds apart in what they switch off.
if (( allow_unsandboxed )) && (( ${#cfgs[@]} )); then
  echo "--no-restriction runs the command with no sandbox at all, so the ${#cfgs[@]} --config file(s) given could not be applied to anything. Giving a policy says a confined run was meant, so this combination is refused rather than run unconfined. Did you mean -nrr (only the resource limits) rather than -nr (the entire sandbox)?" >&2
  usage
fi

if (( allow_unsandboxed )); then
  _log "############################################################"
  _log "#  WARNING: --no-restriction (-nr) given.                  #"
  _log "#  THE COMMAND RUNS COMPLETELY UNCONFINED.                 #"
  _log "############################################################"
  _log "filesystem restriction (Landlock) DISABLED"
  _log "network-system restriction (connect guard and port rules) DISABLED"
  _log "timeout-system restriction (timeout) DISABLED"
  _log "resource-system restriction (rlimits) DISABLED"
  _log "Nothing below this line is contained by Phobos."
  exec "${cmd[@]}"
fi

# Loudly record every restriction the caller switched off, so a run with a layer
# disabled cannot look like an ordinary one in a log.
(( enable_timeout ))    || _log "timeout-system restriction (timeout) DISABLED by --no-timeoutsystem-restriction"
(( enable_network ))    || _log "network-system restriction (connect guard) DISABLED by --no-networksystem-restriction"
(( enable_resources ))  || _log "resource-system restriction (rlimits) DISABLED by --no-resourcesystem-restriction"
(( enable_filesystem )) || _log "filesystem restriction (Landlock) DISABLED by --no-filesystem-restriction"

# Resolve the startup overrides from the flags, with the built-in defaults. The environment
# is deliberately not consulted for any of them.
tail_flags_file="${opt_tail_flags_file:-${HERE}/TailPhobos.cfg}"
landlock_bin="${opt_landlock_bin:-${HERE}/phobos-landlock-filesystem-and-networksystem}"
timeout_bin="${opt_timeout_bin:-timeout}"
pgroup_lock_bin="${opt_pgroup_lock_bin:-${HERE}/phobos-seccomp-timeoutsystem}"
connect_guard_bin="${opt_connect_guard_bin:-${HERE}/phobos-seccomp-networksystem}"
haproxy_bin="${opt_haproxy_bin:-haproxy}"
resolver="${opt_resolver:-}"

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
if (( enable_debug )); then policy_flags+=( --debug ); fi
for c in "${cfgs[@]}"; do policy_flags+=( --config "$c" ); done
"${HERE}/phobos-policysystem.sh" "${policy_flags[@]}"

# The inbound filter and the bind-port lock both live in the network layer now: the filter is the
# inbound haproxy and the lock is the network-only Landlock ruleset the network layer applies. With
# the network restriction off, an [accept] rule starts no filter and the listener's port is not
# locked either, so the listener runs fully exposed. Say so rather than let a disabled restriction
# quietly drop the enforcement.
if [[ -s "${SPEC_DIR}/accept.rules" ]] && (( ! enable_network )); then
  _log "inbound filter from an [accept] rule IGNORED because the network-system restriction is DISABLED; the listener runs unfiltered and its public port is not locked"
fi

# Assemble the layer chain from the flags: a disabled layer is left out of the chain rather
# than entered and skipped, so no PHB_ENABLE_* has to travel with the run. Each wrapper does
# its work and hands on the rest of the chain; the timeout layer, when a timeout is set, runs
# the rest under GNU timeout and waits on it, and the filesystem layer is always last and runs
# the command, applying Landlock unless --no-landlock tells it not to. The resource layer is
# not a link of this chain: the filesystem layer starts it as the last step before
# phobos-landlock-filesystem-and-networksystem, so the command's limits bind the command and none of the helpers around it.
dbg=(); (( enable_debug )) && dbg=(--debug)
chain=()
if (( enable_timeout ));   then chain+=( "${HERE}/phobos-timeoutsystem.sh"   "${dbg[@]}" --timeout-bin "$timeout_bin" --pgroup-lock-bin "$pgroup_lock_bin" "$SPEC_DIR" -- ); fi
network_flags=( "${dbg[@]}" --connect-guard-bin "$connect_guard_bin" --haproxy-bin "$haproxy_bin" --landlock-bin "$landlock_bin" )
# The network layer starts the broker itself when a [connect] rule names a host, so no flag
# selects it here; the resolver it needs for an exact name is passed through when given. It also
# applies the kernel-enforced Landlock TCP-port rules on a network-only ruleset of its own, so the
# whole network restriction, the connect guard and the port rules alike, lives in this one layer
# and is simply left out of the chain when the network restriction is disabled.
if [[ -n "$resolver" ]]; then network_flags+=( --resolver "$resolver" ); fi
if (( enable_network ));   then chain+=( "${HERE}/phobos-networksystem.sh"   "${network_flags[@]}" "$SPEC_DIR" -- ); fi
fs_flags=( "${dbg[@]}" --landlock-bin "$landlock_bin" )
if (( enable_resources )); then fs_flags+=( --resources-layer "${HERE}/phobos-resourcesystem.sh" ); fi
if (( ! enable_filesystem )); then fs_flags+=( --no-landlock ); fi
chain+=( "${HERE}/phobos-filesystem.sh" "${fs_flags[@]}" "$SPEC_DIR" -- )
debug_log phobos "run the layer chain" "${chain[@]}" "${cmd[@]}"
exec "${chain[@]}" "${cmd[@]}"
