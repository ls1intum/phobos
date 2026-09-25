#!/usr/bin/env bash
# shellcheck shell=bash
#
# phobos-policysystem.sh -- turn the base and exercise configuration into a run's specification.
#
# The one place that discovers the base policy, parses every cfg, merges them and writes the
# specification files (read/execute/write/create/delete.paths, net.rules, bind.rules, timeout.sec, tail.flags,
# limits.conf) into a directory the caller owns. phobos.sh calls it once and then assembles
# the layer chain over the same directory; a standalone caller can call it to build a
# specification and then run any single layer script over that directory itself, which is what
# each layer's own --config option does through this program, so no layer ever parses a config.
#
# Usage:
#   phobos-policysystem.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
#
# The caller creates and owns --spec-dir and removes it when the run ends. This script only
# writes into it, using a scratch subdirectory of it for its own temporary files.
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the call is refused because it was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos-policysystem.sh - turn the base and exercise configuration into a run's specification.

This is the one place that discovers the base policy, parses every configuration file,
merges them and writes the specification the layers read. It applies nothing itself and
runs no command: it only writes files into a directory the caller owns.

USAGE
  phobos-policysystem.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
  phobos-policysystem.sh --help

  There is no -- and no command. Every argument is an option.

OPTIONS
  --spec-dir <dir>            REQUIRED. The directory the specification is written into. It
                              must already exist. The caller creates it, owns it and removes
                              it when the run ends; this program only writes into it and
                              keeps its own temporary files in a scratch subdirectory of it.
  --config <file>, -c <file>  An exercise configuration, applied on top of the base. May be
                              given repeatedly and is applied in the order given. A file
                              that does not exist ends the run with PHB-EPOLICY.
  --tail-flags-file <file>    The tail flags, applied last
                              (default: "${HERE}/TailPhobos.cfg").
  --debug, -d                 Print the effective specification on stderr, one line per file.
  --help, -h                  Print this manual and end with status 0.

WHAT IT READS
  Every "${HERE}/Base*.cfg", in the order the shell sorts them, then each --config file. A
  name that matches Base*.cfg but is not a readable file ends the run with PHB-EPOLICY
  rather than being skipped, because skipping it would build a narrower policy and report it
  as a working one. With no Base*.cfg at all there is no sandbox to build, which is likewise
  refused.

WHAT IT WRITES INTO --spec-dir
  read.paths execute.paths write.paths create.paths delete.paths ipc.paths symlink.paths
  refer.paths   the filesystem allow-list, one path per line per right
  net.rules bind.rules accept.rules   the [connect], [bind] and [accept] rules
  timeout.sec   the wall-clock bound, empty when the run is not bounded
  limits.conf   one "key=value" line per resource limit that applies
  tail.flags    the flags handed to the Landlock enforcer last

HOW CONFIGURATIONS ARE MERGED
  Additively, in every dimension. Everything is denied first, and the platform, language and
  exercise configurations each only widen: filesystem paths and network rules are unioned,
  and for the timeout and for each resource limit the largest value any configuration names
  wins, where a zero switches that limit off and beats every finite value. An exercise
  configuration therefore cannot narrow below the base, which is why it is trusted input
  that the graded code must not be able to write; see SECURITY.md.

WITH NO --config AT ALL
  The run takes its most restrictive shape: every [connect], [bind] and [accept] rule the
  base granted is dropped, so the command reaches no network, not even loopback. The
  filesystem sections keep what the base granted, because a command whose own binary and
  libraries were denied could not start at all.

DEFAULTS WHEN NO CONFIGURATION NAMES A VALUE
    timeout   600 s wall-clock        mem_mb    8192  (ulimit -v, address space)
    cpu       600 s CPU time          nofile    1024
    nproc     256                     fsize_mb  256
  A configuration naming a larger value wins over the default, and one naming 0 switches
  that limit off and wins over it too.

EXIT STATUS
  0   the specification was written
  2   phobos-policysystem.sh was called the wrong way (PHB_EXIT_USAGE)
  11  the policy is invalid, missing, or names something that cannot be enforced (PHB-EPOLICY)

EXAMPLE
  mkdir -p /var/tmp/my-spec
  phobos-policysystem.sh --spec-dir /var/tmp/my-spec --config exercise.cfg
  cat /var/tmp/my-spec/read.paths
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

SPEC_DIR=""
tail_flags_file="${HERE}/TailPhobos.cfg"
cfgs=()
while (( "$#" )); do
  case "$1" in
    --spec-dir)        shift; [[ $# -gt 0 ]] || usage; SPEC_DIR="$1"; shift;;
    --tail-flags-file) shift; [[ $# -gt 0 ]] || usage; tail_flags_file="$1"; shift;;
    --config|-c)       shift; [[ $# -gt 0 ]] || usage; cfgs+=("$1"); shift;;
    --debug|-d)        enable_debug_log; shift;;
    --help|-h)         show_help;;
    *) usage;;
  esac
done
[[ -n "$SPEC_DIR" && -d "$SPEC_DIR" ]] || { echo "phobos-policysystem.sh: --spec-dir must name an existing directory" >&2; exit "${PHB_EXIT_USAGE}"; }

# Scratch for the temporary files parse_cfg_policy and the merge make: a subdirectory of the
# specification directory, so they are removed with it rather than left in /tmp. Passed to
# parse_cfg_policy through the environment it reads it from.
refuse_missing_realpath

PHOBOS_SCRATCH="${SPEC_DIR}/${PHB_SPEC_SCRATCH}"
mkdir -p "$PHOBOS_SCRATCH"
export PHOBOS_SCRATCH

# Every --config must name a file that exists.
for c in "${cfgs[@]}"; do
  [[ -f "$c" ]] || { echo "Config not found: $c" >&2; exit "${PHB_EPOLICY}"; }
done

# Every Base*.cfg beside this script, in the order the shell sorts a glob, which is the order
# the documentation promises. Read with a glob rather than by parsing ls, because a name is
# what this repository is careful about everywhere else it reads one.
#
# nullglob, and then a refusal rather than a skip: an unmatched glob has to become no base
# policy at all, while a name the glob did match and this program cannot read has to stop the
# run. Skipping such a name would build a policy from the bases that happened to be readable,
# which is a narrower sandbox reported as a working one. A directory or a broken symbolic
# link named Base*.cfg is therefore said out loud here, rather than left to fail somewhere
# further in with a message about a line that could not be read.
shopt -s nullglob
base_cfgs=( "${HERE}"/Base*.cfg )
shopt -u nullglob
for candidate in "${base_cfgs[@]}"; do
  [[ -f "$candidate" ]] && continue
  report "Policy invalid: '${candidate}' matches Base*.cfg but is not a readable file, so the base policy cannot be built. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
done
if [[ ${#base_cfgs[@]} -eq 0 ]]; then
  report "Policy invalid: no Base*.cfg beside phobos-policysystem.sh, so there is no sandbox to apply; refusing to build a policy. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
fi

base_dir="$(mktemp -d -p "$PHOBOS_SCRATCH")"
base_net="$(mktemp -p "$PHOBOS_SCRATCH")"
base_bind="$(mktemp -p "$PHOBOS_SCRATCH")"
base_accept="$(mktemp -p "$PHOBOS_SCRATCH")"
for r in ${PHB_FS_RIGHTS}; do : >"${base_dir}/${r}.paths"; done
: >"$base_net"; : >"$base_bind"; : >"$base_accept"
# The timeout and each resource limit are pooled across every base and exercise cfg by the
# same rule the setters use within a cfg: a zero anywhere disables that limit and wins, and
# otherwise the largest value is kept, so the order of the cfgs does not matter. Timeouts are
# compared in whole milliseconds, resource limits as base-ten integers.
timeout_disabled=0
timeout_max_ms=-1
declare -A limit_disabled=( [mem_mb]=0 [nproc]=0 [nofile]=0 [fsize_mb]=0 [cpu]=0 )
declare -A limit_max=( [mem_mb]=-1 [nproc]=-1 [nofile]=-1 [fsize_mb]=-1 [cpu]=-1 )

# Folds the PARSED_* values one parse_cfg_policy call produced into the pooled state above.
merge_limits() {
  if (( PARSED_TIMEOUT_DISABLED )); then timeout_disabled=1; fi
  if [[ -n "${PARSED_TIMEOUT:-}" ]]; then
    local ms; ms="$(timeout_to_ms "$PARSED_TIMEOUT")"
    if (( ms > timeout_max_ms )); then timeout_max_ms="$ms"; fi
  fi
  local key
  local upper
  local var
  local dvar
  local val
  for key in mem_mb nproc nofile fsize_mb cpu; do
    upper="${key^^}"
    var="PARSED_LIMIT_${upper}"
    dvar="PARSED_LIMIT_${upper}_DISABLED"
    if (( ${!dvar:-0} )); then limit_disabled[$key]=1; fi
    val="${!var:-}"
    if [[ -n "$val" ]] && (( 10#$val > limit_max[$key] )); then limit_max[$key]="$(( 10#$val ))"; fi
  done
}

# What each limit falls back to when no cfg named it. A fallback, never a cap: the merge
# above has already taken the largest value any cfg named, and a cfg naming zero has already
# set limit_disabled, so both beat the value here.
declare -A limit_default=( [mem_mb]="${PHB_DEFAULT_LIMIT_MEM_MB}" [nproc]="${PHB_DEFAULT_LIMIT_NPROC}" [nofile]="${PHB_DEFAULT_LIMIT_NOFILE}" [fsize_mb]="${PHB_DEFAULT_LIMIT_FSIZE_MB}" [cpu]="${PHB_DEFAULT_LIMIT_CPU}" )

# Resolves the pooled state into one effective value: a disabled limit prints nothing, so it
# is left out of the specification and not applied; otherwise the largest value any cfg named
# prints, and where no cfg named one the default above prints instead. The explicit success
# matters: this runs in a command substitution under set -e, where a final test that answered
# false would end the run.
effective_limit() {
  local key="$1"
  if (( limit_disabled[$key] )); then
    return 0
  fi
  if (( limit_max[$key] >= 0 )); then
    printf '%s' "${limit_max[$key]}"
    return 0
  fi
  printf '%s' "${limit_default[$key]}"
  return 0
}

# Folds one cfg into the policy being built: its filesystem sections are unioned into the
# directory, its [connect] and [bind] rules into the two files, and its [limits] into the
# pooled state. The base policy and every exercise config go through this same call, which is
# what makes the model additive in every dimension. Assumes it is called plainly, not in a
# subshell, because parse_cfg_policy refuses a malformed cfg by ending the run and because
# merge_limits writes the pooled state this shell holds.
fold_cfg_into() {
  local cfg="$1"
  local fs_dir="$2"
  local net_file="$3"
  local bind_file="$4"
  local accept_file="$5"
  local merged
  parse_cfg_policy "$cfg"
  fs_union_dir "$fs_dir" "$PARSED_FS_DIR"
  merged="$(mktemp -p "$PHOBOS_SCRATCH")"
  net_union "$merged" "$net_file" "$PARSED_NET_FILE"
  mv "$merged" "$net_file"
  merged="$(mktemp -p "$PHOBOS_SCRATCH")"
  net_union "$merged" "$bind_file" "$PARSED_BIND_FILE"
  mv "$merged" "$bind_file"
  merged="$(mktemp -p "$PHOBOS_SCRATCH")"
  net_union "$merged" "$accept_file" "$PARSED_ACCEPT_FILE"
  mv "$merged" "$accept_file"
  merge_limits
}

# Empties the three network rule files named by the arguments, for a run that was given no
# exercise configuration. Such a run is a containment posture rather than a working grading
# run, so it reaches no network at all, loopback included, although the base policy grants
# it. The filesystem sections are deliberately left alone: a command whose own binary and
# libraries were denied could not start, so there would be nothing to contain. Assumes every
# configuration has already been folded into these files.
drop_every_network_rule() {
  : > "$1"
  : > "$2"
  : > "$3"
}

# Build the base policy: every Base*.cfg folded in, in sorted order.
for b in "${base_cfgs[@]}"; do
  fold_cfg_into "$b" "$base_dir" "$base_net" "$base_bind" "$base_accept"
done

# Effective policy: start from the base, then add each exercise config on top. The model is
# additive in every dimension. Everything is denied first, and the platform, language and
# exercise configs each only widen: the filesystem paths are unioned exactly as the base
# configs were, matching the union already used for the network and bind sections and the
# largest-wins merge used for the limits. An exercise cannot narrow below the base, so the
# exercise/task config is trusted input and must not be writable by the graded code; see
# SECURITY.md. build_path_args still refuses a nested path granted fewer rights than an
# ancestor, which Landlock could not hold.
eff_dir="$(mktemp -d -p "$PHOBOS_SCRATCH")"
eff_net="$(mktemp -p "$PHOBOS_SCRATCH")"
eff_bind="$(mktemp -p "$PHOBOS_SCRATCH")"
eff_accept="$(mktemp -p "$PHOBOS_SCRATCH")"
for r in ${PHB_FS_RIGHTS}; do cp "${base_dir}/${r}.paths" "${eff_dir}/${r}.paths"; done
cp "$base_net" "$eff_net"; cp "$base_bind" "$eff_bind"; cp "$base_accept" "$eff_accept"

for c in "${cfgs[@]}"; do
  fold_cfg_into "$c" "$eff_dir" "$eff_net" "$eff_bind" "$eff_accept"
done

# A run given no exercise configuration reaches no network at all. Done here, after the base
# has been folded in and before the two refusals below, so they judge the emptied set rather
# than rules that are about to be dropped.
if [[ ${#cfgs[@]} -eq 0 ]]; then
  _log "No --config was given, so this run takes its most restrictive shape: every [connect], [bind] and [accept] rule the base policy granted is dropped and the command reaches no network at all, loopback included. Anything that talks over loopback, a Gradle daemon among it, will fail. Give the exercise's own configuration with --config for a run that may use the network."
  drop_every_network_rule "$eff_net" "$eff_bind" "$eff_accept"
fi

# Resolve the pooled timeout. A disabled one is written as none, a finite one is canonicalised
# so 2 and 2.000 produce the same specification, and a run no cfg bounded takes the default
# rather than running unbounded. The resource limits are resolved where they are written, below.
timeout_eff=""
if (( ! timeout_disabled )); then
  if (( timeout_max_ms < 0 )); then
    timeout_max_ms="$(timeout_to_ms "$PHB_DEFAULT_TIMEOUT_SECONDS")"
  fi
  timeout_eff="$(ms_to_timeout "$timeout_max_ms")"
fi

# Every [connect] and [bind] rule is judged here, once, before anything is written. The
# layer that builds the Landlock port rules checks the same thing, but it is not always in
# the chain: with --no-filesystem-restriction nothing would look at these rules at all, and
# the specification would carry a port the connect guard drops without a word.
refuse_unenforceable_network_rules "$eff_net" "$eff_bind"

# The inbound accept rules are judged against the merged bind set: the public port must not be one
# the graded code may bind itself, and the backend port must be one it may, both known only once
# every config has been folded in.
refuse_unenforceable_accept_rules "$eff_accept" "$eff_bind"

write_spec "$SPEC_DIR" "$eff_dir" "$eff_net" "$timeout_eff" "$tail_flags_file" "$eff_bind" "$eff_accept"

# The specification directory must lie outside every path the command may write, or the command
# could rewrite the connect policy the guard reads at run time, or the record of the hosts file
# the clean-up rewrites. Checked here, where the write union is known and which runs for every layer
# combination, rather than in the filesystem layer, which no longer sees the network runtime
# state now that the port rules and the connect guard live in the network layer.
writable_union="$(mktemp -p "$PHOBOS_SCRATCH")"
cat "${SPEC_DIR}/write.paths" "${SPEC_DIR}/create.paths" "${SPEC_DIR}/delete.paths" \
  "${SPEC_DIR}/ipc.paths" "${SPEC_DIR}/symlink.paths" "${SPEC_DIR}/refer.paths" 2>/dev/null \
  > "$writable_union" || :
refuse_spec_dir_under_write_path "$SPEC_DIR" "$writable_union"

# The resource limits go into the specification, one "key=value" per line for each limit a
# [limits] section named. phobos-resourcesystem.sh reads them and sets them with rlimits right
# before phobos-landlock-filesystem-and-networksystem, so phobos-landlock-filesystem-and-networksystem and the command inherit them, rather than this
# shell setting them and the whole layer chain, with its helpers, running under them.
: > "${SPEC_DIR}/limits.conf"
for key in mem_mb nproc nofile fsize_mb cpu; do
  value="$(effective_limit "$key")"
  [[ -n "$value" ]] && printf '%s=%s\n' "$key" "$value" >> "${SPEC_DIR}/limits.conf"
done

# Under --debug, the effective specification each layer below reads, one line per file.
for spec_file in ${PHB_SPEC_FILES}; do
  [[ -f "${SPEC_DIR}/${spec_file}" ]] || continue
  debug_log policy "${spec_file}: $(tr '\n' ' ' < "${SPEC_DIR}/${spec_file}")"
done

# A loop whose last pass took the false branch of a test answers non-zero, and that would
# otherwise become this script's exit status although the specification was written. Say the
# success rather than leave it to whatever the last command happened to answer.
exit 0
