#!/usr/bin/env bash
# shellcheck shell=bash
#
# phobos-policy.sh -- turn the base and exercise configuration into a run's specification.
#
# The one place that discovers the base policy, parses every cfg, merges them and writes the
# specification files (read/execute/write/create/delete.paths, net.rules, bind.rules, timeout.sec, tail.flags,
# limits.conf) into a directory the caller owns. phobos.sh calls it once and then assembles
# the layer chain over the same directory; a standalone caller can call it to build a
# specification and then run any single layer script over that directory itself.
#
# Usage:
#   phobos-policy.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
#
# The caller creates and owns --spec-dir and removes it when the run ends. This script only
# writes into it, using a scratch subdirectory of it for its own temporary files.
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

# Prints how to call the policy program and ends with PHB_EXIT_USAGE.
usage() {
  echo "Usage: phobos-policy.sh [--debug] --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]..." >&2
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
    --debug)           enable_debug_log; shift;;
    *) usage;;
  esac
done
[[ -n "$SPEC_DIR" && -d "$SPEC_DIR" ]] || { echo "phobos-policy.sh: --spec-dir must name an existing directory" >&2; exit "${PHB_EXIT_USAGE}"; }

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
  report "Policy invalid: no Base*.cfg beside phobos-policy.sh, so there is no sandbox to apply; refusing to build a policy. (PHB-EPOLICY)"
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

# Resolves the pooled state into one effective value: a disabled limit prints nothing, so it
# is left out of the specification and not applied, and otherwise the largest value prints.
# A limit no cfg named prints nothing either. The explicit success matters: this runs in a
# command substitution under set -e, where a final test that answered false would end the run.
effective_limit() {
  local key="$1"
  if (( limit_disabled[$key] == 0 && limit_max[$key] >= 0 )); then
    printf '%s' "${limit_max[$key]}"
  fi
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

# Resolve the pooled timeout. A disabled one is written as none, and a finite one is
# canonicalised so 2 and 2.000 produce the same specification. The resource limits are
# resolved where they are written, below.
timeout_eff=""
if (( ! timeout_disabled )) && (( timeout_max_ms >= 0 )); then
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

# The resource limits go into the specification, one "key=value" per line for each limit a
# [limits] section named. phobos-resources.sh reads them and sets them with rlimits right
# before phobos-landlock, so phobos-landlock and the command inherit them, rather than this
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
