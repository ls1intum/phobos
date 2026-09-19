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
#   phobos-policy.sh --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]...
#
# The caller creates and owns --spec-dir and removes it when the run ends. This script only
# writes into it, using a scratch subdirectory of it for its own temporary files.
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

usage() {
  echo "Usage: phobos-policy.sh --spec-dir <dir> [--tail-flags-file <file>] [--config <file>]..." >&2
  exit 2
}

SPEC_DIR=""
tail_flags_file="${HERE}/TailPhobos.cfg"
cfgs=()
while (( "$#" )); do
  case "$1" in
    --spec-dir)        shift; [[ $# -gt 0 ]] || usage; SPEC_DIR="$1"; shift;;
    --tail-flags-file) shift; [[ $# -gt 0 ]] || usage; tail_flags_file="$1"; shift;;
    --config|-c)       shift; [[ $# -gt 0 ]] || usage; cfgs+=("$1"); shift;;
    *) usage;;
  esac
done
[[ -n "$SPEC_DIR" && -d "$SPEC_DIR" ]] || { echo "phobos-policy.sh: --spec-dir must name an existing directory" >&2; exit 2; }

# Scratch for the temporary files parse_cfg_policy and the merge make: a subdirectory of the
# specification directory, so they are removed with it rather than left in /tmp. Passed to
# parse_cfg_policy through the environment it reads it from.
PHOBOS_SCRATCH="${SPEC_DIR}/${PHB_SPEC_SCRATCH}"
mkdir -p "$PHOBOS_SCRATCH"
export PHOBOS_SCRATCH

# Every --config must name a file that exists.
for c in "${cfgs[@]}"; do
  [[ -f "$c" ]] || { echo "Config not found: $c" >&2; exit "${PHB_EPOLICY}"; }
done

mapfile -t base_cfgs < <(ls -1 "${HERE}"/Base*.cfg 2>/dev/null | sort || true)
if [[ ${#base_cfgs[@]} -eq 0 ]]; then
  report "Policy invalid: no Base*.cfg beside phobos-policy.sh, so there is no sandbox to apply; refusing to build a policy. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
fi

base_dir="$(mktemp -d -p "$PHOBOS_SCRATCH")"; base_net="$(mktemp -p "$PHOBOS_SCRATCH")"; base_bind="$(mktemp -p "$PHOBOS_SCRATCH")"
for r in ${PHB_FS_RIGHTS}; do : >"${base_dir}/${r}.paths"; done
: >"$base_net"; : >"$base_bind"
timeout_eff=""
eff_limit_mem_mb=""; eff_limit_nproc=""; eff_limit_nofile=""; eff_limit_fsize_mb=""; eff_limit_cpu=""

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
  local key upper var dvar val
  for key in mem_mb nproc nofile fsize_mb cpu; do
    upper="${key^^}"
    var="PARSED_LIMIT_${upper}"; dvar="PARSED_LIMIT_${upper}_DISABLED"
    if (( ${!dvar:-0} )); then limit_disabled[$key]=1; fi
    val="${!var:-}"
    if [[ -n "$val" ]] && (( 10#$val > limit_max[$key] )); then limit_max[$key]="$(( 10#$val ))"; fi
  done
}

# Resolves the pooled state into one effective value: a disabled limit prints nothing, so it
# is left out of the specification and not applied, and otherwise the largest value prints.
effective_limit() {
  local key="$1"
  if (( limit_disabled[$key] )); then printf '%s' ""; return 0; fi
  if (( limit_max[$key] >= 0 )); then printf '%s' "${limit_max[$key]}"; return 0; fi
  printf '%s' ""; return 0
}

# Build base policy (FS union, NET union, limits pooled by merge_limits)
for b in "${base_cfgs[@]}"; do
  parse_cfg_policy "$b"
  # FS: union only (no least-privilege checks while building base)
  fs_union_dir "$base_dir" "$PARSED_FS_DIR"
  # NET: union
  tmpnet="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpnet" "$base_net" "$PARSED_NET_FILE"; mv "$tmpnet" "$base_net"
  tmpbind="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpbind" "$base_bind" "$PARSED_BIND_FILE"; mv "$tmpbind" "$base_bind"
  merge_limits
done

# Effective policy: start from the base, then add each exercise config on top. The model is
# additive in every dimension. Everything is denied first, and the platform, language and
# exercise configs each only widen: the filesystem paths are unioned exactly as the base
# configs were, matching the union already used for the network and bind sections and the
# largest-wins merge used for the limits. An exercise cannot narrow below the base, so the
# exercise/task config is trusted input and must not be writable by the graded code; see
# SECURITY.md. build_path_args still refuses a nested path granted fewer rights than an
# ancestor, which Landlock could not hold.
eff_dir="$(mktemp -d -p "$PHOBOS_SCRATCH")"; eff_net="$(mktemp -p "$PHOBOS_SCRATCH")"; eff_bind="$(mktemp -p "$PHOBOS_SCRATCH")"
for r in ${PHB_FS_RIGHTS}; do cp "${base_dir}/${r}.paths" "${eff_dir}/${r}.paths"; done
cp "$base_net" "$eff_net"; cp "$base_bind" "$eff_bind"

for c in "${cfgs[@]}"; do
  parse_cfg_policy "$c"
  fs_union_dir "$eff_dir" "$PARSED_FS_DIR"
  tmpnet="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpnet" "$eff_net" "$PARSED_NET_FILE"; mv "$tmpnet" "$eff_net"
  tmpbind="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpbind" "$eff_bind" "$PARSED_BIND_FILE"; mv "$tmpbind" "$eff_bind"
  merge_limits
done

# Resolve the pooled state into the effective values. A disabled timeout is written as none,
# and a finite one is canonicalised so 2 and 2.000 produce the same specification.
if (( timeout_disabled )); then
  timeout_eff=""
elif (( timeout_max_ms >= 0 )); then
  timeout_eff="$(ms_to_timeout "$timeout_max_ms")"
else
  timeout_eff=""
fi
eff_limit_mem_mb="$(effective_limit mem_mb)"
eff_limit_nproc="$(effective_limit nproc)"
eff_limit_nofile="$(effective_limit nofile)"
eff_limit_fsize_mb="$(effective_limit fsize_mb)"
eff_limit_cpu="$(effective_limit cpu)"

write_spec "$SPEC_DIR" "$eff_dir" "$eff_net" "$timeout_eff" "$tail_flags_file" "$eff_bind"

# The resource limits go into the specification, one "key=value" per line for each limit a
# [limits] section named. phobos-resources.sh reads them and sets them with rlimits right
# before phobos-landlock, so phobos-landlock and the command inherit them, rather than this
# shell setting them and the whole layer chain, with its helpers, running under them.
{
  [[ -n "$eff_limit_mem_mb"   ]] && printf 'mem_mb=%s\n'   "$eff_limit_mem_mb"
  [[ -n "$eff_limit_nproc"    ]] && printf 'nproc=%s\n'    "$eff_limit_nproc"
  [[ -n "$eff_limit_nofile"   ]] && printf 'nofile=%s\n'   "$eff_limit_nofile"
  [[ -n "$eff_limit_fsize_mb" ]] && printf 'fsize_mb=%s\n' "$eff_limit_fsize_mb"
  [[ -n "$eff_limit_cpu"      ]] && printf 'cpu=%s\n'      "$eff_limit_cpu"
} > "${SPEC_DIR}/limits.conf"

# The last conditional above can leave a non-zero status when the final limit is unset, which
# would otherwise become this script's exit status. The specification is written; report success.
exit 0
