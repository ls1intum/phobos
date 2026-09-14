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

Layer options (all enabled by default):
  --no-timeout        Disable timeout wrapper (phobos-timeout.sh).
  --no-network        Disable network sandbox (libnetblocker / phobos-network.sh).
  --no-resources      Disable resource limits (rlimits / phobos-resources.sh).
  --no-filesystem     Disable filesystem sandbox (Landlock / phobos-filesystem.sh).
  --allow-unsandboxed Run the command with no sandbox when no Base*.cfg is present,
                      instead of refusing. For deliberate raw runs only.

Notes:
- Base config: any "${HERE}/Base*.cfg" (INI-like) is applied first (sorted).
- Exercise configs: only files passed via --config/-c are applied in order;
  per-path FS merge, NET union, TIMEOUT last-wins.
- Tail config: "${HERE}/TailPhobos.cfg" (flags only) is applied last.
- If no Base*.cfg is present, Phobos refuses to run (PHB-EPOLICY) rather than run
  the command unconfined. --allow-unsandboxed opts into a raw run on purpose.
- The run's policy is written to a directory under PHOBOS_SPEC_PARENT (default
  /var/tmp), which must lie outside every write path, and removed when the run
  ends, together with the scratch subdirectory this script keeps inside it. A run
  with --no-filesystem and --no-timeout hands the command to exec and leaves that
  directory behind.
USAGE
  exit 2
}

[[ $# -lt 1 ]] && usage

# Layer toggles (default: all enabled)
enable_timeout=1
enable_network=1
enable_resources=1
enable_filesystem=1
# Refusing to run without a base policy is the default; this is the explicit opt-out.
allow_unsandboxed=0

cfgs=()
cmd=()
while (( "$#" )); do
  case "$1" in
    --config|-c)
      shift
      [[ $# -gt 0 ]] || usage
      [[ -f "$1" ]] || { echo "Config not found: $1" >&2; exit ${PHB_EPOLICY}; }
      cfgs+=("$1"); shift;;
    --no-timeout)
      enable_timeout=0; shift;;
    --no-network)
      enable_network=0; shift;;
    --no-resources)
      enable_resources=0; shift;;
    --no-filesystem|--no-fs)
      enable_filesystem=0; shift;;
    --allow-unsandboxed)
      allow_unsandboxed=1; shift;;
    --)
      shift
      while (( "$#" )); do cmd+=("$1"); shift; done
      break;;
    *)
      cmd+=("$1"); shift;;
  esac
done
[[ ${#cmd[@]} -eq 0 ]] && usage

# Export layer selection for inner scripts
export PHB_ENABLE_TIMEOUT="$enable_timeout"
export PHB_ENABLE_NETWORK="$enable_network"
export PHB_ENABLE_RESOURCES="$enable_resources"
export PHB_ENABLE_FILESYSTEM="$enable_filesystem"

mapfile -t base_cfgs < <(ls -1 "${HERE}"/Base*.cfg 2>/dev/null | sort || true)
if [[ ${#base_cfgs[@]} -eq 0 ]]; then
  # No base policy means no sandbox. Running the command anyway would grade an untrusted
  # submission unconfined while looking like Phobos ran, so refuse by default;
  # --allow-unsandboxed is the explicit, per-invocation opt-out for a deliberate raw run.
  if (( allow_unsandboxed )); then
    _log "No Base*.cfg found; --allow-unsandboxed given, running command without sandbox."
    exec "${cmd[@]}"
  fi
  report "Policy invalid: no Base*.cfg beside phobos.sh, so there is no sandbox to apply; refusing to run the command unconfined. Pass --allow-unsandboxed to run it raw on purpose. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
fi

: "${TAIL_FLAGS_FILE:=${HERE}/TailPhobos.cfg}"

# The specification directory is created before any scratch file, so every temporary file
# this script makes lives under it and is removed with it. phobos.sh ends with exec, so its
# own EXIT trap never runs; the layer that finally ends the run removes the specification
# directory, and with it the scratch subdirectory, in one place. It has to lie outside every
# write path, where Landlock keeps the rules file it holds unchangeable. /tmp is a write path
# in both shipped policies; /var/tmp is in neither.
spec_parent="${PHOBOS_SPEC_PARENT:-/var/tmp}"
refuse_unusable_spec_parent "$spec_parent"
SPEC_DIR="$(mktemp -d "${spec_parent%/}/phobos-spec.XXXXXX")"
mark_owned_spec_dir "$SPEC_DIR"
PHOBOS_SCRATCH="${SPEC_DIR}/${PHB_SPEC_SCRATCH}"
mkdir -p "$PHOBOS_SCRATCH"
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

base_ro="$(mktemp -p "$PHOBOS_SCRATCH")"; base_rw="$(mktemp -p "$PHOBOS_SCRATCH")"; base_hide="$(mktemp -p "$PHOBOS_SCRATCH")"; base_net="$(mktemp -p "$PHOBOS_SCRATCH")"
: >"$base_ro"; : >"$base_rw"; : >"$base_hide"; : >"$base_net"
timeout_eff=""
eff_limit_mem_mb=""; eff_limit_nproc=""; eff_limit_nofile=""; eff_limit_fsize_mb=""; eff_limit_cpu=""

# The last cfg that names each resource limit wins, as the timeout does. Reads the
# PARSED_LIMIT_* variables parse_cfg_policy sets, so it is called after each parse.
capture_resource_limits() {
  [[ -n "${PARSED_LIMIT_MEM_MB:-}"   ]] && eff_limit_mem_mb="${PARSED_LIMIT_MEM_MB}"
  [[ -n "${PARSED_LIMIT_NPROC:-}"    ]] && eff_limit_nproc="${PARSED_LIMIT_NPROC}"
  [[ -n "${PARSED_LIMIT_NOFILE:-}"   ]] && eff_limit_nofile="${PARSED_LIMIT_NOFILE}"
  [[ -n "${PARSED_LIMIT_FSIZE_MB:-}" ]] && eff_limit_fsize_mb="${PARSED_LIMIT_FSIZE_MB}"
  [[ -n "${PARSED_LIMIT_CPU:-}"      ]] && eff_limit_cpu="${PARSED_LIMIT_CPU}"
  return 0
}

# Build base policy (FS union, NET union, TIMEOUT last-wins)
for b in "${base_cfgs[@]}"; do
  parse_cfg_policy "$b"
  # FS: union only (no least-privilege checks while building base)
  fs_union_files "$base_ro" "$base_rw" "$base_hide" \
                 "$PARSED_RO_FILE" "$PARSED_RW_FILE" "$PARSED_HIDE_FILE"
  # NET: union
  tmpnet="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpnet" "$base_net" "$PARSED_NET_FILE"; mv "$tmpnet" "$base_net"
  # TIMEOUT: last base wins
  [[ -n "${PARSED_TIMEOUT:-}" || "${PARSED_TIMEOUT:-__unset__}" == "" ]] && timeout_eff="${PARSED_TIMEOUT:-}"
  capture_resource_limits
done

# Effective policy (start from base, then apply exercise overrides)
eff_ro="$(mktemp -p "$PHOBOS_SCRATCH")"; eff_rw="$(mktemp -p "$PHOBOS_SCRATCH")"; eff_hide="$(mktemp -p "$PHOBOS_SCRATCH")"; eff_net="$(mktemp -p "$PHOBOS_SCRATCH")"
cp "$base_ro" "$eff_ro"; cp "$base_rw" "$eff_rw"; cp "$base_hide" "$eff_hide"; cp "$base_net" "$eff_net"

for c in "${cfgs[@]}"; do
  parse_cfg_policy "$c"
  merge_fs_per_path "$base_ro" "$base_rw" "$base_hide" eff_ro eff_rw eff_hide \
                    "$PARSED_RO_FILE" "$PARSED_RW_FILE" "$PARSED_HIDE_FILE"
  tmpnet="$(mktemp -p "$PHOBOS_SCRATCH")"; net_union "$tmpnet" "$eff_net" "$PARSED_NET_FILE"; mv "$tmpnet" "$eff_net"
  [[ -n "${PARSED_TIMEOUT:-}" || "${PARSED_TIMEOUT:-__unset__}" == "" ]] && timeout_eff="${PARSED_TIMEOUT:-}"
  capture_resource_limits
done

write_spec "$SPEC_DIR" "$eff_ro" "$eff_rw" "$eff_hide" "$eff_net" "$timeout_eff" "${TAIL_FLAGS_FILE:-}"

# The resource limits go into the specification, one "key=value" per line for each limit a
# [limits] section named. phobos-resources.sh reads them and sets them with rlimits, so the
# filesystem layer, phobos-landlock and the command inherit them, rather than this shell
# setting them and the whole layer chain running under them.
{
  [[ -n "$eff_limit_mem_mb"   ]] && printf 'mem_mb=%s\n'   "$eff_limit_mem_mb"
  [[ -n "$eff_limit_nproc"    ]] && printf 'nproc=%s\n'    "$eff_limit_nproc"
  [[ -n "$eff_limit_nofile"   ]] && printf 'nofile=%s\n'   "$eff_limit_nofile"
  [[ -n "$eff_limit_fsize_mb" ]] && printf 'fsize_mb=%s\n' "$eff_limit_fsize_mb"
  [[ -n "$eff_limit_cpu"      ]] && printf 'cpu=%s\n'      "$eff_limit_cpu"
} > "${SPEC_DIR}/limits.conf"

# Always enter through the first layer; inner scripts decide whether to apply themselves
exec "${HERE}/phobos-timeout.sh" "$SPEC_DIR" -- "${cmd[@]}"
