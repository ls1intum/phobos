#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

DEBUG=0
if [[ "${1:-}" == "--debug" ]]; then DEBUG=1; shift; fi
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-resources.sh [--debug] <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2
CMD=("$@")
dbg=(); (( DEBUG )) && dbg=(--debug)

# Removes the specification phobos.sh created if this layer ends before it hands over.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

enable_resources="${PHB_ENABLE_RESOURCES:-1}"

# If the resource layer is disabled, hand straight to the filesystem layer.
if [[ "$enable_resources" != "1" ]]; then
  exec "${HERE}/phobos-filesystem.sh" "${dbg[@]}" "${SPEC_DIR}" -- "${CMD[@]}"
fi

# The limits phobos.sh captured from the policy, one "key=value" per line, only for the
# keys a [limits] section set. An absent file or key leaves that limit unset.
mem_mb=""
nproc=""
nofile=""
fsize_mb=""
cpu=""
if [[ -f "${SPEC_DIR}/limits.conf" ]]; then
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    case "$key" in
      mem_mb)   mem_mb="$value" ;;
      nproc)    nproc="$value" ;;
      nofile)   nofile="$value" ;;
      fsize_mb) fsize_mb="$value" ;;
      cpu)      cpu="$value" ;;
    esac
  done < "${SPEC_DIR}/limits.conf"
fi

# Re-validate at this boundary rather than trusting the file. Every limit is a whole number
# where it is set at all; anything else is refused rather than silently dropped, so a
# malformed value fails closed instead of running the command unrestricted, and no
# unchecked text reaches the arithmetic in apply_resource_limits.
for pair in "mem_mb=${mem_mb}" "nproc=${nproc}" "nofile=${nofile}" "fsize_mb=${fsize_mb}" "cpu=${cpu}"; do
  name="${pair%%=*}"
  value="${pair#*=}"
  if [[ -n "$value" && ! "$value" =~ ^[0-9]+$ ]]; then
    report "Policy invalid: resource limit '${name}=${value}' is not a whole number. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
done

# Set the limits in this shell, then exec on, so the filesystem layer, phobos-landlock and
# the command it finally runs all inherit them. rlimits are self-imposed and unprivileged,
# exactly as Landlock is, so they hold inside the ordinary container an exercise runs in.
# The hard caps a machine needs against a determined submission (a fork bomb filling the
# process table, a run filling the disk) are cgroups the container is started with; these
# rlimits are the in-process line of defence beside them.
apply_resource_limits "$mem_mb" "$nproc" "$nofile" "$fsize_mb" "$cpu"

exec "${HERE}/phobos-filesystem.sh" "${dbg[@]}" "${SPEC_DIR}" -- "${CMD[@]}"
