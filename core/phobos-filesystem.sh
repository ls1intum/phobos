#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-filesystem.sh <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2
CMD=("$@")

RO="${SPEC_DIR}/ro.paths"; RW="${SPEC_DIR}/rw.paths"; HIDE="${SPEC_DIR}/hide.paths"; TAIL="${SPEC_DIR}/tail.flags"
LANDLOCK="${PHOBOS_LANDLOCK_BIN:-${HERE}/phobos-landlock}"; TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"

enable_fs="${PHB_ENABLE_FILESYSTEM:-1}"

# If filesystem layer is disabled, run the command directly,
# but still respect PHB_TIMEOUT_SEC if the timeout layer is active.
if [[ "$enable_fs" != "1" ]]; then
  if [[ -n "${PHOBOS_DEBUG:-}" ]]; then
    >&2 printf '[phobos] filesystem layer disabled; exec '
    printf '%q ' "${CMD[@]}"
    echo >&2
  fi

  if [[ -n "${PHB_TIMEOUT_SEC:-}" ]]; then
    set +e
    "${TIMEOUT_BIN}" "--kill-after=5s" "${PHB_TIMEOUT_SEC}s" "${CMD[@]}"
    rc=$?
    set -e
    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
      report "Timed out after ${PHB_TIMEOUT_SEC}s. (PHB-ETIMEOUT)"
      exit ${PHB_ETIMEOUT}
    fi
    exit "$rc"
  else
    exec "${CMD[@]}"
  fi
fi

args=()

# Keep the LD_PRELOAD library reachable: Landlock must allow reading and
# mapping it, otherwise the loader fails before the command starts.
# PHB_NETBLOCKER_SO is set by phobos-network.sh when the lib exists.
if [[ -n "${PHB_NETBLOCKER_SO:-}" && -f "${PHB_NETBLOCKER_SO}" ]]; then
  args+=( --rights=rx "$PHB_NETBLOCKER_SO" )
fi

# Landlock withholds access, it cannot overlay a path with emptiness, and it
# cannot carve an exception out of an allowed subtree. A [hide] path is
# therefore only denied while no allow-listed ancestor covers it: it stays
# visible by name, which is weaker than the tmpfs mask bubblewrap provided.
# If an ancestor IS allowed the path is not denied at all, so the policy is
# unenforceable and we refuse to run rather than pretend it holds.
if [[ -s "${HIDE}" ]]; then
  while IFS= read -r p; do
    [[ -z "$p" ]] && continue
    covering=""
    while IFS= read -r a; do
      [[ -z "$a" ]] && continue
      # "$p" lies beneath "$a" when it equals it or starts with it plus a slash
      if [[ "$p" == "$a" || "$p" == "${a%/}/"* ]]; then covering="$a"; break; fi
    done < <(cat "${RO}" "${RW}" 2>/dev/null)
    if [[ -n "$covering" ]]; then
      report "Policy unenforceable: '$p' is listed as hidden but lies beneath allowed path '$covering'. Landlock grants a whole subtree and cannot except a path inside it. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    _log "hide: '$p' is denied but stays visible (Landlock cannot mask paths)"
  done < "${HIDE}"
fi
# Read paths keep the execute right: bubblewrap's --ro-bind allowed execution
# from the bound tree, and the base policies rely on it, because the JVM and
# every build tool live under [readonly] paths. Splitting those into data and
# programs is a change of policy rather than of mechanism, so it is not made
# here; phobos-landlock can express it, and the configuration format is where
# it has to be decided.
#
# Write paths get rwmd: write, create, delete. That is what --rw granted before,
# minus creating device nodes and symbolic links, which no build tool needs and
# which are the two ways to reach something the policy never named.
build_path_args args "" "${RO}" "${RW}"
build_network_args args "${SPEC_DIR}/net.rules"
if [[ -s "${TAIL}" ]]; then
  # Splitting is intended: tail.flags holds whitespace-separated arguments.
  # Read line by line so a multi-line file works too.
  while IFS= read -r tail_line || [[ -n "$tail_line" ]]; do
    [[ -z "$tail_line" ]] && continue
    read -ra tail_parts <<< "$tail_line"
    args+=( "${tail_parts[@]}" )
  done < "${TAIL}"
fi

if [[ -n "${PHOBOS_DEBUG:-}" ]]; then
  >&2 printf '[phobos] %s ' "${LANDLOCK}"
  printf '%q ' "${args[@]}"
  printf ' -- '
  printf '%q ' "${CMD[@]}"
  echo >&2
fi

OUTLOG="$(mktemp -t phobos-out.XXXXXX)"; ERRLOG="$(mktemp -t phobos-err.XXXXXX)"
trap 'rm -f "$OUTLOG" "$ERRLOG"' EXIT

set +e
(
  if [[ -n "${PHB_TIMEOUT_SEC:-}" ]]; then
    "${TIMEOUT_BIN}" "--kill-after=5s" "${PHB_TIMEOUT_SEC}s" "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"
  else
    "${LANDLOCK}" "${args[@]}" -- "${CMD[@]}"
  fi
) > >(tee "$OUTLOG") 2> >(tee "$ERRLOG" >&2)
rc=$?
set -e

if [[ -n "${PHB_TIMEOUT_SEC:-}" && ( "$rc" -eq 124 || "$rc" -eq 137 ) ]]; then
  report "Timed out after ${PHB_TIMEOUT_SEC}s. (PHB-ETIMEOUT)"
  exit ${PHB_ETIMEOUT}
fi

net_denials=0; fs_denials=0
if [[ -s "$ERRLOG" ]]; then
  net_denials=$(grep -E -c 'EAI_AGAIN|EAI_FAIL|EAI_NONAME|Network is unreachable|Connection timed out' "$ERRLOG" || true)
  fs_denials=$(grep -E -c 'Permission denied|EACCES|EROFS' "$ERRLOG" || true)
fi
if (( net_denials > 0 || fs_denials > 0 )); then
  report "Sandbox denials: network=${net_denials}, filesystem=${fs_denials}. (PHB-EDENY)"
fi

exit "$rc"
