#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"

DEBUG=0
NO_LANDLOCK=0
NO_NETWORK_PORTS=0
LANDLOCK_BIN_OPT=""
TIMEOUT_BIN_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) DEBUG=1; shift ;;
    --no-landlock) NO_LANDLOCK=1; shift ;;
    --no-network-ports) NO_NETWORK_PORTS=1; shift ;;
    --landlock-bin) shift; LANDLOCK_BIN_OPT="${1:-}"; shift ;;
    --timeout-bin) shift; TIMEOUT_BIN_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-filesystem.sh [--debug] [--no-landlock] [--no-network-ports] [--landlock-bin <path>] [--timeout-bin <path>] <SPEC_DIR> -- <cmd...>"; exit 2; }
SPEC_DIR="$1"; shift 2
CMD=("$@")

# Removes the specification phobos.sh created on every way out of this layer except
# the one that hands the command straight to exec, with neither this layer nor a
# timeout to wait on it.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

READ="${SPEC_DIR}/read.paths"; EXECUTE="${SPEC_DIR}/execute.paths"; WRITE="${SPEC_DIR}/write.paths"; CREATE="${SPEC_DIR}/create.paths"; DELETE="${SPEC_DIR}/delete.paths"; TAIL="${SPEC_DIR}/tail.flags"
LANDLOCK="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock}"; TIMEOUT_BIN="${TIMEOUT_BIN_OPT:-timeout}"

# With --no-landlock the filesystem restriction is off, so run the command without Landlock,
# but still under the timeout when one is set. Run it as a child and exit with its status
# rather than exec'ing it, so the EXIT trap still removes the specification directory.
if (( NO_LANDLOCK )); then
  if (( DEBUG )); then
    >&2 printf '[phobos] filesystem layer disabled; run '
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
    set +e
    "${CMD[@]}"
    rc=$?
    set -e
    exit "$rc"
  fi
fi

args=()

# The paths a submission can change: the union of the write, create and delete sections. The
# preload library and its rules file must stay out of this set, or a submission could rewrite
# its own network policy before starting another process.
WRITABLE="$(mktemp -t phobos-writable.XXXXXX)"
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

if (( DEBUG )); then
  >&2 printf '[phobos] %s ' "${LANDLOCK}"
  printf '%q ' "${args[@]}"
  printf ' -- '
  printf '%q ' "${CMD[@]}"
  echo >&2
fi

OUTLOG="$(mktemp -t phobos-out.XXXXXX)"; ERRLOG="$(mktemp -t phobos-err.XXXXXX)"
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR" "$OUTLOG" "$ERRLOG"' EXIT

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
