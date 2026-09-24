#!/usr/bin/env bash
# Builds and runs the phobos-seccomp-networksystem unit tests. With --coverage the build is
# instrumented, and the run fails unless every line of every guard source ran.
# Needs gcc-14, and gcov-14 for --coverage. Every syscall the guard makes is interposed
# through the linker, and fork is wrapped so the parent and child halves are each driven,
# so neither a kernel nor a real fork is involved.
#
#   tests/unit/seccomp_networksystem_run.sh               build with -Werror and run
#   tests/unit/seccomp_networksystem_run.sh --coverage    build instrumented, run, hold lines to 100 %
#
# Lines are gated, by counting gcov's uncovered markers rather than trusting its summary
# percentage, which mis-counts the denominator for these files. Branches are reported but not
# gated: a few of the guard's branches are inside libc macros it cannot steer both ways
# (CMSG_FIRSTHDR's empty-buffer arm, the words of IN6_IS_ADDR_LOOPBACK), so a branch gate
# would fail on unreachable arms, the same reason the Landlock wrapper suite is not
# branch-gated in CI. Only the syscall wraps, which the test answers rather than passing
# through, are measured, so unlike the Landlock suite the figures here are undisturbed.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

COMPILER="${COMPILER:-gcc-14}"
COVERAGE_TOOL="${COVERAGE_TOOL:-gcov-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  echo "This suite needs $COMPILER (the sources are C23). On Ubuntu: apt-get install gcc-14" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The file holding main is included by the test file; the modules beside it are linked,
# built with the define that gives them their per-case reset functions.
CORE="${HERE}/../../core"
MODULES=(
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-child.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-destination.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-diagnostics.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-options.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-rules.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-socket-types.c"
  "${CORE}/phobos-seccomp-networksystem/phobos-seccomp-networksystem-supervisor.c"
)
UNIT_TEST_DEFINE=-DPHOBOS_CONNECT_GUARD_UNIT_TEST

# The commas belong to the -Wl, linker flags, not to the array syntax.
# shellcheck disable=SC2054
WRAPS=(
  -Wl,--wrap=calloc
  -Wl,--wrap=syscall
  -Wl,--wrap=socketpair
  -Wl,--wrap=fork
  -Wl,--wrap=prctl
  -Wl,--wrap=getrlimit
  -Wl,--wrap=dup2
  -Wl,--wrap=signal
  -Wl,--wrap=execvp
  -Wl,--wrap=_exit
  -Wl,--wrap=waitpid
  -Wl,--wrap=sendmsg
  -Wl,--wrap=recvmsg
  -Wl,--wrap=send
  -Wl,--wrap=process_vm_readv
  -Wl,--wrap=socket
  -Wl,--wrap=connect
  -Wl,--wrap=poll
  -Wl,--wrap=getsockopt
  -Wl,--wrap=ioctl
  -Wl,--wrap=fcntl
  -Wl,--wrap=readlink
)

if [[ "${1:-}" == "--coverage" ]]; then
  "$COMPILER" -std=gnu23 -O0 -g --coverage "$UNIT_TEST_DEFINE" -o "$WORK/unit" \
    "${HERE}/seccomp_networksystem_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  ( cd "$WORK" && for notes in unit-*.gcno; do
      "$COVERAGE_TOOL" -b -o "$notes" "${notes%.gcno}" >/dev/null 2>&1
    done )
  uncovered_total=0
  for source in phobos-seccomp-networksystem.c "${MODULES[@]##*/}"; do
    gcov_file="$WORK/${source}.gcov"
    if [[ ! -f "$gcov_file" ]]; then
      echo "no coverage was produced for core/${source}" >&2
      exit 1
    fi
    # A gcov that cannot open the source still writes a .gcov, but one with no counted
    # executable lines, and no ##### markers either. Without this guard that empty file
    # would pass the line gate below having measured nothing, so require real line data.
    counted="$(grep -cE '^[[:space:]]*[0-9]+:' "$gcov_file" || true)"
    if [[ "$counted" -eq 0 ]]; then
      echo "coverage for core/${source} holds no executed lines; gcov likely could not read the source" >&2
      exit 1
    fi
    uncovered="$(grep -c '#####' "$gcov_file" || true)"
    printf '%-44s %s executed lines, %s uncovered\n' "core/${source}" "$counted" "$uncovered"
    if [[ "$uncovered" -ne 0 ]]; then
      grep -nE '#####' "$gcov_file" >&2
    fi
    uncovered_total=$(( uncovered_total + uncovered ))
  done
  if [[ "$uncovered_total" -ne 0 ]]; then
    echo "not every line of the connect guard ran; ${uncovered_total} line(s) uncovered" >&2
    exit 1
  fi
  printf 'every line of the connect guard ran\n'
else
  "$COMPILER" -std=gnu23 -O0 -g -Wall -Wextra -Werror "$UNIT_TEST_DEFINE" -o "$WORK/unit" \
    "${HERE}/seccomp_networksystem_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  "$WORK/unit"
fi
