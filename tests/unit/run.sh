#!/usr/bin/env bash
# Builds and runs the phobos-landlock unit tests, and optionally reports
# coverage. Needs gcc-14 only: the syscalls are interposed through the linker, so
# no Landlock-capable kernel is required and no container flags are involved.
# gcc-14 rather than gcc, because the sources are C23 and Ubuntu 24.04 ships
# gcc 13, which knows that standard only under its draft name.
#
#   tests/unit/run.sh                  build and run
#   tests/unit/run.sh --coverage       build instrumented, run, print the summary
#   tests/unit/run.sh --coverage DIR   the same, but build in DIR and leave it
#                                      there, so a report can be made from it
#
# Without a directory the build happens in a temporary one that is removed on the
# way out, which is why asking for coverage and then looking for the .gcda files
# used to find nothing.
set -euo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The compiler is named rather than inherited, so a machine with an older
# default does not silently build a different language than CI does. gcov has to
# match the compiler that wrote the notes files, or the counters are unreadable.
COMPILER="${COMPILER:-gcc-14}"
COVERAGE_TOOL="${COVERAGE_TOOL:-gcov-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  echo "This suite needs $COMPILER (the sources are C23). On Ubuntu: apt-get install gcc-14" >&2
  exit 1
fi

COVERAGE_DIR=""
if [[ "${1:-}" == "--coverage" ]]; then
  COVERAGE_DIR="${2:-}"
fi

if [[ -n "$COVERAGE_DIR" ]]; then
  mkdir -p "$COVERAGE_DIR"
  WORK="$(cd -- "$COVERAGE_DIR" && pwd)"
else
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
fi

# The stage sequence is included by the test file; its modules are linked.
MODULES=(
  "${HERE}/../../core/phobos-landlock-diagnostics.c"
  "${HERE}/../../core/phobos-landlock-path-rule.c"
  "${HERE}/../../core/phobos-landlock-options.c"
  "${HERE}/../../core/phobos-landlock-ruleset.c"
)

# Every syscall the tool makes is wrapped so a failure can be injected.
# The commas belong to the -Wl, linker flags, not to the array syntax.
# shellcheck disable=SC2054
WRAPS=(
  -Wl,--wrap=open
  -Wl,--wrap=fstat
  -Wl,--wrap=syscall
  -Wl,--wrap=prctl
  -Wl,--wrap=chdir
  -Wl,--wrap=execvp
  -Wl,--wrap=close
)

if [[ "${1:-}" == "--coverage" ]]; then
  "$COMPILER" -std=gnu23 -O0 -g --coverage -o "$WORK/unit" "${HERE}/landlock_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  # One gcov run per compiled module. gcov also knows the test file itself,
  # which is not what is under test here, so only the modules are reported.
  ( cd "$WORK" && for notes in unit-*.gcno; do
      "$COVERAGE_TOOL" -b -o "$notes" "${notes%.gcno}" 2>/dev/null
    done ) \
    | awk '/^File .*phobos-landlock/ { show = 1; print; next }
           /^File / { show = 0 }
           show && /^(Lines|Branches|Taken)/ { print }
           show && /^Taken/ { show = 0 }'
else
  "$COMPILER" -std=gnu23 -O0 -g -Wall -Wextra -Werror -o "$WORK/unit" "${HERE}/landlock_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  "$WORK/unit"
fi
