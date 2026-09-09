#!/usr/bin/env bash
# Builds and runs the phobos-landlock unit tests, and optionally reports
# coverage. Needs gcc only: the syscalls are interposed through the linker, so
# no Landlock-capable kernel is required and no container flags are involved.
#
#   tests/unit/run.sh            build and run
#   tests/unit/run.sh --coverage build instrumented, run, print the summary
set -euo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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
  gcc -O0 -g --coverage -o "$WORK/unit" "${HERE}/landlock_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  # One gcov run per compiled module. gcov also knows the test file itself,
  # which is not what is under test here, so only the modules are reported.
  ( cd "$WORK" && for notes in unit-*.gcno; do
      gcov -b -o "$notes" "${notes%.gcno}" 2>/dev/null
    done ) \
    | awk '/^File .*phobos-landlock/ { show = 1; print; next }
           /^File / { show = 0 }
           show && /^(Lines|Branches|Taken)/ { print }
           show && /^Taken/ { show = 0 }'
else
  gcc -O0 -g -Wall -Wextra -o "$WORK/unit" "${HERE}/landlock_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  "$WORK/unit"
fi
