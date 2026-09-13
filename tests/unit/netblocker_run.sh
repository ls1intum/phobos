#!/usr/bin/env bash
# Builds and runs the libnetblocker unit tests. With --coverage the build is
# instrumented, and the run fails unless every line and every branch of every
# ld_preloader/netblocker*.c ran. Needs gcc-14, and gcov-14 for --coverage. The calls
# the library makes into the C library are interposed through the linker, so neither a
# network nor preloading is involved.
#
#   tests/unit/netblocker_run.sh               build with -Werror and run
#   tests/unit/netblocker_run.sh --coverage    build instrumented, run, hold to 100 %
#
# Unlike tests/unit/run.sh, this suite can be measured: its interposed calls pass
# straight through unless a case arms a failure, so the coverage runtime, which makes
# the same calls on the way out, is left undisturbed.
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIBRARY="$(cd -- "${HERE}/../../ld_preloader" && pwd)"

# Named rather than inherited, for the same reason as in run.sh: the sources are C23,
# and gcov has to match the compiler that wrote the notes files.
COMPILER="${COMPILER:-gcc-14}"
COVERAGE_TOOL="${COVERAGE_TOOL:-gcov-14}"
if ! command -v "$COMPILER" >/dev/null 2>&1; then
  echo "This suite needs $COMPILER (the sources are C23). On Ubuntu: apt-get install gcc-14" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# netblocker.c is included by the test file; the modules beside it are linked.
MODULES=(
  "${LIBRARY}/netblocker-address.c"
  "${LIBRARY}/netblocker-address-cache.c"
  "${LIBRARY}/netblocker-policy.c"
  "${LIBRARY}/netblocker-rule.c"
)

# The number of library sources coverage is reported for: netblocker.c and the modules.
LIBRARY_SOURCES=$(( ${#MODULES[@]} + 1 ))

# The commas belong to the -Wl, linker flags, not to the array syntax.
# shellcheck disable=SC2054
WRAPS=(
  -Wl,--wrap=calloc
  -Wl,--wrap=strdup
  -Wl,--wrap=fstat
  -Wl,--wrap=fcntl
  -Wl,--wrap=fdopen
  -Wl,--wrap=dlsym
)

# Prints one line per library source the instrumented run reached: its path, the share
# of its lines that ran, and the share of its branches taken, or "none" for a source
# without branches. Assumes the build and the run happened in WORK.
coverage_summary() {
  local notes
  for notes in "$WORK"/unit-*.gcno; do
    ( cd "$WORK" && "$COVERAGE_TOOL" --branch-probabilities --no-output \
        --object-directory "$notes" "${notes%.gcno}" 2>/dev/null )
  done | awk '
    /^File / {
      file = $2
      gsub(/\047/, "", file)
      keep = (file ~ /\/netblocker(-[a-z-]+)?\.c$/)
      if (keep && !(file in taken)) { taken[file] = "none" }
      next
    }
    keep && /^Lines executed:/ { value = $0; sub(/^Lines executed:/, "", value); sub(/%.*/, "", value); lines[file] = value }
    keep && /^Taken at least once:/ { value = $0; sub(/^Taken at least once:/, "", value); sub(/%.*/, "", value); taken[file] = value }
    END { for (file in lines) { print file, lines[file], taken[file] } }
  ' | sort
}

if [[ "${1:-}" == "--coverage" ]]; then
  "$COMPILER" -std=gnu23 -O0 -g --coverage -o "$WORK/unit" "${HERE}/netblocker_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  ( cd "$WORK" && ./unit )
  summary="$(coverage_summary)"
  printf '\nCoverage of the library, lines and branches taken:\n%s\n' "$summary"
  if [[ "$(grep -c . <<<"$summary")" -ne "$LIBRARY_SOURCES" ]]; then
    echo "coverage was reported for $(grep -c . <<<"$summary") sources, not the $LIBRARY_SOURCES the library has" >&2
    exit 1
  fi
  if grep -vqE ' 100\.00 (100\.00|none)$' <<<"$summary"; then
    echo "not every line and branch of the library ran" >&2
    exit 1
  fi
else
  "$COMPILER" -std=gnu23 -O0 -g -Wall -Wextra -Werror -o "$WORK/unit" "${HERE}/netblocker_unit.c" "${MODULES[@]}" "${WRAPS[@]}"
  "$WORK/unit"
fi
