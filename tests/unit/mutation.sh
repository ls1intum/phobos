#!/usr/bin/env bash
# Mutation testing for phobos-landlock.
#
# Coverage says a line ran. It does not say a test would notice if that line
# were wrong. This introduces deliberate faults, one at a time, and reports how
# many of them the suite catches. A surviving mutant is a change to the code
# that no test objects to, which for enforcement code is the interesting number.
#
#   tests/unit/mutation.sh            score plus the surviving mutants
#   tests/unit/mutation.sh --quiet    score and survivor count, no breakdown
#
# Needs clang and mull, which is why this runs in a container rather than in
# the runtime image: neither belongs where student code executes.
set -euo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"
LLVM_VERSION=18
MULL_VERSION=0.34.0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# mull reads this from its working directory and offers no way to point it
# elsewhere, so the run happens on a copy inside the container. The repository
# is mounted read-only and never gains a file.
cat > "$WORK/mull.yml" <<'CONFIG'
mutators:
  - cxx_all
includePaths:
  - core/phobos-landlock.*
excludePaths:
  - tests/.*
timeout: 30000
CONFIG

cat > "$WORK/run-inside.sh" <<'INNER'
set -eu
cp -a /repository /build
cp /work/mull.yml /build/mull.yml
cd /build
apt-get update -qq > /dev/null
apt-get install -y -qq "clang-${LLVM_VERSION}" "llvm-${LLVM_VERSION}" curl > /dev/null
# The release assets are named by the container architecture, not the host one.
case "$(uname -m)" in
  x86_64) MULL_ARCHITECTURE=amd64 ;;
  aarch64) MULL_ARCHITECTURE=aarch64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
curl --fail --silent --show-error --location \
  --output /tmp/mull.deb \
  "https://github.com/mull-project/mull/releases/download/${MULL_VERSION}/Mull-${LLVM_VERSION}-${MULL_VERSION}-LLVM-18.1.3-ubuntu-${MULL_ARCHITECTURE}-24.04.deb"
dpkg -i /tmp/mull.deb > /dev/null 2>&1 || apt-get install -f -y -qq > /dev/null

mkdir -p /tmp/objects
# -grecord-command-line is what lets mull re-run a single mutant, and it only
# works with one source file per invocation.
for source in tests/unit/landlock_unit.c core/phobos-landlock-diagnostics.c \
              core/phobos-landlock-path-rule.c core/phobos-landlock-options.c \
              core/phobos-landlock-ruleset.c; do
  "clang-${LLVM_VERSION}" "-fpass-plugin=/usr/lib/mull-ir-frontend-${LLVM_VERSION}" \
    -g -grecord-command-line -O0 -c -o "/tmp/objects/$(basename "${source%.c}").o" "$source"
done
"clang-${LLVM_VERSION}" -g -o /tmp/unit-mutated /tmp/objects/*.o \
  -Wl,--wrap=open -Wl,--wrap=fstat -Wl,--wrap=syscall -Wl,--wrap=prctl \
  -Wl,--wrap=chdir -Wl,--wrap=execvp -Wl,--wrap=close

"mull-runner-${LLVM_VERSION}" --workers 4 /tmp/unit-mutated
INNER

docker run --rm \
  -v "${REPOSITORY}:/repository:ro" \
  -v "$WORK:/work" \
  -w / \
  -e "LLVM_VERSION=${LLVM_VERSION}" \
  -e "MULL_VERSION=${MULL_VERSION}" \
  ubuntu:24.04 sh /work/run-inside.sh > "$WORK/report.txt" 2>&1 || true

if ! grep -q "Mutation score" "$WORK/report.txt"; then
  echo "the mutation run did not finish, its output was:" >&2
  cat "$WORK/report.txt" >&2
  exit 1
fi

if [[ "${1:-}" != "--quiet" ]] && grep -q "warning: Survived:" "$WORK/report.txt"; then
  echo "Surviving mutants, by file:"
  grep "warning: Survived:" "$WORK/report.txt" | sed 's|/build/||' | grep -oE '^[a-z/.-]+\.c' \
    | sort | uniq -c | sed 's/^/  /'
  echo
  echo "Surviving mutants, by operator:"
  # A survivor whose source line is long wraps across several report lines, so
  # the operator tag is collected per entry rather than per line.
  awk '/warning: Survived:/ { inside = 1 }
       inside && match($0, /\[cxx_[a-z_]*\]/) {
         print substr($0, RSTART, RLENGTH); inside = 0 }' "$WORK/report.txt" \
    | sort | uniq -c | sort -rn | sed 's/^/  /'
  echo
fi
grep -E "Mutation score|Surviving mutants" "$WORK/report.txt"
