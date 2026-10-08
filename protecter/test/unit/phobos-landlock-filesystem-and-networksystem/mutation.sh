#!/usr/bin/env bash
# Mutation testing for phobos-landlock-filesystem-and-networksystem.
#
# Coverage says a line ran. It does not say a test would notice if that line
# were wrong. This introduces deliberate faults, one at a time, and reports how
# many of them the suite catches. A surviving mutant is a change to the code
# that no test objects to, which for enforcement code is the interesting number.
#
#   protecter/test/unit/phobos-landlock-filesystem-and-networksystem/mutation.sh            score plus the surviving mutants
#   protecter/test/unit/phobos-landlock-filesystem-and-networksystem/mutation.sh --quiet    score and survivor count, no breakdown
#
# Needs clang and mull, which is why this runs in a container rather than in
# the runtime image: neither belongs where student code executes.
set -euo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd -- "${HERE}/../../../.." && pwd)"
# The C sources are C23 and name their constants with constexpr, which clang accepts from version 19, so the
# version here is 20, the one Ubuntu 26.04 carries, and the mull build is the one made for that release.
LLVM_VERSION=20
LLVM_FULL_VERSION=20.1.8
MULL_VERSION=0.34.1
UBUNTU_VERSION=26.04

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# mull reads this from its working directory and offers no way to point it
# elsewhere, so the run happens on a copy inside the container. The repository
# is mounted read-only and never gains a file.
# How long one mutant's run may take, in milliseconds, before mull counts it as killed by timeout.
MUTANT_TIMEOUT_MILLISECONDS=30000
# How much processor time any process of the mutated run may use, in seconds, before the kernel ends it.
MUTANT_CPU_SECONDS=60
cat > "$WORK/mull.yml" <<CONFIG
mutators:
  - cxx_all
includePaths:
  - protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem.*
excludePaths:
  - protecter/test/.*
timeout: ${MUTANT_TIMEOUT_MILLISECONDS}
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
  "https://github.com/mull-project/mull/releases/download/${MULL_VERSION}/Mull-${LLVM_VERSION}-${MULL_VERSION}-LLVM-${LLVM_FULL_VERSION}-ubuntu-${MULL_ARCHITECTURE}-${UBUNTU_VERSION}.deb"
dpkg -i /tmp/mull.deb > /dev/null 2>&1 || apt-get install -f -y -qq > /dev/null

mkdir -p /tmp/objects
# -grecord-command-line is what lets mull re-run a single mutant, and it only
# works with one source file per invocation.
for source in protecter/test/unit/phobos-landlock-filesystem-and-networksystem/landlock_filesystem_and_networksystem_unit.c protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-diagnostics.c \
              protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-path-rule.c protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-options.c \
              protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-ruleset.c \
              protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-policy.c \
              protecter/src/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem-model.c; do
  "clang-${LLVM_VERSION}" -std=gnu23 "-fpass-plugin=/usr/lib/mull-ir-frontend-${LLVM_VERSION}" \
    -g -grecord-command-line -O0 -c -o "/tmp/objects/$(basename "${source%.c}").o" "$source"
done
"clang-${LLVM_VERSION}" -std=gnu23 -g -o /tmp/unit-mutated /tmp/objects/*.o \
  -Wl,--wrap=open -Wl,--wrap=fstat -Wl,--wrap=syscall -Wl,--wrap=prctl \
  -Wl,--wrap=chdir -Wl,--wrap=execvp -Wl,--wrap=close

# The mutants run in parallel on this many workers.
MULL_WORKERS=4
# A mutant whose loop never ends is killed at mull's timeout, but the unit program forks, so its child
# outlives the kill, keeps the pipe mull reads open and holds the whole run for as long as it spins. A
# processor-time limit, which every child inherits, ends such a child on its own.
ulimit -t "${MUTANT_CPU_SECONDS}"
"mull-runner-${LLVM_VERSION}" --workers "${MULL_WORKERS}" /tmp/unit-mutated
INNER

docker run --rm \
  -v "${REPOSITORY}:/repository:ro" \
  -v "$WORK:/work" \
  -w / \
  -e "LLVM_VERSION=${LLVM_VERSION}" \
  -e "LLVM_FULL_VERSION=${LLVM_FULL_VERSION}" \
  -e "MULL_VERSION=${MULL_VERSION}" \
  -e "MUTANT_CPU_SECONDS=${MUTANT_CPU_SECONDS}" \
  -e "UBUNTU_VERSION=${UBUNTU_VERSION}" \
  "ubuntu:${UBUNTU_VERSION}" sh /work/run-inside.sh > "$WORK/report.txt" 2>&1 || true

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
