#!/usr/bin/env bash
# Lays out what a prune container and the KVM guest are both given: the exercises of one key, the helpers,
# and two small files that say what to do before a prune starts. The default prune and the KVM run of
# prune-kvm.yml read the same directory, which is what makes them prunes of the same exercises.
#
#   stage-prune-inputs.sh <fixture|reference> <key> <destination>
#
# reference  the exercises of the key under exercises/<family>/<exercise>, as the Compose services mount them.
#            Which exercises those are is decided by pruner/exercise_pruner/src/application/discovery.py, the code the pruner
#            itself runs, so the staged tree cannot hold others than the pruner would take.
# fixture    the layer pruner's fixture exercise (pruner/exercise_pruner/test/integration/interface/layer-prune-fixture) under the key java-gradle,
#            with the files it reads laid out by setup.sh and FIXTURE_UDP=1 set in env.sh, so that its
#            build binds a UDP port that only a Landlock version 10 kernel refuses (A.6.9).
#
# It writes <destination>/exercises/<family>/<exercise>/..., helpers/, setup.sh and env.sh. The destination
# is emptied first when this script made it, and refused when anything else lives there. The exercises of
# a reference are chosen before the destination is touched, so a tree the pruner would refuse leaves an
# earlier staging in place.
set -euo pipefail

# The status this script ends with when it was called the wrong way.
readonly EXIT_USAGE=2

[[ $# -eq 3 ]] || { printf 'usage: stage-prune-inputs.sh <fixture|reference> <key> <destination>\n' >&2; exit "${EXIT_USAGE}"; }
KIND="$1"
KEY="$2"
DESTINATION="$3"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"
MARKER=".phobos-prune-inputs"

case "${KIND}" in
  fixture | reference) ;;
  *) printf 'the kind is fixture or reference, not %s\n' "${KIND}" >&2; exit "${EXIT_USAGE}" ;;
esac
# The key ends up on a kernel command line and in file names, so it is a plain word.
[[ "${KEY}" =~ ^[a-z0-9-]+$ ]] || { printf 'the key is lower-case letters, digits and hyphens, not %s\n' "${KEY}" >&2; exit "${EXIT_USAGE}"; }
if [[ "${KIND}" == fixture && "${KEY}" != java-gradle ]]; then
  printf 'the fixture is pruned under the key java-gradle, not %s\n' "${KEY}" >&2
  exit "${EXIT_USAGE}"
fi

# Prints the exercises of the key as <family>/<exercise>, one per line, by the pruner's own discovery.
# Assumes python3. Ends with a status of 1 and the reason on standard error for a tree the pruner refuses.
exercises_of_key() {
  python3 -I -c '
import pathlib
import sys

sys.path.insert(0, sys.argv[1])
from exercise_pruner.src.application import discovery

root = pathlib.Path(sys.argv[2])
try:
    for directory in discovery.exercises_of(root, sys.argv[3]):
        print(directory.relative_to(root))
except discovery.DiscoveryRefused as refusal:
    print(refusal, file=sys.stderr)
    sys.exit(1)
' "${REPOSITORY}/pruner" "${REPOSITORY}/exercises" "${KEY}"
}

SELECTED=""
if [[ "${KIND}" == reference ]]; then
  SELECTED="$(exercises_of_key)" || exit 1
  [[ -n "${SELECTED}" ]] || { printf 'no exercises for the key %s\n' "${KEY}" >&2; exit 1; }
fi
if [[ -e "${DESTINATION}" ]]; then
  if [[ -f "${DESTINATION}/${MARKER}" ]]; then
    rm -rf -- "${DESTINATION:?}"
  elif [[ -n "$(ls -A -- "${DESTINATION}")" ]]; then
    printf '%s is not empty and was not made by this script; remove it first\n' "${DESTINATION}" >&2
    exit 1
  fi
fi
mkdir -p "${DESTINATION}/exercises"
for package in exercise_pruner runtime_pruner shared; do
  mkdir -p "${DESTINATION}/helpers/${package}"
  cp -R "${REPOSITORY}/pruner/${package}/src" "${DESTINATION}/helpers/${package}/src"
done

if [[ "${KIND}" == reference ]]; then
  while IFS= read -r exercise; do
    mkdir -p "${DESTINATION}/exercises/$(dirname -- "${exercise}")"
    cp -R "${REPOSITORY}/exercises/${exercise}" "${DESTINATION}/exercises/${exercise}"
  done <<<"${SELECTED}"
  : > "${DESTINATION}/setup.sh"
  : > "${DESTINATION}/env.sh"
else
  mkdir -p "${DESTINATION}/exercises/java-gradle"
  cp -R "${REPOSITORY}/pruner/exercise_pruner/test/integration/interface/layer-prune-fixture" "${DESTINATION}/exercises/java-gradle/fixture"
  cat > "${DESTINATION}/setup.sh" <<'SETUP'
mkdir -p /srv/prune-fixture/needed /srv/prune-fixture/optional /srv/prune-fixture/unneeded /srv/prune-fixture-secret
printf 'needed\n' > /srv/prune-fixture/needed/data.txt
printf 'maybe\n' > /srv/prune-fixture/optional/maybe.txt
printf 'secret\n' > /srv/prune-fixture/unneeded/secret.txt
printf 'secret\n' > /srv/prune-fixture-secret/x
SETUP
  printf 'export FIXTURE_UDP=1\n' > "${DESTINATION}/env.sh"
fi
touch "${DESTINATION}/${MARKER}"
printf 'Prune inputs for %s (%s) staged in %s\n' "${KEY}" "${KIND}" "${DESTINATION}"
