#!/usr/bin/env bash
# Lays out what a prune container and the KVM guest are both given: the exercises of one key, the helpers,
# and two small files that say what to do before a prune starts. The default prune and the KVM run of
# prune-kvm.yml read the same directory, which is what makes them prunes of the same exercises.
#
#   stage-prune-inputs.sh <fixture|reference> <key> <destination>
#
# reference  the exercises of var/tmp/testing-dir/<key>, as the Compose services mount them.
# fixture    the layer pruner's fixture exercise (tests/integration/layer-prune-fixture) under the key java,
#            with the files it reads laid out by setup.sh and FIXTURE_UDP=1 set in env.sh, so that its
#            build binds a UDP port that only a Landlock version 10 kernel refuses (A.6.9).
#
# It writes <destination>/exercises/<key>/..., helpers/, setup.sh and env.sh. The destination is emptied
# first when this script made it, and refused when anything else lives there.
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
if [[ "${KIND}" == fixture && "${KEY}" != java ]]; then
  printf 'the fixture is pruned under the key java, not %s\n' "${KEY}" >&2
  exit "${EXIT_USAGE}"
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
cp -R "${REPOSITORY}/var/tmp/helpers" "${DESTINATION}/helpers"

if [[ "${KIND}" == reference ]]; then
  [[ -d "${REPOSITORY}/var/tmp/testing-dir/${KEY}" ]] || { printf 'no exercises for the key %s\n' "${KEY}" >&2; exit 1; }
  cp -R "${REPOSITORY}/var/tmp/testing-dir/${KEY}" "${DESTINATION}/exercises/${KEY}"
  : > "${DESTINATION}/setup.sh"
  : > "${DESTINATION}/env.sh"
else
  mkdir -p "${DESTINATION}/exercises/java"
  cp -R "${REPOSITORY}/tests/integration/layer-prune-fixture" "${DESTINATION}/exercises/java/fixture"
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
