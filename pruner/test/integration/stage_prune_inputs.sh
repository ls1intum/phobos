#!/usr/bin/env bash
# Holds .github/scripts/stage-prune-inputs.sh to what it promises, in both directions.
#
#   chosen     a reference is staged with the exercises the pruner's own discovery assigns to the key, in the
#              two-level tree the pruner reads, and the fixture is staged under the key java-gradle;
#   untouched  a tree the pruner would refuse (a prune.json that is not JSON) ends the script with a failure
#              before the destination of an earlier staging is deleted or written to.
#
# The script finds its repository from its own path, so the cases run it from a throwaway repository that holds
# a copy of it, the pruner's helpers and a small exercise tree. Needs python3 and bash, nothing else.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../../protecter/test/harness.sh
source "${HERE}/../../../protecter/test/harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPO="$(cd -- "${HERE}/../../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
FAKE="${WORK}/repo"

# Lays out the throwaway repository: the script, the helpers, the fixture and two reference exercises.
make_repository() {
  mkdir -p "${FAKE}/.github/scripts" "${FAKE}/pruner/test/integration" "${FAKE}/exercises/java/alpha" "${FAKE}/exercises/python/beta"
  cp "${REPO}/.github/scripts/stage-prune-inputs.sh" "${FAKE}/.github/scripts/"
  cp -R "${REPO}/pruner/src" "${FAKE}/pruner/src"
  cp -R "${REPO}/pruner/test/integration/layer-prune-fixture" "${FAKE}/pruner/test/integration/layer-prune-fixture"
  printf '{"key": "java-gradle"}' > "${FAKE}/exercises/java/alpha/prune.json"
}

# Runs the script of the throwaway repository with the arguments given, keeping its status in STATUS and its
# standard error in ERR.
stage() {
  ERR="$(bash "${FAKE}/.github/scripts/stage-prune-inputs.sh" "$@" 2>&1 > /dev/null)"
  STATUS=$?
}

make_repository

echo "== chosen =="
stage reference java-gradle "${WORK}/gradle"
check "a reference is staged" 0 "${STATUS}"
check "with the exercise whose prune.json declares the key, under its family" "exercises/java/alpha" \
  "$(cd "${WORK}/gradle" && find exercises -mindepth 2 -maxdepth 2 | sort | tr '\n' ' ' | sed 's/ $//')"
stage reference python "${WORK}/python"
check "an exercise without a key is staged under its family's key" "exercises/python/beta" \
  "$(cd "${WORK}/python" && find exercises -mindepth 2 -maxdepth 2 | sort | tr '\n' ' ' | sed 's/ $//')"
stage reference java "${WORK}/retired"
check "a key no exercise has is refused" 1 "${STATUS}"
check "and nothing was staged for it" "absent" "$([[ -e "${WORK}/retired" ]] && echo present || echo absent)"
stage fixture java-gradle "${WORK}/fixture"
check "the fixture is staged under java-gradle" "exercises/java-gradle/fixture" \
  "$(cd "${WORK}/fixture" && find exercises -mindepth 2 -maxdepth 2 | sort | tr '\n' ' ' | sed 's/ $//')"
stage fixture java "${WORK}/fixture-java"
check "the fixture under any other key is a usage error" 2 "${STATUS}"

echo "== untouched =="
printf 'earlier' > "${WORK}/gradle/earlier-staging"
printf 'not json' > "${FAKE}/exercises/python/beta/prune.json"
stage reference java-gradle "${WORK}/gradle"
check "a tree the pruner refuses ends the script with a failure" 1 "${STATUS}"
check "the destination of an earlier staging is still there" "earlier" "$(cat "${WORK}/gradle/earlier-staging" 2> /dev/null)"
check "and the reason is given" "yes" "$([[ "${ERR}" == *"prune.json"* ]] && echo yes || echo no)"

finish
