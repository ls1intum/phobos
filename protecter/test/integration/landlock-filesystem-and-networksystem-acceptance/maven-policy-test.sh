#!/usr/bin/env bash
# Runs the Maven reference exercise under the Maven base and each of the four JAVA_USING_MAVEN_*
# programming language configurations the image ships, in both directions.
#
# The exercise is Artemis's Maven test template with Ares 2, built offline. Its own
# SecurityPolicy.yaml is imported with phobos.sh, with only the configuration name changed, so the
# run goes through the base the configuration names (language-configurations/bases/) and no other.
# Permitted direction: all 13 tests of the template pass under every name. Containment direction: a canary file the
# base does not name is refused for read, and a run given no Ares 2 policy, which folds the
# top-level Base*.cfg and never the Maven base, cannot read the Maven dependency repository the
# Maven base grants.
#
# It needs the run-phase image with the exercise mounted read-only at /exercise, and an ordinary
# container: no --privileged, no --cap-add, no --security-opt, and --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

CORE="${PHOBOS_HOME:-/var/tmp/opt/core}"
EXERCISE_SOURCE=/exercise
EXERCISE=/var/tmp/testing-dir
REPOSITORY=/root/.m2/repository
CANARY=/srv/phobos-maven-canary
NAMES=(
  JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ
  JAVA_USING_MAVEN_ARCHUNIT_AND_INSTRUMENTATION
  JAVA_USING_MAVEN_WALA_AND_ASPECTJ
  JAVA_USING_MAVEN_WALA_AND_INSTRUMENTATION
)

if [[ ! -f "${EXERCISE_SOURCE}/SecurityPolicy.yaml" ]]; then
  bad "the Maven reference exercise is mounted at ${EXERCISE_SOURCE}" "no SecurityPolicy.yaml there"
  finish
fi

mkdir -p /srv
printf 'CANARY\n' > "$CANARY"

# Puts a fresh copy of the exercise in place, as grading does, with the configuration name given
# in its policy, and leaves the policy at /tmp/SecurityPolicy.yaml. Takes the name.
prepare_exercise() {
  local name="$1"
  rm -rf "$EXERCISE"
  mkdir -p "$EXERCISE"
  cp -a "${EXERCISE_SOURCE}/." "${EXERCISE}/"
  sed "s/JAVA_USING_MAVEN_ARCHUNIT_AND_ASPECTJ/${name}/" "${EXERCISE_SOURCE}/SecurityPolicy.yaml" > /tmp/SecurityPolicy.yaml
}

for name in "${NAMES[@]}"; do
  prepare_exercise "$name"
  output="$("$CORE/phobos.sh" --config /tmp/SecurityPolicy.yaml --project-root "$EXERCISE" -- /bin/bash "${EXERCISE}/build_script.sh" 2>&1)"
  status=$?
  if (( status == 0 )) && grep -qF "Tests run: 13, Failures: 0, Errors: 0, Skipped: 0" <<<"$output" && grep -qF "BUILD SUCCESS" <<<"$output"; then
    ok "${name}: all 13 tests pass under the Maven base"
  else
    bad "${name}: all 13 tests pass under the Maven base" "status ${status}: $(tail -n 30 <<<"$output")"
  fi
done

prepare_exercise "${NAMES[0]}"
output="$("$CORE/phobos.sh" --config /tmp/SecurityPolicy.yaml --project-root "$EXERCISE" -- /bin/cat "$CANARY" 2>&1)"
status=$?
if (( status != 0 )) && ! grep -qF "CANARY" <<<"$output"; then
  ok "a file the Maven base does not name is refused for read"
else
  bad "a file the Maven base does not name is refused for read" "status ${status}: ${output}"
fi

output="$("$CORE/phobos.sh" --config /tmp/SecurityPolicy.yaml --project-root "$EXERCISE" -- /bin/ls "$REPOSITORY" 2>&1)"
status=$?
if (( status == 0 )) && grep -qF "org" <<<"$output"; then
  ok "the Maven base grants the dependency repository for read"
else
  bad "the Maven base grants the dependency repository for read" "status ${status}: ${output}"
fi

output="$("$CORE/phobos.sh" -- /bin/ls "$REPOSITORY" 2>&1)"
status=$?
if (( status != 0 )) && ! grep -qE "^(org|com|net)$" <<<"$output"; then
  ok "a run with no Ares 2 policy does not fold the Maven base, so the repository stays closed to it"
else
  bad "a run with no Ares 2 policy does not fold the Maven base, so the repository stays closed to it" "status ${status}: ${output}"
fi

finish
