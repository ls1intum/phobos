#!/usr/bin/env bash
# The programming language configurations Phobos ships, read by the real loader: each names exactly
# the base policy of its build tool, the Gradle ones the top-level Java base and the Maven ones the
# Maven base under language-configurations/bases/, which the top-level Base*.cfg glob a run without
# an Ares 2 policy folds never reaches. The Maven base is also held to what a pruned base promises:
# no [execute] on a directory that holds a write-class right or lies above one.
set -uo pipefail

HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../harness.sh
source "${HERE}/../../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
CORE="$(cd -- "${HERE}/../../../src" && pwd)"
CONFIG="${CORE}/config"
# shellcheck source=../../../src/phobos-tools-common/phobos-common.sh
source "${CORE}/phobos-tools-common/phobos-common.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export PHOBOS_SCRATCH="${WORK}/scratch"
mkdir -p "$PHOBOS_SCRATCH"

GRADLE_BASE="${CONFIG}/BaseLanguage-java-gradle.cfg"
MAVEN_BASE="${CONFIG}/language-configurations/bases/BaseLanguage-java-maven.cfg"

# Prints the bases the configuration of that name lists, one per line. Assumes it runs in a
# subshell, since a refusal ends it.
bases_of() {
  load_language_configuration "$1" "$CONFIG"
  printf '%s\n' "${LANGUAGE_CONFIGURATION_BASES[@]}"
}

count=0
for file in "${CONFIG}"/language-configurations/*.cfg; do
  name="$(basename "$file" .cfg)"
  count=$(( count + 1 ))
  bases="$( (bases_of "$name") 2>&1)"
  case "$name" in
    JAVA_USING_GRADLE_*) want="$GRADLE_BASE" ;;
    JAVA_USING_MAVEN_*)  want="$MAVEN_BASE" ;;
    *) want="" ;;
  esac
  if [[ -n "$want" && "$bases" == "$want" ]]; then
    ok "${name} names exactly its own base"
  else
    bad "${name} names exactly its own base" "$want" "$bases"
  fi
done
check "eight configurations ship, four per build tool" "8" "$count"

top_level="$(printf '%s\n' "${CONFIG}"/Base*.cfg | sort)"
if [[ "$top_level" != *"BaseLanguage-java-maven.cfg"* ]]; then
  ok "the top-level Base*.cfg a run without an Ares 2 policy folds never includes the Maven base"
else
  bad "the top-level Base*.cfg a run without an Ares 2 policy folds never includes the Maven base" "no Maven base" "$top_level"
fi

# Whether a path is the same as, or an ancestor of, another. Takes the ancestor candidate and the path.
covers() {
  [[ "$2" == "$1" || "$2" == "${1%/}/"* ]]
}

write_class=()
execute=()
section=""
while IFS= read -r line; do
  line="${line%%#*}"
  [[ -n "${line//[[:space:]]/}" ]] || continue
  if [[ "$line" == \[*\] ]]; then
    section="${line//[\[\]]/}"
    continue
  fi
  case "$section" in
    write|create|delete|restructure|create-ipc|create-symlink) write_class+=("$line") ;;
    execute) execute+=("$line") ;;
  esac
done < "$MAVEN_BASE"

widened=""
for directory in "${execute[@]}"; do
  for writable in "${write_class[@]}"; do
    if covers "$directory" "$writable"; then
      widened+="${directory} above or equal to ${writable}; "
    fi
  done
done
check "the Maven base grants [execute] on no directory that holds a write-class right or lies above one" "" "$widened"

finish
