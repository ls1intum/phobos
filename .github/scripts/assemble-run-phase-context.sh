#!/usr/bin/env bash
# Assembles the build context the run-phase image expects.
#
# The Dockerfile copies the layer scripts flat (*.sh, phobos-cli.sh among them), the
# phobos-tools-* helper folders whole,
# the four C source folders whole (phobos-landlock-filesystem-and-networksystem,
# phobos-seccomp-networksystem, phobos-seccomp-filesystem and phobos-seccomp-timeoutsystem) for its
# build stage, config/*.cfg and the folder config/language-configurations/, and, for the two stages that
# pre-load the dependency repositories, pin/ (pin-repository.sh, the two committed manifests, fact-requirements.txt and swift-mirrors.json) and
# exercises/ (the two reference exercises those stages build). The C folders keep
# their names because the report-only supervisor's sources include the other three folders'
# headers by paths relative to their own. Those files live across several directories of this
# repository, so the context has to be put together before docker build can see it, and no compose
# file or plain `docker build .` can express that.
#
# It exists so that the recipe is written once. The acceptance README used to
# carry its own copy, and the two drifted apart the moment the wrapper was split
# into modules: the README still listed one .c file, the Dockerfile had started
# asking for all of them, and the documented build stopped working.
#
#   assemble-run-phase-context.sh <destination>
set -euo pipefail

# The status this script ends with when it was called the wrong way.
readonly EXIT_USAGE=2

[[ $# -eq 1 ]] || { printf 'usage: assemble-run-phase-context.sh <destination>\n' >&2; exit "${EXIT_USAGE}"; }

DESTINATION="$1"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"

# A context left over from an earlier run can still hold a file that has since been
# renamed or deleted, and the Dockerfile copies by wildcard, so the stale one would be
# built in. The destination is therefore emptied first, but only when this script is
# the one that made it: anything else is refused rather than deleted.
MARKER=".phobos-run-phase-context"
if [[ -e "${DESTINATION}" ]]; then
  if [[ -f "${DESTINATION}/${MARKER}" ]]; then
    rm -rf -- "${DESTINATION:?}"
  elif [[ -n "$(ls -A -- "${DESTINATION}")" ]]; then
    printf '%s is not empty and was not assembled by this script; remove it first\n' \
      "${DESTINATION}" >&2
    exit 1
  fi
fi

mkdir -p "${DESTINATION}/config"
cp "${REPOSITORY}"/protecter/src/*.sh "${DESTINATION}/"
# The command line that starts phobos.sh and the pruners lives at the root of the repository and is shipped
# beside the layer scripts, so that an image can start what it holds through it.
cp "${REPOSITORY}/phobos-cli.sh" "${DESTINATION}/"
# The per-subsystem and shared helpers keep their folders, which the layer scripts source by
# name, so the context mirrors the repository layout.
cp -R "${REPOSITORY}"/protecter/src/phobos-tools-* "${DESTINATION}/"
for source_folder in phobos-landlock-filesystem-and-networksystem phobos-seccomp-networksystem \
                     phobos-seccomp-filesystem phobos-seccomp-timeoutsystem; do
  cp -R "${REPOSITORY}/protecter/src/${source_folder}" "${DESTINATION}/"
done
cp "${REPOSITORY}"/protecter/src/config/*.cfg "${DESTINATION}/config/"
cp -R "${REPOSITORY}"/protecter/src/config/language-configurations "${DESTINATION}/config/"
# The two reference exercises and what pins the dependencies they resolve, in folders of their own so
# that the flat *.sh copy of the layer scripts does not take pin-repository.sh with it. The exercises
# stay in their stages; only the repositories those stages produce enter the image.
mkdir -p "${DESTINATION}/pin" "${DESTINATION}/exercises/java"
cp "${REPOSITORY}"/protecter/image/pin-repository.sh "${DESTINATION}/pin/"
cp "${REPOSITORY}"/protecter/image/maven-repository.sha256 "${DESTINATION}/pin/"
cp "${REPOSITORY}"/protecter/image/gradle-repository.sha256 "${DESTINATION}/pin/"
cp "${REPOSITORY}"/protecter/image/fact-requirements.txt "${DESTINATION}/pin/"
cp "${REPOSITORY}"/protecter/image/swift-mirrors.json "${DESTINATION}/pin/"
cp -R "${REPOSITORY}"/exercises/java/maven-reference "${DESTINATION}/exercises/java/"
cp -R "${REPOSITORY}"/exercises/java/gradle-reference "${DESTINATION}/exercises/java/"

touch "${DESTINATION}/${MARKER}"

printf 'Run-phase build context assembled in %s\n' "${DESTINATION}"
