#!/usr/bin/env bash
# Assembles the build context the run-phase image expects.
#
# The Dockerfile copies the layer scripts flat (*.sh), the phobos-tools-* helper folders whole,
# the enforcer sources flattened (phobos-landlock-filesystem-and-networksystem*.c and .h,
# phobos-seccomp-networksystem*.c and .h, phobos-seccomp-timeoutsystem.c) for its build stage, and
# config/*.cfg. Those files live across several directories of this repository, so the context has
# to be put together before docker build can see it, and no compose file or plain `docker build .`
# can express that.
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
cp "${REPOSITORY}"/core/*.sh "${DESTINATION}/"
# The per-subsystem and shared helpers keep their folders, which the layer scripts source by
# name, so the context mirrors the repository layout. config_doc.txt is documentation, not
# runtime, so it is dropped rather than shipped in the image.
cp -R "${REPOSITORY}"/core/phobos-tools-* "${DESTINATION}/"
rm -f "${DESTINATION}/phobos-tools-policysystem/config_doc.txt"
cp "${REPOSITORY}"/core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem*.c "${DESTINATION}/"
cp "${REPOSITORY}"/core/phobos-landlock-filesystem-and-networksystem/phobos-landlock-filesystem-and-networksystem*.h "${DESTINATION}/"
cp "${REPOSITORY}"/core/phobos-seccomp-networksystem/phobos-seccomp-networksystem*.c "${DESTINATION}/"
cp "${REPOSITORY}"/core/phobos-seccomp-networksystem/phobos-seccomp-networksystem*.h "${DESTINATION}/"
cp "${REPOSITORY}"/core/phobos-seccomp-timeoutsystem/phobos-seccomp-timeoutsystem.c "${DESTINATION}/"
cp "${REPOSITORY}"/core/config/*.cfg "${DESTINATION}/config/"

touch "${DESTINATION}/${MARKER}"

printf 'Run-phase build context assembled in %s\n' "${DESTINATION}"
