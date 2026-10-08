#!/bin/bash
# bash, for process substitution and read -d.
# Pre-loads a build tool's dependency repository from a reference exercise and holds the result to a
# committed manifest, so that the bytes the run-phase image carries are exactly the ones the manifest names.
#
#   pin-repository.sh verify   <repository> <manifest> <command> [argument...]
#   pin-repository.sh generate <repository> <manifest> <command> [argument...]
#
# It records the path and SHA-256 of every file under <repository>, runs the command, which is the exercise's
# own online build, records them again, and takes what the run added or changed. In verify mode that set must
# equal the paths in the manifest exactly, so an added file the manifest does not list fails as well as a listed
# file the run did not produce, and every listed file must then hash to its line. generate mode writes the
# manifest from the set instead, for whoever moves a version, and says what it wrote. Run in the stage of the
# run-phase Dockerfile that builds the repository, and by hand from the same image to regenerate a manifest, for
# example for Maven (from the exercise's folder, in the image the stage uses):
#
#   cp -a exercises/java-maven/maven-reference/. /var/tmp/testing-dir && cd /var/tmp/testing-dir &&
#   pin-repository.sh generate /root/.m2/repository /tmp/maven-repository.sha256 mvn --batch-mode --strict-checksums clean test
#
# Only regular files the run added or changed are seen. A file the run removes, and a symbolic link, are not, and
# a run that adds or changes nothing is refused in both modes, since a manifest that lists nothing pins nothing.
#
# A line is "<sha256>  <path>", the path relative to the repository. The one exception is a file named
# _remote.repositories, which Maven writes beside every artefact with a comment line holding the time it was
# written: its line is the SHA-256 of the file without its comment lines, so that the same build gives the same
# manifest. That makes the manifest a file this script checks, not one sha256sum -c can.
set -euo pipefail

mode="${1:?usage: pin-repository.sh verify|generate <repository> <manifest> <command> [argument...]}"
repository="${2:?no repository}"
manifest="${3:?no manifest}"
shift 3
[[ $# -gt 0 ]] || { echo "pin-repository.sh: no command to run" >&2; exit 2; }
case "$mode" in
  verify|generate) ;;
  *) echo "pin-repository.sh: the mode is verify or generate, not '${mode}'" >&2; exit 2 ;;
esac

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# Prints the SHA-256 of one file, of its content without the comment lines for _remote.repositories.
digest() {
  local file="$1"
  local sum
  if [[ "${file##*/}" == "_remote.repositories" ]]; then
    sum="$(grep -v '^#' "$file" | sha256sum)" || sum=""
  else
    sum="$(sha256sum < "$file")" || sum=""
  fi
  sum="${sum%% *}"
  if [[ ! "$sum" =~ ^[0-9a-f]{64}$ ]]; then
    echo "pin-repository.sh: cannot hash ${file}" >&2
    exit 1
  fi
  printf '%s' "$sum"
}

# Prints "<sha256>  <path>" for every file under the repository, sorted by path, paths relative to it.
snapshot() {
  local file
  (
    cd "$repository"
    find . -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' file; do
      printf '%s  %s\n' "$(digest "$file")" "${file#./}"
    done
  )
}

mkdir -p "$repository"
snapshot > "${scratch}/before"
"$@"
snapshot > "${scratch}/after"

# What the run added or changed: a line of the second snapshot the first does not hold.
LC_ALL=C comm -13 <(LC_ALL=C sort "${scratch}/before") <(LC_ALL=C sort "${scratch}/after") | LC_ALL=C sort -k2 > "${scratch}/changed"
sed 's/^[0-9a-f]*  //' "${scratch}/changed" > "${scratch}/changed.paths"
if [[ ! -s "${scratch}/changed" ]]; then
  echo "pin-repository.sh: the run added or changed no file under ${repository}, so there is nothing to pin." >&2
  exit 1
fi

if [[ "$mode" == generate ]]; then
  cp "${scratch}/changed" "$manifest"
  echo "pin-repository.sh: wrote ${manifest} with $(wc -l < "$manifest") files" >&2
  exit 0
fi

sed 's/^[0-9a-f]*  //' "$manifest" | LC_ALL=C sort > "${scratch}/manifest.paths"
if ! diff "${scratch}/manifest.paths" "${scratch}/changed.paths" > "${scratch}/difference"; then
  echo "pin-repository.sh: the files the run added or changed are not the files the manifest lists." >&2
  echo "pin-repository.sh: '<' is listed and not produced, '>' is produced and not listed:" >&2
  cat "${scratch}/difference" >&2
  exit 1
fi
LC_ALL=C comm -13 <(LC_ALL=C sort "$manifest") <(LC_ALL=C sort "${scratch}/changed") > "${scratch}/wrong"
if [[ -s "${scratch}/wrong" ]]; then
  echo "pin-repository.sh: these files differ from their line of the manifest:" >&2
  cat "${scratch}/wrong" >&2
  exit 1
fi
echo "pin-repository.sh: $(wc -l < "$manifest") files, every one produced by the run and every one as the manifest says" >&2
