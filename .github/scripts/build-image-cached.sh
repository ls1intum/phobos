#!/usr/bin/env bash
# Builds a run-phase image with a BuildKit layer cache that the workflow keeps between runs in actions/cache.
#
#   build-image-cached.sh recipe <context directory> <Dockerfile> <BuildKit image>
#   build-image-cached.sh build <cache directory> <BuildKit image> export|read -- <docker build arguments>
#
# recipe prints the SHA-256 that names what a build reads: a canonical manifest of the assembled context
# (each entry's type, mode, content hash or link target, and path relative to the context, NUL-separated and
# sorted by path, without timestamps), then the Dockerfile, this script, the BuildKit image and the format
# version. Any change to a file the build sees therefore names another cache line. It needs python3.
#
# build runs `docker buildx build --load` on a builder of the docker-container driver named phobos-cache,
# reading the cache in <cache directory>/current when there is one. With export it writes the build's whole cache
# to <cache directory>/next, which replaces current only when the build succeeded; with read it writes none, since
# exporting a cache the run will not keep costs as long as the build saves. The docker-container driver is
# used because it exports a cache on both image stores the runners have (the containerd store on amd64, the
# classic one on arm64), where the default driver cannot on the classic one. Its BuildKit container runs
# privileged, as that driver always does; it is a build service, and the containers the suites and the prunes
# run in stay ordinary ones. --pull and --no-cache are passed through unchanged, so a fresh build still
# re-resolves everything and its cache becomes the newest. While it builds, the free space of the runner's disk
# is sampled every five seconds and the lowest value printed at the end, beside the size of the cache it read
# and of the one it wrote, which both lie on the disk until the second replaces the first.
#
# The image a build loads is the one the job then tests: the cache only reuses layers BuildKit addresses by
# content and instruction. A missing or empty cache is an ordinary miss.
set -euo pipefail

# The status this script ends with when it was called the wrong way, and when the context holds an entry a
# recipe cannot name.
readonly EXIT_USAGE=2
readonly EXIT_CONTEXT=3
# The version of the recipe's format and of the cache's layout; moving it starts every cache line again.
readonly FORMAT_VERSION="phobos-buildkit-cache-v1"
# The builder this script creates and uses, never selected as the default one.
readonly BUILDER="phobos-cache"
# Seconds between two samples of the free disk space.
readonly SAMPLE_SECONDS=5

# Prints the recipe hash of the context $1, the Dockerfile $2 and the BuildKit image $3. The manifest is made in
# Python, on the bytes of every path and link target, so that no name or target is changed on the way and any
# error reading the context ends the call before a hash is printed; an entry that is neither a directory, a
# regular file nor a symbolic link ends it with EXIT_CONTEXT.
recipe() {
  python3 - "$1" "$2" "$3" "${FORMAT_VERSION}" "${BASH_SOURCE[0]}" "${EXIT_CONTEXT}" <<'PYTHON'
import hashlib
import os
import stat
import sys

root = os.fsencode(sys.argv[1])
dockerfile = os.fsencode(sys.argv[2])
buildkit = os.fsencode(sys.argv[3])
version = os.fsencode(sys.argv[4])
script = os.fsencode(sys.argv[5])
exit_context = int(sys.argv[6])


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest().encode()


def entries(directory, relative):
    for entry in os.scandir(directory):
        path = os.path.join(relative, entry.name) if relative else entry.name
        yield path
        if entry.is_dir(follow_symlinks=False):
            yield from entries(entry.path, path)


if not stat.S_ISDIR(os.lstat(root).st_mode):
    sys.exit(f"the context {os.fsdecode(root)} is not a directory")
manifest = hashlib.sha256()
for path in sorted(entries(root, b"")):
    full = os.path.join(root, path)
    status = os.lstat(full)
    mode = b"%o" % stat.S_IMODE(status.st_mode)
    if stat.S_ISLNK(status.st_mode):
        manifest.update(b"l\0" + os.readlink(full) + b"\0" + path + b"\0")
    elif stat.S_ISDIR(status.st_mode):
        manifest.update(b"d\0" + mode + b"\0" + path + b"\0")
    elif stat.S_ISREG(status.st_mode):
        manifest.update(b"f\0" + mode + b"\0" + file_hash(full) + b"\0" + path + b"\0")
    else:
        print(f"the context holds {os.fsdecode(path)}, which is neither a directory, a file nor a link", file=sys.stderr)
        sys.exit(exit_context)
manifest.update(b"dockerfile\0" + file_hash(dockerfile) + b"\0script\0" + file_hash(script) + b"\0")
manifest.update(b"buildkit\0" + buildkit + b"\0format\0" + version + b"\0")
print(manifest.hexdigest())
PYTHON
}

# Writes the lowest free space of the runner's disk, in MiB, to the file $1, sampled until it is killed.
sample_disk() {
  local lowest=""
  local free
  while true; do
    free="$(df --output=avail -B1M / | tail -n 1 | tr -d ' ')"
    if [[ -z "${lowest}" ]] || (( free < lowest )); then
      lowest="${free}"
      printf '%s\n' "${lowest}" > "$1"
    fi
    sleep "${SAMPLE_SECONDS}"
  done
}

# Prints the size of the cache directory $1, or none when there is none.
cache_size() {
  if [[ -d "$1" ]]; then
    du -sh -- "$1" | cut -f 1
  else
    printf 'none'
  fi
}

# Creates the builder with the BuildKit image $1, unless it exists already.
ensure_builder() {
  docker buildx inspect "${BUILDER}" > /dev/null 2>&1 \
    || docker buildx create --name "${BUILDER}" --driver docker-container --driver-opt "image=$1" > /dev/null
}

# Builds with the cache directory $1 and the BuildKit image $2, exporting the cache when $3 is export, and passes
# the arguments after them to the build; ends with the build's status.
build() {
  local cache="$1"
  local mode="$3"
  local sampler
  local status=0
  local samples
  local -a cache_from=()
  local -a cache_to=()
  ensure_builder "$2"
  shift 3
  mkdir -p -- "${cache}"
  rm -rf -- "${cache}/next"
  if [[ -d "${cache}/current" && -f "${cache}/current/index.json" ]]; then
    cache_from=(--cache-from "type=local,src=${cache}/current")
  fi
  if [[ "${mode}" == "export" ]]; then
    cache_to=(--cache-to "type=local,dest=${cache}/next,mode=max")
  fi
  samples="$(mktemp)"
  sample_disk "${samples}" &
  sampler=$!
  docker buildx build --builder "${BUILDER}" --load "${cache_from[@]}" "${cache_to[@]}" "$@" || status=$?
  kill "${sampler}" 2> /dev/null || true
  wait "${sampler}" 2> /dev/null || true
  printf 'Lowest free space on the runner disk during the build: %s MiB\n' "$(cat "${samples}")"
  rm -f -- "${samples}"
  printf 'Build %s, cache before it %s, cache it wrote %s\n' \
    "$( (( ${#cache_from[@]} > 0 )) && printf 'on a restored cache' || printf 'without a cache')" \
    "$(cache_size "${cache}/current")" "$(cache_size "${cache}/next")"
  if (( status == 0 )) && [[ "${mode}" == "export" ]]; then
    rm -rf -- "${cache}/current"
    mv -- "${cache}/next" "${cache}/current"
  fi
  return "${status}"
}

case "${1:-}" in
  recipe)
    [[ $# -eq 4 ]] || { printf 'usage: build-image-cached.sh recipe <context> <Dockerfile> <BuildKit image>\n' >&2; exit "${EXIT_USAGE}"; }
    recipe "$2" "$3" "$4"
    ;;
  build)
    [[ $# -ge 6 && ( "$4" == "export" || "$4" == "read" ) && "$5" == "--" ]] \
      || { printf 'usage: build-image-cached.sh build <cache> <BuildKit image> export|read -- <docker build arguments>\n' >&2; exit "${EXIT_USAGE}"; }
    cache="$2"
    image="$3"
    mode="$4"
    shift 5
    build "${cache}" "${image}" "${mode}" "$@"
    ;;
  *)
    printf 'usage: build-image-cached.sh recipe|build ...\n' >&2
    exit "${EXIT_USAGE}"
    ;;
esac
