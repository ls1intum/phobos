#!/usr/bin/env bash
# Spike only. Records the interactive session in one fresh container, then replays the generated
# configuration under phobos.sh in another fresh container, so the replay starts from the image's
# state and not from what the recording left behind. Every container is ordinary: no
# --privileged, no --cap-add, no --security-opt.
#
#   run-spike.sh <out-dir> [--network]
#
# Without --network both containers run with --network none. With it, both get Docker's default
# network, the session also fetches an HTTPS page by name, and the replay passes the container's
# resolver to phobos.sh as --resolver. The spike image is built from the Dockerfile beside this
# script on top of a run-phase image built from this checkout (AGENTS.md, "Publishing the
# run-phase image", for the context).
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HERE
readonly IMAGE="${SPIKE_IMAGE:-phobos-recorder-spike:local}"

out="$1"
network="${2:-}"
mkdir -p "$out"
out="$(cd -- "$out" && pwd)"
docker_network=(--network none)
[[ -n "$network" ]] && docker_network=()

# Runs one mode of in-container.sh in a container of its own.
in_fresh_container() {
  docker run --rm "${docker_network[@]}" -v "${HERE}:/spike:ro" -v "${out}:/rec" \
    --entrypoint /spike/in-container.sh "$IMAGE" "$1" /rec ${network:+--network}
}

for mode in bare attached record replay; do
  printf '== %s\n' "$mode"
  in_fresh_container "$mode" || printf '(%s ended with status %s)\n' "$mode" "$?"
done
