#!/usr/bin/env bash
# Runs the recording pruner's suites, one ordinary container each, and checks the run-phase image.
#
# The suites run inside the prune image: record_safety.sh, record_interactive.sh, and
# record_replay.sh and record_generate.sh once per phase, each phase in a new container, because a
# replay check must run in a container other than the one that recorded and one container cannot start
# another. From here, outside every container, it also checks the run-phase image an exercise is
# graded in: it holds no strace, and phobos-record started in it with the helpers mounted refuses with
# status 3.
#
#   record_host.sh <prune image> <run-phase image>
#
# Every container is ordinary: --network none, and no --privileged, --cap-add or --security-opt.
# The recordings the phases share live in a Docker volume of this run, removed at the end.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }

PRUNE_IMAGE="${1:?usage: record_host.sh <prune image> <run-phase image>}"
RUN_PHASE_IMAGE="${2:?usage: record_host.sh <prune image> <run-phase image>}"
REPOSITORY="$(cd -- "${HERE}/../.." && pwd)"
# A name of this run's own, so parallel runs never share a volume or a container name.
RUN_ID="record-host-$$-${RANDOM}"
VOLUME="${RUN_ID}-recordings"

# Removes the volume this run created, and only that.
cleanup() {
  docker volume rm -f "${VOLUME}" > /dev/null 2>&1 || true
}
trap cleanup EXIT

# Runs one suite of tests/integration in a new, ordinary container of the given image and reports
# whether it passed; its own output is printed as it comes. Takes the image, the suite and its
# arguments. Assumes the volume exists.
in_container() {
  local image="$1"
  local suite="$2"
  shift 2
  if docker run --rm --name "${RUN_ID}-${RANDOM}" --network none \
      -v "${REPOSITORY}/tests:/tests:ro" \
      -v "${REPOSITORY}/var/tmp/helpers:/var/tmp/helpers:ro" \
      -v "${REPOSITORY}/core:/repo-core:ro" \
      -v "${REPOSITORY}/tests/integration/record-fixture/exercise:/srv/phobos-record-exercise:ro" \
      -v "${VOLUME}:/var/tmp/recordings" \
      --entrypoint bash "${image}" "/tests/integration/${suite}" "$@"; then
    ok "${suite} $* passed in its own container"
  else
    bad "${suite} $* passed in its own container"
  fi
}

# The run-phase image holds no tracer, and the recorder refuses to start in it.
check_run_phase_image() {
  local status
  local answer
  answer="$(docker run --rm --network none --entrypoint sh "${RUN_PHASE_IMAGE}" \
    -c 'if command -v strace > /dev/null; then echo HAS-STRACE; else echo NO-STRACE; fi' 2>&1)"
  check "the run-phase image holds no strace" NO-STRACE "${answer}"
  docker run --rm --network none -v "${REPOSITORY}/var/tmp/helpers:/var/tmp/helpers:ro" \
    --entrypoint /var/tmp/helpers/layer_record/phobos-record "${RUN_PHASE_IMAGE}" record -- true > /dev/null 2>&1
  status=$?
  check "phobos-record in the run-phase image refuses with status 3" 3 "${status}"
}

docker volume create "${VOLUME}" > /dev/null || { echo "cannot create the volume ${VOLUME}" >&2; exit 1; }
check_run_phase_image
in_container "${PRUNE_IMAGE}" record_safety.sh
in_container "${PRUNE_IMAGE}" record_interactive.sh
for phase in record python fresh leftover modified narrowed hand; do
  in_container "${PRUNE_IMAGE}" record_replay.sh "${phase}"
done
for phase in record replay contain second merged1 merged2 narrow limits limitscheck; do
  in_container "${PRUNE_IMAGE}" record_generate.sh "${phase}"
done
finish
