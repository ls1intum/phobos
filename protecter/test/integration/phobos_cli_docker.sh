#!/usr/bin/env bash
# shellcheck shell=bash
# What phobos-cli.sh does with a real Docker, on a run-phase image, in an ordinary container: the
# permitted case still works and the forbidden case is still refused, the container it starts has
# the limits and none of the privileges, and the status and the signals of the command reach the
# caller. phobos_cli.sh covers the same script without Docker; this suite is what proves the
# commands it builds are ones Docker and the sandbox accept.
#
#   phobos_cli_docker.sh <run-phase image>
#
# It needs the docker command, python3 and an image that holds phobos-cli.sh. Everything it starts
# is an ordinary container: no --privileged, no --cap-add, no --security-opt, --network none.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPOSITORY="$(cd -- "${HERE}/../../.." && pwd)"
CLI="${REPOSITORY}/phobos-cli.sh"
IMAGE="${1:?usage: phobos_cli_docker.sh <run-phase image>}"

WORK="$(cd -- "$(mktemp -d)" && pwd -P)"
EXERCISE="${WORK}/exercise"
OUT=""
STATUS=0

# Removes what this suite made, and only that.
cleanup() {
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

mkdir -p "${EXERCISE}"
printf 'hello\n' > "${EXERCISE}/hello.txt"
printf '[read]\n/etc/hostname\n' > "${WORK}/grant.cfg"

# Runs phobos-cli.sh with the arguments given from the repository's checkout and keeps what it
# printed on stdout in OUT and its status in STATUS; its stderr goes to a file of its own.
cli() {
  OUT="$(bash "${CLI}" "$@" 2> "${WORK}/err")"
  STATUS=$?
}

# Waits up to $1 seconds for exactly one container of the image to run, and prints its id.
wait_for_container() {
  local waited=0
  local ids
  while (( waited < $1 * 5 )); do
    ids="$(docker ps -q --filter "ancestor=${IMAGE}")"
    if [[ -n "$ids" && "$ids" != *$'\n'* ]]; then
      printf '%s\n' "$ids"
      return 0
    fi
    sleep 0.2
    waited=$((waited + 1))
  done
  return 1
}

if ! command -v docker > /dev/null 2>&1 || ! docker image inspect "${IMAGE}" > /dev/null 2>&1; then
  skip "everything in this suite" "no docker, or no image ${IMAGE}"
  finish
fi
if [[ -n "$(docker ps -q --filter "ancestor=${IMAGE}")" ]]; then
  skip "everything in this suite" "another container of ${IMAGE} is running, so the one this suite starts cannot be told apart"
  finish
fi

echo "== the control: the file is readable without Phobos, and refused with it"
control="$(docker run --rm --network none "${IMAGE}" cat /etc/hostname 2> /dev/null)"
if [[ -n "${control}" ]]; then ok "an unconfined container reads /etc/hostname"; else bad "an unconfined container reads /etc/hostname"; fi
cli run --image "${IMAGE}" --exercise "${EXERCISE}" -- cat /etc/hostname
if (( STATUS != 0 )) && [[ -z "${OUT}" ]]; then
  ok "phobos-cli.sh run refuses the file the policy does not name"
else
  bad "phobos-cli.sh run refuses the file the policy does not name" "status ${STATUS}: ${OUT}"
fi

echo "== the permitted case: the exercise, and a configuration that names the file"
cli run --image "${IMAGE}" --exercise "${EXERCISE}" -- cat hello.txt
check "the exercise is the working directory and is readable" "hello" "${OUT}"
check "and its status is 0" 0 "${STATUS}"
cli run --image "${IMAGE}" --exercise "${EXERCISE}" --config "${WORK}/grant.cfg" -- cat /etc/hostname
if (( STATUS == 0 )) && [[ "${OUT}" =~ ^[0-9a-f]{12}$ ]]; then ok "a configuration that names the file lets the command read it"; else bad "a configuration that names the file lets the command read it" "status ${STATUS}: ${OUT}"; fi
cli run --image "${IMAGE}" --exercise "${EXERCISE}" -- sh -c 'echo made > made.txt'
check "the command may write in the exercise" 0 "${STATUS}"
check "and what it wrote is on the host" "made" "$(cat "${EXERCISE}/made.txt" 2> /dev/null)"

echo "== what the command's status and signals do"
cli run --image "${IMAGE}" --exercise "${EXERCISE}" -- sh -c 'exit 7'
check "the status of the command is the status of run" 7 "${STATUS}"

echo "== the container it starts"
bash "${CLI}" run --image "${IMAGE}" --exercise "${EXERCISE}" --config "${WORK}/grant.cfg" -- sleep 60 > /dev/null 2>&1 &
cli_pid=$!
container="$(wait_for_container 60)"
if [[ -n "${container}" ]]; then
  ok "run starts exactly one container of the image"
  docker inspect "${container}" > "${WORK}/inspect.json"
  python3 - "${WORK}/inspect.json" > "${WORK}/inspect.out" 2>&1 <<'PYTHON'
import json
import sys

info = json.load(open(sys.argv[1]))[0]
host = info["HostConfig"]
problems = []
if host.get("Privileged"):
    problems.append("privileged")
if host.get("CapAdd"):
    problems.append("capabilities added: %s" % host["CapAdd"])
if host.get("SecurityOpt"):
    problems.append("security options: %s" % host["SecurityOpt"])
if host.get("NetworkMode") != "none":
    problems.append("network %s" % host.get("NetworkMode"))
if host.get("Memory") != 8 * 1024 ** 3:
    problems.append("memory %s" % host.get("Memory"))
if host.get("PidsLimit") != 1024:
    problems.append("pids limit %s" % host.get("PidsLimit"))
if host.get("Devices"):
    problems.append("devices: %s" % host["Devices"])
if host.get("PidMode") or host.get("IpcMode") not in ("", "private", "shareable", None) or host.get("UsernsMode"):
    problems.append("a shared namespace: pid=%s ipc=%s userns=%s" % (host.get("PidMode"), host.get("IpcMode"), host.get("UsernsMode")))
mounts = {mount["Destination"]: mount for mount in info["Mounts"]}
if set(mounts) != {"/var/tmp/testing-dir", "/srv/phobos-cli/config"}:
    problems.append("mounts: %s" % sorted(mounts))
elif not mounts["/var/tmp/testing-dir"]["RW"] or mounts["/srv/phobos-cli/config"]["RW"]:
    problems.append("exercise rw=%s, config rw=%s" % (mounts["/var/tmp/testing-dir"]["RW"], mounts["/srv/phobos-cli/config"]["RW"]))
print("; ".join(problems))
PYTHON
  check "no privilege, no capability, no security option, no device, no host namespace; network none; memory and pids limits set; the exercise the only writable mount, the configurations read-only" "" "$(cat "${WORK}/inspect.out")"
  kill -TERM "${cli_pid}" 2> /dev/null
  waited=0
  while kill -0 "${cli_pid}" 2> /dev/null && (( waited < 100 )); do
    sleep 0.2
    waited=$((waited + 1))
  done
  wait "${cli_pid}" 2> /dev/null
  signalled=$?
  if (( signalled != 0 )); then ok "a SIGTERM to run ends it with a status other than 0 (${signalled})"; else bad "a SIGTERM to run ends it with a status other than 0"; fi
  sleep 1
  if [[ -z "$(docker ps -q --filter "ancestor=${IMAGE}")" ]]; then ok "and the container is gone"; else bad "and the container is gone" "$(docker ps --filter "ancestor=${IMAGE}")"; docker kill "${container}" > /dev/null 2>&1; fi
else
  bad "run starts exactly one container of the image"
  kill "${cli_pid}" 2> /dev/null
fi

echo "== inside the image: the same command line"
inside="$(docker run --rm --network none --mount "type=bind,source=${EXERCISE},target=/var/tmp/testing-dir" --workdir /var/tmp/testing-dir --mount "type=bind,source=${WORK}/grant.cfg,target=/tmp/grant.cfg,readonly" "${IMAGE}" /var/tmp/opt/core/phobos-cli.sh run --config /tmp/grant.cfg -- cat /etc/hostname 2> /dev/null)"
if [[ "${inside}" =~ ^[0-9a-f]{12}$ ]]; then ok "phobos-cli.sh in the image applies the configuration it is given"; else bad "phobos-cli.sh in the image applies the configuration it is given" "${inside}"; fi
docker run --rm --network none --mount "type=bind,source=${EXERCISE},target=/var/tmp/testing-dir" --workdir /var/tmp/testing-dir "${IMAGE}" /var/tmp/opt/core/phobos-cli.sh run -- cat /etc/hostname > "${WORK}/inside.out" 2> /dev/null
check "and without it the file stays refused" 1 "$?"
docker run --rm --network none "${IMAGE}" /var/tmp/opt/core/phobos-cli.sh run --no-restriction -- true > /dev/null 2>&1
check "an image refuses the switch that turns the sandbox off" 2 "$?"
docker run --rm --network none "${IMAGE}" /var/tmp/opt/core/phobos-cli.sh prune java > /dev/null 2>&1
check "and has no helpers to prune with" 15 "$?"

echo "== the Ares 2 policy of the Maven reference exercise, with a project root inside the exercise"
mkdir -p "${WORK}/maven"
cp -R "${REPOSITORY}/exercises/java-maven/maven-reference/." "${WORK}/maven/"
cli run --image "${IMAGE}" --exercise "${WORK}/maven" --config "${WORK}/maven/SecurityPolicy.yaml" --project-root . -- /bin/bash /var/tmp/testing-dir/build_script.sh
if (( STATUS == 0 )) && grep -qF "Tests run: 2, Failures: 0, Errors: 0, Skipped: 0" <<<"${OUT}" && grep -qF "BUILD SUCCESS" <<<"${OUT}"; then
  ok "both tests pass under the policy, found through the staged copy and the translated project root"
else
  bad "both tests pass under the policy, found through the staged copy and the translated project root" "status ${STATUS}: $(tail -n 25 <<<"${OUT}")"
fi

echo "== Compose accepts what prune and record build"
for call in "prune python" "prune java-egress" "record generate --name x"; do
  # shellcheck disable=SC2086
  bash "${CLI}" --dry-run ${call} > "${WORK}/dry.out" 2> /dev/null
  prefix=()
  while IFS= read -r line; do
    [[ "$line" == "COMMAND" ]] && continue
    [[ "$line" == "run" ]] && break
    prefix+=("$line")
  done < "${WORK}/dry.out"
  if "${prefix[@]}" config --services > "${WORK}/services.out" 2>&1; then
    ok "docker compose reads the file, project directory and profile of: ${call}"
  else
    bad "docker compose reads the file, project directory and profile of: ${call}" "$(tail -3 "${WORK}/services.out")"
  fi
done

finish
