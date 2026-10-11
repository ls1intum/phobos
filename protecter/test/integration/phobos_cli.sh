#!/usr/bin/env bash
# shellcheck shell=bash
# What phobos-cli.sh promises, without Docker: its option contract, the places it runs in, the
# commands it builds for run, prune, record and build, and the ways it must not be talked into
# running less confined than the policy says.
#
# Host mode is measured through --dry-run, which prints each command it would start, and through a
# stand-in `docker` that records its arguments and answers with a status the suite chose. Image
# mode is measured against a stand-in installation in /var/tmp/opt/core, which the suite makes and
# removes again, and only where that directory does not exist yet. A suite run inside a real image
# therefore skips the host checks it cannot make, and says so.
#
# Both directions throughout: the accepted spelling is shown to produce the command, and the
# refused one is shown to start nothing.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPOSITORY="$(cd -- "${HERE}/../../.." && pwd)"
CLI="${REPOSITORY}/phobos-cli.sh"
# shellcheck source=../../src/phobos-tools-common/phobos-constants.sh
source "${REPOSITORY}/protecter/src/phobos-tools-common/phobos-constants.sh"

WORK="$(cd -- "$(mktemp -d)" && pwd -P)"
STUBS="${WORK}/stubs"
LOG="${WORK}/docker.log"
PLAN="${WORK}/docker.plan"
IMAGE_HOME=/var/tmp/opt/core
MADE_IMAGE_HOME="no"
MADE_HELPERS="no"
HELPERS=/var/tmp/helpers
OUT=""
ERR=""
STATUS=0

# Removes what this suite made, and only that: its own directory, and the stand-in installation and
# helpers if it made them. A directory it did not make is never touched.
cleanup() {
  if [[ "${MADE_IMAGE_HOME}" == "yes" ]]; then
    rm -rf -- "${IMAGE_HOME}"
    rmdir /var/tmp/opt 2> /dev/null || true
  fi
  if [[ "${MADE_HELPERS}" == "yes" ]]; then
    rm -rf -- "${HELPERS}/exercise_pruner" "${HELPERS}/runtime_pruner"
    rmdir "${HELPERS}" 2> /dev/null || true
  fi
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

mkdir -p "${STUBS}" "${WORK}/exercise/sub" "${WORK}/configs" "${WORK}/cwd"
printf '[read]\n/usr\n' > "${WORK}/configs/exercise.cfg"
printf 'name: policy\n' > "${WORK}/configs/policy.yaml"

# The stand-in docker: records one line per call and ends with the status the plan names for that
# call number (0 when the plan has no line for it). With a marker named by the plan it waits to be
# stopped, which is how the signal is measured.
cat > "${STUBS}/docker" <<'STUB'
#!/bin/bash
log="${STUB_LOG:?}"
plan="${STUB_PLAN:?}"
printf '%s\n' "$*" >> "$log"
calls="$(wc -l < "$log")"
want="$(sed -n "${calls}p" "$plan" 2> /dev/null)"
if [[ "$want" == "wait" ]]; then
  : > "${STUB_STARTED:?}"
  trap 'echo terminated >> "${STUB_STARTED}"; exit 143' TERM
  sleep 30 &
  wait $!
  exit 0
fi
exit "${want:-0}"
STUB
chmod +x "${STUBS}/docker"

# Runs phobos-cli.sh with the arguments given and keeps what it printed and its status in OUT, ERR and STATUS.
# The stand-in docker is first on an absolute PATH, and the working directory is a directory of its own.
cli() {
  OUT="$(cd "${WORK}/cwd" && env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" STUB_STARTED="${WORK}/started" PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" "$@" 2> "${WORK}/err")"
  STATUS=$?
  ERR="$(cat "${WORK}/err")"
}

# Whether the output holds a line equal to $1.
has_line() {
  grep -qxF -- "$1" <<<"${OUT}"
}

# Whether the output holds the line $1 directly followed by the line $2.
has_pair() {
  awk -v a="$1" -v b="$2" 'prev == a && $0 == b { found = 1 } { prev = $0 } END { exit found ? 0 : 1 }' <<<"${OUT}"
}

# Counts the lines of the output that equal $1.
count_line() {
  grep -cxF -- "$1" <<<"${OUT}" || true
}

# Checks that a call ended with the status $2 and printed nothing on stdout that started a command.
# Takes the name of the check and the status expected.
expect_refused() {
  check "$1" "$2" "${STATUS}"
  if grep -q '^COMMAND$' <<<"${OUT}"; then
    bad "$1 starts nothing" "no COMMAND block" "${OUT}"
  fi
}

# Resets the stand-in docker: an empty log and a plan from the words given, one status per call.
plan() {
  : > "${LOG}"
  : > "${PLAN}"
  local word
  for word in "$@"; do
    printf '%s\n' "$word" >> "${PLAN}"
  done
}

# Whether the directory of an installation can be made here, which it can unless it already exists.
can_stand_in() {
  [[ ! -e "${IMAGE_HOME}" ]] && mkdir -p /var/tmp 2> /dev/null && [[ -w /var/tmp ]]
}

if [[ -e "${IMAGE_HOME}" ]]; then
  HOST_CHECKS="no"
else
  HOST_CHECKS="yes"
fi

echo "== the manual and the usage"
cli --help
check "--help ends with 0" 0 "${STATUS}"
if grep -q 'phobos-cli.sh' <<<"${OUT}" && grep -q 'EXIT STATUSES' <<<"${OUT}"; then ok "--help prints the manual on stdout"; else bad "--help prints the manual on stdout" "${OUT}"; fi
cli
check "no command is a usage error" "${PHB_EXIT_USAGE}" "${STATUS}"
cli frobnicate
check "an unknown command is a usage error" "${PHB_EXIT_USAGE}" "${STATUS}"
for sub in "run --help" "run -h" "prune --help" "record --help" "record -h" "build --help"; do
  # shellcheck disable=SC2086
  cli ${sub}
  if (( STATUS == 0 )) && grep -q 'EXIT STATUSES' <<<"${OUT}"; then ok "'${sub}' prints the manual and ends with 0"; else bad "'${sub}' prints the manual and ends with 0" "status ${STATUS}: ${ERR}"; fi
done
cli --frobnicate run -- true
check "an unknown option before the command is a usage error" "${PHB_EXIT_USAGE}" "${STATUS}"
if grep -q '^BOOTSTRAP_REFUSED=15$' "${CLI}" && [[ "${PHB_ERUNTIME}" == 15 ]]; then ok "the bootstrap status is PHB_ERUNTIME"; else bad "the bootstrap status is PHB_ERUNTIME" "${PHB_ERUNTIME}"; fi

if [[ "${HOST_CHECKS}" == "yes" ]]; then

echo "== run on a host: the command it builds"
cli --dry-run run --exercise "${WORK}/exercise" -- echo hello
check "a plain run ends with 0" 0 "${STATUS}"
has_line COMMAND && ok "a dry run prints a COMMAND block" || bad "a dry run prints a COMMAND block" "${OUT}"
has_pair docker run && ok "the command is docker run" || bad "the command is docker run" "${OUT}"
has_pair --network none && ok "the network is none by default" || bad "the network is none by default" "${OUT}"
has_pair --memory 8g && ok "a memory limit is set by default" || bad "a memory limit is set by default" "${OUT}"
has_pair --pids-limit 1024 && ok "a process limit is set by default" || bad "a process limit is set by default" "${OUT}"
has_pair --workdir /var/tmp/testing-dir && ok "the working directory is the exercise's" || bad "the working directory is the exercise's" "${OUT}"
has_line "phobos-run-phase-java" && ok "the Java image is the default" || bad "the Java image is the default" "${OUT}"
has_pair /var/tmp/opt/core/phobos.sh -- && ok "phobos.sh is followed by exactly one --" || bad "phobos.sh is followed by exactly one --" "${OUT}"
check "there is one -- in the command" 1 "$(count_line --)"
has_pair -- echo && ok "the command follows the --" || bad "the command follows the --" "${OUT}"
if grep -q "source=$(cd "${WORK}/exercise" && pwd -P),target=/var/tmp/testing-dir\$" <<<"${OUT}"; then ok "the exercise is the one writable mount"; else bad "the exercise is the one writable mount" "${OUT}"; fi
cli --dry-run run --exercise "${WORK}/exercise" -- ls --no-restriction -nr
check "a word after the command that looks like an option belongs to the command" 0 "${STATUS}"
has_pair -- ls && has_line --no-restriction && ok "the command keeps its own options" || bad "the command keeps its own options" "${OUT}"
cli --dry-run run --exercise "${WORK}/exercise" echo hello
has_pair -- echo && ok "a command without -- starts at the first word that is no option" || bad "a command without -- starts at the first word that is no option" "${OUT}"

cli --dry-run run --language python --exercise "${WORK}/exercise" -- true
has_line "phobos-run-phase-python" && ok "--language python selects the Python image" || bad "--language python selects the Python image" "${OUT}"
cli --dry-run run --image phobos-run-phase:ci --exercise "${WORK}/exercise" -- true
has_line "phobos-run-phase:ci" && ok "--image names the image" || bad "--image names the image" "${OUT}"
cli --dry-run run --image phobos-run-phase:ci --language java --exercise "${WORK}/exercise" -- true
expect_refused "--image and --language together are refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --language ruby --exercise "${WORK}/exercise" -- true
expect_refused "a language that is none of the two is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run -- true
expect_refused "run on a host needs --exercise" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/missing" -- true
expect_refused "an exercise that is no directory is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise"
expect_refused "run without a command is refused" "${PHB_EXIT_USAGE}"

echo "== run on a host: the limits"
cli --dry-run run --exercise "${WORK}/exercise" --memory 2g --pids-limit 64 --cpus 1.5 --network phobos-net -- true
check "chosen limits and a named network are accepted" 0 "${STATUS}"
has_pair --memory 2g && has_pair --pids-limit 64 && has_pair --cpus 1.5 && has_pair --network phobos-net && ok "the chosen values are the ones passed on" || bad "the chosen values are the ones passed on" "${OUT}"
for bad_memory in 0 8x -1 "" "8g --privileged" 08g 1.5g; do
  cli --dry-run run --exercise "${WORK}/exercise" --memory "${bad_memory}" -- true
  expect_refused "--memory '${bad_memory}' is refused" "${PHB_EXIT_USAGE}"
done
for bad_pids in 0 -3 many "5 --privileged" 007; do
  cli --dry-run run --exercise "${WORK}/exercise" --pids-limit "${bad_pids}" -- true
  expect_refused "--pids-limit '${bad_pids}' is refused" "${PHB_EXIT_USAGE}"
done
for bad_cpus in 0 0.0 -1 x "1 --privileged"; do
  cli --dry-run run --exercise "${WORK}/exercise" --cpus "${bad_cpus}" -- true
  expect_refused "--cpus '${bad_cpus}' is refused" "${PHB_EXIT_USAGE}"
done
for bad_network in host container:abc ns:/proc/1/ns/net "none --privileged" "a,b"; do
  cli --dry-run run --exercise "${WORK}/exercise" --network "${bad_network}" -- true
  expect_refused "--network '${bad_network}' is refused" "${PHB_EXIT_USAGE}"
done
cli --dry-run run --exercise "${WORK}/exercise" --network=host -- true
expect_refused "--network=host is no option of this command" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" --image "x --privileged" -- true
expect_refused "an image name with a space is refused" "${PHB_EXIT_USAGE}"

echo "== run: what it refuses in every place"
for refused in --no-restriction -nr --no-filesystem-restriction -nfr --no-networksystem-restriction -nnr --no-timeoutsystem-restriction -ntr --no-resourcesystem-restriction -nrr; do
  cli --dry-run run --exercise "${WORK}/exercise" "${refused}" -- true
  expect_refused "${refused} is refused" "${PHB_EXIT_USAGE}"
done
for refused in --landlock-bin --connect-guard-bin --pgroup-lock-bin --timeout-bin --haproxy-bin; do
  cli --dry-run run --exercise "${WORK}/exercise" "${refused}" /tmp/x -- true
  expect_refused "${refused} is refused" "${PHB_EXIT_USAGE}"
done
cli --dry-run run --exercise "${WORK}/exercise" --frobnicate -- true
expect_refused "an option not listed is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" --privileged -- true
expect_refused "--privileged is no option" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" --memory
expect_refused "an option without its value is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" -- "line one
line two"
expect_refused "an argument with a newline is refused" "${PHB_EXIT_USAGE}"

echo "== run: no way to add what the outer container must not have"
combos=(
  "--language python --memory 1g --pids-limit 10 --cpus 2 --network phobos-net"
  "--image phobos-run-phase:ci --config ${WORK}/configs/exercise.cfg --config ${WORK}/configs/policy.yaml --project-root sub --resolver 10.0.0.2:53 --debug"
)
leak=""
for combo in "${combos[@]}"; do
  read -r -a words <<<"${combo}"
  cli --dry-run run --exercise "${WORK}/exercise" "${words[@]}" -- true
  for forbidden in --privileged --cap-add --security-opt --device --pid --ipc --uts --userns --volumes-from --add-host --dns --entrypoint --user --group-add; do
    has_line "${forbidden}" && leak="${leak} ${forbidden}"
  done
  grep -q 'docker.sock' <<<"${OUT}" && leak="${leak} docker.sock"
  has_pair --network host && leak="${leak} network-host"
done
check "no generated command holds a privilege, a capability, a device, a host namespace or the Docker socket" "" "${leak}"

echo "== run: the configurations"
cli --dry-run run --exercise "${WORK}/exercise" --config "${WORK}/configs/exercise.cfg" --config "${WORK}/configs/policy.yaml" -- true
check "two configurations are accepted" 0 "${STATUS}"
has_pair --config /srv/phobos-cli/config/1/exercise.cfg && has_pair --config /srv/phobos-cli/config/2/policy.yaml && ok "each is passed by its own path, its suffix kept" || bad "each is passed by its own path, its suffix kept" "${OUT}"
if grep -q 'target=/srv/phobos-cli/config,readonly$' <<<"${OUT}"; then ok "the configurations are mounted read-only"; else bad "the configurations are mounted read-only" "${OUT}"; fi
cli --dry-run run --exercise "${WORK}/exercise" --config "${WORK}/configs/missing.cfg" -- true
expect_refused "a configuration that does not exist is refused" "${PHB_EXIT_USAGE}"
mkdir -p "${WORK}/odd,dir" "${WORK}/odd:dir"
printf 'x\n' > "${WORK}/odd,dir/a.cfg"
cli --dry-run run --exercise "${WORK}/odd,dir" -- true
expect_refused "an exercise path with a comma is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/odd:dir" -- true
expect_refused "an exercise path with a colon is refused" "${PHB_EXIT_USAGE}"
mkdir -p "${WORK}/withsocket" "${WORK}/nl"
python3 - "${WORK}/withsocket/s.sock" <<'PYTHON'
import socket
import sys

server = socket.socket(socket.AF_UNIX)
server.bind(sys.argv[1])
PYTHON
cli --dry-run run --exercise "${WORK}/withsocket" -- true
expect_refused "an exercise directory that holds a socket is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise / -- true
expect_refused "the root directory is refused as an exercise" "${PHB_EXIT_USAGE}"
if [[ -d /run ]]; then
  cli --dry-run run --exercise /var/run -- true
  expect_refused "the directory that holds the Docker socket is refused as an exercise" "${PHB_EXIT_USAGE}"
fi
cli --dry-run record --exercise "${WORK}/withsocket" generate
expect_refused "and as a recording exercise too" "${PHB_EXIT_USAGE}"
mkdir "${WORK}/nl"$'\n'
ln -s "${WORK}/nl"$'\n' "${WORK}/linknl"
cli --dry-run run --exercise "${WORK}/linknl" -- true
expect_refused "a link to a directory whose name ends in a newline cannot pass for the directory without one" "${PHB_EXIT_USAGE}"
cp "${WORK}/configs/exercise.cfg" "${WORK}/exercise/inside.cfg"
cli --dry-run run --exercise "${WORK}/exercise" --config "${WORK}/exercise/inside.cfg" -- true
check "a configuration inside the exercise is fine: it is copied, so the exercise cannot write it" 0 "${STATUS}"
ln -s "${WORK}/configs/exercise.cfg" "${WORK}/configs/link.cfg"
cli --dry-run run --exercise "${WORK}/exercise" --config "${WORK}/configs/link.cfg" -- true
check "a symbolic link to a configuration is accepted, and copied by content" 0 "${STATUS}"

echo "== run: the project root"
cli --dry-run run --exercise "${WORK}/exercise" --project-root sub -- true
check "a project root inside the exercise is accepted" 0 "${STATUS}"
has_pair --project-root /var/tmp/testing-dir/sub && ok "it is named by the place the container sees" || bad "it is named by the place the container sees" "${OUT}"
cli --dry-run run --exercise "${WORK}/exercise" --project-root "${WORK}/exercise/sub" -- true
expect_refused "an absolute project root is refused on a host" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" --project-root ../configs -- true
expect_refused "a project root that leaves the exercise is refused" "${PHB_EXIT_USAGE}"
ln -s "${WORK}/configs" "${WORK}/exercise/escape"
cli --dry-run run --exercise "${WORK}/exercise" --project-root escape -- true
expect_refused "a project root that is a link out of the exercise is refused" "${PHB_EXIT_USAGE}"
cli --dry-run run --exercise "${WORK}/exercise" --project-root nothing -- true
expect_refused "a project root that does not exist is refused" "${PHB_EXIT_USAGE}"

echo "== run: a real call, through the stand-in docker"
plan 7
cli run --exercise "${WORK}/exercise" -- true
check "the status of docker is the status of run" 7 "${STATUS}"
plan 127
cli run --exercise "${WORK}/exercise" -- true
check "docker's own failure status is passed on" 127 "${STATUS}"
if grep -q 'Docker itself failing' <<<"${ERR}"; then ok "and said to be Docker's"; else bad "and said to be Docker's" "${ERR}"; fi
plan 0
cli run --exercise "${WORK}/exercise" --config "${WORK}/configs/exercise.cfg" -- true
check "a successful docker is a successful run" 0 "${STATUS}"
if grep -q -- 'type=bind,source=.*,target=/srv/phobos-cli/config,readonly' "${LOG}"; then ok "the real call mounts the staged copy read-only"; else bad "the real call mounts the staged copy read-only" "$(cat "${LOG}")"; fi
staged="$(sed -n 's|.*source=\([^,]*\),target=/srv/phobos-cli/config,readonly.*|\1|p' "${LOG}" | head -1)"
if [[ -n "${staged}" && ! -e "${staged}" ]]; then ok "the staged copy is removed when the run has ended"; else bad "the staged copy is removed when the run has ended" "${staged}"; fi

mkdir -p "${WORK}/exercise/tmp"
plan 0
OUT="$(cd "${WORK}/cwd" && env TMPDIR="${WORK}/exercise/tmp" STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" run --exercise "${WORK}/exercise" --config "${WORK}/configs/exercise.cfg" -- true 2> "${WORK}/err")"
STATUS=$?
check "a TMPDIR inside the exercise is refused, so the exercise cannot write a staged configuration" "${PHB_ERUNTIME}" "${STATUS}"
check "and docker is not called" 0 "$(wc -l < "${LOG}" | tr -d ' ')"
if [[ -z "$(ls -A "${WORK}/exercise/tmp")" ]]; then ok "and the staging directory it made is removed again"; else bad "and the staging directory it made is removed again" "$(ls -A "${WORK}/exercise/tmp")"; fi

echo "== the environment the script is started in"
for variable in BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT; do
  OUT="$(cd "${WORK}/cwd" && env "${variable}=/dev/null" PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" --dry-run build java 2> "${WORK}/err")"
  STATUS=$?
  ERR="$(cat "${WORK}/err")"
  check "a set ${variable} is refused" "${PHB_ERUNTIME}" "${STATUS}"
done
for variable in TMPDIR GCONV_PATH LOCPATH NLSPATH HOSTALIASES TZDIR; do
  OUT="$(cd "${WORK}/cwd" && env "${variable}=relative/entry" PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" --dry-run build java 2> "${WORK}/err")"
  STATUS=$?
  ERR="$(cat "${WORK}/err")"
  if grep -q "${variable}" <<<"${ERR}"; then ok "a relative ${variable} is cleaned and said so"; else bad "a relative ${variable} is cleaned and said so" "${ERR}"; fi
done
mkdir -p "${WORK}/decoy"
for tool in docker env realpath mktemp cp; do
  printf '#!/bin/bash\necho "%s ran" >> "%s/planted"\nexit 0\n' "${tool}" "${WORK}/decoy" > "${WORK}/decoy/${tool}"
  chmod +x "${WORK}/decoy/${tool}"
done
plan 0
OUT="$(cd "${WORK}/decoy" && env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" PATH=".:${STUBS}:/usr/bin:/bin" bash "${CLI}" prune python 2> "${WORK}/err")"
STATUS=$?
check "a PATH with . in it still finds the stand-in docker, not the planted one" 0 "${STATUS}"
if [[ ! -e "${WORK}/decoy/planted" ]]; then ok "nothing in the working directory was run"; else bad "nothing in the working directory was run" "$(cat "${WORK}/decoy/planted")"; fi

echo "== prune and record on a host"
mkdir -p "${WORK}/cwd2"
printf 'services:\n  prune_java_gradle:\n    image: decoy\n' > "${WORK}/cwd2/docker-compose.yaml"
printf 'COMPOSE_PROFILES=egress\nCOMPOSE_FILE=docker-compose.yaml\n' > "${WORK}/cwd2/.env"
OUT="$(cd "${WORK}/cwd2" && env COMPOSE_PROFILES=egress COMPOSE_FILE=decoy.yaml COMPOSE_PROJECT_NAME=decoy PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" --dry-run prune java-gradle 2> "${WORK}/err")"
STATUS=$?
check "prune java-gradle builds a command" 0 "${STATUS}"
has_pair --project-directory "${REPOSITORY}" && ok "Compose is anchored to the checkout's directory" || bad "Compose is anchored to the checkout's directory" "${OUT}"
has_pair -f "${REPOSITORY}/docker-compose.yaml" && ok "and to the checkout's compose file, not the one in the working directory" || bad "and to the checkout's compose file" "${OUT}"
has_pair --env-file /dev/null && ok "a .env file is not read" || bad "a .env file is not read" "${OUT}"
has_line COMPOSE_DISABLE_ENV_FILE=1 && ok "implicit .env loading is switched off" || bad "implicit .env loading is switched off" "${OUT}"
for name in COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES COMPOSE_PATH_SEPARATOR COMPOSE_ENV_FILES RUN_PHASE_IMAGE RUN_PHASE_IMAGE_PYTHON RUN_PHASE_IMAGE_C_FACT RUN_PHASE_IMAGE_R RUN_PHASE_IMAGE_C_GCC RUN_PHASE_IMAGE_CPP; do
  has_pair -u "${name}" && continue
  bad "${name} is unset for the call" "${OUT}"
done
ok "the variables that select a file, a project or a profile are unset"
has_line prune_java_gradle && has_line --build && has_line --no-deps && ok "the service is rebuilt and started alone" || bad "the service is rebuilt and started alone" "${OUT}"
for key in "java-gradle prune_java_gradle" "java-maven prune_java_maven" "python prune_python" "c-fact prune_c_fact" "r prune_r" "c-gcc prune_c_gcc" "cpp prune_cpp"; do
  cli --dry-run prune "${key%% *}"
  has_line "${key##* }" && ok "prune ${key%% *} runs ${key##* }" || bad "prune ${key%% *} runs ${key##* }" "${OUT}"
done
cli --dry-run prune java-egress
has_pair --profile egress && has_line prune_java_egress && ok "prune java-egress runs its service under the egress profile" || bad "prune java-egress runs its service under the egress profile" "${OUT}"
cli --dry-run prune java-gradle --image x
expect_refused "prune takes no --image" "${PHB_EXIT_USAGE}"
cli --dry-run prune java-gradle --language python
expect_refused "prune takes no --language: the key decides" "${PHB_EXIT_USAGE}"
cli --dry-run prune frobnicate
expect_refused "an unknown key is refused" "${PHB_EXIT_USAGE}"
cli --dry-run prune java
expect_refused "the retired key java is refused" "${PHB_EXIT_USAGE}"
if grep -q "java-gradle" <<<"${ERR}"; then ok "and the refusal names java-gradle"; else bad "and the refusal names java-gradle" "${ERR}"; fi
cli --dry-run prune
expect_refused "prune without a key is refused" "${PHB_EXIT_USAGE}"
cli --dry-run prune all
check "prune all builds fifteen commands" 15 "$(count_line COMMAND)"
order="$(grep -E '^(prune_java_gradle|prune_java_maven|prune_python|prune_c_fact|prune_r|prune_c_gcc|prune_cpp|orchestrate|verify_java_gradle|verify_java_maven|verify_python|verify_c_fact|verify_r|verify_c_gcc|verify_cpp)$' <<<"${OUT}" | tr '\n' ' ')"
check "in the order of the pipeline" "prune_java_gradle prune_java_maven prune_python prune_c_fact prune_r prune_c_gcc prune_cpp orchestrate verify_java_gradle verify_java_maven verify_python verify_c_fact verify_r verify_c_gcc verify_cpp " "${order}"
declared="$(awk '/^  [a-z_]+:$/ { name = $1; sub(":", "", name) } /command: \["--(stage|verify|langs)"/ { print name }' "${REPOSITORY}/docker-compose.yaml" | sort | tr '\n' ' ')"
listed="$(grep -E '^(prune_java_gradle|prune_java_maven|prune_python|prune_c_fact|prune_r|prune_c_gcc|prune_cpp|orchestrate|verify_java_gradle|verify_java_maven|verify_python|verify_c_fact|verify_r|verify_c_gcc|verify_cpp)$' <<<"${OUT}" | sort | tr '\n' ' ')"
check "and those are the services of docker-compose.yaml that carry a pipeline command" "${declared}" "${listed}"

for position in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  statuses=()
  for ((call = 1; call < position; call++)); do statuses+=(0); done
  statuses+=($((40 + position)))
  plan "${statuses[@]}"
  cli prune all
  check "prune all stops at the failing job ${position} with its status" "$((40 + position))" "${STATUS}"
  check "and runs no job after it" "${position}" "$(wc -l < "${LOG}" | tr -d ' ')"
done
plan 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
cli prune all
check "prune all ends with 0 when all fifteen jobs end with 0" 0 "${STATUS}"
check "after exactly fifteen jobs" 15 "$(wc -l < "${LOG}" | tr -d ' ')"
if [[ "$(grep -c -- '--build' "${LOG}")" == 15 ]]; then ok "every job is rebuilt first"; else bad "every job is rebuilt first" "$(cat "${LOG}")"; fi

plan wait
rm -f "${WORK}/started"
(cd "${WORK}/cwd" && exec env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" STUB_STARTED="${WORK}/started" PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" prune python > /dev/null 2>&1) &
cli_pid=$!
waited=0
until [[ -e "${WORK}/started" ]]; do
  sleep 0.2
  waited=$((waited + 1))
  (( waited < 100 )) || break
done
kill -TERM "${cli_pid}" 2> /dev/null
wait "${cli_pid}"
interrupted=$?
if (( interrupted != 0 )); then ok "a terminated prune never ends with 0 (status ${interrupted})"; else bad "a terminated prune never ends with 0" "${interrupted}"; fi
if grep -q terminated "${WORK}/started" 2> /dev/null; then ok "the SIGTERM reached the job"; else bad "the SIGTERM reached the job" "$(cat "${WORK}/started" 2> /dev/null)"; fi

# A background job of a shell starts with SIGINT ignored, and bash cannot take that back, so the script is started through python3, which restores the default as a terminal would have it.
plan wait
rm -f "${WORK}/started"
(cd "${WORK}/cwd" && exec env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" STUB_STARTED="${WORK}/started" PATH="${STUBS}:/usr/bin:/bin" python3 -c 'import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); os.execvp("bash", ["bash"] + sys.argv[1:])' "${CLI}" prune python > /dev/null 2>&1) &
cli_pid=$!
waited=0
until [[ -e "${WORK}/started" ]]; do
  sleep 0.2
  waited=$((waited + 1))
  (( waited < 100 )) || break
done
kill -INT "${cli_pid}" 2> /dev/null
wait "${cli_pid}"
interrupted=$?
if (( interrupted != 0 )); then ok "an interrupted prune never ends with 0 (status ${interrupted})"; else bad "an interrupted prune never ends with 0" "${interrupted}"; fi
if grep -q terminated "${WORK}/started" 2> /dev/null; then ok "the SIGINT reached the job, which a background job would otherwise ignore"; else bad "the SIGINT reached the job" "$(cat "${WORK}/started" 2> /dev/null)"; fi

cli --dry-run record generate --name tool
check "record generate builds a command" 0 "${STATUS}"
has_pair --profile record && has_line record && has_line generate && has_line RUN_PHASE_IMAGE=phobos-run-phase-java && ok "the record service runs on the Java image by default" || bad "the record service runs on the Java image by default" "${OUT}"
has_pair run --build && ok "the recorder image is rebuilt first" || bad "the recorder image is rebuilt first" "${OUT}"
cli --dry-run record --language python --exercise "${WORK}/exercise" check --name tool
has_line RUN_PHASE_IMAGE=phobos-run-phase-python && ok "--language python sets the variable the record service reads" || bad "--language python sets the variable the record service reads" "${OUT}"
has_line "RECORD_EXERCISE=$(cd "${WORK}/exercise" && pwd -P)" && ok "--exercise sets RECORD_EXERCISE" || bad "--exercise sets RECORD_EXERCISE" "${OUT}"
cli --dry-run record --networked record --name tool -- python3 -q
has_line record_networked && has_line -- && ok "--networked selects the networked service, and the command after -- is passed on" || bad "--networked selects the networked service" "${OUT}"
cli --dry-run record --image x record
expect_refused "record takes no --image" "${PHB_EXIT_USAGE}"
cli --dry-run record frobnicate
expect_refused "an unknown record verb is refused" "${PHB_EXIT_USAGE}"
cli --dry-run record
expect_refused "record without a verb is refused" "${PHB_EXIT_USAGE}"

echo "== build on a host"
cli --dry-run build java
check "build java builds two commands" 2 "$(count_line COMMAND)"
first="$(sed -n '2p' <<<"${OUT}")"
check "the first is the assembler of this checkout" "${REPOSITORY}/.github/scripts/assemble-run-phase-context.sh" "${first}"
has_pair --project-directory "${REPOSITORY}/docker/protecter/java" && has_pair -f "${REPOSITORY}/docker/protecter/java/docker-compose.yaml" && ok "the second builds the compose file of the language" || bad "the second builds the compose file of the language" "${OUT}"
cli --dry-run build python
has_pair -f "${REPOSITORY}/docker/protecter/python/docker-compose.yaml" && ok "build python builds the Python compose file" || bad "build python builds the Python compose file" "${OUT}"
cli --dry-run build
expect_refused "build without a language is refused" "${PHB_EXIT_USAGE}"
cli --dry-run build java python
expect_refused "build with two languages is refused" "${PHB_EXIT_USAGE}"
cli --dry-run build ruby
expect_refused "build of another language is refused" "${PHB_EXIT_USAGE}"
FAKE="${WORK}/checkout"
mkdir -p "${FAKE}/protecter/src" "${FAKE}/.github/scripts" "${FAKE}/docker/protecter/java" "${FAKE}/docker/protecter/python"
cp -R "${REPOSITORY}/protecter/src/phobos-tools-common" "${FAKE}/protecter/src/"
cp "${CLI}" "${FAKE}/phobos-cli.sh"
printf '#!/bin/bash\necho "assembler $*" >> "%s/steps"\nexit "${ASSEMBLER_STATUS:-0}"\n' "${WORK}" > "${FAKE}/.github/scripts/assemble-run-phase-context.sh"
chmod +x "${FAKE}/.github/scripts/assemble-run-phase-context.sh"
mkdir -p "${WORK}/decoy/.github/scripts"
printf '#!/bin/bash\necho "decoy assembler" >> "%s/steps"\n' "${WORK}" > "${WORK}/decoy/.github/scripts/assemble-run-phase-context.sh"
chmod +x "${WORK}/decoy/.github/scripts/assemble-run-phase-context.sh"
: > "${WORK}/steps"
plan 0
OUT="$(cd "${WORK}/decoy" && env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" PATH="${STUBS}:/usr/bin:/bin" bash "${FAKE}/phobos-cli.sh" build java 2> "${WORK}/err")"
STATUS=$?
check "build ends with 0 when the assembler and the build end with 0" 0 "${STATUS}"
check "the assembler of the checkout ran, once, before docker" "assembler ${FAKE}/build/run-phase-context" "$(cat "${WORK}/steps")"
check "docker was called once, for the build" 1 "$(wc -l < "${LOG}" | tr -d ' ')"
plan 0
: > "${WORK}/steps"
OUT="$(cd "${WORK}/decoy" && env ASSEMBLER_STATUS=9 STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" PATH="${STUBS}:/usr/bin:/bin" bash "${FAKE}/phobos-cli.sh" build java 2> "${WORK}/err")"
STATUS=$?
check "a failing assembler ends build with its status" 9 "${STATUS}"
check "and docker is not called" 0 "$(wc -l < "${LOG}" | tr -d ' ')"
plan 5
OUT="$(cd "${WORK}/decoy" && env STUB_LOG="${LOG}" STUB_PLAN="${PLAN}" PATH="${STUBS}:/usr/bin:/bin" bash "${FAKE}/phobos-cli.sh" build python 2> "${WORK}/err")"
STATUS=$?
check "a failing compose build is passed on unchanged" 5 "${STATUS}"

echo "== the places"
cli --mode image --dry-run run -- true
expect_refused "--mode image outside an image is refused" "${PHB_EXIT_USAGE}"
cli --mode frobnicate --dry-run run -- true
expect_refused "a mode that is none of the two is refused" "${PHB_EXIT_USAGE}"
cli --mode host --dry-run build java
check "--mode host on a host confirms it" 0 "${STATUS}"

fi

echo "== inside an image"
if can_stand_in; then
  mkdir -p "${IMAGE_HOME}"
  MADE_IMAGE_HOME="yes"
  printf '#!/bin/bash\nprintf "phobos.sh"; for a in "$@"; do printf " [%%s]" "$a"; done; printf "\\n"\nexit "${FAKE_STATUS:-0}"\n' > "${IMAGE_HOME}/phobos.sh"
  chmod +x "${IMAGE_HOME}/phobos.sh"
  cli run --config "${WORK}/configs/exercise.cfg" --resolver 10.0.0.2 --debug -- echo hi
  check "run reaches phobos.sh in an image" 0 "${STATUS}"
  check "with the configuration, the resolver, debug and one --" "phobos.sh [--config] [${WORK}/configs/exercise.cfg] [--resolver] [10.0.0.2] [--debug] [--] [echo] [hi]" "${OUT}"
  OUT="$(cd "${WORK}/cwd" && env FAKE_STATUS=9 PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" run -- true 2> /dev/null)"
  check "the command's own status is the status of run" 9 "$?"
  cli run -- ls --no-restriction
  check "a command's own options reach it" "phobos.sh [--] [ls] [--no-restriction]" "${OUT}"
  for refused in --no-restriction -nr --no-filesystem-restriction -nfr -nnr -ntr -nrr --landlock-bin --haproxy-bin --exercise --image --language --network --memory --pids-limit --cpus; do
    cli run "${refused}" x -- true
    expect_refused "${refused} is refused in an image too" "${PHB_EXIT_USAGE}"
  done
  cli run --config "${WORK}/configs/missing.cfg" -- true
  expect_refused "a configuration that is no file of the image is refused" "${PHB_EXIT_USAGE}"
  cli run --project-root /var/tmp/testing-dir/sub -- true
  check "a project root is passed as it is in an image" "phobos.sh [--project-root] [/var/tmp/testing-dir/sub] [--] [true]" "${OUT}"
  cli --mode host --dry-run run -- true
  expect_refused "--mode host inside an image is refused" "${PHB_EXIT_USAGE}"
  cli build java
  check "build is refused inside an image" "${PHB_ERUNTIME}" "${STATUS}"
  cli prune java-gradle
  check "prune without the helpers is an environment error" "${PHB_ERUNTIME}" "${STATUS}"
  cli record generate
  check "record without the helpers is an environment error" "${PHB_ERUNTIME}" "${STATUS}"
  cli prune all
  expect_refused "prune all is refused inside an image" "${PHB_EXIT_USAGE}"
  cli --dry-run prune java-egress
  expect_refused "prune java-egress needs a resolver in an image" "${PHB_EXIT_USAGE}"
  rm -f "${IMAGE_HOME}/phobos.sh"
  cli run -- true
  check "an image without phobos.sh is broken, and never becomes a host" "${PHB_ERUNTIME}" "${STATUS}"
  if [[ ! -e "${HELPERS}" ]] && mkdir "${HELPERS}" 2> /dev/null; then
    MADE_HELPERS="yes"
    mkdir -p "${HELPERS}/exercise_pruner/src/interface" "${HELPERS}/runtime_pruner/src/interface"
    : > "${HELPERS}/exercise_pruner/src/interface/main.py"
    printf '#!/bin/bash\nprintf "record"; for a in "$@"; do printf " [%%s]" "$a"; done; printf "\\n"\n' > "${HELPERS}/runtime_pruner/src/interface/phobos-record"
    chmod +x "${HELPERS}/runtime_pruner/src/interface/phobos-record"
    cli --dry-run prune java-egress --resolver 10.0.0.2
    has_line --stage && bad "java-egress does not run --stage" "${OUT}" || ok "java-egress runs without --stage"
    has_pair --output-dir /var/tmp/path_sets/egress && has_pair --resolver 10.0.0.2 && ok "and keeps its own output directory and its resolver" || bad "and keeps its own output directory and its resolver" "${OUT}"
    cli --dry-run prune python
    has_pair --stage all && has_line python && ok "prune python runs the layer pruner on all stages" || bad "prune python runs the layer pruner on all stages" "${OUT}"
    cli record generate --name tool
    check "record reaches the recorder" "record [generate] [--name] [tool]" "${OUT}"
  else
    skip "the pruner and recorder dispatch in an image" "${HELPERS} exists or cannot be made here"
  fi
else
  skip "everything that needs a stand-in installation" "${IMAGE_HOME} exists or cannot be made here, so this run is inside an image or on a protected machine"
fi

if [[ "${HOST_CHECKS}" == "no" ]]; then
  skip "the host-mode checks" "${IMAGE_HOME} exists, so this machine is an image and the script runs in image mode"
fi

echo "== an old bash"
if [[ -x /bin/bash ]] && /bin/bash -c '(( BASH_VERSINFO[0] < 4 ))' 2> /dev/null && ([[ -x /opt/homebrew/bin/bash ]] || [[ -x /usr/local/bin/bash ]]); then
  OUT="$(cd "${WORK}/cwd" && env PATH="${STUBS}:/usr/bin:/bin" /bin/bash "${CLI}" --help 2> /dev/null)"
  STATUS=$?
  check "bash 3.2 starts a newer bash from a fixed path" 0 "${STATUS}"
else
  skip "bash 3.2 starting a newer bash" "this machine has no bash older than 4.4 beside a newer one"
fi

finish
