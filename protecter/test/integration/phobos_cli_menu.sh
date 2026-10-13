#!/usr/bin/env bash
# shellcheck shell=bash
# What the menu of phobos-cli.sh promises, without Docker and without a real dialog: when it opens,
# that each way through it ends in exactly the call of phobos-cli.sh its answers make, and the ways
# it must not be talked into running something else.
#
# The menu needs a terminal, so every call here runs under script(1), which gives it a pseudo-
# terminal, and with a stand-in `dialog` that records its arguments and answers with the status and
# the text a plan names for each call, one line per box, "status|answer". Host mode is measured
# through --dry-run, whose COMMAND blocks are compared with those of the same call made on the
# command line under the same pseudo-terminal. Inside an image is measured against a stand-in
# installation in /var/tmp/opt/core, made and removed again only where that directory does not exist
# yet. A box the plan has no line for is left with Esc, so a flow that asks more than the plan
# expects goes back to the main menu and ends, rather than waiting.
#
# Both directions throughout: the call an answer should make is shown to be made, and a refused
# answer is shown to start nothing.
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
BARE="${WORK}/bare"
DIALOG_LOG="${WORK}/dialog.log"
DIALOG_PLAN="${WORK}/dialog.plan"
DOCKER_LOG="${WORK}/docker.log"
DOCKER_WAIT=""
DOCKER_STATUS=0
HOOK_CALL=""
HOOK=""
DOCKER_STATUSES=""
RECORDING="menu-suite-$$"
HELPERS=/var/tmp/helpers
RECORDINGS=/var/tmp/recordings
MADE_HELPERS="no"
MADE_RECORDINGS="no"
IMAGE_HOME=/var/tmp/opt/core
MADE_IMAGE_HOME="no"
OUT=""
STATUS=0

# Removes what this suite made, and only that: its own directory, and the stand-in installation if
# it made it. A directory it did not make is never touched.
cleanup() {
  rm -rf -- "${REPOSITORY}/build/pruner/recordings/${RECORDING}"
  if [[ "${MADE_HELPERS}" == "yes" ]]; then
    rm -rf -- "${HELPERS}/runtime_pruner"
    rmdir "${HELPERS}" 2> /dev/null || true
  fi
  if [[ "${MADE_RECORDINGS}" == "yes" ]]; then
    rm -rf -- "${RECORDINGS}"
  fi
  if [[ "${MADE_IMAGE_HOME}" == "yes" ]]; then
    rm -rf -- "${IMAGE_HOME}"
    rmdir /var/tmp/opt 2> /dev/null || true
  fi
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

mkdir -p "${STUBS}" "${BARE}" "${WORK}/exercise/sub" "${WORK}/policies/nested" "${WORK}/cwd" "${WORK}/out"
printf '[read]\n/kept\n' > "${WORK}/out/existing.cfg"
printf '[read]\n/usr\n' > "${WORK}/policies/exercise.cfg"
printf 'name: policy\n' > "${WORK}/policies/nested/policy.yaml"
printf '[read]\n/usr\n' > "${WORK}/exercise/planted.cfg"
ln -s "${WORK}/exercise/planted.cfg" "${WORK}/policies/into-exercise.link"
ln -s "${WORK}/policies/exercise.cfg" "${WORK}/cwd/beside.link"
ln -s "${WORK}/policies/exercise.cfg" "${WORK}/exercise/redirect.link"
ln -s "${WORK}/exercise/redirect.link" "${WORK}/cwd/chain.link"
ln -s "${WORK}/policies" "${WORK}/exercise/redirect.dir"
ln -s "${WORK}/exercise/redirect.dir" "${WORK}/cwd/through.dir"
ln -s "${WORK}/exercise/planted.cfg" "${WORK}/cwd/safe.cfg"$'\n'
printf '[read]\n/usr\n' > "${WORK}/cwd/safe.cfg"
ln -s "safe.cfg"$'\n' "${WORK}/cwd/newline.link"
printf '[read]\n/opt/check.log\n' > "${WORK}/policies/check.log"
printf '[read]\n/opt/specification\n' > "${WORK}/policies/specification"

# The stand-in dialog: records its arguments, one line per box, and answers with the status and the
# text of the plan's line for that box, the text on the descriptor named by --output-fd. A box
# without a line is answered with Esc (status 5, as phobos-cli-ui.sh sets DIALOG_ESC). Before the box
# numbered STUB_DIALOG_HOOK_CALL it runs STUB_DIALOG_HOOK, which is how a change on disk while the
# menu waits for an answer is measured.
cat > "${STUBS}/dialog" <<'STUB'
#!/bin/bash
log="${STUB_DIALOG_LOG:?}"
plan="${STUB_DIALOG_PLAN:?}"
printf '%s\n' "$*" >> "$log"
calls="$(wc -l < "$log")"
if [[ -n "${STUB_DIALOG_HOOK:-}" && "${calls}" == "${STUB_DIALOG_HOOK_CALL:-}" ]]; then
  bash "${STUB_DIALOG_HOOK}"
fi
line="$(sed -n "${calls}p" "$plan")"
status="5"
answer=""
if [[ -n "$line" ]]; then
  status="${line%%|*}"
  answer="${line#*|}"
fi
fd=""
previous=""
for word in "$@"; do
  [[ "$previous" == "--output-fd" ]] && fd="$word"
  previous="$word"
done
if [[ -n "$fd" && -n "$answer" ]]; then
  printf '%b' "$answer" >&"$fd"
fi
exit "$status"
STUB
chmod +x "${STUBS}/dialog"

# The stand-in docker: records its arguments and ends with STUB_DOCKER_STATUS, or, where
# STUB_DOCKER_STATUSES names one status per call, with the status of this call. With STUB_DOCKER_WAIT
# set it writes the PID of the menu (the parent of the phobos-cli.sh that started it) beside that
# file, marks it as started and waits to be stopped, which is how a signal to the menu is measured.
cat > "${STUBS}/docker" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${STUB_DOCKER_LOG:?}"
if [[ -n "${STUB_DOCKER_WAIT:-}" ]]; then
  trap 'echo terminated >> "${STUB_DOCKER_WAIT}"; exit 143' TERM
  awk '{ print $4 }' "/proc/${PPID}/stat" > "${STUB_DOCKER_WAIT}.menu"
  : > "${STUB_DOCKER_WAIT}"
  sleep 30 &
  wait $!
fi
if [[ -n "${STUB_DOCKER_STATUSES:-}" ]]; then
  read -r -a planned <<<"${STUB_DOCKER_STATUSES}"
  calls="$(wc -l < "${STUB_DOCKER_LOG}")"
  exit "${planned[calls - 1]:-0}"
fi
exit "${STUB_DOCKER_STATUS:-0}"
STUB
chmod +x "${STUBS}/docker"

# Runs phobos-cli.sh with the arguments given under a pseudo-terminal, with the PATH given first,
# from the suite's own working directory, and keeps what the terminal showed (carriage returns
# removed) in OUT and its status in STATUS. Takes the PATH, then the arguments.
on_terminal() {
  local path="$1"
  shift
  local command
  command="cd $(printf '%q' "${WORK}/cwd") && exec env STUB_DIALOG_LOG=$(printf '%q' "${DIALOG_LOG}") STUB_DIALOG_PLAN=$(printf '%q' "${DIALOG_PLAN}") STUB_DOCKER_LOG=$(printf '%q' "${DOCKER_LOG}") STUB_DOCKER_WAIT=$(printf '%q' "${DOCKER_WAIT}") STUB_DOCKER_STATUS=$(printf '%q' "${DOCKER_STATUS}") STUB_DOCKER_STATUSES=$(printf '%q' "${DOCKER_STATUSES}") STUB_DIALOG_HOOK=$(printf '%q' "${HOOK}") STUB_DIALOG_HOOK_CALL=$(printf '%q' "${HOOK_CALL}") PATH=$(printf '%q' "${path}") TERM=xterm bash $(printf '%q ' "${CLI}" "$@")"
  OUT="$(SHELL=/bin/bash script -qec "${command}" /dev/null < /dev/null | tr -d '\r')"
  STATUS="${PIPESTATUS[0]}"
}

# Runs the menu under a pseudo-terminal with the stand-in dialog answering the plan given, one
# argument per box. Takes the global options, then --, then the plan.
menu() {
  local -a options=()
  while [[ "$1" != "--" ]]; do
    options+=("$1")
    shift
  done
  shift
  : > "${DIALOG_LOG}"
  printf '%s\n' "$@" > "${DIALOG_PLAN}"
  on_terminal "${STUBS}:/usr/bin:/bin" "${options[@]}"
}

# Prints the COMMAND blocks of $1, so that two outputs can be compared by what they would start.
blocks_of() {
  awk '/^COMMAND$/ { inside = 1 } inside { print } /^END$/ { inside = 0 }' <<<"$1"
}

# Whether the dialog log holds a line that contains $1.
asked() {
  grep -qF -- "$1" "${DIALOG_LOG}"
}

# Whether the output holds the line $1 directly followed by the line $2.
has_pair() {
  awk -v a="$1" -v b="$2" 'prev == a && $0 == b { found = 1 } { prev = $0 } END { exit found ? 0 : 1 }' <<<"${OUT}"
}

if ! command -v script > /dev/null 2>&1; then
  skip "every check of the menu" "script(1) from util-linux is not installed, and the menu needs a terminal"
  finish
fi

echo "== when the menu opens"
OUT="$(cd "${WORK}/cwd" && env PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" < /dev/null 2>&1)"
STATUS=$?
check "without a terminal, no command is still a usage error" "${PHB_EXIT_USAGE}" "${STATUS}"
if grep -q 'EXIT STATUSES' <<<"${OUT}"; then ok "and prints the manual"; else bad "and prints the manual" "${OUT}"; fi
OUT="$(cd "${WORK}/cwd" && env PATH="${STUBS}:/usr/bin:/bin" bash "${CLI}" --dry-run < /dev/null 2>&1)"
STATUS=$?
check "--dry-run without a command and without a terminal is a usage error too" "${PHB_EXIT_USAGE}" "${STATUS}"
if [[ -x /usr/bin/dialog || -x /bin/dialog ]]; then
  skip "a terminal without dialog cannot open the menu" "this machine has a dialog in /usr/bin or /bin"
else
  : > "${DIALOG_LOG}"
  on_terminal "${BARE}:/usr/bin:/bin"
  check "a terminal without dialog cannot open the menu" "${PHB_ERUNTIME}" "${STATUS}"
  if grep -q 'needs dialog' <<<"${OUT}"; then ok "and says what to install"; else bad "and says what to install" "${OUT}"; fi
fi
menu --dry-run -- "0|" "5|"
check "Esc in the main menu ends the menu with 0" 0 "${STATUS}"
if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi
check "two boxes were shown, the welcome and the main menu" 2 "$(wc -l < "${DIALOG_LOG}" | tr -d ' ')"
if head -1 "${DIALOG_LOG}" | grep -q -- '--msgbox' && sed -n 2p "${DIALOG_LOG}" | grep -q -- '--menu'; then ok "in that order"; else bad "in that order" "$(cat "${DIALOG_LOG}")"; fi
if head -1 "${DIALOG_LOG}" | grep -qF -- '- the files it may read or change\n- the hosts it may reach\n- how long and how large it may run'; then ok "the welcome lists what a policy allows"; else bad "the welcome lists what a policy allows" "$(head -1 "${DIALOG_LOG}")"; fi
if head -1 "${DIALOG_LOG}" | grep -qF '\n1 Run a command' && head -1 "${DIALOG_LOG}" | grep -qF '\n2 Write a new policy' && head -1 "${DIALOG_LOG}" | grep -qF '\n3 Record your own reference program' && head -1 "${DIALOG_LOG}" | grep -qF '\n4 Derive a policy from vetted past submissions'; then ok "and names the four ways through the main menu"; else bad "and names the four ways through the main menu" "$(head -1 "${DIALOG_LOG}")"; fi
if grep -q -- '--output-fd 3' "${DIALOG_LOG}" && ! grep -q -- '--no-mouse' "${DIALOG_LOG}"; then ok "dialog answers on descriptor 3 and keeps the mouse"; else bad "dialog answers on descriptor 3 and keeps the mouse" "$(cat "${DIALOG_LOG}")"; fi
menu --dry-run -- "0|" "0|5"
check "the Exit entry ends the menu with 0" 0 "${STATUS}"

echo "== a dialog that misbehaves"
menu --dry-run -- "6|"
check "a dialog error ends the menu as a start failure, not as a cancellation" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q 'could not show the box' <<<"${OUT}"; then ok "and says so"; else bad "and says so" "${OUT}"; fi
menu --dry-run -- "0|" "0|9"
check "a choice the menu did not offer ends the menu" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi
menu --dry-run -- "0|" "0|1+1"
check "a choice that is arithmetic is not evaluated" "${PHB_ERUNTIME}" "${STATUS}"

echo "== run a command under an existing policy, on a host"
if [[ -e "${IMAGE_HOME}" ]]; then
  skip "the host form of the menu" "${IMAGE_HOME} exists, so this is an image"
else
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  check "the walk through ends with 0" 0 "${STATUS}"
  walked="$(blocks_of "${OUT}")"
  on_terminal "${STUBS}:/usr/bin:/bin" --dry-run run --language java --exercise "${WORK}/exercise" --config "${WORK}/policies/exercise.cfg" -- ./gradlew test
  direct="$(blocks_of "${OUT}")"
  check "it starts exactly what the same call on the command line starts" "${direct}" "${walked}"
  if [[ -n "${walked}" ]]; then ok "which is a command"; else bad "which is a command" "nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  if grep -qF -- "phobos-cli.sh --dry-run run --language java --exercise ${WORK}/exercise --config ${WORK}/policies/exercise.cfg -- ./gradlew test (ended with status 0)" <<<"${OUT}"; then
    ok "the menu prints the call it ran, with its status"
  else
    bad "the menu prints the call it ran, with its status" "${OUT}"
  fi
  if asked "${WORK}/policies" && asked './exercise.cfg' && asked './nested/policy.yaml'; then ok "the policies beneath the policy directory are offered"; else bad "the policies beneath the policy directory are offered" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'planted.cfg'; then bad "a policy outside the policy directory is not offered" "$(cat "${DIALOG_LOG}")"; else ok "a policy outside the policy directory is not offered"; fi

  menu --dry-run -- "0|" "0|1" "0|4" "0|${WORK}/exercise" "0|${WORK}/policies" "0|2" "0|sub" "0|python3 -m pytest" "1|" "0|"
  check "an Ares 2 policy with a project root ends with 0" 0 "${STATUS}"
  has_pair --project-root /var/tmp/testing-dir/sub && ok "the project root reaches phobos.sh inside the exercise" || bad "the project root reaches phobos.sh inside the exercise" "${OUT}"
  has_pair --config /srv/phobos-cli/config/1/policy.yaml && ok "the Ares 2 policy keeps its suffix" || bad "the Ares 2 policy keeps its suffix" "${OUT}"
  if grep -qx 'phobos-run-phase-python' <<<"${OUT}"; then ok "the language chooses the image"; else bad "the language chooses the image" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "0|" "0|4g\n512\n\nbridge-1\n10.0.0.53:53" "0|" "0|"
  check "advanced options end with 0" 0 "${STATUS}"
  has_pair --memory 4g && has_pair --pids-limit 512 && has_pair --network bridge-1 && ok "the limits and the network reach docker" || bad "the limits and the network reach docker" "${OUT}"
  has_pair --resolver 10.0.0.53:53 && grep -qx -- '--debug' <<<"${OUT}" && ok "the resolver and the debug report reach phobos.sh" || bad "the resolver and the debug report reach phobos.sh" "${OUT}"
  if grep -qx -- '--cpus' <<<"${OUT}"; then bad "an empty field adds no option" "${OUT}"; else ok "an empty field adds no option"; fi

  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "0|" "0|8g\n1024\n\nhost\n" "0|" "0|"
  check "a network the command line refuses is refused through the menu too" "${PHB_EXIT_USAGE}" "${STATUS}"
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi
  if grep -q 'ended with status 2' <<<"${OUT}"; then ok "and the menu reports the refused call"; else bad "and the menu reports the refused call" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/exercise" "0|1" "1|" "5|" "5|" "5|" "5|" "5|"
  check "declining a policy inside the exercise ends with 0" 0 "${STATUS}"
  if asked 'inside the exercise'; then ok "a policy inside the exercise is warned about"; else bad "a policy inside the exercise is warned about" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q -- '--defaultno' "${DIALOG_LOG}"; then ok "with No as the default answer"; else bad "with No as the default answer" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and declining it starts nothing" "${OUT}"; else ok "and declining it starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/exercise" "0|1" "0|" "0|./gradlew test" "1|" "0|"
  if grep -q '^COMMAND$' <<<"${OUT}"; then ok "confirming it runs the command"; else bad "confirming it runs the command" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/missing" "0|" "5|" "5|"
  if asked 'not an existing directory'; then ok "a directory that does not exist is asked for again"; else bad "a directory that does not exist is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'A dry run creates nothing' && ! asked 'Create it?'; then ok "a dry run does not offer to create it, and says why"; else bad "a dry run does not offer to create it, and says why" "$(cat "${DIALOG_LOG}")"; fi
  if [[ -e "${WORK}/missing" ]]; then bad "and creates nothing" "${WORK}/missing exists"; else ok "and creates nothing"; fi
  menu -- "0|" "0|1" "0|3" "0|${WORK}/created/deep" "0|"
  check "creating the exercise directory and then leaving the menu ends with 0" 0 "${STATUS}"
  if asked 'created/deep does not exist. Create it?'; then ok "a directory that does not exist is offered to be created"; else bad "a directory that does not exist is offered to be created" "$(cat "${DIALOG_LOG}")"; fi
  if [[ -d "${WORK}/created/deep" ]]; then ok "and Yes creates it with its parents"; else bad "and Yes creates it with its parents" "${WORK}/created/deep is missing"; fi
  if asked 'Policy directory'; then ok "and the walk goes on with it"; else bad "and the walk goes on with it" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi
  menu -- "0|" "0|1" "0|3" "0|${WORK}/declined/deep" "1|"
  if [[ -e "${WORK}/declined" ]]; then bad "No creates nothing" "${WORK}/declined exists"; else ok "No creates nothing"; fi
  if sed -n 6p "${DIALOG_LOG}" | grep -q -- '--inputbox' && ! asked 'not an existing directory'; then ok "and asks for the directory again, without a refusal"; else bad "and asks for the directory again, without a refusal" "$(cat "${DIALOG_LOG}")"; fi
  : > "${WORK}/cwd/plain-file"
  menu -- "0|" "0|1" "0|3" "0|${WORK}/cwd/plain-file" "0|"
  if asked 'Create it?'; then bad "a path that names a file is not offered to be created" "$(cat "${DIALOG_LOG}")"; else ok "a path that names a file is not offered to be created"; fi
  if asked 'not an existing directory'; then ok "and is refused"; else bad "and is refused" "$(cat "${DIALOG_LOG}")"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/cwd/plain-file" "0|"
  if asked 'A dry run creates nothing'; then bad "a dry run does not claim a file would be offered to be created" "$(cat "${DIALOG_LOG}")"; else ok "a dry run does not claim a file would be offered to be created"; fi
  ln -s "${WORK}/nowhere" "${WORK}/cwd/dangling.link"
  menu -- "0|" "0|1" "0|3" "0|${WORK}/cwd/dangling.link" "0|"
  if asked 'Create it?'; then bad "a dangling link is not offered to be created" "$(cat "${DIALOG_LOG}")"; else ok "a dangling link is not offered to be created"; fi
  if [[ -e "${WORK}/nowhere" ]]; then bad "and nothing is created through it" "${WORK}/nowhere exists"; else ok "and nothing is created through it"; fi
  menu -- "0|" "0|1" "0|3" "0|${WORK}/escaped" "5|"
  if [[ -e "${WORK}/escaped" ]]; then bad "Esc on the question creates nothing" "${WORK}/escaped exists"; else ok "Esc on the question creates nothing"; fi
  if sed -n 6p "${DIALOG_LOG}" | grep -q -- '--inputbox'; then ok "and asks for the directory again"; else bad "and asks for the directory again" "$(cat "${DIALOG_LOG}")"; fi
  menu -- "0|" "0|1" "0|3" "0|${WORK}/cwd/plain-file/below" "0|" "0|"
  if asked 'could not be created'; then ok "a directory that cannot be created is said to be so"; else bad "a directory that cannot be created is said to be so" "$(cat "${DIALOG_LOG}")"; fi
  if sed -n 7p "${DIALOG_LOG}" | grep -q -- '--inputbox' && ! asked 'not an existing directory'; then ok "and is asked for again"; else bad "and is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  menu -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/new-policies" "0|"
  if [[ -d "${WORK}/new-policies" ]]; then ok "the policy directory is created on Yes too"; else bad "the policy directory is created on Yes too" "$(cat "${DIALOG_LOG}")"; fi

  menu --dry-run -- "0|" "0|1" "0|2" "0|bad name" "0|" "0|registry.example/phobos:1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  check "a run in an image named in the menu ends with 0" 0 "${STATUS}"
  walked="$(blocks_of "${OUT}")"
  if asked 'Other image (name it)'; then ok "the language list offers an image by name"; else bad "the language list offers an image by name" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'That is not an image name'; then ok "a name --image refuses is asked for again"; else bad "a name --image refuses is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  on_terminal "${STUBS}:/usr/bin:/bin" --dry-run run --image registry.example/phobos:1 --exercise "${WORK}/exercise" --config "${WORK}/policies/exercise.cfg" -- ./gradlew test
  direct="$(blocks_of "${OUT}")"
  check "it starts exactly what the same call with --image starts" "${direct}" "${walked}"
  if grep -qx 'registry.example/phobos:1' <<<"${walked}"; then ok "which runs the image named"; else bad "which runs the image named" "${walked}"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|make test" "1|" "0|"
  check "a run of an exercise in no listed language ends with 0" 0 "${STATUS}"
  if asked 'Unknown / None of the following' && grep -qx 'phobos-run-phase-generic' <<<"${OUT}"; then ok "Unknown is offered and runs the generic image"; else bad "Unknown is offered and runs the generic image" "${OUT}"; fi
  if asked '1 Unknown / None of the following 2 Other image (name it) 3 Java (Gradle or Maven)'; then ok "the list starts with 1 Unknown, 2 Other image, 3 Java"; else bad "the list starts with 1 Unknown, 2 Other image, 3 Java" "$(cat "${DIALOG_LOG}")"; fi
  for pair in "3 java" "4 python" "5 c-fact" "6 r" "7 swift" "8 c-gcc" "9 cpp"; do
    menu --dry-run -- "0|" "0|1" "0|${pair%% *}" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|true" "1|" "0|"
    if grep -qx "phobos-run-phase-${pair##* }" <<<"${OUT}"; then ok "tag ${pair%% *} runs the ${pair##* } image"; else bad "tag ${pair%% *} runs the ${pair##* } image" "${OUT}"; fi
  done
  menu --dry-run -- "0|" "0|1" "0|2" "5|" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  check "Esc on the image name goes back to the languages" 0 "${STATUS}"
  if sed -n 5p "${DIALOG_LOG}" | grep -q 'Language' && grep -qx 'phobos-run-phase-java' <<<"${OUT}" && ! grep -qx -- '--image' <<<"${OUT}"; then ok "and a language chosen then runs its own image"; else bad "and a language chosen then runs its own image" "${OUT}"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew\\001 test" "0|" "0|./gradlew test" "1|" "0|"
  if asked 'without control characters'; then ok "a command with a control character is asked for again"; else bad "a command with a control character is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  has_pair ./gradlew test && ok "and the command given then is the one run" || bad "and the command given then is the one run" "${OUT}"
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "1|" "5|" "5|" "5|" "5|" "5|" "5|" "5|" "5|"
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "No at the last question starts nothing" "${OUT}"; else ok "No at the last question starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/policies/exercise.cfg" "0|./gradlew test" "1|" "0|"
  has_pair --config /srv/phobos-cli/config/1/exercise.cfg && ok "a policy given by its path is used" || bad "a policy given by its path is used" "${OUT}"
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/policies/into-exercise.link" "1|" "5|" "5|" "5|" "5|" "5|"
  if asked 'inside the exercise'; then ok "a link from the policy directory into the exercise is warned about"; else bad "a link from the policy directory into the exercise is warned about" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and declining it starts nothing" "${OUT}"; else ok "and declining it starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/cwd/beside.link" "0|./gradlew test" "1|" "0|"
  if asked 'inside the exercise'; then bad "a link to a policy outside the exercise is not warned about" "$(cat "${DIALOG_LOG}")"; else ok "a link to a policy outside the exercise is not warned about"; fi
  has_pair --config /srv/phobos-cli/config/1/beside.link && ok "and is used" || bad "and is used" "${OUT}"
  for chain in chain.link through.dir/exercise.cfg newline.link; do
    menu --dry-run -- "0|" "0|1" "0|3" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/cwd/${chain}" "1|" "5|" "5|" "5|" "5|" "5|"
    if asked 'inside the exercise'; then ok "a path through a link inside the exercise is warned about (${chain})"; else bad "a path through a link inside the exercise is warned about (${chain})" "$(cat "${DIALOG_LOG}")"; fi
  done

  : > "${DOCKER_LOG}"
  DOCKER_WAIT="${WORK}/docker.wait"
  rm -f "${DOCKER_WAIT}" "${DOCKER_WAIT}.menu"
  : > "${DIALOG_LOG}"
  printf '%s\n' "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|" > "${DIALOG_PLAN}"
  ( on_terminal "${STUBS}:/usr/bin:/bin"; printf '%s' "${STATUS}" > "${WORK}/signal.status"; printf '%s\n' "${OUT}" > "${WORK}/signal.out" ) &
  terminal_pid=$!
  waited=0
  until [[ -s "${DOCKER_WAIT}.menu" ]] || (( waited >= 100 )); do
    sleep 0.2
    waited=$((waited + 1))
  done
  menu_pid="$(cat "${DOCKER_WAIT}.menu" 2> /dev/null)"
  if [[ "${menu_pid}" =~ ^[0-9]+$ ]]; then
    kill -TERM "${menu_pid}"
    wait "${terminal_pid}"
    check "a SIGTERM to the menu alone ends it with 143" 143 "$(cat "${WORK}/signal.status")"
    if grep -q terminated "${DOCKER_WAIT}"; then ok "and reaches the command the menu runs"; else bad "and reaches the command the menu runs" "$(cat "${DOCKER_WAIT}")"; fi
    if grep -q 'the menu was interrupted' "${WORK}/signal.out" && grep -q 'ended with status' "${WORK}/signal.out"; then ok "and the interrupted call is reported"; else bad "and the interrupted call is reported" "$(cat "${WORK}/signal.out")"; fi
  else
    bad "the command the menu runs was started" "no PID within 20 seconds"
    wait "${terminal_pid}"
  fi
  DOCKER_WAIT=""
fi

echo "== write a new policy step by step, on a host"
if [[ -e "${IMAGE_HOME}" ]]; then
  skip "the host form of the policy assistant" "${IMAGE_HOME} exists, so this is an image"
else
  written=$'[read]\n/srv/data\n[connect]\nallow repo.example.org:443\n[limits]\ntimeout=120\nmem_mb=2048\n'
  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/new.cfg" "0|1\n10\n13" \
    "0|1" "0|/srv/data" "0|3" "0|1" "0|repo.example.org:443" "0|1" "0|3" "0|120\n\n2048\n\n\n" "0|"
  check "a dry run through the assistant ends with 0" 0 "${STATUS}"
  shown="$(awk 'found { print } /would have been saved to/ { found = 1 }' <<<"${OUT}" | sed '/^$/d')"
  check "it prints the policy the answers make" "${written%$'\n'}" "${shown}"
  if [[ -e "${WORK}/out/new.cfg" ]]; then bad "and writes nothing" "${WORK}/out/new.cfg"; else ok "and writes nothing"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi

  : > "${DOCKER_LOG}"
  menu -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/new.cfg" "0|1\n10\n13" \
    "0|1" "0|/srv/data" "0|3" "0|1" "0|repo.example.org:443" "0|1" "0|3" "0|120\n\n2048\n\n\n" "0|" \
    "0|" "0|" "0|./gradlew test" "1|" "0|"
  check "the assistant saves, checks and runs, ending with the status of the run" 0 "${STATUS}"
  check "the saved policy is exactly the one the answers make" "${written}x" "$(cat "${WORK}/out/new.cfg"; printf x)"
  check "two calls reached docker, the check and the run" 2 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  if head -1 "${DOCKER_LOG}" | grep -q -- '-- /bin/true$' && tail -1 "${DOCKER_LOG}" | grep -q -- '-- ./gradlew test$'; then ok "the check runs /bin/true and the run the command, in that order"; else bad "the check runs /bin/true and the run the command, in that order" "$(cat "${DOCKER_LOG}")"; fi
  if [[ "$(grep -c -- '--config /srv/phobos-cli/config/1/new.cfg' "${DOCKER_LOG}")" == 2 ]]; then ok "both under the saved policy"; else bad "both under the saved policy" "$(cat "${DOCKER_LOG}")"; fi
  if asked 'accepted the policy'; then ok "a check that ended with 0 says so"; else bad "a check that ended with 0 says so" "$(cat "${DIALOG_LOG}")"; fi

  : > "${DOCKER_LOG}"
  menu -- "0|" "0|2" "0|2" "0|registry.example/phobos:1" "0|${WORK}/exercise" "0|${WORK}/out/imaged.cfg" "0|1\n10\n13" \
    "0|1" "0|/srv/data" "0|3" "0|1" "0|repo.example.org:443" "0|1" "0|3" "0|120\n\n2048\n\n\n" "0|" \
    "0|" "0|" "0|./gradlew test" "1|" "0|"
  check "writing a policy for an image named in the menu ends with 0" 0 "${STATUS}"
  if [[ "$(grep -c -- ' registry.example/phobos:1 ' "${DOCKER_LOG}")" == 2 ]] && ! grep -q -- 'phobos-run-phase-' "${DOCKER_LOG}"; then ok "the check and the run both start the image named"; else bad "the check and the run both start the image named" "$(cat "${DOCKER_LOG}")"; fi

  DOCKER_STATUS=7
  menu -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/failing.cfg" "0|1" \
    "0|1" "0|/srv/data" "0|3" "0|" "0|" "0|" "1|" "0|./gradlew test" "1|" "0|"
  DOCKER_STATUS=0
  check "after a failed check that is kept, the menu ends with the status of the run" 7 "${STATUS}"
  if asked 'The check ended with status 7'; then ok "a failed check shows its status"; else bad "a failed check shows its status" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'Go back and change the policy'; then ok "and offers to change the policy"; else bad "and offers to change the policy" "$(cat "${DIALOG_LOG}")"; fi

  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/exercise/inside.cfg" "0|" \
    "0|${WORK}/out/policy.yaml" "0|" "0|${WORK}/out/existing.cfg" "1|" "5|" "5|" "5|" "5|"
  check "refused places end the way with 0" 0 "${STATUS}"
  if asked 'inside the exercise directory'; then ok "a policy is never saved inside the exercise"; else bad "a policy is never saved inside the exercise" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'ending in .cfg'; then ok "a policy is saved only as a .cfg file"; else bad "a policy is saved only as a .cfg file" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'exists. Replace it?'; then ok "an existing file is replaced only after a question"; else bad "an existing file is replaced only after a question" "$(cat "${DIALOG_LOG}")"; fi
  check "and No leaves it as it was" $'[read]\n/kept\nx' "$(cat "${WORK}/out/existing.cfg"; printf x)"

  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/e.cfg" "0|1\n11\n12\n13" \
    "0|1" "0|relative/path" "0|" "0|/srv/x" "0|3" \
    "0|1" "0|70000" "0|" "0|8080" "0|1" "0|3" \
    "0|1" "0|80\n8080\n198.51.100.0/24" "0|" "0|18080\n8080\n198.51.100.0/24, 203.0.113.1" "0|3" \
    "0|1.5\n\n\n\n\n" "0|" "0|2.500\n\n\n\n\n0" "0|" "0|"
  shown="$(awk 'found { print } /would have been saved to/ { found = 1 }' <<<"${OUT}" | sed '/^$/d')"
  check "answers given again after a refusal make the policy" $'[read]\n/srv/x\n[bind]\nallow 8080\n[accept]\nexpose 18080 to 8080 from 198.51.100.0/24, 203.0.113.1\n[limits]\ntimeout=2.500\nfsize_mb=0' "${shown}"
  for refusal in 'must be absolute' 'from 0 to 65535' 'from 1024 to 65535' 'exactly three decimals' 'switches these limits off'; do
    if asked "${refusal}"; then ok "the assistant says '${refusal}'"; else bad "the assistant says '${refusal}'" "$(cat "${DIALOG_LOG}")"; fi
  done

  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/r.cfg" "0|1\n10" \
    "0|1" "0|/a" "0|2" "0|/b" "0|1" "0|" "0|3" \
    "0|1" "0|host:0" "0|" "0|[2001:db8::1]:443" "0|2" "0|3" "0|"
  shown="$(awk 'found { print } /would have been saved to/ { found = 1 }' <<<"${OUT}" | sed '/^$/d')"
  check "an entry removed is gone, and an address of the sixth version keeps its brackets" $'[read]\n/b\n[connect]\nallow [2001:db8::1]:443 udp' "${shown}"
  if asked 'from 1 to 65535, or *'; then ok "a [connect] port of 0 is refused"; else bad "a [connect] port of 0 is refused" "$(cat "${DIALOG_LOG}")"; fi
  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/u.cfg" "0|1\n13" \
    "0|1" "0|/a" "0|3" "0|120\n\n\n\n\n" "5|" "5|" "0|1" "0|3" "0|"
  shown="$(awk 'found { print } /would have been saved to/ { found = 1 }' <<<"${OUT}" | sed '/^$/d')"
  check "a section unticked after it was filled grants nothing" $'[read]\n/a' "${shown}"
  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/z.cfg" "0|13" \
    "0|0.000\n\n\n\n\n" "1|" "0|120\n\n\n\n\n" "0|"
  shown="$(awk 'found { print } /would have been saved to/ { found = 1 }' <<<"${OUT}" | sed '/^$/d')"
  if asked 'whatever the base names: timeout'; then ok "a timeout of 0.000 is confirmed like 0"; else bad "a timeout of 0.000 is confirmed like 0" "$(cat "${DIALOG_LOG}")"; fi
  check "and declining keeps asking" $'[limits]\ntimeout=120' "${shown}"

  printf 'ln -s %q %q\n' "${WORK}/exercise" "${WORK}/out/planted.cfg" > "${WORK}/hook.sh"
  HOOK="${WORK}/hook.sh"
  HOOK_CALL=10
  before_exercise="$(find "${WORK}/exercise" | sort)"
  menu -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/planted.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "0|" \
    "5|" "5|" "5|" "5|" "5|" "5|"
  HOOK=""
  HOOK_CALL=""
  if asked 'not a regular file'; then ok "a link planted at the destination while the policy is written is refused"; else bad "a link planted at the destination while the policy is written is refused" "$(cat "${DIALOG_LOG}")"; fi
  check "and nothing is written where it leads" "${before_exercise}" "$(find "${WORK}/exercise" | sort)"
  if [[ -L "${WORK}/out/planted.cfg" ]]; then ok "and the link is left as it was"; else bad "and the link is left as it was" "$(ls -la "${WORK}/out")"; fi

  printf 'printf "[read]\\n/appeared\\n" > %q\n' "${WORK}/out/appeared.cfg" > "${WORK}/hook.sh"
  HOOK="${WORK}/hook.sh"
  HOOK_CALL=10
  menu -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/appeared.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "1|" \
    "5|" "5|" "5|" "5|" "5|" "5|"
  HOOK=""
  HOOK_CALL=""
  if asked 'appeared while the policy was being written'; then ok "a file that appeared at the destination meanwhile is replaced only after a question"; else bad "a file that appeared at the destination meanwhile is replaced only after a question" "$(cat "${DIALOG_LOG}")"; fi
  check "and No leaves it as it was" $'[read]\n/appeared\nx' "$(cat "${WORK}/out/appeared.cfg"; printf x)"

  : > "${DOCKER_LOG}"
  DOCKER_WAIT="${WORK}/check.wait"
  rm -f "${DOCKER_WAIT}" "${DOCKER_WAIT}.menu"
  captures_before="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'phobos-cli-check.*' | wc -l | tr -d ' ')"
  : > "${DIALOG_LOG}"
  printf '%s\n' "0|" "0|2" "0|1" "0|${WORK}/exercise" "0|${WORK}/out/interrupted.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "0|" > "${DIALOG_PLAN}"
  ( on_terminal "${STUBS}:/usr/bin:/bin"; printf '%s' "${STATUS}" > "${WORK}/check.status" ) &
  terminal_pid=$!
  waited=0
  until [[ -s "${DOCKER_WAIT}.menu" ]] || (( waited >= 100 )); do
    sleep 0.2
    waited=$((waited + 1))
  done
  menu_pid="$(cat "${DOCKER_WAIT}.menu" 2> /dev/null)"
  if [[ "${menu_pid}" =~ ^[0-9]+$ ]]; then
    kill -TERM "${menu_pid}"
    wait "${terminal_pid}"
    check "a SIGTERM during the check ends the menu with 143" 143 "$(cat "${WORK}/check.status")"
    check "and leaves no output of the check behind" "${captures_before}" "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'phobos-cli-check.*' | wc -l | tr -d ' ')"
  else
    bad "the check the menu runs was started" "no PID within 20 seconds"
    wait "${terminal_pid}"
  fi
  DOCKER_WAIT=""
  menu --dry-run -- "0|" "0|2" "0|3" "0|${WORK}/exercise" "0|${WORK}/out/t.cfg" "0|1\n99"
  check "a section the checklist did not offer ends the menu" "${PHB_ERUNTIME}" "${STATUS}"
fi

echo "== record a reference program, on a host"
if [[ -e "${IMAGE_HOME}" ]]; then
  skip "the host form of recording" "${IMAGE_HOME} exists, so this is an image"
else
  menu --dry-run -- "0|" "0|3" "1|" "5|"
  check "declining the warning ends the way with 0" 0 "${STATUS}"
  if asked 'never a student submission'; then ok "recording warns that the program runs without a sandbox"; else bad "recording warns that the program runs without a sandbox" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q -- '--defaultno' "${DIALOG_LOG}"; then ok "with No as the default answer"; else bad "with No as the default answer" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and declining starts nothing" "${OUT}"; else ok "and declining starts nothing"; fi
  if sed -n 4p "${DIALOG_LOG}" | grep -q 'Main menu'; then ok "and leads straight back to the main menu"; else bad "and leads straight back to the main menu" "$(cat "${DIALOG_LOG}")"; fi

  menu --dry-run -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "1|" "0|bad name" "0|" "0|tool" "0|./build_script.sh"
  check "a dry run through recording ends with 0" 0 "${STATUS}"
  walked="$(blocks_of "${OUT}")"
  if asked 'up to 64'; then ok "a recording name the recording pruner refuses is asked for again"; else bad "a recording name the recording pruner refuses is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'Other image'; then bad "recording offers no image by name, since record takes no --image" "$(cat "${DIALOG_LOG}")"; else ok "recording offers no image by name, since record takes no --image"; fi
  menu --dry-run -- "0|" "0|3" "0|" "0|2"
  check "the record list does not offer tag 2" "${PHB_ERUNTIME}" "${STATUS}"
  menu --dry-run -- "0|" "0|3" "0|" "0|1" "0|${WORK}/exercise" "1|" "0|tool" "0|./build_script.sh"
  if grep -qx 'RUN_PHASE_IMAGE=phobos-run-phase-generic' <<<"${OUT}"; then ok "recording an exercise in no listed language uses the generic image"; else bad "recording an exercise in no listed language uses the generic image" "${OUT}"; fi
  if grep -q 'A dry run records nothing' <<<"${OUT}"; then ok "and says there is no policy to save"; else bad "and says there is no policy to save" "${OUT}"; fi
  on_terminal "${STUBS}:/usr/bin:/bin" --dry-run record --language java --exercise "${WORK}/exercise" record --name tool -- ./build_script.sh
  direct="$(blocks_of "${OUT}")"
  on_terminal "${STUBS}:/usr/bin:/bin" --dry-run record --language java --exercise "${WORK}/exercise" generate --name tool
  direct+=$'\n'"$(blocks_of "${OUT}")"
  check "it records and generates exactly as the same calls on the command line" "${direct}" "${walked}"

  mkdir -p "${REPOSITORY}/build/pruner/recordings/${RECORDING}"
  printf '[read]\n/recorded\n' > "${REPOSITORY}/build/pruner/recordings/${RECORDING}/policy.cfg"
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "1|" "0|${RECORDING}" "0|./build_script.sh" \
    "1|" "0|" "0|${WORK}/out/recorded.cfg" "0|" "0|./build_script.sh" "1|" "0|"
  check "recording, generating, replaying, saving and running ends with the status of the run" 0 "${STATUS}"
  check "four calls reached docker" 4 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  if sed -n 1p "${DOCKER_LOG}" | grep -qF -- "record record --name ${RECORDING} -- ./build_script.sh" \
     && sed -n 2p "${DOCKER_LOG}" | grep -qF -- "record generate --name ${RECORDING}" \
     && sed -n 3p "${DOCKER_LOG}" | grep -qF -- "record check --name ${RECORDING} -- ./build_script.sh" \
     && sed -n 4p "${DOCKER_LOG}" | grep -qF -- "--config /srv/phobos-cli/config/1/recorded.cfg"; then
    ok "in the order record, generate, check, run"
  else
    bad "in the order record, generate, check, run" "$(cat "${DOCKER_LOG}")"
  fi
  if cmp -s "${REPOSITORY}/build/pruner/recordings/${RECORDING}/policy.cfg" "${WORK}/out/recorded.cfg"; then ok "the saved policy is the one the recording yielded"; else bad "the saved policy is the one the recording yielded" "$(cat "${WORK}/out/recorded.cfg")"; fi

  DOCKER_STATUSES="0 0 9"
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "1|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "1|"
  check "a failed replay whose policy is not kept ends the menu with its status" 9 "${STATUS}"
  check "and nothing follows it" 3 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  check "and no further question is asked" 11 "$(wc -l < "${DIALOG_LOG}" | tr -d ' ')"
  DOCKER_STATUSES="0 5"
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "1|" "0|${RECORDING}" "0|./build_script.sh" "1|"
  check "a failed generate ends the menu with its status" 5 "${STATUS}"
  check "and nothing follows it" 2 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  check "and no further question is asked" 9 "$(wc -l < "${DIALOG_LOG}" | tr -d ' ')"
  DOCKER_STATUSES="3"
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "1|" "0|${RECORDING}" "0|./build_script.sh" "1|"
  check "a session that ended with a status not kept ends the menu with it" 3 "${STATUS}"
  check "and nothing follows it" 1 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  check "and no further question is asked" 9 "$(wc -l < "${DIALOG_LOG}" | tr -d ' ')"
  DOCKER_STATUSES=""
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "0|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "0|10.0.0.53" "5|"
  if sed -n 1p "${DOCKER_LOG}" | grep -qF -- "--profile record run --build --rm record_networked record --name ${RECORDING}"; then ok "a program that needs the network is recorded on the networked service"; else bad "a program that needs the network is recorded on the networked service" "$(cat "${DOCKER_LOG}")"; fi
  if sed -n 3p "${DOCKER_LOG}" | grep -qF -- "check --name ${RECORDING} --resolver 10.0.0.53 -- ./build_script.sh"; then ok "and its replay gets the resolver given"; else bad "and its replay gets the resolver given" "$(cat "${DOCKER_LOG}")"; fi
  : > "${DOCKER_LOG}"
  menu -- "0|" "0|3" "0|" "0|3" "0|${WORK}/exercise" "0|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "5|" "5|"
  check "Esc at the resolver starts no replay" 2 "$(wc -l < "${DOCKER_LOG}" | tr -d ' ')"
  DOCKER_STATUSES=""
  rm -rf -- "${REPOSITORY}/build/pruner/recordings/${RECORDING}"
fi

echo "== run a command under an existing policy, inside an image"
if [[ -e "${IMAGE_HOME}" ]] || ! mkdir -p "${IMAGE_HOME}" 2> /dev/null; then
  skip "the image form of the menu" "${IMAGE_HOME} exists or cannot be made here"
else
  MADE_IMAGE_HOME="yes"
  printf '#!/bin/bash\nprintf "phobos.sh"; for a in "$@"; do printf " [%%s]" "$a"; done; printf "\\n"\n' > "${IMAGE_HOME}/phobos.sh"
  printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> %q\nwhile (( $# > 0 )); do [[ "$1" == --config ]] && cat -- "$2" >> %q; shift; done\n[[ -f %q ]] && bash %q\nexit "$(cat %q 2> /dev/null || echo 0)"\n' "${WORK}/policysystem.log" "${WORK}/policysystem.log" "${WORK}/policysystem.hook" "${WORK}/policysystem.hook" "${WORK}/policysystem.status" > "${IMAGE_HOME}/phobos-policysystem.sh"
  chmod +x "${IMAGE_HOME}/phobos.sh" "${IMAGE_HOME}/phobos-policysystem.sh"
  before="$(find /var/tmp -maxdepth 1 -name 'phobos-cli-menu.*' | wc -l | tr -d ' ')"
  : > "${WORK}/policysystem.log"
  menu -- "0|" "0|1" "0|${WORK}/policies" "0|1" "0|./build_script.sh" "1|" "0|"
  check "a run inside an image ends with the status of phobos.sh" 0 "${STATUS}"
  run_line="$(grep '^phobos.sh' <<<"${OUT}")"
  if [[ "${run_line}" =~ \[--config\]\ \[(/var/tmp/phobos-cli-menu\.[A-Za-z0-9]+)/policy\.cfg\] ]]; then
    ok "phobos.sh reads a private copy of the policy"
    staging="${BASH_REMATCH[1]}"
    if grep -qF -- "--spec-dir ${staging}/specification --config ${staging}/policy.cfg" "${WORK}/policysystem.log"; then ok "which the policy system checked first, inside the same private directory"; else bad "which the policy system checked first, inside the same private directory" "$(cat "${WORK}/policysystem.log")"; fi
    if [[ -e "${staging}" ]]; then bad "the private directory is removed when the menu ends" "${staging}"; else ok "the private directory is removed when the menu ends"; fi
  else
    bad "phobos.sh reads a private copy of the policy" "${OUT}"
  fi
  if [[ "${run_line}" == *"[--] [./build_script.sh]" ]]; then ok "the command reaches phobos.sh after --"; else bad "the command reaches phobos.sh after --" "${run_line}"; fi
  if asked 'Language' || asked 'Exercise'; then bad "inside an image there is no language or exercise to choose" "$(cat "${DIALOG_LOG}")"; else ok "inside an image there is no language or exercise to choose"; fi
  for name in check.log specification; do
    : > "${WORK}/policysystem.log"
    menu -- "0|" "0|1" "0|${WORK}/policies" "0|3" "0|${WORK}/policies/${name}" "0|./build_script.sh" "1|" "0|"
    if grep -qxF "/opt/${name}" "${WORK}/policysystem.log" && grep -q '^phobos.sh .*/policy\.cfg\]' <<<"${OUT}"; then
      ok "a policy named ${name} reaches the policy system and the run with its own content"
    else
      bad "a policy named ${name} reaches the policy system and the run with its own content" "$(cat "${WORK}/policysystem.log")" "${OUT}"
    fi
  done
  printf '13\n' > "${WORK}/policysystem.status"
  menu -- "0|" "0|1" "0|${WORK}/policies" "0|1" "0|./build_script.sh" "1|" "0|" "0|" "5|"
  check "a policy the policy system refuses ends the way with 0, back in the main menu" 0 "${STATUS}"
  if grep -q '^phobos.sh' <<<"${OUT}"; then bad "and phobos.sh is not started" "${OUT}"; else ok "and phobos.sh is not started"; fi
  if asked 'Policy refused'; then ok "and the refusal is shown"; else bad "and the refusal is shown" "$(cat "${DIALOG_LOG}")"; fi
  rm -f "${WORK}/policysystem.status"
  : > "${WORK}/policysystem.log"
  menu --dry-run -- "0|" "0|1" "0|${WORK}/policies" "0|1" "0|./build_script.sh" "1|" "0|"
  has_pair --config "${WORK}/policies/exercise.cfg" && ok "a dry run inside an image names the policy itself" || bad "a dry run inside an image names the policy itself" "${OUT}"
  check "and copies and checks nothing" "" "$(cat "${WORK}/policysystem.log")"
  : > "${WORK}/policysystem.log"
  menu -- "0|" "0|2" "0|${WORK}/out/image.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "1|" "0|./build_script.sh" "1|" "0|"
  check "the assistant inside an image ends with the status of phobos.sh" 0 "${STATUS}"
  check "and saves the policy the answers make" $'[read]\n/srv/data\nx' "$(cat "${WORK}/out/image.cfg"; printf x)"
  if grep -qE -- "--spec-dir ${WORK}/out/\.phobos-policy\.[A-Za-z0-9]+/specification --config ${WORK}/out/\.phobos-policy\.[A-Za-z0-9]+/policy\.cfg" "${WORK}/policysystem.log"; then ok "after the policy system read it beside its destination"; else bad "after the policy system read it beside its destination" "$(cat "${WORK}/policysystem.log")"; fi
  if [[ -n "$(find "${WORK}/out" -maxdepth 1 -name '.phobos-policy.*')" ]]; then bad "and leaves nothing beside it" "$(ls -a "${WORK}/out")"; else ok "and leaves nothing beside it"; fi
  printf '[read]\n/old\n' > "${WORK}/out/race.cfg"
  printf 'rm -f %q && ln -s %q %q\n' "${WORK}/out/race.cfg" "${WORK}/exercise" "${WORK}/out/race.cfg" > "${WORK}/policysystem.hook"
  before_exercise="$(find "${WORK}/exercise" | sort)"
  menu -- "0|" "0|2" "0|${WORK}/out/race.cfg" "0|" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "1|" "1|" "5|" "5|" "5|"
  rm -f "${WORK}/policysystem.hook"
  check "a link that replaces an agreed destination in the last moment is replaced, not followed" "${before_exercise}" "$(find "${WORK}/exercise" | sort)"
  check "and the policy is saved under its own name" $'[read]\n/srv/data\nx' "$(cat "${WORK}/out/race.cfg"; printf x)"
  if [[ -L "${WORK}/out/race.cfg" ]]; then bad "as a file, not through the link" "$(ls -la "${WORK}/out")"; else ok "as a file, not through the link"; fi
  printf 'printf "[read]\\n/appeared-late\\n" > %q\n' "${WORK}/out/late.cfg" > "${WORK}/policysystem.hook"
  menu -- "0|" "0|2" "0|${WORK}/out/late.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "1|" "5|" "5|" "5|" "5|"
  rm -f "${WORK}/policysystem.hook"
  if asked 'appeared while the policy was being saved'; then ok "a file that appears in the last moment before an unagreed save is asked about"; else bad "a file that appears in the last moment before an unagreed save is asked about" "$(cat "${DIALOG_LOG}")"; fi
  check "and No leaves it as it was" $'[read]\n/appeared-late\nx' "$(cat "${WORK}/out/late.cfg"; printf x)"
  printf '13\n' > "${WORK}/policysystem.status"
  menu -- "0|" "0|2" "0|${WORK}/out/refused.cfg" "0|1" "0|1" "0|/srv/data" "0|3" "0|" "0|" "5|" "5|" "5|" "5|"
  rm -f "${WORK}/policysystem.status"
  if [[ -e "${WORK}/out/refused.cfg" ]]; then bad "a policy the policy system refuses is not saved" "${WORK}/out/refused.cfg"; else ok "a policy the policy system refuses is not saved"; fi
  if asked 'Policy refused'; then ok "and the refusal is shown"; else bad "and the refusal is shown" "$(cat "${DIALOG_LOG}")"; fi
  if [[ -n "$(find "${WORK}/out" -maxdepth 1 -name '.phobos-policy.*')" ]]; then bad "and nothing is left beside it" "$(ls -a "${WORK}/out")"; else ok "and nothing is left beside it"; fi
  after="$(find /var/tmp -maxdepth 1 -name 'phobos-cli-menu.*' | wc -l | tr -d ' ')"
  check "no private directory is left behind" "${before}" "${after}"
fi


echo "== record a reference program, inside an image"
if [[ "${MADE_IMAGE_HOME}" != "yes" ]]; then
  skip "the image form of recording" "there is no stand-in installation"
elif [[ -e "${HELPERS}" || -e "${RECORDINGS}" ]]; then
  skip "the image form of recording" "${HELPERS} or ${RECORDINGS} exists already"
else
  menu -- "0|" "0|3" "0|" "5|"
  if asked 'not possible here: it needs the prune image'; then ok "without the helpers of the pruners, recording says why it is not possible"; else bad "without the helpers of the pruners, recording says why it is not possible" "$(cat "${DIALOG_LOG}")"; fi
  menu -- "0|" "0|4" "0|" "5|"
  if asked 'not possible here: it needs a host'; then ok "inside an image, a policy from submissions says why it is not possible"; else bad "inside an image, a policy from submissions says why it is not possible" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q 'past student submissions (not here)' "${DIALOG_LOG}"; then ok "and the main menu marks it"; else bad "and the main menu marks it" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q 'derive a policy (not here)' "${DIALOG_LOG}"; then ok "and the main menu marks it"; else bad "and the main menu marks it" "$(cat "${DIALOG_LOG}")"; fi
  MADE_HELPERS="yes"
  MADE_RECORDINGS="yes"
  mkdir -p "${HELPERS}/runtime_pruner/src/interface" "${RECORDINGS}"
  printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> %q\nif [[ "$1" == generate ]]; then mkdir -p %q/"$3" && printf "[read]\\\\n/recorded-in-image\\\\n" > %q/"$3"/policy.cfg; fi\n' \
    "${WORK}/recorder.log" "${RECORDINGS}" "${RECORDINGS}" > "${HELPERS}/runtime_pruner/src/interface/phobos-record"
  chmod +x "${HELPERS}/runtime_pruner/src/interface/phobos-record"
  : > "${WORK}/recorder.log"
  : > "${WORK}/policysystem.log"
  menu -- "0|" "0|3" "0|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "0|${WORK}/out/image-recorded.cfg" "1|"
  check "recording inside the prune image ends with 0" 0 "${STATUS}"
  if sed -n 1p "${WORK}/recorder.log" | grep -qxF -- "record --name ${RECORDING} -- ./build_script.sh" && sed -n 2p "${WORK}/recorder.log" | grep -qxF -- "generate --name ${RECORDING}"; then ok "it records and generates through the image's recorder"; else bad "it records and generates through the image's recorder" "$(cat "${WORK}/recorder.log")"; fi
  if asked 'needs a container of its own'; then ok "and says the replay needs a host"; else bad "and says the replay needs a host" "$(cat "${DIALOG_LOG}")"; fi
  check "the policy is saved as the recording yielded it" $'[read]\n/recorded-in-image\nx' "$(cat "${WORK}/out/image-recorded.cfg"; printf x)"
  if asked 'base policy grants nothing'; then ok "and a run here is said not to be the run grading makes"; else bad "and a run here is said not to be the run grading makes" "$(cat "${DIALOG_LOG}")"; fi
  if asked '--exercise <reference directory> check --name'; then ok "the replay is shown with the language and the reference directory it needs"; else bad "the replay is shown with the language and the reference directory it needs" "$(cat "${DIALOG_LOG}")"; fi
  printf '13\n' > "${WORK}/policysystem.status"
  menu -- "0|" "0|3" "0|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "0|${WORK}/out/refused-recorded.cfg" "0|" "5|"
  rm -f "${WORK}/policysystem.status"
  check "a recorded policy the policy system refuses to save ends the menu with the refusal" 13 "${STATUS}"
  if [[ -e "${WORK}/out/refused-recorded.cfg" ]]; then bad "and is not saved" "${WORK}/out/refused-recorded.cfg"; else ok "and is not saved"; fi
  printf 'if [[ -e %q ]]; then printf "13\\n" > %q; else : > %q; fi\n' "${WORK}/policysystem.counter" "${WORK}/policysystem.status" "${WORK}/policysystem.counter" > "${WORK}/policysystem.hook"
  rm -f "${WORK}/policysystem.counter" "${WORK}/policysystem.status"
  menu -- "0|" "0|3" "0|" "0|${RECORDING}" "0|./build_script.sh" "1|" "0|" "0|${WORK}/out/run-refused.cfg" "0|" "0|./build_script.sh" "1|" "0|" "0|"
  rm -f "${WORK}/policysystem.hook" "${WORK}/policysystem.counter" "${WORK}/policysystem.status"
  check "a run under the saved policy that the policy system refuses ends the menu with the refusal" 13 "${STATUS}"
  if grep -q '^phobos.sh' <<<"${OUT}"; then bad "and phobos.sh is not started" "${OUT}"; else ok "and phobos.sh is not started"; fi
fi

finish
