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
IMAGE_HOME=/var/tmp/opt/core
MADE_IMAGE_HOME="no"
OUT=""
STATUS=0

# Removes what this suite made, and only that: its own directory, and the stand-in installation if
# it made it. A directory it did not make is never touched.
cleanup() {
  if [[ "${MADE_IMAGE_HOME}" == "yes" ]]; then
    rm -rf -- "${IMAGE_HOME}"
    rmdir /var/tmp/opt 2> /dev/null || true
  fi
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

mkdir -p "${STUBS}" "${BARE}" "${WORK}/exercise/sub" "${WORK}/policies/nested" "${WORK}/cwd"
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
# without a line is answered with Esc (status 5, as phobos-cli-ui.sh sets DIALOG_ESC).
cat > "${STUBS}/dialog" <<'STUB'
#!/bin/bash
log="${STUB_DIALOG_LOG:?}"
plan="${STUB_DIALOG_PLAN:?}"
printf '%s\n' "$*" >> "$log"
calls="$(wc -l < "$log")"
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

# The stand-in docker: records its arguments, and with STUB_DOCKER_WAIT set writes the PID of the
# menu (the parent of the phobos-cli.sh that started it) beside that file, marks it as started and
# waits to be stopped, which is how a signal to the menu is measured.
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
exit 0
STUB
chmod +x "${STUBS}/docker"

# Runs phobos-cli.sh with the arguments given under a pseudo-terminal, with the PATH given first,
# from the suite's own working directory, and keeps what the terminal showed (carriage returns
# removed) in OUT and its status in STATUS. Takes the PATH, then the arguments.
on_terminal() {
  local path="$1"
  shift
  local command
  command="cd $(printf '%q' "${WORK}/cwd") && exec env STUB_DIALOG_LOG=$(printf '%q' "${DIALOG_LOG}") STUB_DIALOG_PLAN=$(printf '%q' "${DIALOG_PLAN}") STUB_DOCKER_LOG=$(printf '%q' "${DOCKER_LOG}") STUB_DOCKER_WAIT=$(printf '%q' "${DOCKER_WAIT}") PATH=$(printf '%q' "${path}") TERM=xterm bash $(printf '%q ' "${CLI}" "$@")"
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
if grep -q -- '--output-fd 3' "${DIALOG_LOG}" && ! grep -q -- '--no-mouse' "${DIALOG_LOG}"; then ok "dialog answers on descriptor 3 and keeps the mouse"; else bad "dialog answers on descriptor 3 and keeps the mouse" "$(cat "${DIALOG_LOG}")"; fi
menu --dry-run -- "0|" "0|5"
check "the Exit entry ends the menu with 0" 0 "${STATUS}"
for later in 2 3 4; do
  menu --dry-run -- "0|" "0|${later}" "0|" "5|"
  check "entry ${later} ends with 0 after saying it comes later" 0 "${STATUS}"
  if asked 'later version'; then ok "entry ${later} says it comes in a later version"; else bad "entry ${later} says it comes in a later version" "$(cat "${DIALOG_LOG}")"; fi
done

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
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  check "the walk through ends with 0" 0 "${STATUS}"
  walked="$(blocks_of "${OUT}")"
  on_terminal "${STUBS}:/usr/bin:/bin" --dry-run run --language java --exercise "${WORK}/exercise" --config "${WORK}/policies/exercise.cfg" -- ./gradlew test
  direct="$(blocks_of "${OUT}")"
  check "it starts exactly what the same call on the command line starts" "${direct}" "${walked}"
  if [[ -n "${walked}" ]]; then ok "which is a command"; else bad "which is a command" "nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "0|"
  if grep -qF -- "phobos-cli.sh --dry-run run --language java --exercise ${WORK}/exercise --config ${WORK}/policies/exercise.cfg -- ./gradlew test (ended with status 0)" <<<"${OUT}"; then
    ok "the menu prints the call it ran, with its status"
  else
    bad "the menu prints the call it ran, with its status" "${OUT}"
  fi
  if asked "${WORK}/policies" && asked './exercise.cfg' && asked './nested/policy.yaml'; then ok "the policies beneath the policy directory are offered"; else bad "the policies beneath the policy directory are offered" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'planted.cfg'; then bad "a policy outside the policy directory is not offered" "$(cat "${DIALOG_LOG}")"; else ok "a policy outside the policy directory is not offered"; fi

  menu --dry-run -- "0|" "0|1" "0|2" "0|${WORK}/exercise" "0|${WORK}/policies" "0|2" "0|sub" "0|python3 -m pytest" "1|" "0|"
  check "an Ares 2 policy with a project root ends with 0" 0 "${STATUS}"
  has_pair --project-root /var/tmp/testing-dir/sub && ok "the project root reaches phobos.sh inside the exercise" || bad "the project root reaches phobos.sh inside the exercise" "${OUT}"
  has_pair --config /srv/phobos-cli/config/1/policy.yaml && ok "the Ares 2 policy keeps its suffix" || bad "the Ares 2 policy keeps its suffix" "${OUT}"
  if grep -qx 'phobos-run-phase-python' <<<"${OUT}"; then ok "the language chooses the image"; else bad "the language chooses the image" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "0|" "0|4g\n512\n\nbridge-1\n10.0.0.53:53" "0|" "0|"
  check "advanced options end with 0" 0 "${STATUS}"
  has_pair --memory 4g && has_pair --pids-limit 512 && has_pair --network bridge-1 && ok "the limits and the network reach docker" || bad "the limits and the network reach docker" "${OUT}"
  has_pair --resolver 10.0.0.53:53 && grep -qx -- '--debug' <<<"${OUT}" && ok "the resolver and the debug report reach phobos.sh" || bad "the resolver and the debug report reach phobos.sh" "${OUT}"
  if grep -qx -- '--cpus' <<<"${OUT}"; then bad "an empty field adds no option" "${OUT}"; else ok "an empty field adds no option"; fi

  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "0|" "0|8g\n1024\n\nhost\n" "0|" "0|"
  check "a network the command line refuses is refused through the menu too" "${PHB_EXIT_USAGE}" "${STATUS}"
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and starts nothing" "${OUT}"; else ok "and starts nothing"; fi
  if grep -q 'ended with status 2' <<<"${OUT}"; then ok "and the menu reports the refused call"; else bad "and the menu reports the refused call" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/exercise" "0|1" "1|" "5|" "5|" "5|" "5|" "5|"
  check "declining a policy inside the exercise ends with 0" 0 "${STATUS}"
  if asked 'inside the exercise'; then ok "a policy inside the exercise is warned about"; else bad "a policy inside the exercise is warned about" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q -- '--defaultno' "${DIALOG_LOG}"; then ok "with No as the default answer"; else bad "with No as the default answer" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and declining it starts nothing" "${OUT}"; else ok "and declining it starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/exercise" "0|1" "0|" "0|./gradlew test" "1|" "0|"
  if grep -q '^COMMAND$' <<<"${OUT}"; then ok "confirming it runs the command"; else bad "confirming it runs the command" "${OUT}"; fi

  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/missing" "0|" "5|" "5|"
  if asked 'not an existing directory'; then ok "a directory that does not exist is asked for again"; else bad "a directory that does not exist is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew\\001 test" "0|" "0|./gradlew test" "1|" "0|"
  if asked 'without control characters'; then ok "a command with a control character is asked for again"; else bad "a command with a control character is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  has_pair ./gradlew test && ok "and the command given then is the one run" || bad "and the command given then is the one run" "${OUT}"
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|1" "0|./gradlew test" "1|" "1|" "5|" "5|" "5|" "5|" "5|" "5|" "5|" "5|"
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "No at the last question starts nothing" "${OUT}"; else ok "No at the last question starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/policies/exercise.cfg" "0|./gradlew test" "1|" "0|"
  has_pair --config /srv/phobos-cli/config/1/exercise.cfg && ok "a policy given by its path is used" || bad "a policy given by its path is used" "${OUT}"
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/policies/into-exercise.link" "1|" "5|" "5|" "5|" "5|" "5|"
  if asked 'inside the exercise'; then ok "a link from the policy directory into the exercise is warned about"; else bad "a link from the policy directory into the exercise is warned about" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q '^COMMAND$' <<<"${OUT}"; then bad "and declining it starts nothing" "${OUT}"; else ok "and declining it starts nothing"; fi
  menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/cwd/beside.link" "0|./gradlew test" "1|" "0|"
  if asked 'inside the exercise'; then bad "a link to a policy outside the exercise is not warned about" "$(cat "${DIALOG_LOG}")"; else ok "a link to a policy outside the exercise is not warned about"; fi
  has_pair --config /srv/phobos-cli/config/1/beside.link && ok "and is used" || bad "and is used" "${OUT}"
  for chain in chain.link through.dir/exercise.cfg newline.link; do
    menu --dry-run -- "0|" "0|1" "0|1" "0|${WORK}/exercise" "0|${WORK}/policies" "0|3" "0|${WORK}/cwd/${chain}" "1|" "5|" "5|" "5|" "5|" "5|"
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

echo "== run a command under an existing policy, inside an image"
if [[ -e "${IMAGE_HOME}" ]] || ! mkdir -p "${IMAGE_HOME}" 2> /dev/null; then
  skip "the image form of the menu" "${IMAGE_HOME} exists or cannot be made here"
else
  MADE_IMAGE_HOME="yes"
  printf '#!/bin/bash\nprintf "phobos.sh"; for a in "$@"; do printf " [%%s]" "$a"; done; printf "\\n"\n' > "${IMAGE_HOME}/phobos.sh"
  printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> %q\nwhile (( $# > 0 )); do [[ "$1" == --config ]] && cat -- "$2" >> %q; shift; done\nexit "$(cat %q 2> /dev/null || echo 0)"\n' "${WORK}/policysystem.log" "${WORK}/policysystem.log" "${WORK}/policysystem.status" > "${IMAGE_HOME}/phobos-policysystem.sh"
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
  after="$(find /var/tmp -maxdepth 1 -name 'phobos-cli-menu.*' | wc -l | tr -d ' ')"
  check "no private directory is left behind" "${before}" "${after}"
fi

finish
