#!/usr/bin/env bash
# shellcheck shell=bash
# What phobos-cli.sh submissions promises, without Docker: its option contract, the template it
# refuses, how it stages each submission, the exact container calls it makes, and the status it ends
# with for each outcome of a step.
#
# A stand-in docker records every call, one line each, and plays the steps: it answers image
# inspections, writes an image ID for a build, copies a stand-in installation out of a created
# container, and for a run writes what the step would leave in the directories mounted into it, ending
# with the status the suite chose for that step. What the steps compute is measured by the unit tests
# of submissions.py and, with real containers, by phobos_cli_submissions_docker.sh.
#
# Both directions throughout: the accepted call is shown to make its containers, and the refused one
# is shown to start none.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../harness.sh
source "${HERE}/../harness.sh" || { echo "cannot source the harness beside ${HERE}" >&2; exit 1; }
REPOSITORY="$(cd -- "${HERE}/../../.." && pwd)"
CLI="${REPOSITORY}/phobos-cli.sh"
FIXTURE="${HERE}/submissions-fixture"
# shellcheck source=../../src/phobos-tools-common/phobos-constants.sh
source "${REPOSITORY}/protecter/src/phobos-tools-common/phobos-constants.sh"

WORK="$(cd -- "$(mktemp -d)" && pwd -P)"
STUBS="${WORK}/stubs"
LOG="${WORK}/docker.log"
OUT=""
ERR=""
STATUS=0

# Removes what this suite made: its own directory.
cleanup() {
  rm -rf -- "${WORK}"
}
trap cleanup EXIT

mkdir -p "${STUBS}" "${WORK}/cwd"

# The stand-in docker. Every call is one line of the log. A run plays the step its words name:
# check-template, seal, union, batch, validate and verify-report write what the step leaves and end
# with STUB_STEP_<STEP>; a prune writes its submission's artefacts and ends with STUB_PRUNE_<NAME>; a
# verification ends with STUB_VERIFY; the start of the layers under phobos.sh ends with STUB_LAYERS.
cat > "${STUBS}/docker" <<'STUB'
#!/bin/bash
printf '%s\n' "$*" >> "${STUB_LOG:?}"
target_of() {
  local wanted="$1"
  shift
  local previous=""
  local word
  local field
  for word in "$@"; do
    if [[ "$previous" == "--mount" ]]; then
      local source=""
      local target=""
      IFS=, read -r -a fields <<<"$word"
      for field in "${fields[@]}"; do
        [[ "$field" == source=* ]] && source="${field#source=}"
        [[ "$field" == target=* ]] && target="${field#target=}"
      done
      [[ "$target" == "$wanted" ]] && { printf '%s' "$source"; return 0; }
    fi
    previous="$word"
  done
  return 1
}
case "$1 $2" in
  "image inspect")
    [[ -n "${STUB_IMAGE_MISSING:-}" ]] && exit 1
    [[ "$3" == "--format" ]] && printf 'sha256:%064d\n' 1
    exit 0
    ;;
esac
case "$1" in
  build)
    previous=""
    for word in "$@"; do
      [[ "$previous" == "--iidfile" ]] && printf 'sha256:%064d\n' 2 > "$word"
      previous="$word"
    done
    exit 0
    ;;
  create) printf 'stub-container\n'; exit 0 ;;
  rm) exit 0 ;;
  cp)
    if [[ "$2" == *"/." ]]; then
      mkdir -p "$3"
      printf '[read]\n/usr\n' > "$3/BaseLanguage-c-gcc.cfg"
      printf '#!/bin/bash\n' > "$3/phobos.sh"
    else
      printf '# grants nothing\n' > "$3"
    fi
    exit 0
    ;;
  run)
    step=""
    previous=""
    for word in "$@"; do
      [[ "$previous" == */submissions.py ]] && step="$word"
      previous="$word"
    done
    if [[ "$*" == *submissions.py* ]]; then
      variable="STUB_STEP_${step//-/_}"
      variable="${variable^^}"
      run="$(target_of /srv/run "$@")"
      case "$step" in
        seal) printf '{}\n' > "${run}/seal/manifest.json" ;;
        union)
          printf '[read]\n/srv\n' > "${run}/union/candidate.cfg"
          printf '1\t2\tread\t/srv/extra\n2\t2\tread\t/srv/common\n2\t2\tlimits\ttimeout=0\n' > "${run}/union/rows.tsv"
          ;;
      esac
      exit "${!variable:-0}"
    fi
    if [[ "$*" == *"--verify-policy"* ]]; then
      exit "${STUB_VERIFY:-0}"
    fi
    if [[ "$*" == *main.py* ]]; then
      output="$(target_of /var/tmp/path_sets "$@")"
      name="${output##*/}"
      variable="STUB_PRUNE_${name//-/_}"
      variable="${variable^^}"
      status="${!variable:-0}"
      [[ "$status" == 0 ]] && printf '[read]\n/srv\n' > "${output}/c-gcc_${name}.cfg"
      [[ "$status" == 1 ]] && printf '{}\n' > "${output}/c-gcc_${name}.aborted.json"
      exit "$status"
    fi
    exit "${STUB_LAYERS:-0}"
    ;;
esac
exit 0
STUB
chmod +x "${STUBS}/docker"

# The stand-in dialog: records its arguments, one line per box, and answers with the status and the
# text of the plan's line for that box, "status|answer", the text on the descriptor named by
# --output-fd. A box without a line is answered with Esc.
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
DIALOG_LOG="${WORK}/dialog.log"
DIALOG_PLAN="${WORK}/dialog.plan"

# Copies the fixture into a fresh directory, with a prune.json naming the key c-gcc, and sets FRESH to it.
fresh() {
  FRESH="${WORK}/case-$((++CASES))"
  mkdir -p "${FRESH}/out"
  cp -R "${FIXTURE}/." "${FRESH}/"
  printf '{"key": "c-gcc"}\n' > "${FRESH}/template/prune.json"
}
CASES=0

# Runs phobos-cli.sh with the words given from the suite's working directory, with the stand-in docker
# first on PATH and the environment given before the words as NAME=value, and keeps what it printed and
# its status in OUT, ERR and STATUS.
cli() {
  local -a environment=()
  while [[ "${1:-}" == *=* && "${1:-}" != --* ]]; do
    environment+=("$1")
    shift
  done
  : > "${LOG}"
  OUT="$(cd "${WORK}/cwd" && env STUB_LOG="${LOG}" PATH="${STUBS}:/usr/bin:/bin" "${environment[@]}" bash "${CLI}" "$@" 2> "${WORK}/err")"
  STATUS=$?
  ERR="$(cat "${WORK}/err")"
}

# The call of submissions on the fresh copy, with the declaration, and the words given after it.
submissions() {
  local -a environment=()
  while [[ "${1:-}" == *=* && "${1:-}" != --* ]]; do
    environment+=("$1")
    shift
  done
  cli "${environment[@]}" submissions --template "${FRESH}/template" --submissions "${FRESH}/submissions" \
    --output "${FRESH}/out" --assignment-is-student-code "$@"
}

# Sets RUN to the one run directory beneath the fresh copy's output.
the_run() {
  RUN="$(find "${FRESH}/out" -mindepth 1 -maxdepth 1 -name 'submissions-run.*' | head -1)"
}

# Checks that a call ended with the status $2 and made no container. Takes the name of the check.
expect_refused() {
  check "$1" "$2" "${STATUS}"
  if grep -q '^run ' "${LOG}"; then bad "$1 starts no container" "$(cat "${LOG}")"; else ok "$1 starts no container"; fi
}

echo "== the option contract"
fresh
cli submissions --template "${FRESH}/template" --submissions "${FRESH}/submissions" --output "${FRESH}/out"
expect_refused "without the declaration about the assignment directory the call is refused" "${PHB_EXIT_USAGE}"
if grep -q 'assignment-is-student-code' <<<"${ERR}"; then ok "and says which declaration is missing"; else bad "and says which declaration is missing" "${ERR}"; fi
cli submissions --template "${FRESH}/template" --assignment-is-student-code
expect_refused "a call without --submissions and --output is refused" "${PHB_EXIT_USAGE}"
submissions --no-restriction
expect_refused "a switch that turns a layer off is refused" "${PHB_EXIT_USAGE}"
submissions --privileged
expect_refused "an option not listed is refused" "${PHB_EXIT_USAGE}"
submissions --submission "../beta"
expect_refused "a submission named by a path is refused" "${PHB_EXIT_USAGE}"
submissions --submission "delta"
expect_refused "a submission that is not there is refused" "${PHB_EXIT_USAGE}"
cli submissions --template "${FRESH}/template" --submissions "${FRESH}/submissions" --output "${FRESH}/submissions/alpha" --assignment-is-student-code
expect_refused "an output directory inside the submissions is refused" "${PHB_EXIT_USAGE}"
cli submissions --template "${FRESH}/template" --submissions "${FRESH}/template/assignment" --output "${FRESH}/out" --assignment-is-student-code
expect_refused "submissions inside the template are refused" "${PHB_EXIT_USAGE}"

echo "== the template"
fresh
ln -s ../build_script.sh "${FRESH}/template/assignment/run.sh"
submissions
expect_refused "a template holding a link is refused" "${PHB_EXIT_USAGE}"
fresh
rm "${FRESH}/template/prune.json"
submissions
expect_refused "a template without prune.json is refused" "${PHB_EXIT_USAGE}"
fresh
printf '{"key": "c-gcc", "seed": {"key": "python"}}\n' > "${FRESH}/template/prune.json"
submissions
expect_refused "a prune.json naming two keys is refused" "${PHB_EXIT_USAGE}"
fresh
printf '{}\n' > "${FRESH}/template/prune.json"
submissions
expect_refused "a prune.json naming no key is refused" "${PHB_EXIT_USAGE}"
fresh
printf '{"key": "java-egress"}\n' > "${FRESH}/template/prune.json"
submissions
expect_refused "a key no policy from submissions is pruned for is refused" "${PHB_EXIT_USAGE}"
fresh
rm -r "${FRESH}/template/assignment"
submissions
expect_refused "a template without an assignment directory is refused" "${PHB_EXIT_USAGE}"
fresh
submissions STUB_STEP_CHECK_TEMPLATE=4
check "a template the container check refuses ends the call as a failed step" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q 'main.py' "${LOG}"; then bad "and no submission is pruned" "$(cat "${LOG}")"; else ok "and no submission is pruned"; fi

echo "== a dry run and a missing image"
fresh
submissions --dry-run
check "--dry-run after the command is not an option of it" "${PHB_EXIT_USAGE}" "${STATUS}"
cli --dry-run submissions --template "${FRESH}/template" --submissions "${FRESH}/submissions" --output "${FRESH}/out" --assignment-is-student-code
check "a dry run ends with 0" 0 "${STATUS}"
check "and writes nothing" "" "$(find "${FRESH}/out" -mindepth 1)"
check "and calls no docker" "" "$(cat "${LOG}")"
if grep -qx 'COMMAND' <<<"${OUT}" && grep -qx 'build' <<<"${OUT}"; then ok "it prints the build of the prune image"; else bad "it prints the build of the prune image" "${OUT}"; fi
submissions STUB_IMAGE_MISSING=1
check "without the run-phase image the call cannot start" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q 'phobos-cli.sh build c-gcc' <<<"${ERR}"; then ok "and says how to build it"; else bad "and says how to build it" "${ERR}"; fi

echo "== a run"
fresh
before="$(cd "${FRESH}" && find submissions template -type f -exec cksum {} + | sort)"
submissions
check "a run whose every step succeeds ends with 0" 0 "${STATUS}"
the_run
if [[ -n "${RUN}" && -f "${RUN}/policy.cfg" ]]; then ok "and writes the verified policy into its run directory"; else bad "and writes the verified policy into its run directory" "$(find "${FRESH}/out")"; fi
check "the submissions and the template are left as they were" "${before}" "$(cd "${FRESH}" && find submissions template -type f -exec cksum {} + | sort)"
check "every submission is staged under its name" "alpha beta gamma" "$(ls "${RUN}/staging" | tr '\n' ' ' | sed 's/ $//')"
if [[ -f "${RUN}/staging/alpha/submissions/alpha/assignment/solution.sh" && ! -e "${RUN}/staging/alpha/submissions/alpha/assignment/README.md" ]]; then
  ok "a submission replaces the template's assignment"
else
  bad "a submission replaces the template's assignment" "$(find "${RUN}/staging/alpha")"
fi
if cmp -s "${FRESH}/template/build_script.sh" "${RUN}/staging/alpha/submissions/alpha/build_script.sh"; then ok "and the template's build script stays its own"; else bad "and the template's build script stays its own"; fi
check "three prunes, one per submission" 3 "$(grep -c 'main.py --stage all c-gcc$' "${LOG}")"
check "three verifications" 3 "$(grep -c -- '--verify-policy' "${LOG}")"
check "three starts of the layers, one per submission" 3 "$(grep -c '/var/tmp/opt/core/phobos.sh' "${LOG}")"
order="$(sed -n 's/.*submissions\.py \([a-z-]*\).*/\1/p' "${LOG}" | tr '\n' ' ')"
check "the container steps in their order" "check-template seal union batch validate verify-report " "${order}"
starts="$(grep '/var/tmp/opt/core/phobos.sh' "${LOG}")"
if grep -v -- '--config /[^ ]*/1/policy.cfg ' <<<"${starts}" | grep -q .; then bad "the layers start under the batch's copy of the candidate" "${starts}"; else ok "the layers start under the batch's copy of the candidate"; fi
runs="$(grep '^run ' "${LOG}" | grep -v '/var/tmp/opt/core/phobos.sh')"
if grep -v -- '--network none --memory 3g --pids-limit 1024 --entrypoint python3' <<<"${runs}" | grep -q .; then bad "every container of the pruner has no network and the limits" "${runs}"; else ok "every container of the pruner has no network and the limits"; fi
if grep -qE -- '--privileged|--cap-add|--security-opt|docker\.sock|--network host|--pid[ =]|--device|--userns|--ipc' "${LOG}"; then bad "no container gets a privilege" "$(cat "${LOG}")"; else ok "no container gets a privilege"; fi
prunes="$(grep 'main.py --stage all' "${LOG}")"
if grep -v "source=${RUN}/staging/[a-z]*,target=/srv/phobos-prune-exercises,readonly" <<<"${prunes}" | grep -q .; then bad "a prune mounts only its own staging, read-only" "${prunes}"; else ok "a prune mounts only its own staging, read-only"; fi
if grep -c -- '--mount' <<<"$(grep 'main.py --stage all c-gcc$' "${LOG}" | head -1)" > /dev/null && [[ "$(grep 'main.py --stage all c-gcc$' "${LOG}" | head -1 | grep -o -- '--mount' | wc -l | tr -d ' ')" == 3 ]]; then
  ok "and nothing but the helpers, its staging and its own output"
else
  bad "and nothing but the helpers, its staging and its own output" "$(grep 'main.py --stage all' "${LOG}" | head -1)"
fi
if grep 'submissions.py seal' "${LOG}" | grep -q "source=${RUN},target=/srv/run,readonly"; then ok "the seal reads the run read-only"; else bad "the seal reads the run read-only" "$(grep 'submissions.py seal' "${LOG}")"; fi

for verify in "" --no-verify; do
  fresh
  submissions STUB_STEP_VALIDATE=4 ${verify:+"$verify"}
  check "a seal that no longer holds after the layers started ends the call${verify:+ with ${verify}}" "${PHB_ERUNTIME}" "${STATUS}"
  if grep -q -- '--verify-policy' "${LOG}"; then bad "and nothing is verified${verify:+ with ${verify}}" "$(cat "${LOG}")"; else ok "and nothing is verified${verify:+ with ${verify}}"; fi
done

echo "== names and exclusions"
fresh
mkdir -p "${FRESH}/submissions/Alice Smith" "${FRESH}/submissions/alice-smith" "${FRESH}/submissions/!!!" "${FRESH}/submissions/.hidden"
printf 'true\n' > "${FRESH}/submissions/Alice Smith/solution.sh"
printf 'true\n' > "${FRESH}/submissions/alice-smith/solution.sh"
printf 'true\n' > "${FRESH}/submissions/!!!/solution.sh"
ln -s /etc/passwd "${FRESH}/submissions/beta/passwd"
ln -s "${FRESH}/submissions/alpha" "${FRESH}/submissions/linked"
submissions --no-verify
check "a run with exclusions ends with 0" 0 "${STATUS}"
the_run
staged="$(ls "${RUN}/staging" | tr '\n' ' ' | sed 's/ $//')"
check "names are made of lower-case letters, digits and hyphens, and unique" "alice-smith alice-smith-2 alpha gamma submission" "${staged}"
check "a submission holding a link is excluded with its reason" "it holds a link or a special file" "$(cat "${RUN}/excluded/beta" 2> /dev/null)"
if [[ -f "${RUN}/excluded/linked" ]]; then ok "a submission that is a link is excluded"; else bad "a submission that is a link is excluded" "$(ls "${RUN}/excluded")"; fi
if grep -q 'hidden' <<<"$(ls "${RUN}/sources")"; then bad "a hidden directory is no submission" "$(ls "${RUN}/sources")"; else ok "a hidden directory is no submission"; fi
check "the original name is kept beside the staged one" "Alice Smith" "$(cat "${RUN}/sources/alice-smith" 2> /dev/null)"
if grep -q -- '--verify-policy' "${LOG}"; then bad "--no-verify verifies nothing" "$(cat "${LOG}")"; else ok "--no-verify verifies nothing"; fi
if [[ -e "${RUN}/policy.cfg" ]]; then bad "and writes no verified policy" "${RUN}/policy.cfg"; else ok "and writes no verified policy"; fi
fresh
submissions --submission alpha --submission gamma --no-verify
the_run
check "--submission stages only the submissions named" "alpha gamma" "$(ls "${RUN}/staging" | tr '\n' ' ' | sed 's/ $//')"

echo "== the status of each step"
fresh
submissions STUB_PRUNE_BETA=1
check "a prune that aborted is classified, not a failure" 0 "${STATUS}"
fresh
submissions STUB_PRUNE_BETA=137
check "a prune that ended otherwise ends the call" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q 'submissions.py seal' "${LOG}"; then bad "and nothing is sealed" "$(cat "${LOG}")"; else ok "and nothing is sealed"; fi
for step in seal union batch; do
  fresh
  submissions "STUB_STEP_${step^^}=4"
  check "a refused ${step} ends the call" "${PHB_ERUNTIME}" "${STATUS}"
done
fresh
submissions STUB_LAYERS=125
check "layers that do not start under the candidate end the call" "${PHB_ERUNTIME}" "${STATUS}"
if grep -q -- '--verify-policy' "${LOG}"; then bad "and nothing is verified" "$(cat "${LOG}")"; else ok "and nothing is verified"; fi
fresh
submissions STUB_STEP_VERIFY_REPORT=3
check "a verification that did not match ends with 1" 1 "${STATUS}"
the_run
if [[ -e "${RUN}/policy.cfg" ]]; then bad "and writes no verified policy" "${RUN}/policy.cfg"; else ok "and writes no verified policy"; fi
if grep -q 'did not match its reference' <<<"${ERR}"; then ok "and says so"; else bad "and says so" "${ERR}"; fi
fresh
submissions STUB_STEP_VERIFY_REPORT=4
check "a verification that failed otherwise ends the call as a failed step" "${PHB_ERUNTIME}" "${STATUS}"
fresh
submissions STUB_STEP_VERIFY_REPORT=1
check "a verification report that ended with an uncaught exception ends the call as a failed step" "${PHB_ERUNTIME}" "${STATUS}"
the_run
if [[ -e "${RUN}/policy.cfg" ]]; then bad "and writes no verified policy either" "${RUN}/policy.cfg"; else ok "and writes no verified policy either"; fi

echo "== verifying an edited policy"
fresh
submissions --no-verify
the_run
printf '[read]\n/srv\n' > "${FRESH}/edited.cfg"
cli submissions verify --run "${RUN}" --policy "${FRESH}/edited.cfg"
check "an edited policy verified against the run ends with 0" 0 "${STATUS}"
order="$(sed -n 's/.*submissions\.py \([a-z-]*\).*/\1/p' "${LOG}" | tr '\n' ' ')"
check "after the seal is checked again, and again once the layers started" "validate batch validate verify-report " "${order}"
starts="$(grep '/var/tmp/opt/core/phobos.sh' "${LOG}")"
if [[ -n "${starts}" ]] && ! grep -v -- '--config /[^ ]*/1/policy.cfg ' <<<"${starts}" | grep -q .; then ok "the layers start under the batch's copy of the edited policy"; else bad "the layers start under the batch's copy of the edited policy" "${starts}"; fi
if grep -q "submissions.py validate /srv/run c-gcc .* sha256:0*1 sha256:0*2\$" "${LOG}"; then ok "with the images the run recorded"; else bad "with the images the run recorded" "$(grep 'submissions.py validate' "${LOG}")"; fi
if cmp -s "${RUN}/verified-2.cfg" "${RUN}/verify-2/policy.cfg"; then ok "and the verified copy is kept in the run, numbered as its batch after the one of the layer-start check"; else bad "and the verified copy is kept in the run, numbered as its batch after the one of the layer-start check" "$(ls "${RUN}")"; fi
cli submissions verify --run "${RUN}" --policy "${FRESH}/edited.cfg" --layers-only
check "--layers-only ends with 0 when the layers start" 0 "${STATUS}"
if grep -q -- '--verify-policy' "${LOG}"; then bad "and verifies nothing" "$(cat "${LOG}")"; else ok "and verifies nothing"; fi
cli STUB_STEP_VALIDATE=4 submissions verify --run "${RUN}" --policy "${FRESH}/edited.cfg"
check "a run whose seal no longer holds is refused" "${PHB_ERUNTIME}" "${STATUS}"
cli submissions verify --run "${FRESH}/out" --policy "${FRESH}/edited.cfg"
expect_refused "a directory that is no run is refused" "${PHB_EXIT_USAGE}"
ln -s "${FRESH}/edited.cfg" "${FRESH}/edited.link"
cli submissions verify --run "${RUN}" --policy "${FRESH}/edited.link"
expect_refused "a policy given through a link is refused" "${PHB_EXIT_USAGE}"


echo "== the way through the menu"
# Runs the menu under a pseudo-terminal with the stand-in dialog answering the plan given, one
# argument per box, and the environment given before -- as NAME=value. Takes the environment, the
# global options of the menu, then --, then the plan.
menu() {
  local -a environment=()
  local -a options=()
  local command
  while [[ "$1" != "--" && "$1" == *=* ]]; do
    environment+=("$1")
    shift
  done
  while [[ "$1" != "--" ]]; do
    options+=("$1")
    shift
  done
  shift
  : > "${LOG}"
  : > "${DIALOG_LOG}"
  printf '%s\n' "$@" > "${DIALOG_PLAN}"
  command="cd $(printf '%q' "${WORK}/cwd") && exec env STUB_LOG=$(printf '%q' "${LOG}") STUB_DIALOG_LOG=$(printf '%q' "${DIALOG_LOG}") STUB_DIALOG_PLAN=$(printf '%q' "${DIALOG_PLAN}")"
  (( ${#environment[@]} > 0 )) && command+=" $(printf '%q ' "${environment[@]}")"
  command+=" PATH=$(printf '%q' "${STUBS}:/usr/bin:/bin") TERM=xterm bash $(printf '%q ' "${CLI}" "${options[@]}")"
  OUT="$(SHELL=/bin/bash script -qec "${command}" /dev/null < /dev/null | tr -d '\r')"
  STATUS="${PIPESTATUS[0]}"
}

# Sets QUESTIONS to the answers that lead through the questions of the way to its call, for the fresh
# copy: every submission chosen, the declaration made, verification wanted.
questions() {
  QUESTIONS=("0|" "0|4" "0|" "0|${FRESH}/template" "0|${FRESH}/submissions" "0|1\n2\n3" "0|" "0|${FRESH}/out" "0|" "0|")
}

# Whether the dialog log holds a line that contains $1.
asked() {
  grep -qF -- "$1" "${DIALOG_LOG}"
}

if ! command -v script > /dev/null 2>&1; then
  skip "the way through the menu" "script(1) from util-linux is not installed, and the menu needs a terminal"
elif [[ -e /var/tmp/opt/core ]]; then
  skip "the way through the menu" "/var/tmp/opt/core exists, so this is an image, where the way is not offered"
else
  fresh
  questions
  menu --dry-run -- "${QUESTIONS[@]}"
  check "a dry run through the menu ends with 0" 0 "${STATUS}"
  if grep -qF -- "submissions --template ${FRESH}/template --submissions ${FRESH}/submissions --output ${FRESH}/out --submission alpha --submission beta --submission gamma --assignment-is-student-code" <<<"${OUT}"; then
    ok "it makes the call its answers make, naming every submission chosen"
  else
    bad "it makes the call its answers make, naming every submission chosen" "${OUT}"
  fi
  check "and writes nothing" "" "$(find "${FRESH}/out" -mindepth 1)"
  if asked 'never untrusted ones' && grep -q -- '--defaultno' "${DIALOG_LOG}"; then ok "it warns first, with No as the default answer"; else bad "it warns first, with No as the default answer" "$(cat "${DIALOG_LOG}")"; fi
  menu --dry-run -- "0|" "0|4" "1|" "5|"
  if grep -q 'submissions --template' <<<"${OUT}"; then bad "declining the warning starts nothing" "${OUT}"; else ok "declining the warning starts nothing"; fi
  menu --dry-run -- "0|" "0|4" "0|" "0|${FRESH}/template" "0|${FRESH}/submissions" "0|" "5|" "5|" "5|" "5|" "5|"
  if asked 'Choose at least one submission'; then ok "an empty choice of submissions is asked for again"; else bad "an empty choice of submissions is asked for again" "$(cat "${DIALOG_LOG}")"; fi
  menu --dry-run -- "0|" "0|4" "0|" "0|${FRESH}/template" "0|${FRESH}/submissions" "0|1" "1|" "0|" "5|" "5|" "5|" "5|" "5|" "5|"
  if asked 'refuses the template'; then ok "without the declaration about the assignment directory nothing goes on"; else bad "without the declaration about the assignment directory nothing goes on" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q 'submissions --template' <<<"${OUT}"; then bad "and nothing starts" "${OUT}"; else ok "and nothing starts"; fi

  fresh
  questions
  menu -- "${QUESTIONS[@]}" "0|1\n2\n3" "0|" "0|${FRESH}/template/inside.cfg" "0|" "0|${FRESH}/saved.cfg" "1|"
  check "a run through the menu, the rows chosen, verified and saved, ends with 0" 0 "${STATUS}"
  check "the saved policy holds the rows chosen, in the order of a policy file" $'[read]\n/srv/extra\n/srv/common\n[limits]\ntimeout=0\nx' "$(cat "${FRESH}/saved.cfg" 2> /dev/null; printf x)"
  if asked 'switches these limits off for every run under this policy: timeout'; then ok "a limit of 0 among the rows needs a separate Yes"; else bad "a limit of 0 among the rows needs a separate Yes" "$(cat "${DIALOG_LOG}")"; fi
  if asked 'inside '"${FRESH}"'/template'; then ok "the policy is never saved inside the template"; else bad "the policy is never saved inside the template" "$(cat "${DIALOG_LOG}")"; fi
  if grep -q 'submissions.py validate' "${LOG}" && [[ "$(grep -c 'submissions.py verify-report' "${LOG}")" == 2 ]]; then ok "the rows chosen are verified against the sealed run"; else bad "the rows chosen are verified against the sealed run" "$(cat "${LOG}")"; fi

  fresh
  questions
  menu STUB_STEP_VERIFY_REPORT=3 -- "${QUESTIONS[@]}" "0|" "0|1\n2" "0|" "0|${FRESH}/kept.cfg" "1|"
  check "rows kept although a submission did not match end the menu with 1" 1 "${STATUS}"
  if asked 'did not match its reference. Keep them'; then ok "after a question"; else bad "after a question" "$(cat "${DIALOG_LOG}")"; fi
  check "and they are saved" $'[read]\n/srv/extra\n/srv/common\nx' "$(cat "${FRESH}/kept.cfg" 2> /dev/null; printf x)"

  fresh
  questions
  menu STUB_STEP_SEAL=4 -- "${QUESTIONS[@]}"
  check "a run that fails ends the menu with its status" "${PHB_ERUNTIME}" "${STATUS}"
  if asked '[read] /srv/extra'; then bad "and offers no rows" "$(cat "${DIALOG_LOG}")"; else ok "and offers no rows"; fi
fi

finish
