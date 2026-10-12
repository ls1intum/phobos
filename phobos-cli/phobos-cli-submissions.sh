#!/bin/bash
# shellcheck shell=bash
# The command submissions: a policy for an exercise from past student submissions, on a host.
#
# Each submission is staged over the exercise's template, pruned by the layer pruner in a fresh
# container of its own, and the policies are merged into one candidate beside the grading bases of
# the run-phase image, which every submission is then verified against. The pruner runs a
# submission's baseline without Phobos, so a submission can shape its own result: this command rests
# on the instructor's assumption that the submissions are vetted and harmless, and is no defence
# against a malicious one. What it does guarantee is that a submission cannot directly change the
# template, the helpers of the pruner, the extracted grading bases, another submission's input or
# artefacts, or any host file outside its own output directory, and that nothing changes between the
# steps unnoticed: the steps that run no submission code seal every input by its digest and check it
# again before they use it.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, whose places, state
# and helpers it uses. It starts nothing while it is sourced.
# Several values set here are read only by other files of this folder, which the linter cannot follow
# when this file is checked on its own, so SC2034 fires on them by design.
# shellcheck disable=SC2034

# Where the steps that run in a container find the run, a staged exercise, a policy and the helpers.
SUBS_CONTAINER_RUN="/srv/run"
SUBS_CONTAINER_TEMPLATE="/srv/template"
SUBS_CONTAINER_EXERCISES="/srv/phobos-prune-exercises"
SUBS_CONTAINER_POLICY="/srv/phobos-policy/policy.cfg"
SUBS_CONTAINER_OUTPUT="/var/tmp/path_sets"
SUBS_STEPS="${IMAGE_HELPERS}/exercise_pruner/src/interface/submissions.py"
SUBS_PRUNER="${IMAGE_HELPERS}/exercise_pruner/src/interface/main.py"
# The limits of every container that runs a submission or the pruner, those of the compose services.
SUBS_MEMORY="3g"
SUBS_PIDS="1024"
# The statuses of the container steps: a refusal, and a verification that did not match. Neither is 1,
# the status Python ends with on an exception nothing caught.
SUBS_REFUSED=4
SUBS_MISMATCH=3
# The state of one call: the run directory, the key, the language, the images, the template.
SUBS_RUN=""
SUBS_KEY=""
SUBS_LANGUAGE=""
SUBS_RUN_PHASE=""
SUBS_PRUNE=""
SUBS_TEMPLATE=""
SUBS_CREATED=""
SUBS_OK=()
SUBS_SELECTED=()
SUBS_ARGV=()
# The folder of the last verification, beneath the run directory.
SUBS_FOLDER=""
# Its read-only copy of the policy, the one both the layer-start check and the verification read.
SUBS_POLICY=""

# Removes the container a base was copied out of, when one is left. Run on every exit of the command.
subs_cleanup() {
  if [[ -n "$SUBS_CREATED" ]]; then
    docker rm -f "$SUBS_CREATED" > /dev/null 2>&1 || true
  fi
}

# Sets REPLY to the first link, FIFO, socket or device beneath the directory $1, or to empty when it
# holds none. A link could lead a trusted file to student material, or student material outside its
# place, and a special file has no place in an exercise.
subs_odd_entry() {
  REPLY="$(find "$1" \( -type l -o -type p -o -type s -o -type b -o -type c \) -print -quit 2> /dev/null)"
  return 0
}

# Sets SUBS_KEY from the template's prune.json and SUBS_LANGUAGE from the key, and ends the call for a
# template that names no key, more than one, or one this command does not prune. The container
# check reads the file as JSON again; this reading only chooses the image.
subs_read_key() {
  local text
  local count
  text="$(cat -- "${SUBS_TEMPLATE}/prune.json")"
  count="$({ grep -o -E '"key"[[:space:]]*:' <<<"$text" || true; } | wc -l | tr -d ' ')"
  [[ "$count" == "1" && "$text" =~ \"key\"[[:space:]]*:[[:space:]]*\"([a-z0-9]+(-[a-z0-9]+)*)\" ]] \
    || fail_usage "--template: its prune.json must name exactly one key"
  SUBS_KEY="${BASH_REMATCH[1]}"
  subs_language
}

# Sets SUBS_LANGUAGE, the run-phase image's language, from SUBS_KEY, and ends the call for a key a
# policy from submissions is not pruned for.
subs_language() {
  case "$SUBS_KEY" in
    java-gradle | java-maven) SUBS_LANGUAGE="java" ;;
    python | c-fact | r | swift | c-gcc | cpp) SUBS_LANGUAGE="$SUBS_KEY" ;;
    *) fail_usage "the key ${SUBS_KEY} is not one a policy from submissions is pruned for" ;;
  esac
}

# Ends the call unless the template is one student material cannot reach the trusted part of: no
# link or special file anywhere, prune.json and a build script as regular files, an assignment
# directory. The container check adds what needs prune.json read as JSON.
subs_check_template_files() {
  subs_odd_entry "$SUBS_TEMPLATE"
  [[ -z "$REPLY" ]] || fail_usage "--template holds ${REPLY}, which is a link or a special file; a template holds neither"
  [[ -f "${SUBS_TEMPLATE}/prune.json" ]] || fail_usage "--template has no prune.json"
  [[ -f "${SUBS_TEMPLATE}/build_script.sh" || -f "${SUBS_TEMPLATE}/build_script" ]] || fail_usage "--template has no build script"
  [[ -d "${SUBS_TEMPLATE}/assignment" ]] || fail_usage "--template has no assignment directory"
}

# Sets REPLY to a name for the submission directory named $1 that the pruner can carry: lower-case
# letters and digits joined by single hyphens, made unique among the names already staged or excluded.
subs_name() {
  local name="${1,,}"
  local candidate
  local number=2
  name="${name//[^a-z0-9]/-}"
  while [[ "$name" == *--* ]]; do
    name="${name//--/-}"
  done
  name="${name#-}"
  name="${name%-}"
  [[ -n "$name" ]] || name="submission"
  candidate="$name"
  while [[ -e "${SUBS_RUN}/sources/${candidate}" ]]; do
    candidate="${name}-${number}"
    number=$((number + 1))
  done
  REPLY="$candidate"
}

# Stages the submission directory $1 over the template under the name $2, or excludes it with the
# reason, when it or its staged copy holds a link or a special file, or when its copy would change a
# trusted file of the template. Assumes the run directory is made and the template checked.
subs_stage() {
  local submission="$1"
  local name="$2"
  local target="${SUBS_RUN}/staging/${name}/submissions/${name}"
  local script
  printf '%s' "${submission##*/}" > "${SUBS_RUN}/sources/${name}"
  subs_odd_entry "$submission"
  if [[ -L "$submission" || -n "$REPLY" ]]; then
    printf 'it holds a link or a special file\n' > "${SUBS_RUN}/excluded/${name}"
    return 0
  fi
  mkdir -p -- "$target"
  cp -RP -- "${SUBS_TEMPLATE}/." "${target}/"
  [[ -d "${target}/assignment" && ! -L "${target}/assignment" ]] || fail_environment "the staged copy of the template lost its assignment directory"
  find "${target}/assignment" -mindepth 1 -delete
  cp -RP -- "${submission}/." "${target}/assignment/"
  subs_odd_entry "$target"
  for script in prune.json build_script.sh build_script; do
    [[ -e "${SUBS_TEMPLATE}/${script}" ]] || continue
    cmp -s -- "${SUBS_TEMPLATE}/${script}" "${target}/${script}" || REPLY="${target}/${script}"
  done
  if [[ -n "$REPLY" ]]; then
    rm -rf -- "${SUBS_RUN}/staging/${name}"
    printf 'its staged copy changed a trusted file or holds a link\n' > "${SUBS_RUN}/excluded/${name}"
  fi
  return 0
}

# Sets SUBS_ARGV to the start of every container call that runs the pruner or one of its steps: no
# network, the limits of the compose services, the helpers read-only, and for the Maven key the
# manifest of the pre-loaded repository read-only, where the compose service mounts it.
subs_container() {
  SUBS_ARGV=(docker run --rm --network none --memory "$SUBS_MEMORY" --pids-limit "$SUBS_PIDS" --entrypoint python3
    --mount "type=bind,source=${CHECKOUT_ROOT}/pruner,target=${IMAGE_HELPERS},readonly")
  if [[ "$SUBS_KEY" == "java-maven" ]]; then
    SUBS_ARGV+=(--mount "type=bind,source=${CHECKOUT_ROOT}/protecter/image/maven-repository.sha256,target=/srv/phobos-manifest/maven-repository.sha256,readonly")
  fi
  return 0
}

# Starts the command $@ as a child, passing a signal on to it, and sets REPLY to its status.
subs_run() {
  local status=0
  run_child "$@" || status=$?
  REPLY="$status"
  return 0
}

# Ends the call after a step that did not succeed, saying which and with what status. Takes the
# step's name and its status.
subs_failed() {
  fail_environment "the step ${1} of submissions ended with status ${2}; the run directory ${SUBS_RUN} keeps what was done"
}

# Runs the container step $1 of submissions.py, which runs no submission code, with the run directory
# read-only and its subdirectory $2 writable at its place, or nothing writable when $2 is empty, and
# the words after those as its operands. Sets REPLY to its status.
subs_step() {
  local step="$1"
  local writable="$2"
  local -a mounts=(--mount "type=bind,source=${SUBS_RUN},target=${SUBS_CONTAINER_RUN},readonly")
  shift 2
  if [[ -n "$writable" ]]; then
    mkdir -p -- "${SUBS_RUN}/${writable}"
    mounts+=(--mount "type=bind,source=${SUBS_RUN}/${writable},target=${SUBS_CONTAINER_RUN}/${writable}")
  fi
  subs_container
  subs_run "${SUBS_ARGV[@]}" "${mounts[@]}" "$SUBS_PRUNE" "$SUBS_STEPS" "$step" "$@"
}

# Sets SUBS_RUN_PHASE to the ID of the run-phase image of the language and builds the prune image on
# exactly that image, setting SUBS_PRUNE to its ID. The build reads the base by a tag of the run's own
# that names the ID, since a build reads an ID itself as the name of an image to pull. Both IDs are
# kept in the run directory, so that a later verification of the run uses the same images; the tag
# stays, so that the run-phase image it names is not removed when its own tag moves to a rebuild.
subs_images() {
  local pinned
  docker image inspect "phobos-run-phase-${SUBS_LANGUAGE}" > /dev/null 2>&1 \
    || fail_environment "the run-phase image phobos-run-phase-${SUBS_LANGUAGE} does not exist; build it first with phobos-cli.sh build ${SUBS_LANGUAGE}"
  SUBS_RUN_PHASE="$(docker image inspect --format '{{.Id}}' "phobos-run-phase-${SUBS_LANGUAGE}")"
  printf '%s\n' "$SUBS_RUN_PHASE" > "${SUBS_RUN}/run-phase-image.id"
  pinned="phobos-run-phase-submissions:${SUBS_RUN##*.}"
  docker tag "$SUBS_RUN_PHASE" "$pinned" || fail_environment "cannot tag ${SUBS_RUN_PHASE} as ${pinned}"
  subs_run docker build --quiet --iidfile "${SUBS_RUN}/prune-image.id" -f "${CHECKOUT_ROOT}/docker/pruner/layers/Dockerfile" \
    --build-arg "RUN_PHASE_IMAGE=${pinned}" -t "phobos-prune-layers-submissions:${SUBS_LANGUAGE}" "$CHECKOUT_ROOT"
  [[ "$REPLY" == "0" ]] || subs_failed "build of the prune image" "$REPLY"
  SUBS_PRUNE="$(cat "${SUBS_RUN}/prune-image.id")"
}

# Copies the grading bases out of the run-phase image into run/bases, and the prune image's own base
# into run/prune-base, each from a container that is created, never started, and removed again.
subs_bases() {
  local base
  SUBS_CREATED="$(docker create "$SUBS_RUN_PHASE" /bin/true)" || fail_environment "cannot create a container of ${SUBS_RUN_PHASE}"
  docker cp "${SUBS_CREATED}:${IMAGE_HOME}/." "${SUBS_RUN}/core" > /dev/null || fail_environment "cannot copy the installation out of ${SUBS_RUN_PHASE}"
  subs_cleanup
  for base in "${SUBS_RUN}"/core/Base*.cfg; do
    [[ -f "$base" && ! -L "$base" ]] && cp -- "$base" "${SUBS_RUN}/bases/"
  done
  rm -rf -- "${SUBS_RUN}/core"
  SUBS_CREATED="$(docker create "$SUBS_PRUNE" /bin/true)" || fail_environment "cannot create a container of ${SUBS_PRUNE}"
  docker cp "${SUBS_CREATED}:${IMAGE_HOME}/BasePrune.cfg" "${SUBS_RUN}/prune-base/BasePrune.cfg" > /dev/null \
    || fail_environment "cannot copy BasePrune.cfg out of ${SUBS_PRUNE}"
  subs_cleanup
  SUBS_CREATED=""
}

# Prunes every staged submission in a fresh container of its own: its staged exercise read-only, its
# own output directory writable, nothing else of the run. Keeps each status in run/results; a status
# other than 0 or 1 is no prune result and ends the call.
subs_prune_all() {
  local name
  local -a names=()
  mapfile -t names < <(find "${SUBS_RUN}/staging" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)
  (( ${#names[@]} > 0 )) || fail_environment "every submission was excluded; the run directory ${SUBS_RUN} says why"
  for name in "${names[@]}"; do
    printf 'phobos-cli.sh submissions: pruning %s\n' "$name" >&2
    mkdir -p -- "${SUBS_RUN}/output/${name}"
    subs_container
    subs_run "${SUBS_ARGV[@]}" \
      --mount "type=bind,source=${SUBS_RUN}/staging/${name},target=${SUBS_CONTAINER_EXERCISES},readonly" \
      --mount "type=bind,source=${SUBS_RUN}/output/${name},target=${SUBS_CONTAINER_OUTPUT}" \
      "$SUBS_PRUNE" "$SUBS_PRUNER" --stage all "$SUBS_KEY"
    [[ "$REPLY" == "0" || "$REPLY" == "1" ]] || subs_failed "prune of ${name}" "$REPLY"
    printf '%s\n' "$REPLY" > "${SUBS_RUN}/results/${name}"
  done
}

# Sets SUBS_OK to the submissions whose prune succeeded, from their results, and ends the call when
# there is none. Assumes the seal or its check has just found each result to be the one sealed.
subs_ok_names() {
  local result
  SUBS_OK=()
  for result in "${SUBS_RUN}"/results/*; do
    [[ -f "$result" && "$(cat "$result")" == "0" ]] && SUBS_OK+=("${result##*/}")
  done
  (( ${#SUBS_OK[@]} > 0 )) || fail_environment "the run directory ${SUBS_RUN} records no pruned submission"
  return 0
}

# Runs /bin/true under the policy $1 with each pruned submission's staged exercise as the working
# directory, through phobos-cli.sh run on the run-phase image: the policy system reads the policy beside
# the grading bases, the filesystem layer builds its rules and checks their hierarchy, and every layer
# starts. Ends the call when it fails for any submission.
subs_layers_start() {
  local name
  for name in "${SUBS_OK[@]}"; do
    subs_run "$BASH" "${HERE}/phobos-cli.sh" run --image "$SUBS_RUN_PHASE" \
      --exercise "${SUBS_RUN}/staging/${name}/submissions/${name}" --config "$1" -- /bin/true
    [[ "$REPLY" == "0" ]] || subs_failed "start of the layers under the policy for ${name}" "$REPLY"
  done
}

# Copies the policy $1 into a fresh run/verify-<n>/policy.cfg, read-only, and has the batch step fix
# its digest, the bases a verification must find and the helpers, so that the layer-start check and
# the verification both read that copy. Sets SUBS_FOLDER to verify-<n> and SUBS_POLICY to the copy.
subs_batch() {
  local number=1
  while [[ -e "${SUBS_RUN}/verify-${number}" ]]; do
    number=$((number + 1))
  done
  SUBS_FOLDER="verify-${number}"
  SUBS_POLICY="${SUBS_RUN}/${SUBS_FOLDER}/policy.cfg"
  mkdir -p -- "${SUBS_RUN}/${SUBS_FOLDER}/status" "${SUBS_RUN}/${SUBS_FOLDER}/records"
  cp -- "$1" "$SUBS_POLICY"
  chmod 0444 "$SUBS_POLICY"
  subs_step batch "$SUBS_FOLDER" "$SUBS_CONTAINER_RUN" "${SUBS_CONTAINER_RUN}/${SUBS_FOLDER}" "$IMAGE_HELPERS"
  [[ "$REPLY" == "0" ]] || subs_failed "batch" "$REPLY"
}

# Ends the call unless the sealed run still holds as sealed, with the images recorded for it.
subs_validate() {
  subs_step validate "" "$SUBS_CONTAINER_RUN" "$SUBS_KEY" "$IMAGE_HELPERS" "$SUBS_RUN_PHASE" "$SUBS_PRUNE"
  [[ "$REPLY" == "0" ]] || subs_failed "check of the seal" "$REPLY"
}

# Verifies the policy copy of the batch SUBS_FOLDER against every pruned submission in a fresh
# container each, with the grading bases mounted beside phobos.sh. Sets REPLY to the status of
# verify-report: 0 when every submission matched its reference, SUBS_MISMATCH when some did not,
# anything else when a verification failed for another reason. Assumes subs_batch has run.
subs_verify() {
  local name
  local base
  local -a bases=()
  for base in "${SUBS_RUN}"/bases/*; do
    bases+=(--mount "type=bind,source=${base},target=${IMAGE_HOME}/${base##*/},readonly")
  done
  for name in "${SUBS_OK[@]}"; do
    printf 'phobos-cli.sh submissions: verifying %s\n' "$name" >&2
    mkdir -p -- "${SUBS_RUN}/${SUBS_FOLDER}/records/${name}"
    subs_container
    subs_run "${SUBS_ARGV[@]}" "${bases[@]}" \
      --mount "type=bind,source=${SUBS_RUN}/staging/${name},target=${SUBS_CONTAINER_EXERCISES},readonly" \
      --mount "type=bind,source=${SUBS_RUN}/${SUBS_FOLDER}/policy.cfg,target=${SUBS_CONTAINER_POLICY},readonly" \
      --mount "type=bind,source=${SUBS_RUN}/${SUBS_FOLDER}/records/${name},target=${SUBS_CONTAINER_OUTPUT}" \
      "$SUBS_PRUNE" "$SUBS_PRUNER" --verify-policy "$SUBS_CONTAINER_POLICY" "$SUBS_KEY"
    printf '%s\n' "$REPLY" > "${SUBS_RUN}/${SUBS_FOLDER}/status/${name}"
  done
  subs_step verify-report "$SUBS_FOLDER" "$SUBS_CONTAINER_RUN" "${SUBS_CONTAINER_RUN}/${SUBS_FOLDER}" "$SUBS_KEY" "$IMAGE_HELPERS"
}

# Ends the call with the outcome of a verification, from the status in REPLY: 0 and the verified
# policy copied to the file $1 when every submission matched, 1 when some did not, and a start
# failure otherwise. Assumes subs_verify has just run.
subs_finish_verification() {
  case "$REPLY" in
    0)
      cp -- "${SUBS_RUN}/${SUBS_FOLDER}/policy.cfg" "$1"
      chmod 0644 "$1"
      printf 'phobos-cli.sh submissions: verified against every pruned submission; the policy is %s\n' "$1" >&2
      exit 0
      ;;
    "$SUBS_MISMATCH")
      printf 'phobos-cli.sh submissions: the verification failed: a submission did not match its reference under the policy; see %s\n' "${SUBS_RUN}/${SUBS_FOLDER}/result.json" >&2
      exit 1
      ;;
    *) subs_failed "verification" "$REPLY" ;;
  esac
}

# Ends the call when the directories $1 and $2 (physical paths), given to the options $3 and $4, are
# one or lie in one another.
subs_distinct() {
  [[ "$1" != "$2" && "$1" != "$2/"* && "$2" != "$1/"* ]] || fail_usage "${3} and ${4} lie in one another"
  return 0
}

# Sets SUBS_SELECTED to the submission directories to stage: the direct children of the directory $1
# named by the words after it, or, when none is named, every child that is a directory or a link,
# leaving out the hidden ones. A link is listed so that its exclusion is reported.
subs_select() {
  local directory="$1"
  local name
  local entry
  shift
  SUBS_SELECTED=()
  for name in "$@"; do
    [[ -n "$name" && "$name" != */* && "$name" != "." && "$name" != ".." ]] || fail_usage "--submission takes the name of a directory directly in --submissions, not '${name}'"
    [[ -d "${directory}/${name}" || -L "${directory}/${name}" ]] || fail_usage "--submission: '${name}' is not a directory in ${directory}"
    SUBS_SELECTED+=("${directory}/${name}")
  done
  (( $# > 0 )) && return 0
  while IFS= read -r -d '' entry; do
    [[ "${entry##*/}" == .* ]] && continue
    SUBS_SELECTED+=("$entry")
  done < <(find "$directory" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -print0 | sort -z)
  return 0
}

# The command submissions: a policy from past student submissions, or with the word verify first, a
# further verification of a policy against a finished run. Takes the words after "submissions".
command_submissions() {
  local template=""
  local submissions=""
  local output=""
  local verify="yes"
  local declared="no"
  local -a names=()
  local directory
  if [[ "${1:-}" == "verify" ]]; then
    shift
    command_submissions_verify "$@"
    return 0
  fi
  while (( $# > 0 )); do
    case "$1" in
      --template) need_value "$@"; template="$2"; shift 2 ;;
      --submissions) need_value "$@"; submissions="$2"; shift 2 ;;
      --output) need_value "$@"; output="$2"; shift 2 ;;
      --submission) need_value "$@"; names+=("$2"); shift 2 ;;
      --no-verify) verify="no"; shift ;;
      --assignment-is-student-code) declared="yes"; shift ;;
      --help | -h) help_text 1; exit 0 ;;
      *) refuse_option "$1" submissions ;;
    esac
  done
  [[ "$MODE" == "host" ]] || fail_environment "submissions needs a host with Docker; there is no docker inside an image"
  [[ -n "$template" && -n "$submissions" && -n "$output" ]] || fail_usage "submissions needs --template, --submissions and --output"
  [[ "$declared" == "yes" ]] || fail_usage "submissions needs --assignment-is-student-code, the declaration that the template's assignment directory holds only student material the submissions replace"
  require_checkout submissions
  mount_safe "$CHECKOUT_ROOT" || fail_environment "the checkout's path ${CHECKOUT_ROOT} holds a comma, a colon or a newline, which a mount cannot carry"
  resolve_directory "$template" "--template"
  SUBS_TEMPLATE="$REPLY"
  resolve_directory "$submissions" "--submissions"
  submissions="$REPLY"
  resolve_directory "$output" "--output"
  output="$REPLY"
  refuse_socket_directory "$output" "--output"
  subs_distinct "$SUBS_TEMPLATE" "$submissions" --template --submissions
  subs_distinct "$output" "$SUBS_TEMPLATE" --output --template
  subs_distinct "$output" "$submissions" --output --submissions
  subs_check_template_files
  subs_read_key
  subs_select "$submissions" "${names[@]}"
  (( ${#SUBS_SELECTED[@]} > 0 )) || fail_usage "--submissions holds no submission directory"
  if [[ "$DRY_RUN" == "yes" ]]; then
    print_command docker build -f "${CHECKOUT_ROOT}/docker/pruner/layers/Dockerfile" --build-arg "RUN_PHASE_IMAGE=phobos-run-phase-${SUBS_LANGUAGE}" "$CHECKOUT_ROOT"
    printf 'phobos-cli.sh submissions: a dry run stops here, before the run directory would be made; %s submissions would be staged under the key %s\n' "${#SUBS_SELECTED[@]}" "$SUBS_KEY" >&2
    exit 0
  fi
  require_docker
  trap subs_cleanup EXIT
  SUBS_RUN="$(mktemp -d "${output}/submissions-run.XXXXXXXX")"
  mkdir -p -- "${SUBS_RUN}"/{bases,prune-base,staging,output,results,sources,excluded}
  printf '%s\n' "$SUBS_KEY" > "${SUBS_RUN}/key"
  printf 'phobos-cli.sh submissions: the run is in %s\n' "$SUBS_RUN" >&2
  subs_images
  subs_bases
  subs_container
  subs_run "${SUBS_ARGV[@]}" --mount "type=bind,source=${SUBS_TEMPLATE},target=${SUBS_CONTAINER_TEMPLATE},readonly" \
    "$SUBS_PRUNE" "$SUBS_STEPS" check-template "$SUBS_CONTAINER_TEMPLATE" "$SUBS_KEY"
  [[ "$REPLY" == "0" ]] || subs_failed "check of the template" "$REPLY"
  for directory in "${SUBS_SELECTED[@]}"; do
    subs_name "${directory##*/}"
    subs_stage "$directory" "$REPLY"
  done
  subs_prune_all
  subs_step seal seal "$SUBS_CONTAINER_RUN" "$SUBS_KEY" "$IMAGE_HELPERS" "$SUBS_RUN_PHASE" "$SUBS_PRUNE"
  [[ "$REPLY" == "0" ]] || subs_failed "seal" "$REPLY"
  subs_step union union "$SUBS_CONTAINER_RUN" "$SUBS_KEY" "$IMAGE_HELPERS"
  [[ "$REPLY" == "0" ]] || subs_failed "union" "$REPLY"
  subs_ok_names
  subs_batch "${SUBS_RUN}/union/candidate.cfg"
  subs_layers_start "$SUBS_POLICY"
  subs_validate
  if [[ "$verify" == "no" ]]; then
    printf 'phobos-cli.sh submissions: not verified; the layers start under the candidate %s\n' "${SUBS_RUN}/union/candidate.cfg" >&2
    exit 0
  fi
  subs_verify
  subs_finish_verification "${SUBS_RUN}/policy.cfg"
}

# The command submissions verify: checks the policy given against a finished run again, after the
# run's seal is checked: the layers start under it with every pruned submission, and unless
# --layers-only every pruned submission is verified under it. Takes the words after "verify".
command_submissions_verify() {
  local run=""
  local policy=""
  local layers_only="no"
  while (( $# > 0 )); do
    case "$1" in
      --run) need_value "$@"; run="$2"; shift 2 ;;
      --policy) need_value "$@"; policy="$2"; shift 2 ;;
      --layers-only) layers_only="yes"; shift ;;
      --help | -h) help_text 1; exit 0 ;;
      *) refuse_option "$1" "submissions verify" ;;
    esac
  done
  [[ "$MODE" == "host" ]] || fail_environment "submissions verify needs a host with Docker"
  [[ -n "$run" && -n "$policy" ]] || fail_usage "submissions verify needs --run and --policy"
  [[ -f "$policy" && ! -L "$policy" ]] || fail_usage "--policy: '${policy}' is not a regular file"
  require_checkout "submissions verify"
  resolve_directory "$run" "--run"
  SUBS_RUN="$REPLY"
  [[ -f "${SUBS_RUN}/key" && -f "${SUBS_RUN}/prune-image.id" && -f "${SUBS_RUN}/run-phase-image.id" && -f "${SUBS_RUN}/seal/manifest.json" ]] \
    || fail_usage "--run: ${SUBS_RUN} is not the directory of a finished submissions run"
  SUBS_KEY="$(cat "${SUBS_RUN}/key")"
  SUBS_PRUNE="$(cat "${SUBS_RUN}/prune-image.id")"
  SUBS_RUN_PHASE="$(cat "${SUBS_RUN}/run-phase-image.id")"
  [[ "$SUBS_KEY" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && "$SUBS_PRUNE" =~ ^sha256:[0-9a-f]{64}$ && "$SUBS_RUN_PHASE" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail_usage "--run: the key or the image IDs recorded in ${SUBS_RUN} are not of the form a run writes"
  subs_language
  if [[ "$DRY_RUN" == "yes" ]]; then
    printf 'phobos-cli.sh submissions verify: a dry run starts nothing; the policy would be checked against %s\n' "$SUBS_RUN" >&2
    exit 0
  fi
  require_docker
  subs_validate
  subs_ok_names
  subs_batch "$policy"
  subs_layers_start "$SUBS_POLICY"
  subs_validate
  if [[ "$layers_only" == "yes" ]]; then
    printf 'phobos-cli.sh submissions verify: the layers start under %s with every pruned submission; not verified\n' "$policy" >&2
    exit 0
  fi
  subs_verify
  subs_finish_verification "${SUBS_RUN}/verified-${SUBS_FOLDER#verify-}.cfg"
}
