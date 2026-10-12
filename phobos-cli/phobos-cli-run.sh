#!/bin/bash
# shellcheck shell=bash
# The command run: a command under phobos.sh, in the image or through docker run on a host.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, whose places, state
# and helpers it uses. It starts nothing while it is sourced.

# Copies the configuration $1 into the private staging directory as number $STAGED_COUNT, and sets
# REPLY to the path the container sees it under. Content only (cp of a file, not a link), so that no
# writable alias of it can exist; the directory is made on first use and removed on exit. In a dry
# run nothing is copied and REPLY names the place a copy would have.
stage_configuration() {
  local source="$1"
  local base="${source##*/}"
  mount_safe "$base" || fail_usage "--config: the file name '$base' holds a comma, a colon or a newline"
  STAGED_COUNT=$((STAGED_COUNT + 1))
  REPLY="${CONTAINER_CONFIG}/${STAGED_COUNT}/${base}"
  [[ "$DRY_RUN" == "yes" ]] && return 0
  if [[ -z "$STAGING" ]]; then
    STAGING="$(mktemp -d "${TMPDIR:-/tmp}/phobos-cli.XXXXXXXX")"
    trap cleanup_staging EXIT
    chmod 0700 "$STAGING"
    STAGING="$(cd -- "$STAGING" && pwd -P)"
    if [[ "$STAGING" == "$EXERCISE_PHYSICAL" || "$STAGING" == "${EXERCISE_PHYSICAL}/"* || "$EXERCISE_PHYSICAL" == "${STAGING}/"* ]]; then
      fail_environment "the staging directory ${STAGING} and the exercise ${EXERCISE_PHYSICAL} lie in one another, so the exercise could write the configurations; point TMPDIR elsewhere"
    fi
    mount_safe "$STAGING" || fail_environment "the staging directory ${STAGING} holds a comma, a colon or a newline, which a mount cannot carry; point TMPDIR elsewhere"
  fi
  mkdir -p -- "${STAGING}/${STAGED_COUNT}"
  cp -- "$source" "${STAGING}/${STAGED_COUNT}/${base}"
  chmod 0444 "${STAGING}/${STAGED_COUNT}/${base}"
}

# Sets REPLY to the directory $1 given to --project-root in a form phobos.sh in a container accepts.
# Image mode takes it as it is. A host takes it relative to the exercise $2 (a physical path), refuses
# an absolute one and any that leaves the exercise, and names it by the place the container sees.
translate_project_root() {
  local root="$1"
  local exercise="$2"
  local resolved
  if [[ "$MODE" == "image" ]]; then
    REPLY="$root"
    return 0
  fi
  [[ "$root" != /* ]] || fail_usage "--project-root is relative to --exercise on a host, not absolute"
  [[ "/${root}/" != */../* ]] || fail_usage "--project-root must stay inside the exercise"
  [[ -d "${exercise}/${root}" ]] || fail_usage "--project-root: '${root}' is not a directory of the exercise"
  resolved="$(cd -- "${exercise}/${root}" && pwd -P; printf x)"
  resolved="${resolved%x}"
  resolved="${resolved%$'\n'}"
  single_line "$resolved" || fail_usage "--project-root: the path of '${root}' holds a newline"
  [[ "$resolved" == "$exercise" || "$resolved" == "${exercise}/"* ]] || fail_usage "--project-root leaves the exercise"
  REPLY="${CONTAINER_EXERCISE}${resolved#"$exercise"}"
}

# The command run: parses its options, then hands phobos.sh (image) or docker run (host) the command.
# Takes the words after "run".
command_run() {
  local -a configs=()
  local -a words=()
  local language=""
  local image=""
  local exercise=""
  local network="${DEFAULT_NETWORK}"
  local memory="${DEFAULT_MEMORY}"
  local pids="${DEFAULT_PIDS_LIMIT}"
  local cpus=""
  local project_root=""
  local resolver=""
  local debug="no"
  local host_only=""
  local word
  while (( $# > 0 )); do
    case "$1" in
      --) shift; words=("$@"); break ;;
      --config | -c) need_value "$@"; configs+=("$2"); shift 2 ;;
      --project-root) need_value "$@"; project_root="$2"; shift 2 ;;
      --resolver) need_value "$@"; check_resolver "$2"; resolver="$2"; shift 2 ;;
      --debug | -d) debug="yes"; shift ;;
      --help | -h) help_text 1; exit 0 ;;
      --language) need_value "$@"; language="$2"; host_only="--language"; shift 2 ;;
      --image) need_value "$@"; check_image_name "$2"; image="$2"; host_only="--image"; shift 2 ;;
      --exercise) need_value "$@"; exercise="$2"; host_only="--exercise"; shift 2 ;;
      --network) need_value "$@"; check_network "$2"; network="$2"; host_only="--network"; shift 2 ;;
      --memory) need_value "$@"; check_memory "$2"; memory="$2"; host_only="--memory"; shift 2 ;;
      --pids-limit) need_value "$@"; positive_integer "$2" || fail_usage "--pids-limit takes a positive integer, not '$2'"; pids="$2"; host_only="--pids-limit"; shift 2 ;;
      --cpus) need_value "$@"; check_cpus "$2"; cpus="$2"; host_only="--cpus"; shift 2 ;;
      -*) refuse_option "$1" run ;;
      *) words=("$@"); break ;;
    esac
  done
  (( ${#words[@]} > 0 )) || fail_usage "run needs a command"
  for word in "${words[@]}"; do
    single_line "$word" || fail_usage "the command holds a newline in an argument"
  done
  [[ -z "$image" || -z "$language" ]] || fail_usage "--image and --language exclude each other"
  if [[ "$MODE" == "image" ]]; then
    [[ -z "$host_only" ]] || fail_usage "${host_only} belongs to a host; inside an image there is nothing to choose"
    run_in_image "${project_root}" "${resolver}" "${debug}" "${configs[@]}" -- "${words[@]}"
  else
    run_on_host "${project_root}" "${resolver}" "${debug}" "${language}" "${image}" "${exercise}" "${network}" "${memory}" "${pids}" "${cpus}" "${#configs[@]}" "${configs[@]}" "${words[@]}"
  fi
}

# Image mode of run: starts phobos.sh with the accepted options and the command. Takes the project
# root, the resolver, whether to debug, then the configurations, a --, and the command.
run_in_image() {
  local project_root="$1"
  local resolver="$2"
  local debug="$3"
  shift 3
  local -a argv=("${IMAGE_HOME}/phobos.sh")
  local config
  [[ -x "${IMAGE_HOME}/phobos.sh" ]] || fail_environment "${IMAGE_HOME}/phobos.sh is missing or not executable, so this is a broken image and not a host"
  while [[ "$1" != "--" ]]; do
    config="$1"
    [[ -f "$config" ]] || fail_usage "--config: '$config' is not a file of this image"
    argv+=(--config "$config")
    shift
  done
  shift
  [[ -z "$project_root" ]] || argv+=(--project-root "$project_root")
  [[ -z "$resolver" ]] || argv+=(--resolver "$resolver")
  [[ "$debug" == "no" ]] || argv+=(--debug)
  argv+=(-- "$@")
  hand_over "${argv[@]}"
}

# Host mode of run: stages the configurations, builds the docker run command and runs it. Takes the
# project root, the resolver, whether to debug, the language, the image, the exercise, the network, the
# memory, the pids limit, the cpus, the number of configurations, the configurations, and the command.
run_on_host() {
  local project_root="$1"
  local resolver="$2"
  local debug="$3"
  local language="$4"
  local image="$5"
  local exercise="$6"
  local network="$7"
  local memory="$8"
  local pids="$9"
  local cpus="${10}"
  local count="${11}"
  shift 11
  local -a configs=("${@:1:count}")
  shift "$count"
  local -a argv=(docker run --rm -i)
  local -a phobos=("${IMAGE_HOME}/phobos.sh")
  local config
  local physical
  local staged=0
  [[ -n "$exercise" ]] || fail_usage "run needs --exercise on a host"
  resolve_directory "$exercise" "--exercise"
  physical="$REPLY"
  refuse_socket_directory "$physical" "--exercise"
  EXERCISE_PHYSICAL="$physical"
  if [[ -z "$image" ]]; then
    image_of_language "${language:-java}"
    image="$IMAGE_NAME"
  fi
  require_docker
  for config in "${configs[@]}"; do
    [[ -f "$config" ]] || fail_usage "--config: '$config' is not a file"
    stage_configuration "$config"
    phobos+=(--config "$REPLY")
    staged=$((staged + 1))
  done
  if [[ -n "$project_root" ]]; then
    translate_project_root "$project_root" "$physical"
    phobos+=(--project-root "$REPLY")
  fi
  [[ -z "$resolver" ]] || phobos+=(--resolver "$resolver")
  [[ "$debug" == "no" ]] || phobos+=(--debug)
  [[ -t 0 && -t 1 ]] && argv+=(-t)
  argv+=(--network "$network" --memory "$memory" --pids-limit "$pids")
  [[ -z "$cpus" ]] || argv+=(--cpus "$cpus")
  argv+=(--mount "type=bind,source=${physical},target=${CONTAINER_EXERCISE}" --workdir "${CONTAINER_EXERCISE}")
  if (( staged > 0 )); then
    if [[ "$DRY_RUN" == "yes" ]]; then
      argv+=(--mount "type=bind,source=<staging>,target=${CONTAINER_CONFIG},readonly")
    else
      argv+=(--mount "type=bind,source=${STAGING},target=${CONTAINER_CONFIG},readonly")
    fi
  fi
  argv+=("$image" "${phobos[@]}" -- "$@")
  step "${argv[@]}"
}
