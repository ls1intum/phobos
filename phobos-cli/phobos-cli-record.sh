#!/bin/bash
# shellcheck shell=bash
# The command record: the recording pruner, in the prune image or through Docker Compose on a host.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, whose places, state
# and helpers it uses. It starts nothing while it is sourced.
# The command record: the recording pruner. Takes the words after "record".
command_record() {
  local language="java"
  local exercise=""
  local networked="no"
  local host_only=""
  local word
  while (( $# > 0 )); do
    case "$1" in
      --language) need_value "$@"; language="$2"; host_only="--language"; shift 2 ;;
      --exercise) need_value "$@"; exercise="$2"; host_only="--exercise"; shift 2 ;;
      --networked) networked="yes"; host_only="--networked"; shift ;;
      --help | -h) help_text 1; exit 0 ;;
      --image) fail_usage "record takes no --image: --language decides which run-phase image it is built on" ;;
      record | generate | check | diff) break ;;
      *) refuse_option "$1" record ;;
    esac
  done
  (( $# > 0 )) || fail_usage "record needs a verb: record, generate, check or diff"
  for word in "$@"; do
    single_line "$word" || fail_usage "an argument holds a newline"
  done
  if [[ "$MODE" == "image" ]]; then
    [[ -z "$host_only" ]] || fail_usage "${host_only} belongs to a host; inside an image there is nothing to choose"
    require_helper "${IMAGE_HELPERS}/runtime_pruner/src/interface/phobos-record"
    hand_over "${IMAGE_HELPERS}/runtime_pruner/src/interface/phobos-record" "$@"
  else
    record_on_host "$language" "$exercise" "$networked" "$@"
  fi
}

# Host mode of record. Takes the language, the exercise (or empty), whether the networked service is
# wanted, then the verb and its arguments.
record_on_host() {
  local language="$1"
  local exercise="$2"
  local networked="$3"
  shift 3
  local service="record"
  local physical=""
  local -a pairs=()
  require_checkout record
  require_docker
  image_of_language "$language"
  pairs+=("RUN_PHASE_IMAGE=${IMAGE_NAME}")
  if [[ -n "$exercise" ]]; then
    resolve_directory "$exercise" "--exercise"
    physical="$REPLY"
    refuse_socket_directory "$physical" "--exercise"
    pairs+=("RECORD_EXERCISE=${physical}")
  fi
  [[ "$networked" == "no" ]] || service="record_networked"
  compose_prefix "$CHECKOUT_ROOT" "${CHECKOUT_ROOT}/docker-compose.yaml" "${pairs[@]}"
  local -a prefix=("${COMPOSE_PREFIX[@]}" --profile record run --build --rm)
  [[ -t 0 ]] || prefix+=(-T)
  step "${prefix[@]}" "$service" "$@"
}
