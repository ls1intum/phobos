#!/bin/bash
# shellcheck shell=bash
# The command prune: the layer pruner, in the image or through Docker Compose on a host.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, whose places, state
# and helpers it uses. It starts nothing while it is sourced.

# Ends the script unless the pruner or recorder file $1 exists in this image, naming what is missing.
require_helper() {
  [[ -f "$1" ]] || fail_environment "$1 is missing: the helpers of the pruners are mounted into the prune image, and are not part of the run-phase image"
}

# Sets REPLY to the Compose service and PROFILE to the profile for the prune key $1, and ends the
# script for a key that is none.
prune_service() {
  PROFILE=""
  case "$1" in
    java) fail_usage "the prune key java is now java-gradle" ;;
    java-gradle) REPLY="prune_java_gradle" ;;
    java-maven) REPLY="prune_java_maven" ;;
    python) REPLY="prune_python" ;;
    c-fact) REPLY="prune_c_fact" ;;
    r) REPLY="prune_r" ;;
    swift) REPLY="prune_swift" ;;
    c-gcc) REPLY="prune_c_gcc" ;;
    cpp) REPLY="prune_cpp" ;;
    generic) REPLY="prune_generic" ;;
    java-egress) REPLY="prune_java_egress"; PROFILE="egress" ;;
    *) fail_usage "prune takes java-gradle, java-maven, python, c-fact, r, swift, c-gcc, cpp, generic, java-egress or all, not '$1'" ;;
  esac
}

# Runs the service $1 of the compose file of the checkout, rebuilt first, with the profile $2 when it
# is not empty. The words after those are given to the service as its command.
compose_run() {
  local service="$1"
  local profile="$2"
  shift 2
  local -a prefix=("${COMPOSE_PREFIX[@]}")
  local -a options=(--build --rm --no-deps)
  [[ -z "$profile" ]] || prefix+=(--profile "$profile")
  [[ -t 0 ]] || options+=(-T)
  step "${prefix[@]}" run "${options[@]}" "$service" "$@"
}

# The command prune: one key, or all of them in order. Takes the words after "prune".
command_prune() {
  local key=""
  local resolver=""
  while (( $# > 0 )); do
    case "$1" in
      --resolver) need_value "$@"; check_resolver "$2"; resolver="$2"; shift 2 ;;
      --help | -h) help_text 1; exit 0 ;;
      --image | --language) fail_usage "prune takes no ${1}: the key decides which run-phase image it is built on" ;;
      -*) refuse_option "$1" prune ;;
      *) [[ -z "$key" ]] || fail_usage "prune takes one key"; key="$1"; shift ;;
    esac
  done
  [[ -n "$key" ]] || fail_usage "prune needs a key: java-gradle, java-maven, python, c-fact, r, swift, c-gcc, cpp, generic, java-egress or all"
  if [[ "$MODE" == "image" ]]; then
    prune_in_image "$key" "$resolver"
  else
    [[ -z "$resolver" ]] || fail_usage "--resolver is for the image form of prune; the Compose service of java-egress names its own"
    prune_on_host "$key"
  fi
}

# Image mode of prune: starts the layer pruner. Takes the key and the resolver, which java-egress needs.
prune_in_image() {
  local key="$1"
  local resolver="$2"
  case "$key" in
    java) fail_usage "the prune key java is now java-gradle" ;;
    java-gradle | java-maven | python | c-fact | r | swift | c-gcc | cpp | generic)
      [[ -z "$resolver" ]] || fail_usage "--resolver belongs to java-egress"
      require_helper "${IMAGE_HELPERS}/exercise_pruner/src/interface/main.py"
      hand_over python3 "${IMAGE_HELPERS}/exercise_pruner/src/interface/main.py" --stage all "$key" ;;
    java-egress)
      [[ -n "$resolver" ]] || fail_usage "prune java-egress needs --resolver"
      require_helper "${IMAGE_HELPERS}/exercise_pruner/src/interface/main.py"
      hand_over python3 "${IMAGE_HELPERS}/exercise_pruner/src/interface/main.py" --resolver "$resolver" --output-dir /var/tmp/path_sets/egress java-egress ;;
    all) fail_usage "prune all needs a host: the merge and the verification are separate images" ;;
    *) fail_usage "prune takes java-gradle, java-maven, python, c-fact, r, swift, c-gcc, cpp, generic, java-egress or all, not '$key'" ;;
  esac
}

# Host mode of prune: runs the Compose service of the key, or the nineteen jobs of all in order.
prune_on_host() {
  local key="$1"
  local service
  require_checkout prune
  require_docker
  compose_prefix "$CHECKOUT_ROOT" "${CHECKOUT_ROOT}/docker-compose.yaml"
  if [[ "$key" == "all" ]]; then
    for service in prune_java_gradle prune_java_maven prune_python prune_c_fact prune_r prune_swift prune_c_gcc prune_cpp prune_generic orchestrate verify_java_gradle verify_java_maven verify_python verify_c_fact verify_r verify_swift verify_c_gcc verify_cpp verify_generic; do
      compose_run "$service" ""
    done
    return 0
  fi
  prune_service "$key"
  compose_run "$REPLY" "$PROFILE"
}
