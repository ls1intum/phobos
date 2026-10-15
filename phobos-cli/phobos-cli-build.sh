#!/bin/bash
# shellcheck shell=bash
# The command build: the image context and the run-phase image of a language, on a host.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, whose places, state
# and helpers it uses. It starts nothing while it is sourced.

# The command build: assembles the image context and builds the image of a language. Host only.
command_build() {
  local language=""
  if (( $# == 1 )) && [[ "$1" == "--help" || "$1" == "-h" ]]; then
    help_text 1
    exit 0
  fi
  (( $# == 1 )) || fail_usage "build takes exactly one language: java, python, c-fact, r, swift, c-gcc, cpp or generic"
  language="$1"
  case "$language" in
    java | python | c-fact | r | swift | c-gcc | cpp | generic) ;;
    *) fail_usage "build takes java, python, c-fact, r, swift, c-gcc, cpp or generic, not '$language'" ;;
  esac
  if [[ "$MODE" == "image" ]]; then
    fail_environment "build needs a host with Docker; there is no docker inside an image"
  fi
  require_checkout build
  require_docker
  step "${CHECKOUT_ROOT}/.github/scripts/assemble-run-phase-context.sh" "${CHECKOUT_ROOT}/build/run-phase-context"
  compose_prefix "${CHECKOUT_ROOT}/docker/protecter/${language}" "${CHECKOUT_ROOT}/docker/protecter/${language}/docker-compose.yaml"
  step "${COMPOSE_PREFIX[@]}" build
}
