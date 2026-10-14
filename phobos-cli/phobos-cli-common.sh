#!/bin/bash
# shellcheck shell=bash
# What the commands of phobos-cli.sh share: the fixed places and defaults, the state of one call,
# and the helpers that refuse a wrong call, start a command or print it in a dry run.
#
# Sourced by phobos-cli.sh alone, at the top level and after the startup cleaning, before any other
# file of this folder. It sets no shell option and starts nothing while it is sourced.
# Most of the places, the state and the values the helpers set here are read by the other files of
# this folder and never in this one, so SC2034 fires on them by design when this file is checked
# on its own; checked through phobos-cli.sh, which sources every file, it does not.
# shellcheck disable=SC2034

# Where an image keeps Phobos. A fixed path, never read from the environment, so that nothing a
# caller sets can decide which installation is run or which mode this is.
IMAGE_HOME="/var/tmp/opt/core"
# Where the images mount the helpers of the pruners, and where a host mounts the exercise and the
# configurations of a run.
IMAGE_HELPERS="/var/tmp/helpers"
CONTAINER_EXERCISE="/var/tmp/testing-dir"
CONTAINER_CONFIG="/srv/phobos-cli/config"
# The status for a call made the wrong way, and for a run that cannot start.
EXIT_USAGE="${PHB_EXIT_USAGE}"
EXIT_ENVIRONMENT="${PHB_ERUNTIME}"
# What a container is given when the caller names nothing: the limits the outer container owes
# the sandbox, and no network at all.
DEFAULT_MEMORY="8g"
DEFAULT_PIDS_LIMIT="1024"
DEFAULT_NETWORK="none"
# The images the compose files and the Dockerfiles tag, by language.
IMAGE_JAVA="phobos-run-phase-java"
IMAGE_PYTHON="phobos-run-phase-python"
IMAGE_C_FACT="phobos-run-phase-c-fact"
IMAGE_R="phobos-run-phase-r"
IMAGE_SWIFT="phobos-run-phase-swift"
IMAGE_C_GCC="phobos-run-phase-c-gcc"
IMAGE_CPP="phobos-run-phase-cpp"

MODE=""
DRY_RUN="no"
CHECKOUT_ROOT=""
STAGING=""
STAGED_COUNT=0
EXERCISE_PHYSICAL=""

# Says what was wrong with the call on stderr and ends the script with EXIT_USAGE. Takes the message.
fail_usage() {
  printf 'phobos-cli.sh: %s (see --help)\n' "$1" >&2
  exit "${EXIT_USAGE}"
}

# Says why the command cannot start on stderr and ends the script with EXIT_ENVIRONMENT. Takes the message.
fail_environment() {
  printf 'phobos-cli.sh: %s (PHB-ERUNTIME)\n' "$1" >&2
  exit "${EXIT_ENVIRONMENT}"
}

# Whether $1 contains no newline, which would split an argument in a dry run and a mount string.
single_line() {
  [[ "$1" != *$'\n'* ]]
}

# Whether $1 can sit inside a --mount string: not empty, one line, and neither a comma nor a colon,
# which would change what the string means.
mount_safe() {
  [[ -n "$1" && "$1" != *,* && "$1" != *:* && "$1" != *$'\n'* ]]
}

# Ends the script with a usage error unless $2 is the value of the option named $1, that is, a word
# that exists and is not another option.
need_value() {
  if (( $# < 2 )) || [[ -z "$2" ]] || [[ "$2" == -* ]]; then
    fail_usage "$1 needs a value"
  fi
  single_line "$2" || fail_usage "$1 takes one line"
}

# Ends the script with a usage error for a word that asks to take a layer or an enforcer away, or
# that is no option of this command. Takes the word and the name of the command it was given to.
refuse_option() {
  case "$1" in
    --no-restriction | -nr | --no-*-restriction | -nnr | -ntr | -nrr | -nfr)
      fail_usage "$1 would run less confined than the policy says, so $2 refuses it; call phobos.sh directly to debug with a layer off" ;;
    --*-bin)
      fail_usage "$1 would replace an enforcer, so $2 refuses it; call phobos.sh directly" ;;
    *)
      fail_usage "$2 has no option $1" ;;
  esac
}

# Sets MODE to host or image. Image when the fixed directory of an image exists, host otherwise;
# --mode may only confirm that. Assumes the argument $1 is the value of --mode, or empty.
choose_mode() {
  local found="host"
  [[ -d "${IMAGE_HOME}" ]] && found="image"
  if [[ -n "$1" && "$1" != "$found" ]]; then
    fail_usage "--mode $1 contradicts the place this runs in, which is ${found}"
  fi
  MODE="$found"
}

# Ends the script when the environment holds something bash or the loader reads before the first
# line of a script and that can run other code. Assumes it is called after the startup cleaning.
refuse_leaked_environment() {
  local name
  for name in BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT; do
    if [[ -n "${!name:-}" ]]; then
      fail_environment "${name} is set, and bash or the loader has read it before this script could look; start it without ${name}"
    fi
  done
}

# Sets CHECKOUT_ROOT to the repository this script sits in, and ends the script when it sits in an
# image instead, since the host side needs the compose files and the assembler of a checkout.
require_checkout() {
  if [[ "$LAYOUT" != "checkout" ]]; then
    fail_environment "$1 needs a checkout of the repository; this script sits in an image's installation"
  fi
  CHECKOUT_ROOT="$HERE"
}

# Ends the script unless Docker can be started and its daemon answers, so that a stopped Docker
# Desktop or a socket this user may not open is named before the first step rather than by the
# failure of one, with what Docker said on one line. Skipped in a dry run, which starts nothing.
# Assumes the docker found on PATH is the client the steps start, as they look it up the same way.
require_docker() {
  local answer
  [[ "$DRY_RUN" == "yes" ]] && return 0
  command -v docker > /dev/null 2>&1 || fail_environment "docker is not on PATH"
  answer="$(docker version --format '{{.Server.Version}}' 2>&1 > /dev/null)" \
    || fail_environment "docker is installed, but its daemon does not answer; start Docker Desktop or the Docker service, or check DOCKER_HOST and whether this user may open its socket. Docker said: ${answer//$'\n'/ }"
  return 0
}

# Prints one command for a dry run: COMMAND, each argument on a line of its own, END.
print_command() {
  local word
  printf 'COMMAND\n'
  for word in "$@"; do
    printf '%s\n' "$word"
  done
  printf 'END\n'
}

# Removes the private directory of staged configurations, when this script made one.
cleanup_staging() {
  if [[ -n "$STAGING" && -d "$STAGING" ]]; then
    rm -rf -- "$STAGING"
  fi
}

# Starts the command $@ as a child, hands SIGINT and SIGTERM on to it as SIGTERM, and returns its status.
# A background job of a script starts with SIGINT ignored, so a SIGINT passed on as it is would stop
# nothing, and SIGTERM is what docker and a shell script both act on. The standard input is given to
# the child because a background job of a script would otherwise lose it.
run_child() {
  local child
  local status=0
  "$@" <&0 &
  child=$!
  trap 'kill -TERM "$child" 2> /dev/null || true' TERM INT
  wait "$child" || status=$?
  while kill -0 "$child" 2> /dev/null; do
    wait "$child" || status=$?
  done
  trap - TERM INT
  return "$status"
}

# Runs one command of a sequence: prints it in a dry run, otherwise runs it as a child and ends the
# script with its status when that is not zero. Takes the command and its arguments.
step() {
  local status=0
  if [[ "$DRY_RUN" == "yes" ]]; then
    print_command "$@"
    return 0
  fi
  run_child "$@" || status=$?
  if (( status == 125 || status == 126 || status == 127 )) && [[ "$1" == "env" || "$1" == "docker" ]]; then
    printf 'phobos-cli.sh: %s ended with %s, which is Docker itself failing rather than the command\n' "$1" "$status" >&2
  fi
  (( status == 0 )) || exit "$status"
}

# Hands the process over to the command $@ (image mode), or prints it in a dry run.
hand_over() {
  if [[ "$DRY_RUN" == "yes" ]]; then
    print_command "$@"
    exit 0
  fi
  exec "$@"
}

# Sets the array COMPOSE_PREFIX to what starts Docker Compose on the compose file $2 with the project
# directory $1, whatever the caller's environment and working directory hold: the variables that
# select a file, a project or a profile are unset, the .env file is not read, and the three variables
# the compose files interpolate are the only ones passed, from the pairs after $2 (NAME=value).
# Assumes the checkout root is known.
compose_prefix() {
  local project="$1"
  local file="$2"
  shift 2
  COMPOSE_PREFIX=(env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME -u COMPOSE_PROFILES -u COMPOSE_PATH_SEPARATOR -u COMPOSE_ENV_FILES -u RUN_PHASE_IMAGE -u RUN_PHASE_IMAGE_PYTHON -u RUN_PHASE_IMAGE_C_FACT -u RUN_PHASE_IMAGE_R -u RUN_PHASE_IMAGE_SWIFT -u RUN_PHASE_IMAGE_C_GCC -u RUN_PHASE_IMAGE_CPP -u RECORD_EXERCISE COMPOSE_DISABLE_ENV_FILE=1)
  COMPOSE_PREFIX+=("$@")
  COMPOSE_PREFIX+=(docker compose --project-directory "$project" -f "$file" --env-file /dev/null)
}

# Whether $1 is a positive integer without a sign or leading zero.
positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

# Ends the script with a usage error unless $1 is a memory size Docker accepts for --memory in the
# one form this command allows: a positive integer with an optional k, m or g.
check_memory() {
  [[ "$1" =~ ^[1-9][0-9]*[kmg]?$ ]] || fail_usage "--memory takes a positive integer with an optional k, m or g, not '$1'"
}

# Ends the script with a usage error unless $1 is a positive decimal.
check_cpus() {
  [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ && "$1" =~ [1-9] ]] || fail_usage "--cpus takes a positive number, not '$1'"
}

# Ends the script with a usage error unless $1 names a Docker network this command may use. The host's
# own network, another container's and a namespace are refused, because they take the isolation away.
check_network() {
  case "$1" in
    host | container:* | ns:* | "") fail_usage "--network ${1:-''} would give the command the network of the host or of another container" ;;
  esac
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail_usage "--network takes a Docker network name, not '$1'"
}

# Returns 0 when $1 is the name of an image as --image takes it, and 1 otherwise. The menu asks with
# it too, so that both refuse the same names.
image_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]]
}

# Ends the script with a usage error unless $1 is the name of an image.
check_image_name() {
  image_name "$1" || fail_usage "--image takes an image name, not '$1'"
}

# Ends the script with a usage error unless $1 is a resolver as phobos.sh takes it: an address with an
# optional port.
check_resolver() {
  [[ "$1" =~ ^[0-9A-Fa-f.:]+$ ]] || fail_usage "--resolver takes an address with an optional port, not '$1'"
}

# Sets REPLY to the physical path of the directory $1, and ends the script when it is no directory
# or cannot be named safely in a mount. Takes the option the value belongs to as $2.
resolve_directory() {
  [[ -d "$1" ]] || fail_usage "$2: '$1' is not a directory"
  REPLY="$(cd -- "$1" && pwd -P; printf x)"
  REPLY="${REPLY%x}"
  REPLY="${REPLY%$'\n'}"
  mount_safe "$REPLY" || fail_usage "$2: the path '$REPLY' holds a comma, a colon or a newline, which a mount cannot carry"
}

# Ends the script unless the directory $1 (a physical path) is fit to be mounted writable into a
# container: not the root, not a directory that holds a Docker socket by its usual name or any
# socket at its top level, and not the parent of one of the usual places of that socket.
# Takes the option the value belongs to as $2.
refuse_socket_directory() {
  local candidate
  local home="${HOME:-}"
  [[ "$1" != "/" ]] || fail_usage "$2: the root directory cannot be mounted"
  for candidate in /run/docker.sock /var/run/docker.sock "${home}/.docker/run/docker.sock"; do
    if [[ "$candidate" == "$1" || "$candidate" == "$1/"* ]]; then
      fail_usage "$2: '$1' holds the Docker socket"
    fi
  done
  if [[ -n "$(find "$1" -maxdepth 1 -type s -print -quit 2> /dev/null)" ]]; then
    fail_usage "$2: '$1' holds a socket, and a socket in a mounted directory reaches the container"
  fi
}

# Sets IMAGE_NAME from the language $1 (java, python, c-fact, r, swift, c-gcc or cpp), and ends the script for any other word.
image_of_language() {
  case "$1" in
    java) IMAGE_NAME="${IMAGE_JAVA}" ;;
    python) IMAGE_NAME="${IMAGE_PYTHON}" ;;
    c-fact) IMAGE_NAME="${IMAGE_C_FACT}" ;;
    r) IMAGE_NAME="${IMAGE_R}" ;;
    swift) IMAGE_NAME="${IMAGE_SWIFT}" ;;
    c-gcc) IMAGE_NAME="${IMAGE_C_GCC}" ;;
    cpp) IMAGE_NAME="${IMAGE_CPP}" ;;
    *) fail_usage "--language takes java, python, c-fact, r, swift, c-gcc or cpp, not '$1'" ;;
  esac
}
