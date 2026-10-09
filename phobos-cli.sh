#!/bin/bash
# shellcheck shell=bash
# One command line for the sandbox and for both pruners: run a command under Phobos, prune or
# record a reference program, and build the run-phase image.
#
#   phobos-cli.sh [--mode host|image] [--dry-run] <command> [arguments]
#
# It works in two places. Inside an image it starts what the image holds: phobos.sh, and where
# the helpers are mounted the layer pruner and the recording pruner. On a host it starts Docker,
# the images being the unit that carries the sandbox, and gives every container the limits
# SECURITY.md says only the outer container can set.
#
# It is not the grading entry point. A grader calls phobos.sh, which can switch a layer off for
# diagnosis; this command refuses those switches in both places, so that nothing started through
# it runs less confined than the policy says.
#
# Bash 4.4 or newer is needed (phobos-environment.sh uses it). macOS ships 3.2, so a shell that is
# too old starts a newer one from a fixed absolute path, never one found through PATH.

set -euo pipefail

# The status this script ends with when it cannot start: PHB_ERUNTIME of phobos-constants.sh, as
# a plain number because the file that defines it cannot be found yet, and it is checked against
# that file by protecter/test/integration/phobos_cli.sh.
BOOTSTRAP_REFUSED=15

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "$candidate" ]] && "$candidate" -c '(( BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4) ))'; then
      exec "$candidate" "${BASH_SOURCE[0]}" "$@"
    fi
  done
  printf '%s\n' "phobos-cli.sh needs bash 4.4 or newer and this is bash ${BASH_VERSION}; install one (brew install bash) and start the script again. (PHB-ERUNTIME)" >&2
  exit "${BOOTSTRAP_REFUSED}"
fi

# This script's directory, found in bash alone so that PATH and CDPATH are cleaned before any
# program is looked up or any cd made, and made absolute once they are: phobos-environment.sh.
case "${BASH_SOURCE[0]}" in */*) HERE="${BASH_SOURCE[0]%/*}/" ;; *) HERE="./" ;; esac
if [[ -f "${HERE}phobos-tools-common/phobos-environment.sh" ]]; then
  COMMON="${HERE}phobos-tools-common"
  LAYOUT="image"
elif [[ -f "${HERE}protecter/src/phobos-tools-common/phobos-environment.sh" ]]; then
  COMMON="${HERE}protecter/src/phobos-tools-common"
  LAYOUT="checkout"
else
  printf '%s\n' "phobos-cli.sh finds neither phobos-tools-common beside itself nor protecter/src/phobos-tools-common in a checkout; it must be started from the image or from a checkout, not through a symbolic link elsewhere. (PHB-ERUNTIME)" >&2
  exit "${BOOTSTRAP_REFUSED}"
fi
# shellcheck source=protecter/src/phobos-tools-common/phobos-environment.sh
source "${COMMON}/phobos-environment.sh"
clean_startup_environment
HERE="$(cd -- "$HERE" && pwd -P)"
COMMON="$(cd -- "$COMMON" && pwd -P)"

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

MODE=""
DRY_RUN="no"
CHECKOUT_ROOT=""
STAGING=""
STAGED_COUNT=0
EXERCISE_PHYSICAL=""

# Prints the manual on the file descriptor named by $1. Assumes nothing.
help_text() {
  cat >&"$1" <<'PHOBOS_CLI_HELP'
phobos-cli.sh - run a command under Phobos, prune or record a reference program, build the image.

USAGE
  phobos-cli.sh [--mode host|image] [--dry-run] run [options] [--] <command> [args...]
  phobos-cli.sh [--mode host|image] [--dry-run] prune <java|java-maven|python|java-egress|all>
  phobos-cli.sh [--mode host|image] [--dry-run] record [options] <record|generate|check|diff> [args...]
  phobos-cli.sh [--mode host|image] [--dry-run] build <java|python>
  phobos-cli.sh --help

PLACES
  Inside an image (the directory /var/tmp/opt/core exists) the command starts what the image holds.
  On a host it starts Docker. --mode may confirm the place and never overrides it. --dry-run prints
  what would be started, one block per command: COMMAND, one argument per line, END.

run
  Starts the command under phobos.sh. Accepted in both places:
    --config <file>, -c <file>   an exercise configuration; repeatable
    --project-root <dir>         the project directory an Ares 2 policy resolves against
    --resolver <ip[:port]>       the resolver the egress broker uses for an exact host name
    --debug, -d                  the effective policy and what each layer does, on stderr
  Refused in both places, with status 2: every --no-* and -n* switch that turns a layer off, every
  --*-bin override of an enforcer, and any option not listed here. To debug with a layer off, call
  phobos.sh directly. Everything after -- (or after the first word that is not an option) is the
  command, options of its own included.
  On a host also:
    --language <java|python>     the run-phase image to use (default java)
    --image <name>               a run-phase image by name; not with --language
    --exercise <dir>             required; mounted read-write as /var/tmp/testing-dir, the working
                                 directory of the command
    --network <name>             a Docker network; default none; host and container: are refused
    --memory <size>              default 8g
    --pids-limit <n>             default 1024
    --cpus <n>                   no default
  A host copies each configuration into a private directory and mounts it read-only, so that the
  command can never write one. --project-root is then relative to --exercise.

prune
  Host: runs the Compose service of the key, rebuilt first; "all" runs the seven jobs of the layer
  pruner in order (the three prunes, the merge, the three verifications) and stops at the first one
  that fails. Image: runs the layer pruner (/var/tmp/helpers/layer_prune/main.py); java-egress needs
  --resolver <ip[:port]>.

record
  Runs the recording pruner, which runs the program unsandboxed: for the instructor's reference
  program only, never for a submission. On a host also --language <java|python> (default java),
  --exercise <dir> (mounted read-only) and --networked.

build
  Host only: assembles build/run-phase-context and builds the image of the language.

EXIT STATUSES
  The command's own, when it ran; 2 for a call made the wrong way; 15 (PHB-ERUNTIME) when a
  command cannot start: no Docker, a missing component, a leaked BASH_ENV or LD_PRELOAD.
  Start it without BASH_ENV, ENV, LD_PRELOAD, LD_LIBRARY_PATH and LD_AUDIT: bash and the loader
  read them before the first line, so this script can only refuse when it finds them set.
PHOBOS_CLI_HELP
}

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

# Ends the script unless Docker can be started. Skipped in a dry run, which starts nothing.
require_docker() {
  [[ "$DRY_RUN" == "yes" ]] && return 0
  command -v docker > /dev/null 2>&1 || fail_environment "docker is not on PATH"
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
  COMPOSE_PREFIX=(env -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME -u COMPOSE_PROFILES -u COMPOSE_PATH_SEPARATOR -u COMPOSE_ENV_FILES -u RUN_PHASE_IMAGE -u RUN_PHASE_IMAGE_PYTHON -u RECORD_EXERCISE COMPOSE_DISABLE_ENV_FILE=1)
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

# Ends the script with a usage error unless $1 is the name of an image.
check_image_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || fail_usage "--image takes an image name, not '$1'"
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

# Sets IMAGE_NAME from the language $1 (java or python), and ends the script for any other word.
image_of_language() {
  case "$1" in
    java) IMAGE_NAME="${IMAGE_JAVA}" ;;
    python) IMAGE_NAME="${IMAGE_PYTHON}" ;;
    *) fail_usage "--language takes java or python, not '$1'" ;;
  esac
}

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

# Ends the script unless the pruner or recorder file $1 exists in this image, naming what is missing.
require_helper() {
  [[ -f "$1" ]] || fail_environment "$1 is missing: the helpers of the pruners are mounted into the prune image, and are not part of the run-phase image"
}

# Sets REPLY to the Compose service and PROFILE to the profile for the prune key $1, and ends the
# script for a key that is none.
prune_service() {
  PROFILE=""
  case "$1" in
    java) REPLY="prune_java" ;;
    java-maven) REPLY="prune_java_maven" ;;
    python) REPLY="prune_python" ;;
    java-egress) REPLY="prune_java_egress"; PROFILE="egress" ;;
    *) fail_usage "prune takes java, java-maven, python, java-egress or all, not '$1'" ;;
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
  [[ -n "$key" ]] || fail_usage "prune needs a key: java, java-maven, python, java-egress or all"
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
    java | java-maven | python)
      [[ -z "$resolver" ]] || fail_usage "--resolver belongs to java-egress"
      require_helper "${IMAGE_HELPERS}/layer_prune/main.py"
      hand_over python3 "${IMAGE_HELPERS}/layer_prune/main.py" --stage all "$key" ;;
    java-egress)
      [[ -n "$resolver" ]] || fail_usage "prune java-egress needs --resolver"
      require_helper "${IMAGE_HELPERS}/layer_prune/main.py"
      hand_over python3 "${IMAGE_HELPERS}/layer_prune/main.py" --resolver "$resolver" --output-dir /var/tmp/path_sets/egress java-egress ;;
    all) fail_usage "prune all needs a host: the merge and the verification are separate images" ;;
    *) fail_usage "prune takes java, java-maven, python, java-egress or all, not '$key'" ;;
  esac
}

# Host mode of prune: runs the Compose service of the key, or the seven jobs of all in order.
prune_on_host() {
  local key="$1"
  local service
  require_checkout prune
  require_docker
  compose_prefix "$CHECKOUT_ROOT" "${CHECKOUT_ROOT}/docker-compose.yaml"
  if [[ "$key" == "all" ]]; then
    for service in prune_java prune_java_maven prune_python orchestrate verify_java verify_java_maven verify_python; do
      compose_run "$service" ""
    done
    return 0
  fi
  prune_service "$key"
  compose_run "$REPLY" "$PROFILE"
}

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
    require_helper "${IMAGE_HELPERS}/layer_record/phobos-record"
    hand_over "${IMAGE_HELPERS}/layer_record/phobos-record" "$@"
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

# The command build: assembles the image context and builds the image of a language. Host only.
command_build() {
  local language=""
  if (( $# == 1 )) && [[ "$1" == "--help" || "$1" == "-h" ]]; then
    help_text 1
    exit 0
  fi
  (( $# == 1 )) || fail_usage "build takes exactly one language: java or python"
  language="$1"
  case "$language" in
    java | python) ;;
    *) fail_usage "build takes java or python, not '$language'" ;;
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

# Reads the global options and the command, and starts it. Takes the whole command line.
main() {
  local mode_option=""
  while (( $# > 0 )); do
    case "$1" in
      --help | -h) help_text 1; exit 0 ;;
      --mode) need_value "$@"; mode_option="$2"; shift 2 ;;
      --dry-run) DRY_RUN="yes"; shift ;;
      -*) fail_usage "unknown option $1 before the command" ;;
      *) break ;;
    esac
  done
  (( $# > 0 )) || { help_text 2; exit "${EXIT_USAGE}"; }
  refuse_leaked_environment
  case "$mode_option" in
    "" | host | image) ;;
    *) fail_usage "--mode takes host or image" ;;
  esac
  choose_mode "$mode_option"
  local command="$1"
  shift
  case "$command" in
    run) command_run "$@" ;;
    prune) command_prune "$@" ;;
    record) command_record "$@" ;;
    build) command_build "$@" ;;
    *) fail_usage "unknown command '$command'" ;;
  esac
}

main "$@"
