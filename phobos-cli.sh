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
# This file starts the shell safely and reads the call; the commands and the helpers they share
# live in phobos-cli/ beside it, one file each, in the image as in a checkout.
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

# Ends the script before anything starts when a file of phobos-cli/ cannot be sourced, with
# BOOTSTRAP_REFUSED, because the helpers that would word the refusal live in those files. Takes the
# path of the file.
bootstrap_refused() {
  printf '%s\n' "phobos-cli.sh cannot source $1, so its installation is incomplete; it must be started from the image or from a checkout that holds phobos-cli/ beside it. (PHB-ERUNTIME)" >&2
  exit "${BOOTSTRAP_REFUSED}"
}

# Ends the script before anything starts unless every file of phobos-cli/ beside this script is a
# readable regular file. Its loop variable is local, so that a variable of the caller's environment
# with the same name reaches the commands this script starts unchanged. Assumes HERE is the
# physical directory of this script.
require_modules() {
  local module
  for module in phobos-cli-common.sh phobos-cli-help.sh phobos-cli-run.sh phobos-cli-prune.sh phobos-cli-record.sh phobos-cli-build.sh \
                phobos-cli-ui.sh phobos-cli-pick.sh phobos-cli-wizard.sh phobos-cli-menu.sh; do
    [[ -f "${HERE}/phobos-cli/${module}" && -r "${HERE}/phobos-cli/${module}" ]] || bootstrap_refused "${HERE}/phobos-cli/${module}"
  done
}

# The commands and the helpers they share live in phobos-cli/ beside this script, one file each.
# Each is named by its absolute path beside this script, never looked up, so the working directory
# cannot supply one, and is sourced here at the top level so that what it declares is global. No
# variable is set to load them, so none of the caller's environment is changed on the way.
require_modules
# shellcheck source=phobos-cli/phobos-cli-common.sh
source "${HERE}/phobos-cli/phobos-cli-common.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-common.sh"
# shellcheck source=phobos-cli/phobos-cli-help.sh
source "${HERE}/phobos-cli/phobos-cli-help.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-help.sh"
# shellcheck source=phobos-cli/phobos-cli-run.sh
source "${HERE}/phobos-cli/phobos-cli-run.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-run.sh"
# shellcheck source=phobos-cli/phobos-cli-prune.sh
source "${HERE}/phobos-cli/phobos-cli-prune.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-prune.sh"
# shellcheck source=phobos-cli/phobos-cli-record.sh
source "${HERE}/phobos-cli/phobos-cli-record.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-record.sh"
# shellcheck source=phobos-cli/phobos-cli-build.sh
source "${HERE}/phobos-cli/phobos-cli-build.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-build.sh"
# shellcheck source=phobos-cli/phobos-cli-ui.sh
source "${HERE}/phobos-cli/phobos-cli-ui.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-ui.sh"
# shellcheck source=phobos-cli/phobos-cli-pick.sh
source "${HERE}/phobos-cli/phobos-cli-pick.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-pick.sh"
# shellcheck source=phobos-cli/phobos-cli-wizard.sh
source "${HERE}/phobos-cli/phobos-cli-wizard.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-wizard.sh"
# shellcheck source=phobos-cli/phobos-cli-menu.sh
source "${HERE}/phobos-cli/phobos-cli-menu.sh" || bootstrap_refused "${HERE}/phobos-cli/phobos-cli-menu.sh"

# Reads the global options and the command, and starts it. Takes the whole command line. Without a
# command it opens the menu when its standard input and output are a terminal, and prints the
# manual and refuses the call otherwise, so a script or a pipeline never waits for an answer.
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
  if (( $# == 0 )) && ! [[ -t 0 && -t 1 ]]; then
    help_text 2
    exit "${EXIT_USAGE}"
  fi
  refuse_leaked_environment
  case "$mode_option" in
    "" | host | image) ;;
    *) fail_usage "--mode takes host or image" ;;
  esac
  choose_mode "$mode_option"
  if (( $# == 0 )); then
    menu_main
  fi
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
