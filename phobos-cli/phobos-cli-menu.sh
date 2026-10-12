#!/bin/bash
# shellcheck shell=bash
# The menu phobos-cli.sh opens when it is called on a terminal without a command.
#
# The menu is a front end and nothing more. Each way through it collects the answers to the
# questions of one command of phobos-cli.sh, shows the call they make, and starts phobos-cli.sh
# itself with exactly that call as a child, so every check and every refusal of the command line
# applies unchanged and what the menu prints at the end is what ran. Like the boxes of
# phobos-cli-ui.sh, every function here returns 0 and reports through the MENU_* and FLOW_*
# variables, so that set -e stays in force throughout.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, phobos-cli-ui.sh and
# phobos-cli-pick.sh. It starts nothing while it is sourced.

# The calls of phobos-cli.sh the menu has started, each as bash would quote it, and the status each
# ended with.
MENU_LOG=()
# The status of the last call the menu started, which the menu ends with.
MENU_STATUS=0
# Whether the way through the menu ended in a call.
MENU_RAN="no"
# The private directory a run inside an image reads its policy from, removed when the menu ends.
MENU_STAGING=""
# The private copy of the policy in it, empty when the policy system refused the policy.
MENU_STAGED=""
# The call of phobos-cli.sh running as the menu's child, and the status a signal to the menu asked
# the menu to end with once that child has ended.
MENU_CHILD=""
MENU_SIGNAL=""
# The answers of the way through "run a command under an existing policy".
FLOW_LANGUAGE="java"
FLOW_EXERCISE=""
FLOW_POLICY_DIRECTORY=""
FLOW_POLICY=""
FLOW_PROJECT_ROOT=""
FLOW_COMMAND_TEXT=""
FLOW_WORDS=()
FLOW_OPTIONS=()
# The call the answers make, as phobos-cli.sh is given it, and as it is shown.
FLOW_ARGV=()
FLOW_SHOWN=()

# Removes the private policy directory of a run inside an image, when the menu made one. Run on
# every exit of the menu.
menu_cleanup() {
  if [[ -n "$MENU_STAGING" && -d "$MENU_STAGING" ]]; then
    rm -rf -- "$MENU_STAGING"
  fi
}

# Prints, on stderr, every call of phobos-cli.sh the menu started and how it ended, quoted as bash
# would read it, so that it can be repeated without the menu.
menu_report() {
  local entry
  (( ${#MENU_LOG[@]} > 0 )) || return 0
  printf '\nThe menu ran (quoted for bash):\n' >&2
  for entry in "${MENU_LOG[@]}"; do
    printf '  %s\n' "$entry" >&2
  done
}

# Handles a signal to the menu, with $1 the status it ends the menu with. While a call of
# phobos-cli.sh runs, the call is asked to end with SIGTERM, which it passes on to its command, and
# the menu ends once it has; otherwise the menu ends now.
menu_signalled() {
  MENU_SIGNAL="$1"
  if [[ -n "$MENU_CHILD" ]]; then
    kill -TERM "$MENU_CHILD" 2> /dev/null || true
    return 0
  fi
  menu_interrupted "$1"
}

# Ends the menu after a signal: restores the terminal dialog may have left in its own mode, reports
# what ran, and ends with the status $1. No further call is started.
menu_interrupted() {
  stty sane 2> /dev/null || true
  printf '\nphobos-cli.sh: the menu was interrupted.\n' >&2
  menu_report
  exit "$1"
}

# Ends the menu with the status $1, after reporting every call it started.
menu_finish() {
  menu_report
  exit "$1"
}

# Starts phobos-cli.sh as a child with the words given as its call, the global options of this call
# in front, waits for it, and records the call as shown in FLOW_SHOWN, with its status, in MENU_LOG.
# The child keeps the terminal as its input and output. It runs as a background job, so that the
# menu's wait can be interrupted: a SIGINT or SIGTERM to the menu, Ctrl-C included, reaches the
# child as SIGTERM through menu_signalled, as run_child passes a signal on to its own command, and
# once the child has ended the menu ends with the status of the signal. Sets MENU_STATUS.
menu_spawn() {
  local -a global=()
  local shown
  [[ "$DRY_RUN" == "yes" ]] && global+=(--dry-run)
  MENU_STATUS=0
  "$BASH" "${HERE}/phobos-cli.sh" "${global[@]}" "$@" <&0 &
  MENU_CHILD=$!
  wait "$MENU_CHILD" || MENU_STATUS=$?
  while kill -0 "$MENU_CHILD" 2> /dev/null; do
    wait "$MENU_CHILD" || MENU_STATUS=$?
  done
  MENU_CHILD=""
  shown="$(printf '%q ' "${HERE}/phobos-cli.sh" "${global[@]}" "${FLOW_SHOWN[@]}")"
  MENU_LOG+=("${shown% } (ended with status ${MENU_STATUS})")
  [[ -z "$MENU_SIGNAL" ]] || menu_interrupted "$MENU_SIGNAL"
}

# The first box: what Phobos is and how the menu is used.
menu_welcome() {
  local text="Phobos runs a program, such as the tests of a student submission, with access to only what a policy allows: the files it may read or change, the hosts it may reach, and how long and how large it may run.\n\nThis menu builds a call of phobos-cli.sh from your answers, runs it, and prints it at the end, so that you can repeat it without the menu. Choose with the arrow keys or the mouse and Enter; Esc goes back."
  [[ "$MODE" == "image" ]] && text+="\n\nThis is an image: the command runs here, in ${CONTAINER_EXERCISE}, the working directory the image's policy sets."
  [[ "$DRY_RUN" == "yes" ]] && text+="\n\nThis is a dry run: nothing is started or written; the commands are printed instead."
  ui_message "Welcome to Phobos" "$text"
}

# Shows the main menu until a way through it ends in a call or the menu is left, then ends the menu.
# Assumes MODE and DRY_RUN are set and the terminal is the one the menu runs on.
menu_main() {
  ui_require_dialog
  trap 'menu_signalled 130' INT
  trap 'menu_signalled 143' TERM
  trap menu_cleanup EXIT
  menu_welcome
  while :; do
    ui_menu "Main menu" "What would you like to do?" \
      1 "Run a command under an existing policy" \
      2 "Write a new policy step by step (in a later version)" \
      3 "Record a reference program and derive a policy (in a later version)" \
      4 "Derive a policy from past student submissions (in a later version)" \
      5 "Exit"
    [[ "$UI_MOVE" == "next" && "$UI_RESULT" != "5" ]] || menu_finish 0
    case "$UI_RESULT" in
      1) menu_flow_run ;;
      *) ui_message "Not yet" "This part of the menu arrives in a later version of Phobos." ;;
    esac
    [[ "$MENU_RAN" == "yes" ]] && menu_finish "$MENU_STATUS"
  done
}

# Walks the steps named by the words given, forwards on an answer and backwards on Esc, each step
# being the function menu_step_<word>. Sets UI_MOVE to next when the last step was answered and to
# back when the first one was left.
menu_walk() {
  local -a steps=("$@")
  local position=0
  local direction="next"
  while (( position >= 0 && position < ${#steps[@]} )); do
    UI_MOVE="$direction"
    "menu_step_${steps[position]}"
    direction="$UI_MOVE"
    if [[ "$UI_MOVE" == "next" ]]; then
      position=$((position + 1))
    else
      position=$((position - 1))
    fi
  done
  UI_MOVE="$direction"
}

# The way through "run a command under an existing policy": the questions, then the run.
menu_flow_run() {
  local -a steps=()
  MENU_RAN="no"
  [[ "$MODE" == "host" ]] && steps+=(language exercise)
  steps+=(policy_directory policy project_root command advanced confirm)
  menu_walk "${steps[@]}"
  [[ "$UI_MOVE" == "next" ]] || return 0
  menu_execute_run
}

# Asks for the language, which decides the run-phase image on a host.
menu_step_language() {
  pick_language
  [[ "$UI_MOVE" == "next" ]] && FLOW_LANGUAGE="$PICKED_LANGUAGE"
  return 0
}

# Asks for the exercise directory a host mounts as the working directory of the command.
menu_step_exercise() {
  pick_directory "Exercise" "The exercise directory. It becomes the working directory of the command, which may change it as far as the policy lets it." "${FLOW_EXERCISE:-$PWD}"
  [[ "$UI_MOVE" == "next" ]] && FLOW_EXERCISE="$PICKED_DIRECTORY"
  return 0
}

# Asks where to look for policy files.
menu_step_policy_directory() {
  pick_directory "Policy directory" "Where should the menu look for policy files? Choose the instructor's own files rather than the exercise: a submission can place a policy file in the exercise." "${FLOW_POLICY_DIRECTORY:-$PWD}"
  [[ "$UI_MOVE" == "next" ]] && FLOW_POLICY_DIRECTORY="$PICKED_DIRECTORY"
  return 0
}

# Sets REPLY to the exercise directory of the run as a physical path: the one chosen on a host, and
# inside an image the working directory the shipped tail flags give every run, whichever directory
# the menu was started in.
menu_exercise_directory() {
  REPLY="$FLOW_EXERCISE"
  if [[ "$MODE" == "image" ]]; then
    REPLY="${CONTAINER_EXERCISE}"
    [[ -d "${CONTAINER_EXERCISE}" ]] && REPLY="$(cd -- "${CONTAINER_EXERCISE}" && pwd -P)"
  fi
  return 0
}

# Asks for the policy the command runs under.
menu_step_policy() {
  menu_exercise_directory
  pick_policy "$FLOW_POLICY_DIRECTORY" "$REPLY"
  [[ "$UI_MOVE" == "next" ]] && FLOW_POLICY="$PICKED_POLICY"
  return 0
}

# Asks for the project root an Ares 2 policy resolves its paths against; skipped for a Phobos policy.
menu_step_project_root() {
  local prompt="An Ares 2 policy resolves its relative paths against the directory the build tool starts the tests in. Leave this empty for the default, the working directory of the command."
  case "$FLOW_POLICY" in
    *.yaml | *.yml) ;;
    *)
      FLOW_PROJECT_ROOT=""
      return 0
      ;;
  esac
  [[ "$MODE" == "host" ]] && prompt+=" On a host, give it relative to the exercise directory."
  while :; do
    ui_input "Project root" "$prompt" "$FLOW_PROJECT_ROOT"
    [[ "$UI_MOVE" == "next" ]] || return 0
    ui_printable "$UI_RESULT"
    if [[ "$REPLY" == "yes" ]]; then
      FLOW_PROJECT_ROOT="$UI_RESULT"
      return 0
    fi
    ui_message "Project root" "Give a directory without control characters, or leave it empty."
  done
}

# Asks for the command to run, offering the exercise's build script or the language's usual one.
menu_step_command() {
  local language=""
  menu_exercise_directory
  [[ "$MODE" == "host" ]] && language="$FLOW_LANGUAGE"
  pick_offered_command "$REPLY" "$language"
  pick_command "${FLOW_COMMAND_TEXT:-$REPLY}"
  if [[ "$UI_MOVE" == "next" ]]; then
    FLOW_WORDS=("${PICKED_WORDS[@]}")
    FLOW_COMMAND_TEXT="${PICKED_WORDS[*]}"
  fi
  return 0
}

# Asks whether to change the defaults of the run, and which: on a host the limits and the network of
# the container, in both places the resolver and the debug report.
menu_step_advanced() {
  FLOW_OPTIONS=()
  ui_yesno "Advanced options" "Change the defaults of the run? They are: no network, 8g of memory and 1024 processes for the container on a host, no resolver, and no debug report." no
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || return 0
  if [[ "$MODE" == "host" ]]; then
    ui_form "Advanced options" "Change a value or leave it. An empty field keeps the default. The command line checks every value again." \
      "Memory (e.g. 8g)" "${DEFAULT_MEMORY}" "Processes" "${DEFAULT_PIDS_LIMIT}" "CPUs (e.g. 1.5)" "" \
      "Docker network" "${DEFAULT_NETWORK}" "Resolver (ip[:port])" ""
    [[ "$UI_MOVE" == "next" ]] || return 0
    menu_add_option --memory "${UI_FIELDS[0]}"
    menu_add_option --pids-limit "${UI_FIELDS[1]}"
    menu_add_option --cpus "${UI_FIELDS[2]}"
    menu_add_option --network "${UI_FIELDS[3]}"
    menu_add_option --resolver "${UI_FIELDS[4]}"
  else
    ui_form "Advanced options" "An empty field keeps the default. The command line checks the value again." "Resolver (ip[:port])" ""
    [[ "$UI_MOVE" == "next" ]] || return 0
    menu_add_option --resolver "${UI_FIELDS[0]}"
  fi
  ui_yesno "Debug report" "Print the effective policy and what each layer does, on the error stream?" no
  [[ "$UI_MOVE" == "next" ]] || return 0
  [[ "$UI_ANSWER" == "yes" ]] && FLOW_OPTIONS+=(--debug)
  return 0
}

# Adds the option $1 with the value $2 to FLOW_OPTIONS when the value is not empty.
menu_add_option() {
  [[ -n "$2" ]] && FLOW_OPTIONS+=("$1" "$2")
  return 0
}

# Sets FLOW_ARGV and FLOW_SHOWN to the call of phobos-cli.sh the answers make, with the policy named
# by $1, which is the policy chosen or the private copy of it a run inside an image reads.
menu_build_run() {
  local policy="$1"
  local -a host=()
  local -a root=()
  [[ "$MODE" == "host" ]] && host=(--language "$FLOW_LANGUAGE" --exercise "$FLOW_EXERCISE")
  [[ -n "$FLOW_PROJECT_ROOT" ]] && root=(--project-root "$FLOW_PROJECT_ROOT")
  FLOW_ARGV=(run "${host[@]}" --config "$policy" "${root[@]}" "${FLOW_OPTIONS[@]}" -- "${FLOW_WORDS[@]}")
  FLOW_SHOWN=(run "${host[@]}" --config "$FLOW_POLICY" "${root[@]}" "${FLOW_OPTIONS[@]}" -- "${FLOW_WORDS[@]}")
  return 0
}

# Shows the call the answers make and asks whether to run it.
menu_step_confirm() {
  local shown
  menu_build_run "$FLOW_POLICY"
  shown="$(printf '%q ' phobos-cli.sh "${FLOW_SHOWN[@]}")"
  ui_yesno "Run it?" "The answers make this call:\n\n${shown% }\n\nRun it now?"
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "no" ]] && UI_MOVE="back"
  return 0
}

# Copies the chosen policy into a private directory under /var/tmp and has phobos-policysystem.sh
# build the run's specification from that copy in a subdirectory beside it. The policy system
# refuses a specification directory beneath any path the policy lets the command write, create,
# delete, rename or link in, so it refuses every grant on the private directory or above it; the
# copy itself could be named only by its random path, which no policy can know beforehand. The copy
# has a fixed name that keeps the suffix the policy system reads its format from, so no name of the
# original can coincide with the log or the specification beside it. Sets MENU_STAGED to the copy, or to empty after telling the person why the policy was
# refused. A directory left by an earlier attempt is removed first. Inside an image only, where the
# run does not copy the policy itself.
menu_stage_in_image() {
  local copy
  local status=0
  local -a root=()
  menu_cleanup
  MENU_STAGED=""
  MENU_STAGING="$(mktemp -d /var/tmp/phobos-cli-menu.XXXXXXXX)"
  chmod 0700 "$MENU_STAGING"
  case "$FLOW_POLICY" in
    *.yaml) copy="${MENU_STAGING}/policy.yaml" ;;
    *.yml) copy="${MENU_STAGING}/policy.yml" ;;
    *) copy="${MENU_STAGING}/policy.cfg" ;;
  esac
  mkdir "${MENU_STAGING}/specification"
  cp -- "$FLOW_POLICY" "$copy"
  chmod 0444 "$copy"
  [[ -n "$FLOW_PROJECT_ROOT" ]] && root=(--project-root "$FLOW_PROJECT_ROOT")
  "${IMAGE_HOME}/phobos-policysystem.sh" --spec-dir "${MENU_STAGING}/specification" "${root[@]}" --config "$copy" \
    > "${MENU_STAGING}/policy-check.log" 2>&1 || status=$?
  if (( status != 0 )); then
    menu_show_refusal "${MENU_STAGING}/policy-check.log"
    return 0
  fi
  MENU_STAGED="$copy"
}

# Tells the person that the policy system refused the policy, with the last lines it printed. A
# line that holds a control character is left out rather than drawn.
menu_show_refusal() {
  local line
  local text="The policy system refused this policy, so nothing was run. Where it says the specification directory lies beneath a write path, the policy lets the command change where the menu keeps its copy of the policy; run it from a host instead, which keeps the copy outside the container.\n"
  while IFS= read -r line; do
    ui_printable "$line"
    [[ "$REPLY" == "yes" ]] && text+="\n${line}"
  done < <(tail -n 8 "$1")
  ui_message "Policy refused" "$text"
}

# Runs the call the answers make. Inside an image, and not in a dry run, the policy is first copied
# to a place the command cannot change; a dry run writes nothing.
menu_execute_run() {
  local policy="$FLOW_POLICY"
  if [[ "$MODE" == "image" && "$DRY_RUN" == "no" ]]; then
    menu_stage_in_image
    [[ -n "$MENU_STAGED" ]] || return 0
    policy="$MENU_STAGED"
  fi
  menu_build_run "$policy"
  MENU_RAN="yes"
  menu_spawn "${FLOW_ARGV[@]}"
}
