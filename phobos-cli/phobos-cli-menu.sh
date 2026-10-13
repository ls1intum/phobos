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
# What the menu prints after the calls when it ends, such as the policy a dry run would have saved.
MENU_NOTES=()
# Whether the last check of a new policy ended with 0.
MENU_CHECKED="no"
# The private directory a run inside an image reads its policy from, removed when the menu ends.
MENU_STAGING=""
# The private copy of the policy in it, empty when the policy system refused the policy.
MENU_STAGED=""
# The status the policy system refused the last policy it read with, empty when it accepted it.
MENU_REFUSAL=""
# The private directory a new policy is read in beside its destination, and the file a check's
# output is kept in, while they exist, so that the menu removes them on every exit.
MENU_PROBE=""
MENU_CAPTURE=""
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
# Where the way through "write a new policy" saves the policy, and whether replacing a file there
# was agreed to.
FLOW_DESTINATION=""
FLOW_REPLACE="no"
# The name of a recording, whether the recorded program needs the network, and the resolver a
# replay of it is given.
FLOW_RECORDING="reference"
FLOW_NETWORKED="no"
FLOW_RESOLVER=""
# The call the answers make, as phobos-cli.sh is given it, and as it is shown.
FLOW_ARGV=()
FLOW_SHOWN=()

# Removes the private policy directory of a run inside an image, when the menu made one. Run on
# every exit of the menu.
menu_cleanup() {
  if [[ -n "$MENU_STAGING" && -d "$MENU_STAGING" ]]; then
    rm -rf -- "$MENU_STAGING"
  fi
  if [[ -n "$MENU_PROBE" && -d "$MENU_PROBE" ]]; then
    rm -rf -- "$MENU_PROBE"
  fi
  if [[ -n "$MENU_CAPTURE" ]]; then
    rm -f -- "$MENU_CAPTURE"
  fi
}

# Prints, on stderr, every call of phobos-cli.sh the menu started and how it ended, quoted as bash
# would read it, so that it can be repeated without the menu, and then the notes of the way through.
menu_report() {
  local entry
  if (( ${#MENU_LOG[@]} > 0 )); then
    printf '\nThe menu ran (quoted for bash):\n' >&2
    for entry in "${MENU_LOG[@]}"; do
      printf '  %s\n' "$entry" >&2
    done
  fi
  for entry in "${MENU_NOTES[@]}"; do
    printf '\n%s\n' "$entry" >&2
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
# The child keeps the terminal as its input and output. Sets MENU_STATUS.
menu_spawn() {
  local -a global=()
  [[ "$DRY_RUN" == "yes" ]] && global+=(--dry-run)
  menu_wait_child "-" "$BASH" "${HERE}/phobos-cli.sh" "${global[@]}" "$@"
  menu_log_call "${global[@]}"
}

# Starts phobos-cli.sh as menu_spawn does, but with its input from /dev/null and its output kept in
# the file $1 rather than shown, so that the menu can show it in a box. Takes the file, then the call.
menu_spawn_captured() {
  local file="$1"
  local -a global=()
  shift
  [[ "$DRY_RUN" == "yes" ]] && global+=(--dry-run)
  menu_wait_child "$file" "$BASH" "${HERE}/phobos-cli.sh" "${global[@]}" "$@"
  menu_log_call "${global[@]}"
}

# Starts the command after $1 as a background job and waits for it, with $1 either "-", for a child
# that keeps the terminal as its input and output, or a file its output goes to, its input then
# being /dev/null. It runs as a background job so that the menu's wait can be interrupted: a SIGINT
# or SIGTERM to the menu, Ctrl-C included, reaches the child as SIGTERM through menu_signalled, as
# run_child passes a signal on to its own command. Sets MENU_STATUS.
menu_wait_child() {
  local output="$1"
  shift
  MENU_STATUS=0
  if [[ "$output" == "-" ]]; then
    "$@" <&0 &
  else
    "$@" > "$output" 2>&1 < /dev/null &
  fi
  MENU_CHILD=$!
  wait "$MENU_CHILD" || MENU_STATUS=$?
  while kill -0 "$MENU_CHILD" 2> /dev/null; do
    wait "$MENU_CHILD" || MENU_STATUS=$?
  done
  MENU_CHILD=""
}

# Adds the call shown in FLOW_SHOWN, with the global options given in front and MENU_STATUS after
# it, to MENU_LOG, quoted as bash would read it. After a signal to the menu it then ends the menu,
# with the status of the signal, so that no further call starts.
menu_log_call() {
  local shown
  shown="$(printf '%q ' "${HERE}/phobos-cli.sh" "$@" "${FLOW_SHOWN[@]}")"
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
  local record_label="Record a reference program and derive a policy"
  local record_reason
  ui_require_dialog
  record_unavailable
  record_reason="$REPLY"
  [[ -n "$record_reason" ]] && record_label+=" (not here)"
  trap 'menu_signalled 130' INT
  trap 'menu_signalled 143' TERM
  trap menu_cleanup EXIT
  menu_welcome
  while :; do
    ui_menu "Main menu" "What would you like to do?" \
      1 "Run a command under an existing policy" \
      2 "Write a new policy step by step" \
      3 "$record_label" \
      4 "Derive a policy from past student submissions (in a later version)" \
      5 "Exit"
    [[ "$UI_MOVE" == "next" && "$UI_RESULT" != "5" ]] || menu_finish 0
    case "$UI_RESULT" in
      1) menu_flow_run ;;
      2) menu_flow_write ;;
      3) menu_flow_record "$record_reason" ;;
      *) ui_message "Not yet" "This part of the menu arrives in a later version of Phobos." ;;
    esac
    [[ "$MENU_RAN" == "yes" ]] && menu_finish "$MENU_STATUS"
  done
}

# Walks the steps named by the words given, forwards on an answer and backwards on Esc, each step
# being the function menu_step_<word>. Sets UI_MOVE to next when the last step was answered and to
# back when the first one was left. A step that sets UI_MOVE to stop ends the walk there, with
# UI_MOVE left at stop.
menu_walk() {
  local -a steps=("$@")
  local position=0
  local direction="next"
  while (( position >= 0 && position < ${#steps[@]} )); do
    UI_MOVE="$direction"
    "menu_step_${steps[position]}"
    [[ "$UI_MOVE" == "stop" ]] && return 0
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
    MENU_REFUSAL="$status"
    menu_show_refusal "${MENU_STAGING}/policy-check.log"
    return 0
  fi
  MENU_REFUSAL=""
  MENU_STAGED="$copy"
}

# Tells the person that the policy system refused the policy, with the last lines it printed.
menu_show_refusal() {
  menu_show_tail "Policy refused" "The policy system refused this policy, so nothing was run. Where it says the specification directory lies beneath a write path, the policy lets the command change where the menu keeps its copy of the policy; run it from a host instead, which keeps the copy outside the container." "$1"
}

# Shows the text $2 under the title $1, followed by the last lines of the file $3. A line that holds
# a control character is left out rather than drawn.
menu_show_tail() {
  local line
  local text="${2}\n"
  while IFS= read -r line; do
    ui_printable "$line"
    [[ "$REPLY" == "yes" ]] && text+="\n${line}"
  done < <(tail -n 8 "$3")
  ui_message "$1" "$text"
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

# The way through "write a new policy step by step": the destination, the sections and their
# entries, saving, an optional check, then the run as in "run a command under an existing policy".
menu_flow_write() {
  local -a steps=()
  MENU_RAN="no"
  wizard_reset
  FLOW_PROJECT_ROOT=""
  [[ "$MODE" == "host" ]] && steps+=(language exercise)
  steps+=(destination sections editors save check command advanced confirm)
  menu_walk "${steps[@]}"
  [[ "$UI_MOVE" == "next" ]] || return 0
  menu_execute_run
}

# Sets REPLY to the reason the policy file $1 cannot be written there, or to empty when it can, and
# FLOW_DESTINATION to its path with the directory made physical. A policy is never kept inside the
# exercise, which the sandboxed command may change, and an existing one is replaced only when it is
# a regular file, never through a link.
menu_destination_problem() {
  local directory
  local exercise
  REPLY=""
  ui_printable "$1"
  if [[ "$REPLY" != "yes" || "$1" != *.cfg || "$1" == */ ]]; then
    REPLY="Give the path of a file ending in .cfg, without control characters. A .yaml file would be read as an Ares 2 policy."
    return 0
  fi
  REPLY=""
  directory="$(dirname -- "$1")"
  if [[ ! -d "$directory" ]]; then
    REPLY="The directory ${directory} does not exist."
    return 0
  fi
  directory="$(cd -- "$directory" && pwd -P)"
  FLOW_DESTINATION="${directory}/${1##*/}"
  menu_exercise_directory
  exercise="$REPLY"
  REPLY=""
  if [[ "$directory" == "$exercise" || "$directory" == "${exercise}/"* ]]; then
    REPLY="That lies inside the exercise directory, which the sandboxed command may change. Keep the policy with your own files."
  elif [[ -L "$FLOW_DESTINATION" || ( -e "$FLOW_DESTINATION" && ! -f "$FLOW_DESTINATION" ) ]]; then
    REPLY="${FLOW_DESTINATION} exists and is not a regular file. Choose another name."
  fi
  return 0
}

# Asks where to save the new policy until the place can take it, and whether to replace a file
# that is there already.
menu_step_destination() {
  local offered="${FLOW_DESTINATION:-${PWD}/phobos-exercise.cfg}"
  while :; do
    ui_input "Policy file" "Where should the new policy be saved? Keep it with your own files, never inside the exercise." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    menu_destination_problem "$offered"
    if [[ -n "$REPLY" ]]; then
      ui_message "Policy file" "$REPLY"
      continue
    fi
    FLOW_REPLACE="no"
    [[ -e "$FLOW_DESTINATION" ]] || return 0
    ui_yesno "Policy file" "${FLOW_DESTINATION} exists. Replace it?" no
    if [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]]; then
      FLOW_REPLACE="yes"
      return 0
    fi
  done
}

# Asks which sections the new policy fills.
menu_step_sections() {
  wizard_choose_sections
}

# Asks for the entries of every section chosen.
menu_step_editors() {
  wizard_edit_chosen
}

# Shows the policy the answers make and saves it on Yes. In a dry run nothing is written: the policy
# is printed when the menu ends, and the way through stops here, because what follows would read
# the file.
menu_step_save() {
  local shown
  wizard_render
  shown="${WIZARD_TEXT//$'\n'/\\n}"
  [[ -n "$WIZARD_TEXT" ]] || shown="(nothing: under this policy the command gets the image's base policy alone)"
  ui_yesno "Save the policy?" "The new policy for ${FLOW_DESTINATION}:\n\n${shown}\nSave it?"
  [[ "$UI_MOVE" == "next" ]] || return 0
  if [[ "$UI_ANSWER" == "no" ]]; then
    UI_MOVE="back"
    return 0
  fi
  if [[ "$DRY_RUN" == "yes" ]]; then
    MENU_NOTES+=("A dry run writes nothing. The policy would have been saved to ${FLOW_DESTINATION}:" "$WIZARD_TEXT")
    MENU_RAN="yes"
    UI_MOVE="stop"
    return 0
  fi
  menu_save_policy
}

# Writes WIZARD_TEXT, or a copy of the file $1 when one is given, to FLOW_DESTINATION by giving a
# complete file its name, so that no reader ever sees half a policy. The destination is checked
# again first, since screens have passed since it was chosen: it must still be a place the policy
# may go, in the same directory. A file that appeared
# there is replaced only after a question, even one that appears in the last moment, because without
# agreement the save replaces nothing. Inside an image the file is first read by the policy system
# in a private directory beside the destination, which refuses a policy that lets the sandboxed
# command change that directory, and is saved only when it is accepted. Where the policy is not
# saved, UI_MOVE is back. Sets FLOW_POLICY.
menu_save_policy() {
  local confirmed="$FLOW_DESTINATION"
  local directory="${FLOW_DESTINATION%/*}"
  local probe
  local status=0
  menu_destination_problem "$confirmed"
  [[ -z "$REPLY" && "$FLOW_DESTINATION" != "$confirmed" ]] && REPLY="The directory of ${confirmed} now leads somewhere else."
  FLOW_DESTINATION="$confirmed"
  if [[ -n "$REPLY" ]]; then
    ui_message "Policy file" "Nothing was saved. ${REPLY}"
    UI_MOVE="back"
    return 0
  fi
  if [[ -e "$FLOW_DESTINATION" && "$FLOW_REPLACE" != "yes" ]]; then
    ui_yesno "Policy file" "${FLOW_DESTINATION} appeared while the policy was being written. Replace it?" no
    if [[ "$UI_MOVE" != "next" || "$UI_ANSWER" != "yes" ]]; then
      UI_MOVE="back"
      return 0
    fi
    FLOW_REPLACE="yes"
  fi
  probe="$(mktemp -d "${directory}/.phobos-policy.XXXXXXXX")" || fail_environment "cannot write in ${directory}"
  MENU_PROBE="$probe"
  mkdir "${probe}/specification"
  if (( $# > 0 )); then
    cp -- "$1" "${probe}/policy.cfg"
  else
    printf '%s' "$WIZARD_TEXT" > "${probe}/policy.cfg"
  fi
  chmod 0644 "${probe}/policy.cfg"
  if [[ "$MODE" == "image" ]]; then
    "${IMAGE_HOME}/phobos-policysystem.sh" --spec-dir "${probe}/specification" --config "${probe}/policy.cfg" \
      > "${probe}/check.log" 2>&1 || status=$?
    if (( status != 0 )); then
      MENU_REFUSAL="$status"
      menu_show_refusal "${probe}/check.log"
      rm -rf -- "$probe"
      MENU_PROBE=""
      UI_MOVE="back"
      return 0
    fi
  fi
  if [[ "$FLOW_REPLACE" == "yes" ]]; then
    menu_rename "${probe}/policy.cfg" "$FLOW_DESTINATION"
  else
    menu_link_new "${probe}/policy.cfg" "$FLOW_DESTINATION"
  fi
  rm -rf -- "$probe"
  MENU_PROBE=""
  if [[ "$REPLY" == "exists" ]]; then
    ui_yesno "Policy file" "${FLOW_DESTINATION} appeared while the policy was being saved. Replace it?" no
    if [[ "$UI_MOVE" != "next" || "$UI_ANSWER" != "yes" ]]; then
      UI_MOVE="back"
      return 0
    fi
    FLOW_REPLACE="yes"
    menu_save_policy "$@"
    return 0
  fi
  MENU_REFUSAL=""
  FLOW_POLICY="$FLOW_DESTINATION"
}

# Gives the file $1 the further name $2 with a single link(2), which never replaces anything: it
# fails when anything is named $2, a file, a directory or a link, and never follows a link there. So
# a destination nobody agreed to replace is never overwritten, even when something appears there in
# the last moment. Sets REPLY to "exists" when something was there and to empty when the name was
# given. perl's link does it, and GNU ln with -T. Ends the script when neither is there, or when the
# link failed for another reason.
menu_link_new() {
  local status=0
  if command -v perl > /dev/null 2>&1; then
    perl -e 'link($ARGV[0], $ARGV[1]) or exit 1' -- "$1" "$2" || status=$?
  elif ln --version > /dev/null 2>&1; then
    ln -T -- "$1" "$2" 2> /dev/null || status=$?
  else
    fail_environment "cannot save $2 safely: neither perl nor GNU ln is there to link it"
  fi
  REPLY=""
  if (( status != 0 )); then
    [[ -e "$2" || -L "$2" ]] || fail_environment "cannot save $2"
    REPLY="exists"
  fi
  return 0
}

# Renames the file $1 to the name $2 with a single rename(2), which replaces a file or a link named
# $2 itself and never follows a link there to a directory, as mv would by moving the file into it.
# GNU mv does that with -T, and elsewhere, macOS among them, perl's rename does. Ends the script
# when neither is there or the rename fails. Sets REPLY to empty.
menu_rename() {
  if mv --version > /dev/null 2>&1; then
    mv -f -T -- "$1" "$2" || fail_environment "cannot save $2"
  elif command -v perl > /dev/null 2>&1; then
    perl -e 'rename($ARGV[0], $ARGV[1]) or exit 1' -- "$1" "$2" || fail_environment "cannot save $2"
  else
    fail_environment "cannot save $2 safely: neither GNU mv nor perl is there to rename it"
  fi
  REPLY=""
  return 0
}

# Offers to run /bin/true under the new policy, which shows whether the policy system accepts it
# and the layers start with it, and shows how that ended. Its answer is kept apart from the run
# that follows: a failed check leads back to the policy only when asked.
menu_step_check() {
  local -a words=("${FLOW_WORDS[@]}")
  local -a options=("${FLOW_OPTIONS[@]}")
  ui_yesno "Check the policy" "Run /bin/true under the new policy now? It shows whether the policy system accepts the policy and the layers start with it."
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || return 0
  FLOW_WORDS=(/bin/true)
  FLOW_OPTIONS=()
  menu_execute_check
  FLOW_WORDS=("${words[@]}")
  FLOW_OPTIONS=("${options[@]}")
  [[ "$MENU_CHECKED" == "yes" ]] && return 0
  ui_yesno "Check the policy" "Go back and change the policy?"
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] && UI_MOVE="back"
  return 0
}

# Runs /bin/true under the saved policy as the way through would run its command, with its output
# kept rather than shown, and shows how it ended. Inside an image the policy is copied and checked
# first, as for any run. Sets MENU_CHECKED to yes when the check ended with 0.
menu_execute_check() {
  local policy="$FLOW_POLICY"
  local output
  MENU_CHECKED="no"
  if [[ "$MODE" == "image" ]]; then
    menu_stage_in_image
    [[ -n "$MENU_STAGED" ]] || return 0
    policy="$MENU_STAGED"
  fi
  menu_build_run "$policy"
  output="$(mktemp "${TMPDIR:-/tmp}/phobos-cli-check.XXXXXXXX")"
  MENU_CAPTURE="$output"
  menu_spawn_captured "$output" "${FLOW_ARGV[@]}"
  if (( MENU_STATUS == 0 )); then
    MENU_CHECKED="yes"
    ui_message "Check the policy" "The policy system accepted the policy, and /bin/true ran under it."
  else
    menu_show_tail "Check the policy" "The check ended with status ${MENU_STATUS}. The last lines it printed:" "$output"
  fi
  rm -f -- "$output"
  MENU_CAPTURE=""
}

# The way through "record a reference program": the questions, the recording and the policy it
# yields, then the policy saved and, when wanted, a command run under it. Takes the reason
# recording is not possible here, empty when it is. Since the recording itself has run, the menu
# ends after this way through; a refusal of the policy system that was not overcome by a later
# save is the status it ends with.
menu_flow_record() {
  local -a steps=(record_warning)
  MENU_RAN="no"
  if [[ -n "$1" ]]; then
    ui_message "Record" "Recording is not possible here: ${1}."
    return 0
  fi
  FLOW_PROJECT_ROOT=""
  [[ "$MODE" == "host" ]] && steps+=(language record_exercise networked)
  steps+=(recording command)
  menu_walk "${steps[@]}"
  [[ "$UI_MOVE" == "next" ]] || return 0
  MENU_RAN="yes"
  menu_record_sessions
  menu_record_generate
  if [[ "$DRY_RUN" == "yes" ]]; then
    MENU_NOTES+=("A dry run records nothing, so there is no policy yet to check, save or run.")
    return 0
  fi
  menu_record_check
  MENU_REFUSAL=""
  menu_walk destination save_recorded run_now command advanced confirm
  if [[ "$UI_MOVE" == "back" ]]; then
    record_policy_file "$FLOW_RECORDING"
    MENU_NOTES+=("The policy of the recording stays where it was generated: ${REPLY}")
  fi
  [[ "$UI_MOVE" == "next" ]] && menu_execute_run
  [[ -n "$MENU_REFUSAL" ]] && MENU_STATUS="$MENU_REFUSAL"
  return 0
}

# Warns that the program runs without a sandbox while it is recorded, and goes on only on Yes.
menu_step_record_warning() {
  ui_yesno "Record a reference program" "While it is recorded, the program runs with no sandbox at all: the recording pruner grants it everything and watches what it uses. Record your own reference program only, never a student submission.\n\nGo on?" no
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "no" ]] && UI_MOVE="back"
  return 0
}

# Asks for the directory of the reference program, which a host mounts read-only for the recording.
menu_step_record_exercise() {
  pick_directory "Reference exercise" "The directory of the reference program. It is mounted read-only and copied into the directory the program runs in." "${FLOW_EXERCISE:-$PWD}"
  [[ "$UI_MOVE" == "next" ]] && FLOW_EXERCISE="$PICKED_DIRECTORY"
  return 0
}

# Asks whether the recorded program needs to reach hosts on the network.
menu_step_networked() {
  ui_yesno "Network" "Does the program need to reach hosts on the network while it is recorded?" no
  [[ "$UI_MOVE" == "next" ]] && FLOW_NETWORKED="$UI_ANSWER"
  return 0
}

# Asks for the name of the recording until it is one the recording pruner takes.
menu_step_recording() {
  local offered="$FLOW_RECORDING"
  while :; do
    ui_input "Recording" "A name for the recording. Sessions recorded under one name make one policy." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    if [[ "$offered" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; then
      FLOW_RECORDING="$offered"
      return 0
    fi
    ui_message "Recording" "A name is up to 64 letters, digits, dots, hyphens and underscores, and begins with a letter or a digit."
  done
}

# Sets FLOW_ARGV and FLOW_SHOWN to the call of phobos-cli.sh's record command with the words given
# after it: on a host with the language, the exercise and the network chosen, inside an image as
# they are, since there is nothing to choose there.
menu_build_record() {
  local -a host=()
  if [[ "$MODE" == "host" ]]; then
    host=(--language "$FLOW_LANGUAGE" --exercise "$FLOW_EXERCISE")
    [[ "$FLOW_NETWORKED" == "yes" ]] && host+=(--networked)
  fi
  FLOW_ARGV=(record "${host[@]}" "$@")
  FLOW_SHOWN=("${FLOW_ARGV[@]}")
  return 0
}

# Records sessions of the program until no further one is wanted. The program has the terminal for
# each. A session that ends with a status other than 0 is kept only on Yes, since that status may
# be the program's own result or the recording's failure; otherwise the menu ends with it.
menu_record_sessions() {
  while :; do
    menu_build_record record --name "$FLOW_RECORDING" -- "${FLOW_WORDS[@]}"
    menu_spawn "${FLOW_ARGV[@]}"
    [[ "$DRY_RUN" == "yes" ]] && return 0
    if (( MENU_STATUS != 0 )); then
      ui_yesno "Record" "The session ended with status ${MENU_STATUS}. That may be the program's own result, or the recording may have failed; the output above the menu says which.\n\nKeep the recording and go on?" no
      [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || menu_finish "$MENU_STATUS"
    fi
    ui_yesno "Record" "Record another session of the program, for a path the first did not take?" no
    [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || return 0
  done
}

# Generates the policy of the recording from its sessions, and ends the menu with the status of
# generate when that is not 0.
menu_record_generate() {
  menu_build_record generate --name "$FLOW_RECORDING"
  menu_spawn "${FLOW_ARGV[@]}"
  (( MENU_STATUS == 0 )) || menu_finish "$MENU_STATUS"
  return 0
}

# Offers on a host to replay a session under phobos.sh with the generated policy, in a new
# container, which fails on every refusal of something the recording did, and asks for a resolver
# when the program needs the network. A failed replay ends the menu with its status unless the
# policy is kept on Yes. Inside an image a replay is not possible, because it needs a container of
# its own, and the menu says how to make it from a host.
menu_record_check() {
  local -a resolver=()
  local command
  if [[ "$MODE" == "image" ]]; then
    command="$(printf '%q ' "${FLOW_WORDS[@]}")"
    ui_message "Check" "A replay of the recording needs a container of its own, which cannot be started from here. Make it from a host whose checkout holds this recording in build/pruner/recordings, with the language and the reference directory it was recorded from, and --networked when it needed the network:\n\nphobos-cli.sh record --language <language> --exercise <reference directory> check --name ${FLOW_RECORDING} -- ${command% }"
    return 0
  fi
  ui_yesno "Check" "Replay the session under phobos.sh with the generated policy, in a new container? The replay fails on every refusal of something the recording did."
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || return 0
  while [[ "$FLOW_NETWORKED" == "yes" ]]; do
    ui_input "Check" "The resolver phobos.sh gives the network layer for a host name in the policy, as ip or ip:port. Leave it empty when the policy names no host by name." "$FLOW_RESOLVER"
    [[ "$UI_MOVE" == "next" ]] || return 0
    if [[ -z "$UI_RESULT" || "$UI_RESULT" =~ ^[0-9A-Fa-f.:]+$ ]]; then
      FLOW_RESOLVER="$UI_RESULT"
      break
    fi
    ui_message "Check" "A resolver is an address with an optional port, such as 10.0.0.53 or 10.0.0.53:53."
  done
  [[ -n "$FLOW_RESOLVER" ]] && resolver=(--resolver "$FLOW_RESOLVER")
  menu_build_record check --name "$FLOW_RECORDING" "${resolver[@]}" -- "${FLOW_WORDS[@]}"
  menu_spawn "${FLOW_ARGV[@]}"
  (( MENU_STATUS == 0 )) && return 0
  ui_yesno "Check" "The replay ended with status ${MENU_STATUS}, so the policy may lack something the program needs.\n\nSave the policy all the same?" no
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || menu_finish "$MENU_STATUS"
  return 0
}

# Saves the policy the recording yielded to the destination chosen, through the same save as a
# written policy, once generate is seen to have left a regular file there and not a link, and checks
# that the saved file is that policy. Ends the menu when there is no policy to save.
menu_step_save_recorded() {
  local source
  record_policy_file "$FLOW_RECORDING"
  source="$REPLY"
  if [[ -L "$source" || ! -f "$source" ]]; then
    ui_message "Save" "The recording left no policy at ${source}, so there is nothing to save."
    menu_finish "${EXIT_ENVIRONMENT}"
  fi
  menu_save_policy "$source"
  [[ "$UI_MOVE" == "next" ]] || return 0
  cmp -s -- "$source" "$FLOW_DESTINATION" || fail_environment "${FLOW_DESTINATION} is not the policy the recording yielded"
  return 0
}

# Asks whether to run a command under the saved policy now, and ends the way through on No. Inside
# the prune image it says that such a run is not the run grading makes.
menu_step_run_now() {
  local text="The policy is saved. Run a command under it now?"
  [[ "$MODE" == "image" ]] && text+="\n\nThis is the prune image, whose base policy grants nothing, so a run here is not the run grading makes in a run-phase image."
  ui_yesno "Run" "$text"
  [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "no" ]] && UI_MOVE="stop"
  return 0
}
