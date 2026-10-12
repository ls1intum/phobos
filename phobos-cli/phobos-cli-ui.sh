#!/bin/bash
# shellcheck shell=bash
# The boxes of the menu: one function per kind of box, each drawn by dialog on the terminal.
#
# Every function here returns 0 and reports through the UI_* variables, so that no caller has to
# test one as a condition: a function called as a condition runs with set -e switched off for
# everything it calls, and the menu relies on set -e. dialog is started with a fixed configuration:
# the variables that would let the environment change its options, its colours or its exit
# statuses are replaced, so a cancellation can never read as a choice and an error never as a
# cancellation. Text the menu shows from outside (a path, a command) is checked for control
# characters before it is drawn, and is never passed as an argument of its own, so it cannot be
# read as an option of dialog.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh. It starts nothing
# while it is sourced.
# The answers set here are read by the other files of this folder and never in this one, so
# SC2034 fires on them by design when this file is checked on its own; checked through
# phobos-cli.sh, which sources every file, it does not.
# shellcheck disable=SC2034

# The statuses dialog is told to end with. Each is distinct, so an error is told apart from Cancel
# and Esc.
UI_STATUS_OK=0
UI_STATUS_CANCEL=1
UI_STATUS_HELP=2
UI_STATUS_EXTRA=3
UI_STATUS_ITEM_HELP=4
UI_STATUS_ESC=5
UI_STATUS_ERROR=6
UI_STATUS_TIMEOUT=7
# The title on the backdrop of every box.
UI_BACKTITLE="Phobos"
# How the last box was left: next (OK, Yes, No or a choice) or back (Cancel or Esc).
UI_MOVE=""
# The answer of the last box: the text dialog returned, the yes or no of a question, the fields of
# a form.
UI_RESULT=""
UI_ANSWER=""
UI_FIELDS=()
# The status dialog ended the last box with.
UI_STATUS=0

# Ends the script unless dialog can be started, naming how to install it. Assumes the startup
# cleaning has made PATH safe to look it up in.
ui_require_dialog() {
  command -v dialog > /dev/null 2>&1 || fail_environment "the menu needs dialog, which is not on PATH; install it (brew install dialog, or apt-get install dialog) or call phobos-cli.sh with a command (see --help)"
}

# Draws one box with the arguments given and sets UI_STATUS, UI_MOVE and UI_RESULT from the answer.
# The result comes back on file descriptor 3, which is open only while dialog runs, and the box
# itself is drawn on the terminal the menu runs in. A status dialog reserves for errors, or any
# status it was not told to use, ends the script, because the box was not shown as asked.
ui_box() {
  UI_STATUS=0
  exec 4>&1
  UI_RESULT="$(env -u DIALOGOPTS -u DIALOG_TTY DIALOGRC=/dev/null \
    DIALOG_OK="${UI_STATUS_OK}" DIALOG_CANCEL="${UI_STATUS_CANCEL}" DIALOG_HELP="${UI_STATUS_HELP}" \
    DIALOG_EXTRA="${UI_STATUS_EXTRA}" DIALOG_ITEM_HELP="${UI_STATUS_ITEM_HELP}" DIALOG_ESC="${UI_STATUS_ESC}" \
    DIALOG_ERROR="${UI_STATUS_ERROR}" DIALOG_TIMEOUT="${UI_STATUS_TIMEOUT}" \
    dialog --backtitle "${UI_BACKTITLE}" --output-fd 3 "$@" 3>&1 1>&4 4>&-)" || UI_STATUS=$?
  exec 4>&-
  case "$UI_STATUS" in
    "${UI_STATUS_OK}") UI_MOVE="next" ;;
    "${UI_STATUS_CANCEL}" | "${UI_STATUS_ESC}") UI_MOVE="back" ;;
    *) fail_environment "dialog could not show the box and ended with status ${UI_STATUS}; a terminal of at least 80 columns and 24 lines is needed" ;;
  esac
  return 0
}

# Sets REPLY to "yes" when $1 holds no control character but the tab, and to "no" otherwise. A
# control character in text shown on a terminal can move the cursor or change what is displayed.
ui_printable() {
  REPLY="yes"
  [[ "${1//$'\t'/ }" =~ [[:cntrl:]] ]] && REPLY="no"
  return 0
}

# Shows the message $2 under the title $1 until it is acknowledged or left with Esc.
ui_message() {
  ui_box --title "$1" --msgbox "$2" 0 0
}

# Asks the question $2 under the title $1. UI_ANSWER is yes or no and UI_MOVE next when it was
# answered, and UI_MOVE is back when it was left with Esc. With $3 set to "no", the No button is
# the one chosen by default.
ui_yesno() {
  local -a options=()
  [[ "${3:-yes}" == "no" ]] && options+=(--defaultno)
  ui_box --title "$1" "${options[@]}" --yesno "$2" 0 0
  UI_ANSWER="yes"
  if [[ "$UI_STATUS" == "${UI_STATUS_CANCEL}" ]]; then
    UI_ANSWER="no"
    UI_MOVE="next"
  fi
  return 0
}

# Asks for one line of text under the title $1 with the prompt $2, offering $3 as the answer. The
# answer is UI_RESULT when UI_MOVE is next.
ui_input() {
  ui_box --title "$1" --inputbox "$2" 0 0 "$3"
}

# Offers a choice under the title $1 with the prompt $2. The words after those come in pairs, a
# numeric tag and the text shown for it. The chosen tag is UI_RESULT when UI_MOVE is next. A tag is
# used as an index by the callers, and shell arithmetic would run a command named in one, so an
# answer that is not one of the tags offered ends the script.
ui_menu() {
  local title="$1"
  local prompt="$2"
  local -a tags=()
  local index
  shift 2
  for (( index = 1; index <= $#; index += 2 )); do
    tags+=("${!index}")
  done
  ui_box --title "$title" --menu "$prompt" 0 0 0 "$@"
  [[ "$UI_MOVE" == "next" ]] || return 0
  for index in "${tags[@]}"; do
    [[ "$UI_RESULT" == "$index" ]] && return 0
  done
  fail_environment "dialog answered the menu with a choice it did not offer"
}

# Shows a form under the title $1 with the prompt $2. The words after those come in pairs, the
# label of a field and the value it starts with. UI_FIELDS holds the values in the order of the
# fields when UI_MOVE is next, an empty one for a field left empty.
ui_form() {
  local title="$1"
  local prompt="$2"
  local -a fields=()
  local row=1
  local count=0
  shift 2
  while (( $# >= 2 )); do
    fields+=("$1" "$row" 1 "$2" "$row" 24 32 0)
    row=$((row + 1))
    count=$((count + 1))
    shift 2
  done
  ui_box --title "$title" --form "$prompt" 0 0 0 "${fields[@]}"
  UI_FIELDS=()
  [[ "$UI_MOVE" == "next" ]] || return 0
  mapfile -t UI_FIELDS <<<"$UI_RESULT"
  while (( ${#UI_FIELDS[@]} < count )); do
    UI_FIELDS+=("")
  done
  return 0
}

# Offers several choices under the title $1 with the prompt $2. The words after those come in
# threes, a numeric tag, the text shown for it and on or off for whether it starts ticked. UI_FIELDS
# holds the ticked tags when UI_MOVE is next, none when nothing was ticked. A tag is used as an
# index by the callers, so an answer that is not one of the tags offered ends the script.
ui_checklist() {
  local title="$1"
  local prompt="$2"
  local -a tags=()
  local -a ticked=()
  local index
  local tag
  local known
  shift 2
  for (( index = 1; index <= $#; index += 3 )); do
    tags+=("${!index}")
  done
  ui_box --title "$title" --separate-output --checklist "$prompt" 0 0 0 "$@"
  UI_FIELDS=()
  [[ "$UI_MOVE" == "next" ]] || return 0
  mapfile -t ticked <<<"$UI_RESULT"
  for tag in "${ticked[@]}"; do
    [[ -n "$tag" ]] || continue
    known="no"
    for index in "${tags[@]}"; do
      [[ "$tag" == "$index" ]] && known="yes"
    done
    [[ "$known" == "yes" ]] || fail_environment "dialog answered the checklist with a choice it did not offer"
    UI_FIELDS+=("$tag")
  done
  return 0
}
