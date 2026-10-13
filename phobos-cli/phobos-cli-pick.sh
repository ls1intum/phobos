#!/bin/bash
# shellcheck shell=bash
# The choices the flows of the menu share: a language, a directory, a policy file and a command.
#
# Each function asks with the boxes of phobos-cli-ui.sh, checks the answer and asks again until it
# is usable or the person goes back. It returns 0 and reports through UI_MOVE and the PICKED_*
# variables it names, for the reason phobos-cli-ui.sh gives. Nothing here decides what a run may
# reach: every answer ends up as an option of phobos-cli.sh, which checks it again and refuses what
# it would refuse from a command line.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh and
# phobos-cli-ui.sh. It starts nothing while it is sourced.
# The answers set here are read by the other files of this folder and never in this one, so
# SC2034 fires on them by design when this file is checked on its own; checked through
# phobos-cli.sh, which sources every file, it does not.
# shellcheck disable=SC2034

# The languages a run-phase image exists for, in the order the menu offers them.
PICK_LANGUAGES=(java python c-fact r swift c-gcc cpp)
# What each language is called in the menu.
PICK_LANGUAGE_TITLES=("Java (Gradle or Maven)" "Python" "C (FACT template)" "R" "Swift" "C (GCC template)" "C++")
# The command offered for a language whose exercise has no build script.
PICK_COMMANDS=("./gradlew test" "python3 -m pytest" "make" "" "swift test" "make" "make")
# How deep and how many policy files the search goes and lists, so that a large tree stays quick.
PICK_SEARCH_DEPTH=8
PICK_SEARCH_LIMIT=200
# What the choices were answered with.
PICKED_LANGUAGE=""
PICKED_IMAGE=""
PICKED_DIRECTORY=""
PICKED_POLICY=""
PICKED_WORDS=()
# The policy files the last search found.
PICK_FOUND=()

# Asks for the language of the exercise, which decides the run-phase image. With $1 set to image it
# first offers to name an image instead, for a command that runs it with --image. When UI_MOVE is
# next, PICKED_LANGUAGE holds the language and PICKED_IMAGE is empty, or PICKED_IMAGE holds the image
# and PICKED_LANGUAGE is empty.
pick_language() {
  local -a items=()
  local index
  [[ "${1:-}" == "image" ]] && items+=(0 "Other image (name it)")
  for index in "${!PICK_LANGUAGES[@]}"; do
    items+=("$((index + 1))" "${PICK_LANGUAGE_TITLES[index]}")
  done
  while :; do
    ui_menu "Language" "Which language is the exercise written in? It decides the image the command runs in." "${items[@]}"
    [[ "$UI_MOVE" == "next" ]] || return 0
    if [[ "$UI_RESULT" != "0" ]]; then
      PICKED_LANGUAGE="${PICK_LANGUAGES[UI_RESULT - 1]}"
      PICKED_IMAGE=""
      return 0
    fi
    pick_image
    if [[ "$UI_MOVE" == "next" ]]; then
      PICKED_LANGUAGE=""
      return 0
    fi
  done
}

# Asks for the name of a run-phase image, such as a grading image that embeds Phobos, until the name
# is one --image takes. PICKED_IMAGE holds it when UI_MOVE is next. The run applies the base policy
# that image ships, so naming one grants nothing beyond what the image itself grants. Assumes
# IMAGE_HOME is set.
pick_image() {
  local offered="$PICKED_IMAGE"
  while :; do
    ui_input "Image" "The name of a run-phase image that holds Phobos in ${IMAGE_HOME}, such as a grading image built on one. The command runs in it under the base policy that image ships." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    if image_name "$offered"; then
      PICKED_IMAGE="$offered"
      return 0
    fi
    ui_message "Image" "That is not an image name. Give one such as registry.example/phobos:latest: letters, digits and . _ / : @ -, beginning with a letter or a digit."
  done
}

# Asks for a directory under the title $1 with the prompt $2, offering $3, until the answer names an
# existing directory. With $4 set to create, a path that names nothing yet is created after a
# question, except in a dry run, which creates nothing. PICKED_DIRECTORY holds its physical path when
# UI_MOVE is next. Assumes DRY_RUN is set.
pick_directory() {
  local title="$1"
  local prompt="$2"
  local offered="$3"
  local create="${4:-}"
  local usable
  local asked
  local physical
  while :; do
    ui_input "$title" "$prompt" "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    ui_printable "$offered"
    usable="$REPLY"
    [[ -n "$offered" ]] || usable="no"
    REPLY=""
    [[ "$usable" == "yes" && "$create" == "create" ]] && pick_create_directory "$title" "$offered"
    asked="$REPLY"
    if [[ "$usable" == "yes" && -d "$offered" ]]; then
      physical="$(cd -- "$offered" && pwd -P; printf x)"
      physical="${physical%x}"
      PICKED_DIRECTORY="${physical%$'\n'}"
      return 0
    fi
    [[ "$asked" == "asked" ]] || pick_directory_refused "$title" "$create" "$offered"
  done
}

# Offers, under the title $1, to create the directory $2 with its missing parents when $2 names
# nothing yet, and creates it on Yes. Asks nothing for a path that exists, of whatever kind, nor in a
# dry run. Sets REPLY to asked when it asked, whatever the answer, and to nothing otherwise, and
# leaves UI_MOVE at next, since Esc only declines. Assumes $2 holds no control character and
# DRY_RUN is set.
pick_create_directory() {
  REPLY=""
  [[ -e "$2" || -L "$2" || "$DRY_RUN" == "yes" ]] && return 0
  ui_yesno "$1" "${2} does not exist. Create it?"
  if [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]]; then
    mkdir -p -- "$2" 2> /dev/null || ui_message "$1" "${2} could not be created. Give another directory, or create it yourself first."
  fi
  UI_MOVE="next"
  REPLY="asked"
  return 0
}

# Says, under the title $1, that the answer $3 named no existing directory, and, where $2 is create,
# this is a dry run and $3 names nothing at all, why it was not offered to be created. Assumes
# DRY_RUN is set.
pick_directory_refused() {
  local text="That is not an existing directory. Give the path of one, absolute or relative to the directory the menu was started in."
  [[ "$2" == "create" && "$DRY_RUN" == "yes" && -n "$3" && ! -e "$3" && ! -L "$3" ]] && text+=" A dry run creates nothing; without --dry-run the menu offers to create it."
  ui_message "$1" "$text"
}

# Sets PICK_FOUND to the policy files beneath the directory $1, sorted and at most PICK_SEARCH_LIMIT
# of them, leaving out version control, build output and dependency folders and every name that
# holds a control character. Assumes $1 is a physical path.
pick_find_policies() {
  local path
  PICK_FOUND=()
  while IFS= read -r -d '' path; do
    ui_printable "$path"
    [[ "$REPLY" == "yes" ]] || continue
    PICK_FOUND+=("$path")
    (( ${#PICK_FOUND[@]} < PICK_SEARCH_LIMIT )) || break
  done < <(find "$1" -maxdepth "${PICK_SEARCH_DEPTH}" \( -name .git -o -name build -o -name node_modules -o -name .gradle \) -prune \
             -o -type f \( -name '*.cfg' -o -name '*.yaml' -o -name '*.yml' \) -print0 2> /dev/null | sort -z)
}

# Sets REPLY to "yes" when the directory $1 (a physical path, empty for the root) is the directory $2
# or lies beneath it, and to "no" otherwise.
pick_beneath() {
  REPLY="no"
  [[ "$1" == "$2" || "$1" == "$2/"* ]] && REPLY="yes"
  return 0
}

# Sets REPLY to "yes" when the exercise directory $2 (a physical path) has a say in which file the
# path $1 names, and to "no" otherwise. The path is resolved one component at a time, the way the
# kernel would, and the answer is yes when the file lies in the exercise, or when any symbolic link
# on the way, a file link or a directory link, lies in it: a submission controls such a link and so
# where it leads, even when the path both begins and ends outside the exercise. A path whose links
# do not end, that leads nowhere, or that passes a link whose target holds a control character,
# which the shell could not follow exactly as the kernel does, counts as inside.
pick_inside() {
  local exercise="$2"
  local current=""
  local component
  local target
  local hops=0
  local -a pending=()
  local -a parts=()
  [[ "$1" == /* ]] || current="$(pwd -P)"
  IFS=/ read -r -a pending <<<"$1"
  while (( ${#pending[@]} > 0 )); do
    component="${pending[0]}"
    pending=("${pending[@]:1}")
    case "$component" in
      "" | .) continue ;;
      ..)
        current="${current%/*}"
        continue
        ;;
    esac
    if [[ -L "${current}/${component}" ]]; then
      pick_beneath "$current" "$exercise"
      [[ "$REPLY" == "yes" ]] && return 0
      hops=$((hops + 1))
      if (( hops > 40 )); then
        REPLY="yes"
        return 0
      fi
      target="$(readlink -- "${current}/${component}"; printf x)"
      target="${target%x}"
      target="${target%$'\n'}"
      ui_printable "$target"
      if [[ "$REPLY" != "yes" ]]; then
        REPLY="yes"
        return 0
      fi
      [[ "$target" == /* ]] && current=""
      IFS=/ read -r -a parts <<<"$target"
      pending=("${parts[@]}" "${pending[@]}")
      continue
    fi
    current="${current}/${component}"
  done
  if [[ ! -e "$current" ]]; then
    REPLY="yes"
    return 0
  fi
  pick_beneath "${current%/*}" "$exercise"
  return 0
}

# Asks for a policy file, listing those found beneath the directory $1 (a physical path) and
# offering to type a path instead, as the last entry. The tags count from 1 in the order shown,
# because dialog takes a digit key as the position of an entry, not as its tag. One that lies inside the exercise directory $2 (a physical path,
# empty for none) is used only after a second confirmation, because a submission can place a
# policy there. PICKED_POLICY holds the chosen file when UI_MOVE is next.
pick_policy() {
  local base="$1"
  local exercise="$2"
  local -a items=()
  local index
  local chosen
  pick_find_policies "$base"
  while :; do
    items=()
    for index in "${!PICK_FOUND[@]}"; do
      items+=("$((index + 1))" "./${PICK_FOUND[index]#"$base"/}")
    done
    items+=("$((${#PICK_FOUND[@]} + 1))" "Enter the path of a policy file")
    ui_menu "Policy" "Which policy should the command run under? A .cfg file is a Phobos policy, a .yaml or .yml file an Ares 2 security policy. Found ${#PICK_FOUND[@]} beneath ${base}." "${items[@]}"
    [[ "$UI_MOVE" == "next" ]] || return 0
    if (( UI_RESULT == ${#PICK_FOUND[@]} + 1 )); then
      ui_input "Policy" "The path of the policy file, absolute or relative to the directory the menu was started in:" "./"
      [[ "$UI_MOVE" == "next" ]] || continue
      chosen="$UI_RESULT"
      ui_printable "$chosen"
      if [[ "$REPLY" != "yes" || ! -f "$chosen" ]]; then
        ui_message "Policy" "That is not an existing file."
        continue
      fi
    else
      chosen="${PICK_FOUND[UI_RESULT - 1]}"
    fi
    if [[ -n "$exercise" ]]; then
      pick_inside "$chosen" "$exercise"
      if [[ "$REPLY" == "yes" ]]; then
        ui_yesno "Policy inside the exercise" "This policy lies inside the exercise directory. A submission can place a policy file there that grants it whatever it wants, so a policy for grading belongs with the instructor's files, not with the exercise.\n\nUse it anyway?" no
        [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] || continue
      fi
    fi
    PICKED_POLICY="$chosen"
    UI_MOVE="next"
    return 0
  done
}

# Sets REPLY to the command offered for an exercise in the directory $1 (empty when there is none)
# written in the language $2 (empty when it is not known): its build script when it has one, the
# usual test command of the language otherwise.
pick_offered_command() {
  local index
  REPLY=""
  if [[ -n "$1" && -f "$1/build_script.sh" ]]; then
    REPLY="./build_script.sh"
    return 0
  fi
  for index in "${!PICK_LANGUAGES[@]}"; do
    [[ "${PICK_LANGUAGES[index]}" == "$2" ]] && REPLY="${PICK_COMMANDS[index]}"
  done
  return 0
}

# Asks for the command to run, offering $1, until the answer is one or more words without a control
# character. The words are split at spaces and tabs only: no quote, variable or wildcard is
# interpreted, so what is shown is what runs. PICKED_WORDS holds them when UI_MOVE is next.
pick_command() {
  local offered="$1"
  while :; do
    ui_input "Command" "The command to run in the exercise directory, as its words separated by spaces. Quotes, variables and wildcards are not interpreted, so a word cannot hold a space. Name a program in the exercise by its path, for example ./gradlew." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    ui_printable "$offered"
    if [[ "$REPLY" == "yes" ]]; then
      IFS=$' \t' read -r -a PICKED_WORDS <<<"$offered"
      (( ${#PICKED_WORDS[@]} > 0 )) && return 0
    fi
    ui_message "Command" "Give a command of one or more words, without control characters."
  done
}
