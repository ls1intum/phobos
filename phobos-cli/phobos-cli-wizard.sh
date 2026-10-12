#!/bin/bash
# shellcheck shell=bash
# The policy assistant of the menu: a new Phobos policy, written section by section from answers.
#
# Each section of the policy reference has an editor here that asks for its entries in the shape
# its grammar takes and refuses what it plainly cannot hold: a relative path, a port out of range,
# a timeout with the wrong number of decimals. Those checks only spare a round trip. The policy
# system is what decides, and the menu has it read the finished file before anything runs under
# it. Like the rest of the menu, every function returns 0 and reports through UI_MOVE and the
# WIZARD_* variables.
#
# Sourced by phobos-cli.sh alone, at the top level, after phobos-cli-common.sh, phobos-cli-ui.sh and
# phobos-cli-pick.sh. It starts nothing while it is sourced.
# The entries and the rendered text are read by phobos-cli-menu.sh and never in this file, so
# SC2034 fires on them by design when this file is checked on its own; checked through
# phobos-cli.sh, which sources every file, it does not.
# shellcheck disable=SC2034

# The sections of a policy, in the order of the policy reference, and what each grants, in a line.
WIZARD_SECTIONS=(read execute write create delete create-ipc create-symlink restructure ioctl connect bind accept limits)
WIZARD_HINTS=(
  "paths that may be read"
  "paths whose files may be executed"
  "paths whose existing files may be written and shortened"
  "paths where files and directories may be created"
  "paths whose files and directories may be deleted"
  "paths where sockets and named pipes may be created"
  "paths where symbolic links may be created"
  "paths that may be created in, deleted in and rearranged"
  "device paths that take ioctl calls"
  "outbound hosts and ports"
  "local ports that may be listened on"
  "a listener exposed behind a source filter"
  "the timeout and the five resource limits"
)
# The keys of [limits], in the order the form shows them, and what each is.
WIZARD_LIMIT_KEYS=(timeout cpu mem_mb nproc nofile fsize_mb)
WIZARD_LIMIT_LABELS=("timeout (seconds)" "cpu (seconds)" "mem_mb (megabytes)" "nproc (processes)" "nofile (open files)" "fsize_mb (megabytes)")
# The entries of each section, one per line, keyed by the section's name, and the limits by key.
declare -A WIZARD_ENTRIES=()
declare -A WIZARD_LIMITS=()
# The sections chosen to fill, by name.
WIZARD_CHOSEN=()
# The entries of the section being edited, one per element.
WIZARD_LIST=()
# The policy as it will be written.
WIZARD_TEXT=""

# Clears every answer, so that a second way through the assistant starts from an empty policy.
wizard_reset() {
  WIZARD_ENTRIES=()
  WIZARD_LIMITS=()
  WIZARD_CHOSEN=()
  WIZARD_TEXT=""
}

# Sets WIZARD_LIST to the entries of the section $1.
wizard_list() {
  WIZARD_LIST=()
  [[ -n "${WIZARD_ENTRIES[$1]:-}" ]] && mapfile -t WIZARD_LIST <<<"${WIZARD_ENTRIES[$1]}"
  return 0
}

# Adds the entry $2 to the section $1 unless it holds it already.
wizard_add() {
  local entry
  wizard_list "$1"
  for entry in "${WIZARD_LIST[@]}"; do
    [[ "$entry" == "$2" ]] && return 0
  done
  WIZARD_LIST+=("$2")
  WIZARD_ENTRIES[$1]="$(printf '%s\n' "${WIZARD_LIST[@]}")"
}

# Removes the entry at position $2, counted from 1, from the section $1.
wizard_remove() {
  wizard_list "$1"
  unset 'WIZARD_LIST[$2 - 1]'
  WIZARD_ENTRIES[$1]=""
  (( ${#WIZARD_LIST[@]} > 0 )) && WIZARD_ENTRIES[$1]="$(printf '%s\n' "${WIZARD_LIST[@]}")"
  return 0
}

# Sets REPLY to "yes" when $1 is a whole number from $2 to $3 without a sign or a leading zero.
wizard_number_in() {
  REPLY="no"
  [[ "$1" =~ ^(0|[1-9][0-9]{0,5})$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )) && REPLY="yes"
  return 0
}

# Sets REPLY to the reason the path $1 cannot stand in a section, or to empty when it can: it must
# be absolute, and hold no wildcard, no comment sign, no control character and no space at its ends,
# because Phobos takes a path as written, one per line.
wizard_path_problem() {
  REPLY=""
  ui_printable "$1"
  if [[ "$REPLY" != "yes" ]]; then
    REPLY="A path cannot hold a control character."
  elif [[ "$1" != /* ]]; then
    REPLY="A path must be absolute, beginning with /. Phobos does not expand ~, variables or quotes."
  elif [[ "$1" == *[\*\?\[#]* ]]; then
    REPLY="A path cannot hold *, ?, [ or #. Phobos takes a path as written, so it would name the one entry with that literal name."
  elif [[ "$1" == [[:space:]]* || "$1" == *[[:space:]] ]]; then
    REPLY="A path cannot begin or end with a space."
  else
    REPLY=""
  fi
  return 0
}

# Sets REPLY to the reason the destination $1 of a [connect] rule cannot stand, or to empty when it
# can: a host, an address, a range or *, with a port from 1 to 65535 or * after a colon, and an
# address of the sixth version in brackets when it carries a port. Whether a host may go without a
# port is the policy system's decision.
wizard_destination_problem() {
  local port=""
  REPLY=""
  ui_printable "$1"
  if [[ "$REPLY" != "yes" || -z "$1" || "$1" =~ [[:space:]#] ]]; then
    REPLY="Give one host, address or range, with no space, no # and no control character."
    return 0
  fi
  REPLY=""
  if [[ "$1" =~ ^\[[^]]+\](:(.*))?$ ]]; then
    port="${BASH_REMATCH[2]}"
  elif [[ "$1" =~ ^[^:]+:([^:]*)$ ]]; then
    port="${BASH_REMATCH[1]}"
  elif [[ "$1" == *:*:* ]]; then
    return 0
  fi
  [[ -n "$port" || "$1" != *: ]] || REPLY="A colon must be followed by a port."
  if [[ -n "$port" && "$port" != "*" ]]; then
    wizard_number_in "$port" 1 65535
    if [[ "$REPLY" == "yes" ]]; then
      REPLY=""
    else
      REPLY="A port is a whole number from 1 to 65535, or *."
    fi
  fi
  return 0
}

# Sets REPLY to the reason the value $2 cannot stand for the limit $1, or to empty when it can: a
# whole number, and for the timeout whole or with exactly three decimals, with no leading zero.
wizard_limit_problem() {
  REPLY=""
  [[ -z "$2" ]] && return 0
  if [[ "$1" == "timeout" ]]; then
    [[ "$2" =~ ^(0|[1-9][0-9]{0,14})(\.[0-9]{3})?$ ]] || REPLY="A timeout is a number of seconds, whole or with exactly three decimals, such as 120 or 2.500."
  else
    [[ "$2" =~ ^(0|[1-9][0-9]{0,17})$ ]] || REPLY="${1} is a whole number without a leading zero."
  fi
  return 0
}

# Asks which sections to fill, with what each grants. WIZARD_CHOSEN holds their names when UI_MOVE
# is next; choosing none is allowed and makes a policy that adds nothing to the base.
wizard_choose_sections() {
  local -a items=()
  local index
  local tag
  local state
  for index in "${!WIZARD_SECTIONS[@]}"; do
    state="off"
    for tag in "${WIZARD_CHOSEN[@]}"; do
      [[ "$tag" == "${WIZARD_SECTIONS[index]}" ]] && state="on"
    done
    items+=("$((index + 1))" "[${WIZARD_SECTIONS[index]}] ${WIZARD_HINTS[index]}" "$state")
  done
  ui_checklist "Sections" "Which sections should the new policy fill? Everything a section does not name stays denied, and the image's own base policy is applied beneath it. Space ticks a section." "${items[@]}"
  [[ "$UI_MOVE" == "next" ]] || return 0
  WIZARD_CHOSEN=()
  for tag in "${UI_FIELDS[@]}"; do
    WIZARD_CHOSEN+=("${WIZARD_SECTIONS[tag - 1]}")
  done
  return 0
}

# Lists the entries of the section $1 with the hint $2 and asks what to do: remove an entry, add
# one, or finish the section. Sets UI_RESULT to "add", "done" or the position of an entry, counted
# from 1, when UI_MOVE is next.
wizard_entry_menu() {
  local section="$1"
  local -a items=()
  local index
  local count
  wizard_list "$section"
  count="${#WIZARD_LIST[@]}"
  for index in "${!WIZARD_LIST[@]}"; do
    items+=("$((index + 1))" "Remove: ${WIZARD_LIST[index]}")
  done
  items+=("$((count + 1))" "Add an entry" "$((count + 2))" "Done with [${section}]")
  ui_menu "[${section}]" "${2}. ${count} entries so far." "${items[@]}"
  [[ "$UI_MOVE" == "next" ]] || return 0
  if (( UI_RESULT == count + 1 )); then
    UI_RESULT="add"
  elif (( UI_RESULT == count + 2 )); then
    UI_RESULT="done"
  fi
  return 0
}

# Asks for one entry of the section $1 and adds it once it can stand. Sets UI_MOVE to back when the
# question was left, so the section's list is shown again.
wizard_ask_entry() {
  case "$1" in
    connect) wizard_ask_connect ;;
    bind) wizard_ask_bind ;;
    accept) wizard_ask_accept ;;
    *) wizard_ask_path "$1" ;;
  esac
}

# Asks for a path of the section $1 until it can stand, and adds it.
wizard_ask_path() {
  local offered="/"
  while :; do
    ui_input "[${1}]" "An absolute path. A directory grants its whole tree. Inside an image, a path in [read] or [execute] must exist." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    wizard_path_problem "$offered"
    if [[ -z "$REPLY" ]]; then
      wizard_add "$1" "$offered"
      return 0
    fi
    ui_message "[${1}]" "$REPLY"
  done
}

# Sets REPLY to tcp or udp, asking which transport a rule is for, and UI_MOVE to back when left.
wizard_ask_transport() {
  ui_menu "Transport" "Which transport is the rule for?" 1 "tcp, a stream (the default)" 2 "udp, datagrams (needs Landlock version 10 where a port is named)"
  REPLY="tcp"
  [[ "$UI_MOVE" == "next" && "$UI_RESULT" == "2" ]] && REPLY="udp"
  return 0
}

# Asks for a [connect] rule until it can stand, and adds it.
wizard_ask_connect() {
  local offered=""
  local destination
  while :; do
    ui_input "[connect]" "The host and port to allow, as host:port. The host may be an address, a range such as 198.51.100.0/24, an exact host name (which needs --resolver), localhost, or * for every host. Write an address of the sixth version in brackets: [2001:db8::1]:443." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    wizard_destination_problem "$offered"
    [[ -z "$REPLY" ]] && break
    ui_message "[connect]" "$REPLY"
  done
  destination="$offered"
  wizard_ask_transport
  [[ "$UI_MOVE" == "next" ]] || return 0
  if [[ "$REPLY" == "udp" ]]; then
    wizard_add connect "allow ${destination} udp"
  else
    wizard_add connect "allow ${destination}"
  fi
}

# Asks for a [bind] rule until it can stand, and adds it.
wizard_ask_bind() {
  local offered=""
  local port
  while :; do
    ui_input "[bind]" "The local port the command may listen on, from 1 to 65535, or 0 for a port the kernel chooses." "$offered"
    [[ "$UI_MOVE" == "next" ]] || return 0
    offered="$UI_RESULT"
    wizard_number_in "$offered" 0 65535
    [[ "$REPLY" == "yes" ]] && break
    ui_message "[bind]" "A port is a whole number from 0 to 65535, without a leading zero."
  done
  port="$offered"
  wizard_ask_transport
  [[ "$UI_MOVE" == "next" ]] || return 0
  if [[ "$REPLY" == "udp" ]]; then
    wizard_add bind "allow ${port} udp"
  else
    wizard_add bind "allow ${port}"
  fi
}

# Asks for an [accept] rule until it can stand, and adds it. Whether its backend port is named in
# [bind] is checked once the whole policy is known, by the policy system.
wizard_ask_accept() {
  local public=""
  local backend=""
  local sources=""
  local source
  local problem
  local -a list=()
  while :; do
    ui_form "[accept]" "Expose a listener of the command. The backend port must be named in [bind] as well; the public port is at least 1024 and not in [bind]. Sources are addresses or ranges separated by commas; none admits nobody." \
      "Public port" "$public" "Backend port" "$backend" "Sources" "$sources"
    [[ "$UI_MOVE" == "next" ]] || return 0
    public="${UI_FIELDS[0]}"
    backend="${UI_FIELDS[1]}"
    sources="${UI_FIELDS[2]//[[:space:]]/}"
    problem=""
    wizard_number_in "$public" 1024 65535
    [[ "$REPLY" == "yes" ]] || problem="The public port is a whole number from 1024 to 65535."
    wizard_number_in "$backend" 1 65535
    [[ "$REPLY" == "yes" ]] || problem="The backend port is a whole number from 1 to 65535."
    IFS=, read -r -a list <<<"$sources"
    for source in "${list[@]}"; do
      [[ "$source" =~ ^[0-9A-Fa-f:./]+$ ]] || problem="A source is an address or a range, such as 198.51.100.0/24."
    done
    [[ -z "$problem" ]] && break
    ui_message "[accept]" "$problem"
  done
  if [[ -z "$sources" ]]; then
    wizard_add accept "expose ${public} to ${backend} from"
  else
    wizard_add accept "expose ${public} to ${backend} from ${sources//,/, }"
  fi
}

# Edits the section $1 until it is done: its entries are listed, and an entry is added or removed.
# UI_MOVE is next when it was finished and back when it was left with Esc.
wizard_edit_section() {
  local hint="$2"
  local position
  while :; do
    wizard_entry_menu "$1" "$hint"
    [[ "$UI_MOVE" == "next" ]] || return 0
    case "$UI_RESULT" in
      done) return 0 ;;
      add) wizard_ask_entry "$1" ;;
      *)
        position="$UI_RESULT"
        wizard_list "$1"
        ui_yesno "[${1}]" "Remove this entry?\n\n${WIZARD_LIST[position - 1]}"
        [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] && wizard_remove "$1" "$position"
        ;;
    esac
  done
}

# Asks for the limits in one form until every value can stand. An empty field leaves that limit to
# the base and the defaults, and a zero, written 0 or for the timeout 0.000 as well, switches it
# off, which is confirmed separately.
wizard_edit_limits() {
  local -a fields=()
  local index
  local problem
  local zero
  while :; do
    fields=()
    for index in "${!WIZARD_LIMIT_KEYS[@]}"; do
      fields+=("${WIZARD_LIMIT_LABELS[index]}" "${WIZARD_LIMITS[${WIZARD_LIMIT_KEYS[index]}]:-}")
    done
    ui_form "[limits]" "Leave a field empty to keep the default. A larger value from the base still wins, and 0 switches a limit off." "${fields[@]}"
    [[ "$UI_MOVE" == "next" ]] || return 0
    problem=""
    zero=""
    for index in "${!WIZARD_LIMIT_KEYS[@]}"; do
      wizard_limit_problem "${WIZARD_LIMIT_KEYS[index]}" "${UI_FIELDS[index]}"
      [[ -n "$REPLY" ]] && problem="$REPLY"
      [[ "${UI_FIELDS[index]}" =~ ^0(\.000)?$ ]] && zero+=" ${WIZARD_LIMIT_KEYS[index]}"
      WIZARD_LIMITS[${WIZARD_LIMIT_KEYS[index]}]="${UI_FIELDS[index]}"
    done
    if [[ -n "$problem" ]]; then
      ui_message "[limits]" "$problem"
      continue
    fi
    [[ -z "$zero" ]] && return 0
    ui_yesno "[limits]" "A value of 0 switches these limits off for every run under this policy, whatever the base names:${zero}.\n\nKeep them off?" no
    [[ "$UI_MOVE" == "next" && "$UI_ANSWER" == "yes" ]] && return 0
  done
}

# Walks the editors of the chosen sections, forwards when one is finished and backwards on Esc.
# UI_MOVE is back when the first one was left.
wizard_edit_chosen() {
  local position=0
  local index
  local hint
  while (( position >= 0 && position < ${#WIZARD_CHOSEN[@]} )); do
    if [[ "${WIZARD_CHOSEN[position]}" == "limits" ]]; then
      wizard_edit_limits
    else
      for index in "${!WIZARD_SECTIONS[@]}"; do
        [[ "${WIZARD_SECTIONS[index]}" == "${WIZARD_CHOSEN[position]}" ]] && hint="${WIZARD_HINTS[index]}"
      done
      wizard_edit_section "${WIZARD_CHOSEN[position]}" "${hint^}"
    fi
    if [[ "$UI_MOVE" == "next" ]]; then
      position=$((position + 1))
    else
      position=$((position - 1))
    fi
  done
  UI_MOVE="next"
  (( position >= 0 )) || UI_MOVE="back"
  return 0
}

# Sets REPLY to "yes" when the section $1 is among those chosen to fill, and to "no" otherwise.
wizard_chosen() {
  local section
  REPLY="no"
  for section in "${WIZARD_CHOSEN[@]}"; do
    [[ "$section" == "$1" ]] && REPLY="yes"
  done
  return 0
}

# Sets WIZARD_TEXT to the policy the answers make: the chosen sections that hold an entry, in the
# order of the policy reference, one entry per line, every line ending in a line feed. A section
# that was filled and then unticked in the checklist keeps its entries for a later tick, but grants
# nothing while it is unticked.
wizard_render() {
  local section
  local key
  local entry
  WIZARD_TEXT=""
  for section in "${WIZARD_SECTIONS[@]}"; do
    wizard_chosen "$section"
    [[ "$REPLY" == "yes" ]] || continue
    if [[ "$section" == "limits" ]]; then
      entry=""
      for key in "${WIZARD_LIMIT_KEYS[@]}"; do
        [[ -n "${WIZARD_LIMITS[$key]:-}" ]] && entry+="${key}=${WIZARD_LIMITS[$key]}"$'\n'
      done
      [[ -n "$entry" ]] && WIZARD_TEXT+="[limits]"$'\n'"${entry}"
      continue
    fi
    wizard_list "$section"
    (( ${#WIZARD_LIST[@]} > 0 )) || continue
    WIZARD_TEXT+="[${section}]"$'\n'
    for entry in "${WIZARD_LIST[@]}"; do
      WIZARD_TEXT+="${entry}"$'\n'
    done
  done
  return 0
}
