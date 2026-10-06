#!/usr/bin/env bash
# shellcheck shell=bash
# One programming language configuration in, the base policies it names and the values of its
# placeholders out.
#
# A component of phobos-common.sh, which sources this file after phobos-policy-yaml.sh and is
# what every caller sources. It sets no shell option and sources nothing, so that sourcing the
# aggregate twice keeps doing exactly what it did before the split.
#
# A programming language configuration is data, one file per configuration name under
# language-configurations/ beside phobos-policysystem.sh. It is the one place a programming
# language enters Phobos: it names the base policies a run under that configuration folds and how
# each placeholder of the language is determined. The code here knows no language. It knows two
# sections, [base] and [placeholders], and three generic ways of determining a value, and every
# value it determines comes from the environment and the PATH of the process that loads it, from
# the image and from the configuration file, all of which are fixed before the command exists.
# PARSE_LOCATION is set here and read by refuse_cfg in phobos-policy-parse.sh, never in this file,
# so SC2034 would fire on it by design.
# shellcheck disable=SC2034

# The folder beside phobos-policysystem.sh that holds the programming language configurations.
LANGUAGE_CONFIGURATION_FOLDER="language-configurations"
# A configuration name, as Ares 2 writes one. The letters are listed rather than written as a range,
# because a range is read in the collation order of the locale. A name of this shape cannot hold a
# slash or a dot, so it can only ever name a file inside the folder.
LANGUAGE_CONFIGURATION_NAME_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZ][ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*$'
# A placeholder line, "<name> = <primitive> <arguments>", and the name it may give: letters,
# digits, dots and underscores, starting with a letter.
LANGUAGE_PLACEHOLDER_LINE_PATTERN='^([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._]*)[[:space:]]*=[[:space:]]*(.*)$'
# An environment variable's name.
LANGUAGE_VARIABLE_NAME_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_][ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_]*$'
# A command's name: no slash, so that it is looked up on the PATH and never taken as a path.
LANGUAGE_COMMAND_NAME_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-]+$'
# How many directory levels command-ancestor goes up: one to ninety-nine.
LANGUAGE_LEVELS_PATTERN='^[123456789][0123456789]?$'
# The placeholder Phobos determines itself, from --project-root or the tail flags, and which a
# programming language configuration therefore may not name.
LANGUAGE_RESERVED_PLACEHOLDER="PROJECT_ROOT"

# Prints the path of the file a configuration name would be read from. Takes the name, which has
# the shape LANGUAGE_CONFIGURATION_NAME_PATTERN accepts, and the folder of phobos-policysystem.sh.
# Needs no environment.
language_configuration_file() {
  printf '%s/%s/%s.cfg' "$2" "$LANGUAGE_CONFIGURATION_FOLDER" "$1"
}

# Whether a programming language configuration of that name is shipped: the name has the shape of
# one and its file exists. Takes the name and the folder of phobos-policysystem.sh. Needs no
# environment.
language_configuration_exists() {
  local name="$1"
  local home="$2"
  [[ "$name" =~ $LANGUAGE_CONFIGURATION_NAME_PATTERN ]] || return 1
  [[ -f "$(language_configuration_file "$name" "$home")" ]]
}

# Refuses a configuration name that is not one, and one that has no file, so that a configuration
# Phobos does not know is never run under a base it guessed. Takes the name and the folder of
# phobos-policysystem.sh. Assumes PARSE_LOCATION names where the name was read, or is empty, and
# that it is called plainly, so that a refusal ends the run.
refuse_unknown_language_configuration() {
  local name="$1"
  local home="$2"
  if [[ ! "$name" =~ $LANGUAGE_CONFIGURATION_NAME_PATTERN ]]; then
    refuse_cfg "${name@Q} is not the name of a programming language configuration, which is capital letters, digits and underscores, starting with a letter"
  fi
  if ! language_configuration_exists "$name" "$home"; then
    refuse_cfg "the programming language configuration ${name@Q} has no file '${LANGUAGE_CONFIGURATION_FOLDER}/${name}.cfg' beside phobos-policysystem.sh, so Phobos does not know which base policy it runs under"
  fi
}

# Refuses a section a programming language configuration does not have. Asked at the section's
# header, so an unknown section is refused whether or not it holds any line. Takes the section.
# Assumes PARSE_LOCATION names the line and that it is called plainly, so that a refusal ends the run.
refuse_unknown_language_section() {
  local section="$1"
  case "$section" in
    base|placeholders) ;;
    *) refuse_cfg "unknown section ${section@Q}; a programming language configuration has the sections [base] and [placeholders]" ;;
  esac
}

# Appends one [base] entry to LANGUAGE_CONFIGURATION_BASES as the absolute path of the file it
# names, resolved through its symbolic links. A bare file name is looked for beside
# phobos-policysystem.sh, where the Base*.cfg every run folds live; a name with a slash is looked
# for under language-configurations/, which the Base*.cfg glob does not reach. An absolute name, a
# ".." segment, a file that does not exist and a symbolic link that leads out of its folder are
# refused, so that a configuration can only name a base the image ships beside it. Takes the entry
# and the folder of phobos-policysystem.sh. Assumes GNU realpath, PARSE_LOCATION naming the line,
# and that it is called plainly, so that a refusal ends the run.
add_language_base() {
  local entry="$1"
  local home="$2"
  local folder="$home"
  local where="beside phobos-policysystem.sh"
  local resolved_folder
  local resolved
  if [[ "$entry" == /* ]]; then
    refuse_cfg "${entry@Q} in [base] is an absolute path; name a base policy beside phobos-policysystem.sh, or one under ${LANGUAGE_CONFIGURATION_FOLDER}/ with a slash"
  fi
  if [[ "/${entry}/" == */../* ]]; then
    refuse_cfg "${entry@Q} in [base] holds a '..' segment, and a base may only be named inside its folder"
  fi
  if [[ "$entry" == */* ]]; then
    folder="${home}/${LANGUAGE_CONFIGURATION_FOLDER}"
    where="under ${LANGUAGE_CONFIGURATION_FOLDER}/"
  fi
  if [[ ! -f "${folder}/${entry}" ]]; then
    refuse_cfg "the base policy ${entry@Q} named in [base] does not exist ${where}"
  fi
  resolved_folder="$(realpath -e -- "$folder")"
  resolved="$(realpath -e -- "${folder}/${entry}")"
  if [[ "$resolved" != "${resolved_folder%/}/"* ]]; then
    refuse_cfg "the base policy ${entry@Q} named in [base] is a symbolic link that leads out of the folder it is named in, to ${resolved@Q}"
  fi
  LANGUAGE_CONFIGURATION_BASES+=( "$resolved" )
}

# Sets language_value to the value of an environment variable, or to the fallback when the
# variable is unset or empty. Only the process environment is read, through printenv, never a
# shell variable of this script, so a value is what the caller of phobos.sh exported. Takes the
# placeholder's name, the primitive as written, and the primitive's arguments, the variable and an
# optional fallback. Assumes it runs inside load_language_configuration, with PARSE_LOCATION
# naming the line, and that it is called plainly, so that a refusal ends the run.
determine_by_environment() {
  local placeholder="$1"
  local written="$2"
  local variable="${3:-}"
  local fallback="${4:-}"
  if (( $# < 3 || $# > 4 )); then
    refuse_cfg "'environment' takes a variable and an optional fallback, as in 'environment HOME /root', not ${written@Q}"
  fi
  if [[ ! "$variable" =~ $LANGUAGE_VARIABLE_NAME_PATTERN ]]; then
    refuse_cfg "${variable@Q} in ${written@Q} is not a variable name"
  fi
  language_value="$(printenv -- "$variable" || true)"
  if [[ -z "$language_value" ]]; then
    language_value="$fallback"
  fi
  if [[ -z "$language_value" ]]; then
    refuse_cfg "\${${placeholder}} cannot be determined: ${written@Q} found the variable ${variable@Q} unset or empty in the environment, and names no fallback"
  fi
}

# Sets language_value to the directory a command on the PATH lives in, that many levels up from
# the command resolved through every symbolic link: java at /opt/java/openjdk/bin/java with 2
# gives /opt/java/openjdk. The command is looked up on the PATH alone, never in the current
# directory, and a command name with a slash is refused. Takes the placeholder's name, the
# primitive as written, and the primitive's arguments, the command and the levels. Assumes GNU
# realpath, that it runs inside load_language_configuration, with PARSE_LOCATION naming the line,
# and that it is called plainly, so that a refusal ends the run.
determine_by_command_ancestor() {
  local placeholder="$1"
  local written="$2"
  local command="${3:-}"
  local levels="${4:-}"
  local found
  local step
  if (( $# != 4 )); then
    refuse_cfg "'command-ancestor' takes a command and a number of levels, as in 'command-ancestor java 2', not ${written@Q}"
  fi
  if [[ ! "$command" =~ $LANGUAGE_COMMAND_NAME_PATTERN ]]; then
    refuse_cfg "${command@Q} in ${written@Q} is not a command name; it is looked up on the PATH, so it holds no slash"
  fi
  if [[ ! "$levels" =~ $LANGUAGE_LEVELS_PATTERN ]]; then
    refuse_cfg "${levels@Q} in ${written@Q} is not a number of levels from 1 to 99"
  fi
  found="$(type -P -- "$command" || true)"
  if [[ "$found" != /* ]]; then
    refuse_cfg "\${${placeholder}} cannot be determined: ${written@Q} found no command ${command@Q} on the PATH"
  fi
  language_value="$(realpath -e -- "$found")"
  for (( step = 0; step < 10#$levels; step++ )); do
    if [[ "$language_value" == "/" ]]; then
      refuse_cfg "\${${placeholder}} cannot be determined: ${written@Q} resolved ${command@Q} to ${found@Q}, which has fewer than ${levels} levels above it"
    fi
    language_value="$(dirname -- "$language_value")"
  done
}

# Sets language_value to a constant path. Takes the placeholder's name, the primitive as written,
# and the primitive's one argument. Assumes it runs inside load_language_configuration, with
# PARSE_LOCATION naming the line, and that it is called plainly, so that a refusal ends the run.
determine_fixed() {
  local written="$2"
  if (( $# != 3 )); then
    refuse_cfg "'fixed' takes one absolute path, as in 'fixed /tmp', not ${written@Q}"
  fi
  language_value="$3"
}

# Whether the text holds a control character, a newline among them. Takes the text. Compares in the
# C locale, which it sets for itself alone, so that the class is read as bytes.
language_value_has_control_character() {
  local LC_ALL=C
  [[ "$1" == *[[:cntrl:]]* ]]
}

# Refuses a determined value that is not an absolute path to an existing directory, or that holds a
# control character, which would break the line-based files a path is later written to. Takes the
# placeholder's name, the primitive as written and the value. Assumes PARSE_LOCATION names the line
# and that it is called plainly, so that a refusal ends the run.
refuse_unusable_placeholder_value() {
  local placeholder="$1"
  local written="$2"
  local value="$3"
  if language_value_has_control_character "$value"; then
    refuse_cfg "\${${placeholder}} cannot be used: ${written@Q} gave ${value@Q}, which holds a control character"
  fi
  if [[ "$value" != /* ]]; then
    refuse_cfg "\${${placeholder}} cannot be used: ${written@Q} gave ${value@Q}, which is not an absolute path"
  fi
  if [[ ! -d "$value" ]]; then
    refuse_cfg "\${${placeholder}} cannot be used: ${written@Q} gave ${value@Q}, which is not an existing directory"
  fi
}

# Reads one [placeholders] line, "<name> = <primitive> <arguments>", determines the value with the
# one primitive it names, and records it in LANGUAGE_CONFIGURATION_PLACEHOLDERS. A placeholder named
# twice, the one Phobos determines itself, and an unknown primitive are refused. Takes the line.
# Assumes it runs inside load_language_configuration, with PARSE_LOCATION naming the line, and that
# it is called plainly, so that a refusal ends the run.
read_language_placeholder_line() {
  local line="$1"
  local placeholder
  local written
  local primitive
  local -a words=()
  local language_value=""
  if [[ ! "$line" =~ $LANGUAGE_PLACEHOLDER_LINE_PATTERN ]]; then
    refuse_cfg "${line@Q} is not a '<name> = <primitive> <arguments>' placeholder line"
  fi
  placeholder="${BASH_REMATCH[1]}"
  written="${BASH_REMATCH[2]}"
  read -ra words <<< "$written"
  primitive="${words[0]:-}"
  if [[ "$placeholder" == "$LANGUAGE_RESERVED_PLACEHOLDER" ]]; then
    refuse_cfg "\${${LANGUAGE_RESERVED_PLACEHOLDER}} is determined by Phobos, from --project-root or the tail flags, and not by a programming language configuration"
  fi
  if [[ -v "LANGUAGE_CONFIGURATION_PLACEHOLDERS[$placeholder]" ]]; then
    refuse_cfg "the placeholder ${placeholder@Q} is named twice"
  fi
  case "$primitive" in
    environment) determine_by_environment "$placeholder" "$written" "${words[@]:1}" ;;
    command-ancestor) determine_by_command_ancestor "$placeholder" "$written" "${words[@]:1}" ;;
    fixed) determine_fixed "$placeholder" "$written" "${words[@]:1}" ;;
    *) refuse_cfg "unknown primitive ${primitive@Q} in ${line@Q}; the primitives are 'environment <variable> [<fallback>]', 'command-ancestor <command> <levels>' and 'fixed <absolute path>'" ;;
  esac
  refuse_unusable_placeholder_value "$placeholder" "$written" "$language_value"
  LANGUAGE_CONFIGURATION_PLACEHOLDERS["$placeholder"]="$language_value"
}

# Reads the programming language configuration of that name and sets LANGUAGE_CONFIGURATION_BASES,
# the absolute paths of the base policies it names in order, and LANGUAGE_CONFIGURATION_PLACEHOLDERS,
# each placeholder it names mapped to the value determined for it now. The file is read with the
# discipline of a policy cfg: no byte order mark, no NUL, no carriage return, everything from a "#"
# a comment, nothing before the first section, no unknown section, and every refusal names the file
# and the line. A configuration that names no base is refused. Takes the name and the folder of
# phobos-policysystem.sh. Assumes GNU realpath, and that it is called plainly, never in a subshell,
# so that a refusal ends the run. PARSE_LOCATION is left as the caller had it.
load_language_configuration() {
  local name="$1"
  local home="$2"
  local caller_location="$PARSE_LOCATION"
  local file
  local line
  local number=0
  local section=""
  refuse_unknown_language_configuration "$name" "$home"
  file="$(language_configuration_file "$name" "$home")"
  LANGUAGE_CONFIGURATION_BASES=()
  declare -gA LANGUAGE_CONFIGURATION_PLACEHOLDERS=()
  refuse_unusable_cfg_file "$file"
  refuse_binary_cfg "$file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$(( number + 1 ))
    PARSE_LOCATION="${file@Q}, line ${number}"
    if [[ "$line" == *$'\r'* ]]; then
      refuse_cfg "this line contains a carriage return, which a Windows line ending leaves at its end and which would become part of the value. Save the file with LF line endings"
    fi
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "$line" ]] || continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      refuse_unknown_language_section "$section"
      continue
    fi
    case "$section" in
      base) add_language_base "$line" "$home" ;;
      placeholders) read_language_placeholder_line "$line" ;;
      *) refuse_cfg "${line@Q} appears before any [section] header" ;;
    esac
  done < "$file"
  PARSE_LOCATION="${file@Q}"
  if (( ${#LANGUAGE_CONFIGURATION_BASES[@]} == 0 )); then
    refuse_cfg "the programming language configuration ${name@Q} names no base policy in [base], so there is no base for a run under it"
  fi
  PARSE_LOCATION="$caller_location"
}
