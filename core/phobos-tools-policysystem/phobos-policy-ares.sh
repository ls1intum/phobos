#!/bin/bash
# shellcheck shell=bash
# One Ares 2 security policy in, the same parsed state and specification files a policy cfg gives out.
#
# A component of phobos-common.sh, which sources this file after phobos-language-configuration.sh
# and is what every caller sources. It sets no shell option and sources nothing, so that sourcing
# the aggregate twice keeps doing exactly what it did before the split.
#
# The policy is read with read_yaml_subset and checked against the Ares 2 schema, version 1. The
# file system, network and timeout domains are mapped onto the internals a cfg line goes through,
# so every translated value meets the refusals a hand-written line meets; every element that would
# widen or narrow the sandbox without saying so is refused with the file and the line, and every
# element Phobos has no equivalent for is named in the one summary line each file gets. Nothing
# here knows a programming language: the base policies and the placeholders come from the
# programming language configuration the policy names. The schema is the one of Ares 2 at commit
# 18062fca42a5e337ec63b30655497c4071f765f8 (ls1intum/Ares2, 2026-10-05).
# PARSE_LOCATION and the PARSED_* results are set here and read by refuse_cfg and by
# phobos-policysystem.sh, never in this file, so SC2034 would fire on them by design.
# shellcheck disable=SC2034

# The record paths of the two mappings every other field of the schema sits in.
ARES_SUPERVISED=".regardingTheSupervisedCode"
ARES_ACCESSES=".regardingTheSupervisedCode.theFollowingResourceAccessesArePermitted"
# The keys each mapping of the schema has, and those of them it requires.
ARES_ROOT_KEYS="thisPolicyFileCompliesToThePolicyVersion regardingTheSupervisedCode"
ARES_SUPERVISED_KEYS="theFollowingProgrammingLanguageConfigurationIsUsed theSupervisedCodeUsesTheFollowingPackage theMainClassInsideThisPackageIs theFollowingClassesAreTestClasses theFollowingTestBehaviorIsConfigured theFollowingResourceAccessesArePermitted"
ARES_SUPERVISED_REQUIRED="theFollowingProgrammingLanguageConfigurationIsUsed theFollowingClassesAreTestClasses theFollowingResourceAccessesArePermitted"
ARES_ACCESS_KEYS="regardingFileSystemInteractions regardingNetworkConnections regardingCommandExecutions regardingThreadCreations regardingPackageImports regardingTimeouts"
ARES_FILE_KEYS="onThisPathAndAllPathsBelow readAllFiles overwriteAllFiles createAllFiles executeAllFiles deleteAllFiles"
ARES_NETWORK_KEYS="onTheHost onThePort openConnections sendData receiveData"
ARES_COMMAND_KEYS="executeTheCommand withTheseArguments"
ARES_THREAD_KEYS="createTheFollowingNumberOfThreads ofThisClass"
ARES_PACKAGE_KEYS="importTheFollowingPackage"
ARES_TIMEOUT_KEYS="timeout"
# The one policy version Phobos reads.
ARES_POLICY_VERSION="1"
# A programming language configuration's name, as Ares 2 writes one.
ARES_CONFIGURATION_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZ][ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*$'
# The largest port, and the most digits it has.
ARES_LARGEST_PORT=65535
ARES_PORT_DIGITS=5
# What opens a placeholder in a value. The single quotes keep it from being expanded here.
# shellcheck disable=SC2016
ARES_PLACEHOLDER_OPEN='${'
# The placeholder Phobos determines itself, from --project-root or the tail flags.
ARES_PROJECT_ROOT_PLACEHOLDER="PROJECT_ROOT"
# A host name with a label of letters, digits and hyphens on either side of each dot, the
# letters listed rather than written as a range, which a locale could widen.
ARES_HOST_NAME_PATTERN='^[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-]*[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789])?(\.[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789]([ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-]*[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789])?)*$'

# Reads the records read_yaml_subset wrote into the arrays of the caller: the type, the value and
# the line of every path, the keys of every mapping, and the number of items of every sequence.
# Takes the records file. Assumes it runs inside parse_ares_policy or ares_read_configuration_name,
# which declare ares_type, ares_value, ares_line, ares_keys and ares_count.
ares_load_records() {
  local records="$1"
  local line
  local path
  local type
  local value
  local parent
  while IFS=$'\t' read -r line path type value; do
    ares_type["$path"]="$type"
    ares_value["$path"]="$value"
    ares_line["$path"]="$line"
    if [[ "$type" == "seq" ]]; then
      ares_count["$path"]=0
    fi
    [[ "$path" != "." ]] || continue
    if [[ "$path" == *"]" ]]; then
      parent="${path%\[*}"
      ares_count["${parent:-.}"]=$(( ${ares_count["${parent:-.}"]:-0} + 1 ))
    else
      parent="${path%.*}"
      ares_keys["${parent:-.}"]+=" ${path##*.}"
    fi
  done < "$records"
}

# Prints a record path the way a message names it: below the resource accesses or the supervised
# code without the path of that mapping, and otherwise without the leading dot. Takes the path.
# Needs no environment.
ares_shown() {
  local path="$1"
  case "$path" in
    "${ARES_ACCESSES}."*) printf '%s' "${path#"${ARES_ACCESSES}."}" ;;
    "${ARES_SUPERVISED}."*) printf '%s' "${path#"${ARES_SUPERVISED}."}" ;;
    ".") printf 'the policy' ;;
    *) printf '%s' "${path#.}" ;;
  esac
}

# Prints the path of a mapping's key. Takes the mapping's path and the key. Needs no environment.
ares_child() {
  if [[ "$1" == "." ]]; then
    printf '.%s' "$2"
  else
    printf '%s.%s' "$1" "$2"
  fi
}

# Points PARSE_LOCATION at the line of a record, or, for a record that is absent, at the line of
# the nearest mapping or sequence above it that is present. Takes the path. Assumes it runs inside
# a reader that loaded the records and set ares_file.
ares_at() {
  local path="$1"
  while [[ -z "${ares_line["$path"]:-}" && "$path" != "." ]]; do
    if [[ "$path" == *"]" ]]; then
      path="${path%\[*}"
    else
      path="${path%.*}"
    fi
    path="${path:-.}"
  done
  PARSE_LOCATION="${ares_file@Q}, line ${ares_line["$path"]:-1}"
}

# Refuses a mapping that holds a key its place in the schema does not have, or lacks one it
# requires, as Ares refuses both. Takes the mapping's path, its keys and its required keys, each a
# space-separated list. Assumes it runs inside a reader that loaded the records, and that it is
# called plainly, so that a refusal ends the run.
ares_check_keys() {
  local map="$1"
  local allowed=" $2 "
  local required="$3"
  local key
  local known="the keys ${2// /, }"
  [[ -n "$2" ]] || known="no keys"
  for key in ${ares_keys["$map"]:-}; do
    if [[ "$allowed" != *" ${key} "* ]]; then
      ares_at "$(ares_child "$map" "$key")"
      refuse_cfg "unknown key ${key@Q} in $(ares_shown "$map"); Ares 2 policy version ${ARES_POLICY_VERSION} has ${known} here"
    fi
  done
  for key in $required; do
    if [[ -z "${ares_type["$(ares_child "$map" "$key")"]:-}" ]]; then
      ares_at "$map"
      refuse_cfg "$(ares_shown "$map") has no key ${key@Q}, which Ares 2 requires"
    fi
  done
}

# Prints what a record type is called in a message. Takes the type, or nothing for an absent
# record. Needs no environment.
ares_type_name() {
  case "$1" in
    map) printf 'a mapping' ;;
    seq) printf 'a list' ;;
    str) printf 'text' ;;
    int) printf 'a whole number' ;;
    bool) printf 'true or false' ;;
    null) printf 'null' ;;
    *) printf 'absent' ;;
  esac
}

# Refuses a record whose type is not the one its field needs. Takes the path and "map", "seq",
# "str", "int" or "bool". Assumes it runs inside a reader that loaded the records, and that it is
# called plainly, so that a refusal ends the run.
ares_check_type() {
  local path="$1"
  local want="$2"
  [[ "${ares_type["$path"]:-}" != "$want" ]] || return 0
  ares_at "$path"
  refuse_cfg "$(ares_shown "$path") must be $(ares_type_name "$want"), and it is $(ares_type_name "${ares_type["$path"]:-}")"
}

# Refuses a record that is not text, empty text, and, when the second argument is "no-placeholder",
# text that holds "${", which Phobos expands only in a file system path. Takes the path and an
# optional "no-placeholder". Assumes it runs inside a reader that loaded the records, and that it
# is called plainly, so that a refusal ends the run.
ares_check_text() {
  local path="$1"
  local placeholders="${2:-}"
  ares_check_type "$path" str
  ares_at "$path"
  if [[ -z "${ares_value["$path"]}" ]]; then
    refuse_cfg "$(ares_shown "$path") must not be empty"
  fi
  if [[ "$placeholders" == "no-placeholder" && "${ares_value["$path"]}" == *"$ARES_PLACEHOLDER_OPEN"* ]]; then
    refuse_cfg "$(ares_shown "$path") ${ares_value["$path"]@Q} holds a placeholder, and Phobos expands placeholders only in onThisPathAndAllPathsBelow"
  fi
}

# Refuses a top level that is not a version 1 policy with a mapping of the supervised code, and a
# configuration name of another shape. Assumes it runs inside a reader that loaded the records, and
# that it is called plainly, so that a refusal ends the run.
ares_check_root() {
  local version=".thisPolicyFileCompliesToThePolicyVersion"
  local configuration="${ARES_SUPERVISED}.theFollowingProgrammingLanguageConfigurationIsUsed"
  if [[ "${ares_type["."]:-}" != "map" ]]; then
    ares_at "."
    refuse_cfg "an Ares 2 policy is a mapping at its top level"
  fi
  ares_check_keys "." "$ARES_ROOT_KEYS" "$ARES_ROOT_KEYS"
  if [[ "${ares_type["$version"]}" != "int" || "${ares_value["$version"]}" != "$ARES_POLICY_VERSION" ]]; then
    ares_at "$version"
    refuse_cfg "thisPolicyFileCompliesToThePolicyVersion must be exactly ${ARES_POLICY_VERSION}, the one Ares 2 policy version Phobos reads"
  fi
  ares_check_type "$ARES_SUPERVISED" map
  ares_check_keys "$ARES_SUPERVISED" "$ARES_SUPERVISED_KEYS" "$ARES_SUPERVISED_REQUIRED"
  ares_check_type "$configuration" str
  if [[ ! "${ares_value["$configuration"]}" =~ $ARES_CONFIGURATION_PATTERN ]]; then
    ares_at "$configuration"
    refuse_cfg "${ares_value["$configuration"]@Q} is not the name of a programming language configuration, which is capital letters, digits and underscores, starting with a letter"
  fi
}

# Refuses the fields of the supervised code that grant nothing at the operating-system level when
# their structure is not the schema's: the package and the main class, absent, null or text; the
# test classes, a list of text; the test behaviour, absent or an empty mapping; and the resource
# accesses, a mapping of the six lists. Their values are not checked against a language's naming
# rules, which Ares checks itself. Assumes it runs inside a reader that loaded the records, and that
# it is called plainly, so that a refusal ends the run.
ares_check_supervised_code() {
  local field
  local index
  local tests="${ARES_SUPERVISED}.theFollowingClassesAreTestClasses"
  local behaviour="${ARES_SUPERVISED}.theFollowingTestBehaviorIsConfigured"
  for field in theSupervisedCodeUsesTheFollowingPackage theMainClassInsideThisPackageIs; do
    field="${ARES_SUPERVISED}.${field}"
    if [[ -n "${ares_type["$field"]:-}" && "${ares_type["$field"]}" != "null" ]]; then
      ares_check_text "$field" no-placeholder
    fi
  done
  ares_check_type "$tests" seq
  for (( index = 0; index < ares_count["$tests"]; index++ )); do
    ares_check_text "${tests}[${index}]" no-placeholder
  done
  if [[ -n "${ares_type["$behaviour"]:-}" ]]; then
    ares_check_type "$behaviour" map
    ares_check_keys "$behaviour" "" ""
  fi
  ares_check_type "$ARES_ACCESSES" map
  ares_check_keys "$ARES_ACCESSES" "$ARES_ACCESS_KEYS" "$ARES_ACCESS_KEYS"
  for field in $ARES_ACCESS_KEYS; do
    ares_check_type "${ARES_ACCESSES}.${field}" seq
  done
}

# Refuses an entry of a resource list that is not a mapping with exactly the keys of its kind.
# Takes the entry's path and the keys. Assumes it runs inside a reader that loaded the records, and
# that it is called plainly, so that a refusal ends the run.
ares_check_entry() {
  ares_check_type "$1" map
  ares_check_keys "$1" "$2" "$2"
}

# Refuses every entry of the resource lists whose structure or type is not the schema's: a file
# entry's path and five booleans, a network entry's host, its port from 0 to 65535 and three
# booleans, a command as text or as a mapping of the command and its arguments, a thread entry's
# number and class, a package entry's name, and a timeout of at least one millisecond. Assumes it
# runs inside a reader that loaded the records, and that it is called plainly, so that a refusal
# ends the run.
ares_check_resource_entries() {
  local list
  local entry
  local index
  local item
  local key
  list="${ARES_ACCESSES}.regardingFileSystemInteractions"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    ares_check_entry "$entry" "$ARES_FILE_KEYS"
    ares_check_text "${entry}.onThisPathAndAllPathsBelow"
    for key in readAllFiles overwriteAllFiles createAllFiles executeAllFiles deleteAllFiles; do
      ares_check_type "${entry}.${key}" bool
    done
  done
  list="${ARES_ACCESSES}.regardingNetworkConnections"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    ares_check_entry "$entry" "$ARES_NETWORK_KEYS"
    ares_check_text "${entry}.onTheHost" no-placeholder
    ares_check_type "${entry}.onThePort" int
    if (( ${#ares_value["${entry}.onThePort"]} > ARES_PORT_DIGITS )) || (( 10#${ares_value["${entry}.onThePort"]} > ARES_LARGEST_PORT )); then
      ares_at "${entry}.onThePort"
      refuse_cfg "$(ares_shown "${entry}.onThePort") ${ares_value["${entry}.onThePort"]@Q} must be a whole number from 0 to ${ARES_LARGEST_PORT}"
    fi
    for key in openConnections sendData receiveData; do
      ares_check_type "${entry}.${key}" bool
    done
  done
  list="${ARES_ACCESSES}.regardingCommandExecutions"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    if [[ "${ares_type["$entry"]}" == "str" ]]; then
      ares_check_text "$entry"
      continue
    fi
    ares_check_entry "$entry" "$ARES_COMMAND_KEYS"
    ares_check_text "${entry}.executeTheCommand"
    ares_check_type "${entry}.withTheseArguments" seq
    for (( item = 0; item < ares_count["${entry}.withTheseArguments"]; item++ )); do
      ares_check_text "${entry}.withTheseArguments[${item}]"
    done
  done
  list="${ARES_ACCESSES}.regardingThreadCreations"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    ares_check_entry "$entry" "$ARES_THREAD_KEYS"
    ares_check_type "${entry}.createTheFollowingNumberOfThreads" int
    ares_check_text "${entry}.ofThisClass" no-placeholder
  done
  list="${ARES_ACCESSES}.regardingPackageImports"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    ares_check_entry "$entry" "$ARES_PACKAGE_KEYS"
    ares_check_text "${entry}.importTheFollowingPackage" no-placeholder
  done
  list="${ARES_ACCESSES}.regardingTimeouts"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    entry="${list}[${index}]"
    ares_check_entry "$entry" "$ARES_TIMEOUT_KEYS"
    ares_check_type "${entry}.timeout" int
    if [[ "${ares_value["${entry}.timeout"]}" == "0" ]]; then
      ares_at "${entry}.timeout"
      refuse_cfg "$(ares_shown "${entry}.timeout") '0' must be a whole number of milliseconds of at least 1"
    fi
  done
}

# Reads an Ares 2 policy far enough to know the programming language configuration it names, and
# sets ares_configuration_name to it and ares_configuration_location to where it is written. The top
# level is checked as parse_ares_policy checks it, so a malformed file is refused here already.
# Takes the policy file. Assumes the file was found readable, and that it is called plainly, so that
# a refusal ends the run. PARSE_LOCATION is left empty.
ares_read_configuration_name() {
  local ares_file="$1"
  local records
  local -A ares_type=()
  local -A ares_value=()
  local -A ares_line=()
  local -A ares_keys=()
  local -A ares_count=()
  records="$(new_scratch_file phobos-ares-records.XXXXXX)"
  read_yaml_subset "$ares_file" "$records"
  ares_load_records "$records"
  rm -f "$records"
  ares_check_root
  ares_configuration_name="${ares_value["${ARES_SUPERVISED}.theFollowingProgrammingLanguageConfigurationIsUsed"]}"
  ares_at "${ARES_SUPERVISED}.theFollowingProgrammingLanguageConfigurationIsUsed"
  ares_configuration_location="$PARSE_LOCATION"
  PARSE_LOCATION=""
}

# Whether a configuration file is an Ares 2 policy, which is decided by its name alone: one ending
# in .yaml or .yml. Takes the file's path. Needs no environment.
is_ares_policy_file() {
  [[ "$1" == *.yaml || "$1" == *.yml ]]
}

# Loads the programming language configuration the Ares 2 policies among the configuration files
# name, and sets ARES_SELECTED_CONFIGURATION to its name, or to nothing when no file is an Ares
# policy. Two Ares policies that name different configurations are refused, even where their bases
# agree, because one run has one base and one set of placeholder values, and so is a configuration
# with no file. Takes the folder of phobos-policysystem.sh and the configuration files. Assumes it
# is called plainly, so that a refusal ends the run, and leaves PARSE_LOCATION empty.
ares_select_language_configuration() {
  local home="$1"
  local cfg
  local ares_configuration_name=""
  local ares_configuration_location=""
  local first=""
  local first_file=""
  shift
  ARES_SELECTED_CONFIGURATION=""
  for cfg in "$@"; do
    is_ares_policy_file "$cfg" || continue
    ares_read_configuration_name "$cfg"
    if [[ -n "$first" && "$ares_configuration_name" != "$first" ]]; then
      PARSE_LOCATION="$ares_configuration_location"
      refuse_cfg "this policy names the programming language configuration ${ares_configuration_name@Q} and ${first_file@Q} names ${first@Q}; one run has one base and one set of placeholder values, so every Ares 2 policy of a run names the same configuration"
    fi
    first="$ares_configuration_name"
    first_file="$cfg"
    PARSE_LOCATION="$ares_configuration_location"
    refuse_unknown_language_configuration "$ares_configuration_name" "$home"
    PARSE_LOCATION=""
  done
  if [[ -n "$first" ]]; then
    PARSE_LOCATION="$ares_configuration_location"
    load_language_configuration "$first" "$home"
    PARSE_LOCATION=""
    ARES_SELECTED_CONFIGURATION="$first"
  fi
}

# Prints the directory the enforcer changes into before it runs the command: the value of the last
# --chdir in the tail flags, which is the one phobos-landlock-filesystem-and-networksystem keeps.
# Prints nothing when the tail flags name none or the file is absent, and never substitutes a
# current directory for it. Reads the tail flags as write_spec does, a "#" starting a comment and
# the rest split on white space. Takes the tail flags file. Needs no environment.
tail_flags_working_directory() {
  local file="$1"
  local -a words=()
  local index
  local found=""
  [[ -n "$file" && -f "$file" ]] || return 0
  read -ra words <<< "$(sed -E 's/#.*$//' "$file" | tr '\n' ' ')"
  for (( index = 0; index + 1 < ${#words[@]}; index++ )); do
    if [[ "${words[index]}" == "--chdir" ]]; then
      found="${words[index + 1]}"
    fi
  done
  printf '%s' "$found"
}

# Refuses a project root that a relative path or ${PROJECT_ROOT} cannot be resolved against: none,
# or a relative one. Takes the project root and the value that needs it. Assumes PARSE_LOCATION
# names the value's line and that it is called plainly, so that a refusal ends the run.
ares_refuse_unusable_project_root() {
  local project_root="$1"
  local value="$2"
  if [[ -z "$project_root" ]]; then
    refuse_cfg "this run has no project root to resolve ${value@Q} against; give --project-root, or write the absolute path"
  fi
  if [[ "$project_root" != /* ]]; then
    refuse_cfg "the project root ${project_root@Q}, the last --chdir of the tail flags, is relative, so ${value@Q} cannot be resolved against it; give --project-root, or write the absolute path"
  fi
}

# Sets ares_expanded to the path with each ${name} replaced: ${PROJECT_ROOT} by the project root,
# and every other placeholder by the value the programming language configuration determines for
# it, on its first use. An unterminated "${" is refused, and so are a placeholder the configuration
# does not name and one it cannot determine. Takes the path and the project root. Assumes
# PARSE_LOCATION names the path's line, that a programming language configuration was loaded, and
# that it is called plainly, so that a refusal ends the run.
ares_expand_placeholders() {
  local rest="$1"
  local project_root="$2"
  local name
  local location="$PARSE_LOCATION"
  ares_expanded=""
  while [[ "$rest" == *"$ARES_PLACEHOLDER_OPEN"* ]]; do
    ares_expanded+="${rest%%"$ARES_PLACEHOLDER_OPEN"*}"
    rest="${rest#*"$ARES_PLACEHOLDER_OPEN"}"
    if [[ "$rest" != *"}"* ]]; then
      refuse_cfg "${1@Q} opens a placeholder with \${ that it does not close"
    fi
    name="${rest%%\}*}"
    rest="${rest#*\}}"
    if [[ "$name" == "$ARES_PROJECT_ROOT_PLACEHOLDER" ]]; then
      ares_refuse_unusable_project_root "$project_root" "$1"
      ares_expanded+="$project_root"
      continue
    fi
    determine_language_placeholder "$name"
    PARSE_LOCATION="$location"
    debug_log policy "\${${name}} is ${LANGUAGE_PLACEHOLDER_VALUE}, from ${LANGUAGE_CONFIGURATION_NAME}"
    ares_expanded+="$LANGUAGE_PLACEHOLDER_VALUE"
  done
  ares_expanded+="$rest"
}

# Sets ares_path to the absolute path an onThisPathAndAllPathsBelow value names, or refuses it: "*",
# which would mean the whole file system, a backslash, a placeholder that cannot be expanded, a ".."
# segment, a relative path when the run has no absolute project root, a wildcard character, and a
# path that does not exist, in every section, because Ares does not say whether a path is a file or
# a directory and the filesystem layer would create a missing changeable one as an empty file.
# Takes the value, the project root and the section the row is for. Assumes PARSE_LOCATION names the
# value's line, and that it is called plainly, so that a refusal ends the run.
ares_resolve_policy_path() {
  local value="$1"
  local project_root="$2"
  local section="$3"
  local ares_expanded=""
  if [[ "$value" == "*" ]]; then
    refuse_cfg "onThisPathAndAllPathsBelow '*' would grant these rights on the whole file system; name the directory instead"
  fi
  if [[ "$value" == *\\* ]]; then
    refuse_cfg "onThisPathAndAllPathsBelow ${value@Q} holds a backslash, which Ares reads as a separator on Windows and Linux reads as part of a name; write the path with slashes"
  fi
  ares_expand_placeholders "$value" "$project_root"
  ares_path="$ares_expanded"
  if [[ "/${ares_path}/" == */../* ]]; then
    refuse_cfg "onThisPathAndAllPathsBelow ${value@Q} holds a '..' segment, which Ares refuses too"
  fi
  if [[ "$ares_path" != /* ]]; then
    ares_refuse_unusable_project_root "$project_root" "$value"
    ares_path="${project_root%/}/${ares_path}"
  fi
  refuse_relative_path "$ares_path" "$section"
  refuse_wildcard_path "$ares_path" "$section"
  refuse_missing_path "$ares_path" "$section"
}

# Whether the folded base already grants this section's right on the imported path: the base's
# file for the same section names a path that exists and that, both resolved through their
# symbolic links as the filesystem layer resolves them, is the imported path or an ancestor of it.
# realpath -e is used rather than resolve_symlinks, which passes a path it cannot resolve through
# as written: here a failed resolution has to mean "not covered", never a lexical comparison. For
# an existing path both give the same answer. The root resolves to "/", and "${x%/}/" of it is "/",
# so the root is an ancestor of every path. Takes the section file name without ".paths", the
# absolute imported path, which exists, and the directory the base policies were folded into. A
# missing base path is no ancestor, because the filesystem layer drops a missing read or execute
# path. Assumes GNU realpath, which refuse_missing_realpath has established.
ares_row_covered_by_base() {
  local section="$1"
  local path="$2"
  local base_dir="$3"
  local resolved_path
  local candidate
  local resolved_candidate
  [[ -s "${base_dir}/${section}.paths" ]] || return 1
  resolved_path="$(realpath -e -- "$path" 2>/dev/null)" || return 1
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    resolved_candidate="$(realpath -e -- "$candidate" 2>/dev/null)" || continue
    [[ "$resolved_path" == "$resolved_candidate" ]] && return 0
    [[ "$resolved_path" == "${resolved_candidate%/}/"* ]] && return 0
  done < "${base_dir}/${section}.paths"
  return 1
}

# Writes one imported file system row into the parse directory, unless the folded base already
# grants that right on that path, in which case it counts the row in ares_skipped and writes
# nothing. Takes the parse directory, the section file name without ".paths", the absolute path
# and the base directory. Assumes it runs inside parse_ares_policy.
ares_write_row() {
  local tdir="$1"
  local section="$2"
  local path="$3"
  local base_dir="$4"
  if [[ -n "$base_dir" ]] && ares_row_covered_by_base "$section" "$path" "$base_dir"; then
    ares_skipped=$(( ares_skipped + 1 ))
    return 0
  fi
  printf '%s\n' "$path" >> "${tdir}/${section}.paths"
  ares_rows=$(( ares_rows + 1 ))
}

# Maps one file system entry onto the sections its granted rights name: readAllFiles to read,
# overwriteAllFiles to write, createAllFiles to create and create-symlink, since Ares counts
# createSymbolicLink as creation, executeAllFiles to execute, deleteAllFiles to delete, and
# createAllFiles with deleteAllFiles to refer as well, since Ares lets such an entry move files. An
# entry that grants nothing writes nothing. Takes the parse directory, the entry's path, the project
# root and the base directory. Assumes it runs inside parse_ares_policy, and that it is called
# plainly, so that a refusal ends the run.
ares_map_file_entry() {
  local tdir="$1"
  local entry="$2"
  local project_root="$3"
  local base_dir="$4"
  local value="${ares_value["${entry}.onThisPathAndAllPathsBelow"]}"
  local read="${ares_value["${entry}.readAllFiles"]}"
  local write="${ares_value["${entry}.overwriteAllFiles"]}"
  local create="${ares_value["${entry}.createAllFiles"]}"
  local execute="${ares_value["${entry}.executeAllFiles"]}"
  local delete="${ares_value["${entry}.deleteAllFiles"]}"
  local ares_path=""
  local section
  local -a sections=()
  [[ "$read" == "true" ]] && sections+=( read )
  [[ "$write" == "true" ]] && sections+=( write )
  [[ "$create" == "true" ]] && sections+=( create symlink )
  [[ "$execute" == "true" ]] && sections+=( execute )
  [[ "$delete" == "true" ]] && sections+=( delete )
  [[ "$create" == "true" && "$delete" == "true" ]] && sections+=( refer )
  (( ${#sections[@]} > 0 )) || return 0
  ares_at "${entry}.onThisPathAndAllPathsBelow"
  ares_resolve_policy_path "$value" "$project_root" "${sections[0]}"
  for section in "${sections[@]}"; do
    ares_write_row "$tdir" "$section" "$ares_path" "$base_dir"
  done
}

# Sets ares_rule to the [connect] line one network entry becomes, or refuses the entry: localhost,
# an IPv4 or an IPv6 address with a port, or for a loopback address with port 0 every port, a host
# name or "*" with a port, each as a .cfg line would write it, so that append_connect_rule judges it
# as it judges one. A host name ending in a dot, any host but loopback with port 0, and anything
# Ares's host pattern does not admit are refused here, where the entry's line is known. Takes the host and the port. Assumes PARSE_LOCATION names the entry's line and
# that it is called plainly, so that a refusal ends the run.
ares_network_rule_line() {
  local host="$1"
  local port="$2"
  local every=0
  [[ "$port" != "0" ]] || every=1
  if [[ "$host" == "localhost" ]]; then
    if (( every )); then ares_rule="allow localhost"; else ares_rule="allow localhost:${port}"; fi
  elif is_ipv4_literal "$host" || is_ipv6_literal "$host"; then
    if (( every )) && ! is_loopback_host "$host"; then
      refuse_cfg "onTheHost ${host@Q} with onThePort 0 would permit every port of a host other than loopback; name the port"
    fi
    if is_ipv6_literal "$host"; then
      if (( every )); then ares_rule="allow [${host}]"; else ares_rule="allow [${host}]:${port}"; fi
    elif (( every )); then
      ares_rule="allow ${host}:*"
    else
      ares_rule="allow ${host}:${port}"
    fi
  elif [[ "$host" == "*" ]]; then
    if (( every )); then
      refuse_cfg "onTheHost '*' with onThePort 0 would permit every host on every port; name the port"
    fi
    ares_rule="allow *:${port}"
  elif [[ "$host" == *. ]]; then
    refuse_cfg "onTheHost ${host@Q} ends in a dot; drop the dot, since the egress broker compares host names without it"
  elif [[ "$host" =~ $ARES_HOST_NAME_PATTERN ]]; then
    if (( every )); then
      refuse_cfg "onTheHost ${host@Q} with onThePort 0 would permit every port of a host other than loopback; name the port"
    fi
    ares_rule="allow ${host}:${port}"
  else
    refuse_cfg "onTheHost ${host@Q} is neither localhost, an IPv4 or IPv6 address, '*' nor a host name"
  fi
}

# Maps one network entry: all three flags true becomes the entry's [connect] rule twice, once for
# TCP and once for UDP, since Ares's connect covers stream and datagram sockets; all three false
# becomes nothing; any other combination is refused, because Phobos cannot let a connection be
# opened while forbidding sending or receiving on it, and granting the connection would permit more
# than the policy states. Takes the entry's path and the rules file. Assumes it runs inside
# parse_ares_policy, and that it is called plainly, so that a refusal ends the run.
ares_map_network_entry() {
  local entry="$1"
  local net="$2"
  local open="${ares_value["${entry}.openConnections"]}"
  local send="${ares_value["${entry}.sendData"]}"
  local receive="${ares_value["${entry}.receiveData"]}"
  local host="${ares_value["${entry}.onTheHost"]}"
  local port="${ares_value["${entry}.onThePort"]}"
  local ares_rule=""
  local granted=""
  local withheld=""
  local flag
  [[ "$open$send$receive" != "falsefalsefalse" ]] || return 0
  ares_at "$entry"
  if [[ "$open$send$receive" != "truetruetrue" ]]; then
    for flag in openConnections sendData receiveData; do
      if [[ "${ares_value["${entry}.${flag}"]}" == "true" ]]; then granted+=" ${flag}"; else withheld+=" ${flag}"; fi
    done
    refuse_cfg "$(ares_shown "$entry") grants${granted} but not${withheld}, and Phobos cannot let a connection be opened while forbidding sending or receiving on it; grant all three or none"
  fi
  ares_network_rule_line "$host" "$port"
  if [[ "$host" == "*" ]]; then
    _log "NOTICE: $(ares_shown "$entry") in ${ares_file@Q} permits every host on port ${port}, over TCP and UDP."
  fi
  append_connect_rule "$ares_rule" "$net"
  append_connect_rule "${ares_rule} udp" "$net"
  ares_network_entries=$(( ares_network_entries + 1 ))
}

# Whether the first whole number is smaller than the second, compared as digit strings so that
# no length overflows the arithmetic. Takes two strings of digits without leading zeros.
# Needs no environment.
digits_less_than() {
  local left="$1"
  local right="$2"
  if (( ${#left} != ${#right} )); then
    (( ${#left} < ${#right} ))
    return
  fi
  [[ "$left" < "$right" ]]
}

# Prints a whole number of milliseconds as seconds with exactly three decimals, by moving the
# decimal point, so that no value is rounded and none can overflow the arithmetic. A rounding of
# a value below one second to zero would switch the timeout off, which is why nothing here rounds.
# Takes the digits as the schema check accepted them. Needs no environment.
ares_millis_to_timeout() {
  local digits="${1#"${1%%[!0]*}"}"
  local seconds
  local millis
  while (( ${#digits} < 4 )); do
    digits="0${digits}"
  done
  seconds="${digits:0:${#digits}-3}"
  millis="${digits: -3}"
  seconds="${seconds#"${seconds%%[!0]*}"}"
  printf '%s.%s' "${seconds:-0}" "$millis"
}

# Imports the tightest of the policy's timeouts, as Ares computes it, into PARSED_TIMEOUT through
# set_parsed_timeout, which refuses one too long for the arithmetic; an empty list imports none and
# says so. Sets ares_timeout_text to what the summary says about it. Assumes it runs inside
# parse_ares_policy, and that it is called plainly, so that a refusal ends the run.
ares_map_timeouts() {
  local list="${ARES_ACCESSES}.regardingTimeouts"
  local index
  local value
  local tightest=""
  local tightest_path=""
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    value="${ares_value["${list}[${index}].timeout"]}"
    if [[ -z "$tightest" ]] || digits_less_than "$value" "$tightest"; then
      tightest="$value"
      tightest_path="${list}[${index}].timeout"
    fi
  done
  if [[ -z "$tightest" ]]; then
    ares_timeout_text="no timeout imported, as regardingTimeouts is empty"
    return 0
  fi
  ares_at "$tightest_path"
  if (( ${#tightest} > PHB_LARGEST_TIMEOUT_SECOND_DIGITS + 3 )); then
    refuse_cfg "$(ares_shown "$tightest_path") ${tightest@Q} milliseconds has more than ${PHB_LARGEST_TIMEOUT_SECOND_DIGITS} digits of seconds, which is not a time but a number the arithmetic would read as another one"
  fi
  set_parsed_timeout "$(ares_millis_to_timeout "$tightest")"
  ares_timeout_text="a timeout of ${PARSED_TIMEOUT} s imported, which bounds the whole run, not only the supervised code"
}

# Prints the one line every imported file gets: what was imported, what the base already covered,
# and what Phobos does not enforce. Takes nothing. Assumes it runs inside parse_ares_policy.
ares_report_summary() {
  local commands="${ares_count["${ARES_ACCESSES}.regardingCommandExecutions"]}"
  local threads="${ares_count["${ARES_ACCESSES}.regardingThreadCreations"]}"
  local packages="${ares_count["${ARES_ACCESSES}.regardingPackageImports"]}"
  _log "Ares 2 policy ${ares_file@Q} (${LANGUAGE_CONFIGURATION_NAME}): file system rows imported: ${ares_rows}; network entries imported, each as a TCP and a UDP rule: ${ares_network_entries}; file system rows already covered by the base policy: ${ares_skipped}, for which Phobos adds nothing, as their narrower intent is enforced by Ares inside the JVM, not by Phobos; ${ares_timeout_text}; not enforced by Phobos: command entries ${commands}, thread entries ${threads}, package entries ${packages}, and the test-class exemption, since test classes get no exemption from Phobos."
}

# Reads one Ares 2 policy as an exercise configuration. Its file system rows go into the
# "<right>.paths" files of a fresh directory and its network entries into net.rules, as
# parse_cfg_policy writes them, and its tightest timeout into PARSED_TIMEOUT. Sets PARSED_FS_DIR,
# PARSED_NET_FILE, PARSED_BIND_FILE and PARSED_ACCEPT_FILE, which an Ares policy always leaves
# empty, PARSED_ARES_CONFIGURATION to the configuration it names and PARSED_ARES_SKIPPED to the
# number of rows the base already covered. Takes the policy file, the project root, which may be
# empty, and the directory the base policies were folded into. Assumes the programming language
# configuration the policy names was loaded by ares_select_language_configuration, and that it is
# called plainly, never in a subshell, so that a refusal ends the run.
parse_ares_policy() {
  local ares_file="$1"
  local project_root="$2"
  local base_dir="$3"
  local tdir
  local records
  local right
  local index
  local list
  local configuration
  local -A ares_type=()
  local -A ares_value=()
  local -A ares_line=()
  local -A ares_keys=()
  local -A ares_count=()
  local ares_rows=0
  local ares_skipped=0
  local ares_network_entries=0
  local ares_timeout_text=""
  tdir="$(new_parse_directory)"
  for right in ${PHB_FS_RIGHTS}; do
    : > "${tdir}/${right}.paths"
  done
  : > "${tdir}/net.rules"
  : > "${tdir}/bind.rules"
  : > "${tdir}/accept.rules"
  reset_parsed_limits
  records="${tdir}/ares.records"
  read_yaml_subset "$ares_file" "$records"
  ares_load_records "$records"
  ares_check_root
  configuration="${ares_value["${ARES_SUPERVISED}.theFollowingProgrammingLanguageConfigurationIsUsed"]}"
  if [[ "$configuration" != "${LANGUAGE_CONFIGURATION_NAME:-}" ]]; then
    ares_at "${ARES_SUPERVISED}.theFollowingProgrammingLanguageConfigurationIsUsed"
    refuse_cfg "the programming language configuration ${configuration@Q} was not loaded for this run, which loaded ${LANGUAGE_CONFIGURATION_NAME:-none}"
  fi
  ares_check_supervised_code
  ares_check_resource_entries
  list="${ARES_ACCESSES}.regardingFileSystemInteractions"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    ares_map_file_entry "$tdir" "${list}[${index}]" "$project_root" "$base_dir"
  done
  list="${ARES_ACCESSES}.regardingNetworkConnections"
  for (( index = 0; index < ares_count["$list"]; index++ )); do
    ares_map_network_entry "${list}[${index}]" "${tdir}/net.rules"
  done
  ares_map_timeouts
  PARSE_LOCATION=""
  ares_report_summary
  PARSED_FS_DIR="$tdir"
  PARSED_NET_FILE="${tdir}/net.rules"
  PARSED_BIND_FILE="${tdir}/bind.rules"
  PARSED_ACCEPT_FILE="${tdir}/accept.rules"
  PARSED_ARES_CONFIGURATION="$configuration"
  PARSED_ARES_SKIPPED="$ares_skipped"
}
