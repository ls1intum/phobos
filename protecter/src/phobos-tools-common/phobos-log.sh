#!/bin/bash
# shellcheck shell=bash
# Reporting.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
# Prints one line on stderr, prefixed with the UTC time, for the operator reading the run's log.
_log()   { printf '%s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >&2; }
# Logs the message and ends the shell with the given status, 1 when none is given.
die()    { _log "$1"; exit "${2:-1}"; }
# Prints a refusal or a finding for the person reading the run, on stderr, so it never mixes
# with the command's own output.
report() { printf '%s\n' "$1" >&2; }
# Whether --debug was given to the script that sourced this file. Reset on every source,
# because bash imports each environment variable as a shell variable of the same name, and
# --debug must never be switched on from the environment: only a script's own option parsing
# sets it.
PHB_DEBUG_ENABLED=0
# Switches debug_log on for the rest of this script. Called only from a script's own --debug
# option, never from anything the environment decides.
enable_debug_log() { PHB_DEBUG_ENABLED=1; }
# Prints one line on stderr, "[phobos] <layer>: <message>", followed by any further arguments
# quoted the way the shell would read them back, when --debug was given. Assumes the calling
# script set PHB_DEBUG_ENABLED from its own options.
debug_log() {
  (( PHB_DEBUG_ENABLED )) || return 0
  local layer="$1"
  local message="$2"
  local quoted=""
  shift 2
  if (( $# > 0 )); then quoted=" $(printf '%q ' "$@")"; fi
  printf '[phobos] %s: %s%s\n' "$layer" "$message" "${quoted% }" >&2
}

# Sets REPLY to the processor time, in clock ticks, that the processes this shell has waited for used,
# and the processes they waited for in turn, read from the shell's own /proc entry (the cutime and
# cstime fields) without forking, since a subshell would have waited for nothing. Assumes /proc is
# mounted; without it REPLY is 0, which can only mean no line is worded.
waited_children_cpu_ticks() {
  local stat=""
  local -a fields=()
  REPLY=0
  read -r -d '' stat 2> /dev/null < "/proc/${BASHPID}/stat" || true
  stat="${stat##*) }"
  read -r -a fields <<< "$stat"
  REPLY=$(( ${fields[PHB_STAT_CUTIME_INDEX]:-0} + ${fields[PHB_STAT_CSTIME_INDEX]:-0} ))
}

# Prints the line for a resource limit the command's exit status shows it hit. The file size limit
# is SIGXFSZ, status 153, and is worded when the limits file names it and does not switch it off with
# 0. The CPU limit cannot be told from its status alone: the resource layer sets the soft and the
# hard limit to the same value, so the kernel ends the command with SIGKILL, 137, at the limit, as
# it ends one that a timeout or the out-of-memory killer stopped. So it is worded for 137, and for a
# 152 that only a command lowering its own soft limit can cause, only when the processes this shell
# waited for used the limit in processor time (PHB_CPU_LIMIT_SLACK_TICKS short of it counts), which
# the command did if the limit ended it. That is necessary and not sufficient: the limit is per process
# and the sum is over the whole tree, so a tree of processes that together used the limit and was then
# stopped some other way (the out-of-memory killer, an outside kill) gets the line wrongly.
# Takes the status, the CPU limit in seconds and the file size limit in megabytes, either empty when
# not set. A command that exits with 153 by itself gets the file size line, which a shell cannot
# tell apart from the signal; the process, open file and memory limits are not detectable from a
# status at all, since they surface as an error the command handles.
report_resource_limit_hit() {
  local status="$1"
  local cpu="$2"
  local fsize_mb="$3"
  if (( status == PHB_STATUS_SIGXFSZ )) && [[ -n "$fsize_mb" ]] && (( 10#$fsize_mb != 0 )); then
    report "Phobos Security Error: the program tried to illegally exceed the File Size Limit of $(( 10#$fsize_mb )) MB but was blocked by Phobos."
    return 0
  fi
  if (( status != PHB_STATUS_SIGKILL && status != PHB_STATUS_SIGXCPU )) || [[ -z "$cpu" ]] || (( 10#$cpu == 0 )); then
    return 0
  fi
  waited_children_cpu_ticks
  if (( REPLY + PHB_CPU_LIMIT_SLACK_TICKS >= 10#$cpu * PHB_CLOCK_TICKS_PER_SECOND )); then
    report "Phobos Security Error: the program tried to illegally exceed the CPU Time Limit of $(( 10#$cpu )) seconds but was blocked by Phobos."
  fi
}
