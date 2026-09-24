#!/usr/bin/env bash
# shellcheck shell=bash
# Reporting, and counting what a run was denied.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
# What the denial report counts in the command's stderr, one extended regular expression each.
PHB_NETWORK_DENIAL_PATTERN='EAI_AGAIN|EAI_FAIL|EAI_NONAME|Network is unreachable|Connection timed out'
PHB_FILESYSTEM_DENIAL_PATTERN='Permission denied|EACCES|EROFS'
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

# Reads a command's stderr on standard input and prints one line, "<network> <filesystem>",
# the number of lines matching each denial pattern, counted as grep -c would, a last line
# without a newline included. Assumes it runs in a process of its own, a process substitution,
# since it sets that process's rlimits to the counter's own bounds and then becomes awk. The
# counter's own errors, its out-of-memory message when one endless line exceeds its bound
# among them, go nowhere: they are not the command's output, and a counter that fails only
# means the run reports no counts.
count_denials() {
  ulimit -v "$PHB_DENIAL_COUNTER_MEMORY_KB"
  ulimit -t "$PHB_DENIAL_COUNTER_CPU_SECONDS"
  LC_ALL=C exec awk -v network="$PHB_NETWORK_DENIAL_PATTERN" -v filesystem="$PHB_FILESYSTEM_DENIAL_PATTERN" \
    '$0 ~ network { n++ } $0 ~ filesystem { f++ } END { printf "%d %d\n", n, f }' 2>/dev/null
}
