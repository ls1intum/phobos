#!/usr/bin/env bash
# shellcheck shell=bash
# The environment an entry point is started in, made safe to look things up in.
#
# A grader may start Phobos with the submission's tree as the current directory, and the
# caller's PATH may hold an entry that names that directory: ".", any other relative path, an
# empty entry (a leading or trailing colon, or two in a row), or one beginning with a tilde,
# which bash expands but execvp, and so env in every #! line and the enforcers, takes as a
# directory in the current one. Every external program Phobos runs before the sandbox exists
# would then be looked up there first. CDPATH would likewise move the cd an entry point makes
# to find its own directory, and a relative TMPDIR would put the network layer's scratch files
# in the submission's tree.
#
# Every entry point sources this file first, before phobos-common.sh, by a path it builds in
# bash alone, and calls clean_startup_environment before it runs any external program or cd.
# Nothing in this file may run either. It sources phobos-constants.sh for the exit status, which
# only assigns plain variables and is sourced again by phobos-common.sh to no effect.
#
# What it cannot reach is stated in SECURITY.md: the #! line finds bash through the caller's
# PATH before any of this runs, and bash reads BASH_ENV, and the dynamic loader LD_LIBRARY_PATH
# and LD_PRELOAD, before the first line of a script.
# shellcheck source=phobos-constants.sh
source "${BASH_SOURCE[0]%/*}/phobos-constants.sh"

# Sets REPLY to the entries of the colon-separated list $1 that begin with a slash, in their
# order and joined with colons, leaving out every other entry, the empty ones included. Assumes
# nothing: it is bash alone, runs no program and looks at no file, so an absolute entry is kept
# whether or not it names a directory, since it names the same place from every directory.
absolute_path_entries() {
  local rest="$1:"
  local entry
  REPLY=""
  while [[ -n "$rest" ]]; do
    entry="${rest%%:*}"
    rest="${rest#*:}"
    if [[ "$entry" == /* ]]; then
      REPLY="${REPLY:+${REPLY}:}${entry}"
    fi
  done
}

# Removes from PATH every entry that is not absolute, unsets CDPATH, and unsets TMPDIR when it
# is not absolute, so that nothing this script or a program it starts looks up depends on the
# current directory, the command's own environment included. Says on stderr what it removed
# from PATH and TMPDIR. Ends the script with PHB_ERUNTIME when PATH has no absolute entry at
# all, because it never adds one and an empty PATH is searched as the current directory.
# Assumes it is called before the script runs any external program or cd, and that PATH, when
# bash invented it because the environment had none, is left unexported by the assignment.
clean_startup_environment() {
  absolute_path_entries "${PATH-}"
  if [[ -z "$REPLY" ]]; then
    printf '%s\n' "PATH '${PATH-}' names no absolute directory, and an empty PATH is searched as the current directory; start Phobos with a PATH of absolute directories. (PHB-ERUNTIME)" >&2
    exit "${PHB_ERUNTIME}"
  fi
  if [[ "$REPLY" != "${PATH-}" ]]; then
    printf '%s\n' "NOTICE: PATH '${PATH-}' holds entries that are not absolute, which would be looked up in the current directory; they are removed for this run and its command, which see PATH '${REPLY}'." >&2
  fi
  PATH="$REPLY"
  unset CDPATH
  if [[ -n "${TMPDIR+set}" && "${TMPDIR}" != /* ]]; then
    printf '%s\n' "NOTICE: TMPDIR '${TMPDIR}' is not absolute, so temporary files would be made beneath the current directory; it is unset for this run and its command." >&2
    unset TMPDIR
  fi
}
