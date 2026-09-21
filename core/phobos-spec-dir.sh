#!/usr/bin/env bash
# shellcheck shell=bash
# The directory a run's specification lives in, and its lifetime.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034

# Makes one temporary file for a layer's own use and prints it. Under the scratch directory
# when the caller set PHOBOS_SCRATCH, so it is removed with the specification directory even
# when the run ends at a refusal, which exits without reaching the rm that follows the use;
# otherwise a plain temporary file. Takes a name template ending in XXXXXX.
new_scratch_file() {
  local template="$1"
  if [[ -n "${PHOBOS_SCRATCH:-}" ]]; then
    mktemp -p "$PHOBOS_SCRATCH" "$template"
  else
    mktemp -t "$template"
  fi
}

# --------------------------------------------------------------------------
# The directory a run's specification lives in.
#
# phobos.sh writes the effective policy there, and the rules file in it is read by
# every process the command starts. It is created per run, marked as created by
# Phobos, and removed by whichever layer ends the run, so that neither a stale
# policy nor a directory a caller handed in is ever left behind or deleted.
# --------------------------------------------------------------------------

# The file that marks a specification directory as one phobos.sh created.
PHB_SPEC_MARKER=".phobos-owned-spec"

# The files write_spec creates, the only ones remove_owned_spec_dir deletes.
PHB_SPEC_FILES="read.paths execute.paths write.paths create.paths delete.paths tail.flags net.rules bind.rules timeout.sec limits.conf"

# The subdirectory phobos.sh keeps its own scratch files in, so they live under the
# specification directory and are removed with it rather than left in /tmp. phobos.sh ends
# with exec, so its own EXIT trap never runs; this is how the scratch is cleaned regardless.
PHB_SPEC_SCRATCH="scratch"

# Refuses a parent for the specification directory that is not an absolute path
# to an existing directory. Assumes it is called plainly, not in a command
# substitution, so that the refusal ends the run.
refuse_unusable_spec_parent() {
  local parent="$1"
  [[ "$parent" == /* && -d "$parent" ]] && return 0
  report "Policy invalid: the --spec-parent '${parent}' is not an absolute path to an existing directory. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
}

# Marks a directory phobos.sh has just created with mktemp as its own. Assumes
# nothing else can write there yet, which mktemp's private mode guarantees.
mark_owned_spec_dir() {
  : > "$1/${PHB_SPEC_MARKER}"
}

# Removes a specification directory phobos.sh created, and does nothing to any
# other. Deletes the scratch subdirectory phobos.sh made, the files write_spec writes
# and the marker, then the directory itself, so a directory that has gained anything
# else stays and the failure is returned rather than the contents deleted. Assumes the
# path may be empty, missing or not a directory, all of which leave nothing to do.
remove_owned_spec_dir() {
  local directory="$1"
  local name
  [[ -n "$directory" && -d "$directory" && ! -L "$directory" ]] || return 0
  [[ -f "$directory/${PHB_SPEC_MARKER}" && ! -L "$directory/${PHB_SPEC_MARKER}" ]] || return 0
  rm -rf -- "${directory:?}/${PHB_SPEC_SCRATCH}" || return 1
  for name in ${PHB_SPEC_FILES}; do
    rm -f -- "$directory/$name" || return 1
  done
  rm -f -- "$directory/${PHB_SPEC_MARKER}" || return 1
  rmdir -- "$directory"
}

# Ends the shell with the given status after removing the owned specification directory,
# which carries the scratch subdirectory every layer makes its temporary files in. A
# directory that cannot be removed is reported, and turns a run that had otherwise
# succeeded into a PHB-ERUNTIME failure rather than leaving a policy behind unnoticed; a
# run that had already failed keeps its own status. Meant for an EXIT trap, which passes $?
# as the first argument, so that it is read before anything else runs.
finish_owned_spec_dir() {
  local status="$1"
  local directory="$2"
  if ! remove_owned_spec_dir "$directory"; then
    _log "cleanup: could not remove the specification directory '${directory}'"
    if (( status == 0 )); then status="${PHB_ERUNTIME}"; fi
  fi
  exit "$status"
}
