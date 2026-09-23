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

# The file the network layer writes the egress broker's process id into, so the layer that ends
# the run can stop the broker, which the network layer cannot do itself because it execs.
PHB_SPEC_BROKER_PID="broker.pid"

# The file the network layer writes the inbound filter's process id into, so the layer that ends
# the run can stop it and free the fixed public port it holds, which the network layer cannot do
# itself because it execs. It is separate from the broker's, so one is stopped without the other.
PHB_SPEC_INBOUND_PID="inbound.pid"

# The files write_spec creates, the only ones remove_owned_spec_dir deletes.
PHB_SPEC_FILES="read.paths execute.paths write.paths create.paths delete.paths tail.flags net.rules bind.rules accept.rules timeout.sec limits.conf"

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

# Refuses a policy whose write, create or delete paths would make the specification directory
# writable by the graded command. The directory holds net.rules, which the connect guard reads
# before Landlock is applied, and the broker's and inbound filter's process-id files, which the
# trusted clean-up kills; a command that could write there could rewrite the connect policy or aim
# the kill at any process. refuse_unusable_spec_parent only checks the parent is an absolute
# existing directory, not the write paths, so this is the sole guarantor the directory lies outside
# them. Both sides are resolved through their symbolic links, because Landlock anchors a rule on the
# inode it opens. Takes the specification directory and a file holding the write paths, one per
# line. Assumes it is called plainly, so a refusal ends the run.
refuse_spec_dir_under_write_path() {
  local spec_dir="$1"
  local write_file="$2"
  local resolved
  local write_path
  local resolved_write
  resolved="$(printf '%s\n' "$spec_dir" | resolve_symlinks)"
  while IFS= read -r write_path || [[ -n "$write_path" ]]; do
    [[ -z "$write_path" ]] && continue
    resolved_write="$(printf '%s\n' "$write_path" | resolve_symlinks)"
    if [[ "$resolved" == "$resolved_write" || "$resolved" == "${resolved_write%/}/"* ]]; then
      report "Policy unenforceable: the specification directory '${spec_dir}' lies beneath the write path '${write_path}', so the graded command could rewrite the connect policy or the clean-up's process-id files. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
  done < "$write_file"
}

# Marks a directory phobos.sh has just created with mktemp as its own. Assumes
# nothing else can write there yet, which mktemp's private mode guarantees.
mark_owned_spec_dir() {
  : > "$1/${PHB_SPEC_MARKER}"
}

# Builds a specification directory a single layer owns, for a standalone run from one or more
# exercise configs, and leaves its path in BUILT_SPEC_DIR. It creates and marks the directory
# under the parent, sets an EXIT trap that removes it, and fills it through phobos-policy.sh, the
# one parser, so a layer never parses a config itself. The caller then runs the layer over
# BUILT_SPEC_DIR in specification-directory mode as a child and exits with the child's status, so
# the trap removes the directory once the run ends; a layer that execs its way to the command
# leaves no waiter of its own, which is why the owner is this outer shell rather than the layer.
# The trap is set before phobos-policy.sh runs, so a policy refusal removes the half-built
# directory too. Assumes it is called plainly, not in a command substitution, so that a refusal
# ends the run and phobos-policy.sh's messages reach the caller's own streams. Takes the directory
# holding phobos-policy.sh, the spec parent, the tail flags file (empty for phobos-policy.sh's own
# default), then the configs.
build_owned_spec_from_configs() {
  local policy_dir="$1"
  local spec_parent="$2"
  local tail_flags_file="$3"
  shift 3
  refuse_unusable_spec_parent "$spec_parent"
  BUILT_SPEC_DIR="$(mktemp -d "${spec_parent%/}/phobos-spec.XXXXXX")"
  mark_owned_spec_dir "$BUILT_SPEC_DIR"
  mkdir -p "${BUILT_SPEC_DIR}/${PHB_SPEC_SCRATCH}"
  # The directory is expanded into the trap now, so the trap removes this run's directory even
  # after BUILT_SPEC_DIR is reused or unset.
  # shellcheck disable=SC2064
  trap "finish_owned_spec_dir \"\$?\" \"${BUILT_SPEC_DIR}\"" EXIT
  local policy_args=( --spec-dir "$BUILT_SPEC_DIR" )
  [[ -n "$tail_flags_file" ]] && policy_args+=( --tail-flags-file "$tail_flags_file" )
  local cfg
  for cfg in "$@"; do policy_args+=( --config "$cfg" ); done
  "${policy_dir}/phobos-policy.sh" "${policy_args[@]}"
}

# Stops the egress broker whose process id the network layer recorded in the specification
# directory, if it recorded one, so the broker does not outlive the run it served. A pid file
# that names nothing running is simply removed. Assumes the directory is one Phobos owns.
stop_recorded_broker() {
  local directory="$1"
  local pid_file="$directory/${PHB_SPEC_BROKER_PID}"
  local pid
  [[ -f "$pid_file" && ! -L "$pid_file" ]] || return 0
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null
  rm -f -- "$pid_file"
}

# Stops the inbound filter whose process id the network layer recorded in the specification
# directory, if it recorded one, so the filter does not outlive the run and its fixed public port
# is freed. A pid file that names nothing running is simply removed. Assumes the directory is one
# Phobos owns.
stop_recorded_inbound() {
  local directory="$1"
  local pid_file="$directory/${PHB_SPEC_INBOUND_PID}"
  local pid
  [[ -f "$pid_file" && ! -L "$pid_file" ]] || return 0
  pid="$(cat "$pid_file" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null
  rm -f -- "$pid_file"
}

# Removes a specification directory phobos.sh created, and does nothing to any
# other. Stops any egress broker it recorded, then deletes the scratch subdirectory phobos.sh
# made, the files write_spec writes and the marker, then the directory itself, so a directory
# that has gained anything else stays and the failure is returned rather than the contents
# deleted. Assumes the path may be empty, missing or not a directory, all of which leave nothing to do.
remove_owned_spec_dir() {
  local directory="$1"
  local name
  [[ -n "$directory" && -d "$directory" && ! -L "$directory" ]] || return 0
  [[ -f "$directory/${PHB_SPEC_MARKER}" && ! -L "$directory/${PHB_SPEC_MARKER}" ]] || return 0
  stop_recorded_broker "$directory"
  stop_recorded_inbound "$directory"
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
