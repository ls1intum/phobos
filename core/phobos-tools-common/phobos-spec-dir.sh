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

# The file the network layer writes before it maps an exact [connect] name in a hosts file, naming
# that hosts file, so that whichever layer removes the specification directory also removes the
# run's lines from it. It is written before the first line is, so a run that dies in between
# leaves a record that finds nothing to remove rather than a line nothing will remove. A run that
# maps no name writes none, and its clean-up never opens the hosts file.
PHB_SPEC_HOSTS_RECORD="hosts.record"

# The name, before a random suffix, of the copy remove_run_hosts_entries filters the hosts file into
# inside the specification directory. A clean-up killed while the copy exists leaves it behind, so
# remove_owned_spec_dir deletes any such copy rather than find the directory not empty for ever.
PHB_SPEC_HOSTS_KEPT="hosts.kept"

# The file every writer and remover of a run's hosts-file lines locks, rather than the hosts file
# itself. The shipped policies grant the graded command read on /etc, and a process that can open a
# file can hold its flock, so locking /etc/hosts would let a command stall its own clean-up and
# other runs' start. No shipped policy grants /run. The lock is shared by every run in the
# container, whatever specification parent it uses, because they all write the same hosts file.
PHB_HOSTS_LOCK="/run/lock/phobos-hosts.lock"

# How long a writer or remover waits for that lock, so a lock nothing lets go of ends in a refused
# run or a kept specification directory rather than in a run that hangs.
PHB_HOSTS_LOCK_WAIT_SECONDS=10

# The files write_spec creates, the only ones remove_owned_spec_dir deletes.
PHB_SPEC_FILES="read.paths execute.paths write.paths create.paths delete.paths ipc.paths symlink.paths refer.paths tail.flags net.rules bind.rules accept.rules timeout.sec limits.conf"

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
# before Landlock is applied, and the record of the hosts file whose lines the trusted clean-up
# rewrites; a command that could write there could rewrite the connect policy or aim that rewrite
# at another file. refuse_unusable_spec_parent only checks the parent is an absolute
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
      report "Policy unenforceable: the specification directory '${spec_dir}' lies beneath the write path '${write_path}', so the graded command could rewrite the connect policy or the record the clean-up acts on. (PHB-EPOLICY)"
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
# under the parent, sets an EXIT trap that removes it, and fills it through phobos-policysystem.sh, the
# one parser, so a layer never parses a config itself. The caller then runs the layer over
# BUILT_SPEC_DIR in specification-directory mode as a child and exits with the child's status, so
# the trap removes the directory once the run ends; a layer that execs its way to the command
# leaves no waiter of its own, which is why the owner is this outer shell rather than the layer.
# The trap is set before phobos-policysystem.sh runs, so a policy refusal removes the half-built
# directory too. Assumes it is called plainly, not in a command substitution, so that a refusal
# ends the run and phobos-policysystem.sh's messages reach the caller's own streams. Takes the directory
# holding phobos-policysystem.sh, the spec parent, the tail flags file (empty for phobos-policysystem.sh's own
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
  "${policy_dir}/phobos-policysystem.sh" "${policy_args[@]}"
}

# Prints the tag that marks a hosts-file line as one this run added: the name of its
# specification directory, which mktemp made unique among the runs that share a parent and which
# holds no white space. The writer and every remover derive it the same way from the directory, so
# nothing else has to be passed between them.
run_hosts_tag() {
  printf 'phobos-run %s' "$(basename -- "$1")"
}

# Runs the given command while holding an exclusive flock on PHB_HOSTS_LOCK, waiting for it at most
# PHB_HOSTS_LOCK_WAIT_SECONDS, and answers the command's status, or failure when the lock could not
# be had in time. Every writer and remover of a run's hosts-file lines goes through here, so one
# run can neither add a line between another's read and write-back nor read a half-written file.
# Assumes flock(1) from util-linux, and that the lock's directory exists or can be created.
with_hosts_lock() {
  mkdir -p -- "$(dirname -- "$PHB_HOSTS_LOCK")" 2>/dev/null || :
  ( flock -x -w "$PHB_HOSTS_LOCK_WAIT_SECONDS" 9 && "$@" ) 9>> "$PHB_HOSTS_LOCK"
}

# Appends to the content file a comment line of exactly the given number of bytes, a bare newline
# when that number is one, so the content grows to the hosts file's current length. Written over
# the hosts file in one piece, it then leaves no byte of the old tail behind for a reader to parse,
# and what a reader may see past the new end until the truncate is a comment, not a broken line.
pad_with_comment() {
  local content="$1"
  local bytes="$2"
  if (( bytes == 1 )); then
    printf '\n' >> "$content"
    return
  fi
  printf '#%*s\n' "$(( bytes - 2 ))" '' >> "$content"
}

# Writes the content file over the target file in place and then shortens the target to the given
# length, without truncating it first. A hosts file is bind-mounted into a container, so it cannot
# be replaced by a rename, and a reader resolving a name takes no lock, so an emptied file would
# fail even localhost for the moment of the write; this way the unchanged beginning of the file is
# rewritten with the same bytes and is never absent. Assumes GNU dd and truncate.
overwrite_in_place() {
  local content="$1"
  local target="$2"
  local final_size="$3"
  local size
  size="$(wc -c < "$content")"
  if (( size > 0 )); then
    dd if="$content" of="$target" bs="$size" count=1 iflag=fullblock conv=notrunc status=none || return 1
  fi
  truncate -s "$final_size" -- "$target"
}

# Writes the hosts file without the lines that end in this run's tag into the kept file and, only
# when it removed any, writes that back over the hosts file, padded to the old length and then
# shortened, so a run whose lines are already gone leaves the file untouched. Lines of other runs,
# lines without a tag and every other byte stay as they were. Assumes the caller holds the hosts
# lock, and that the kept file lies where the graded command cannot write.
strip_run_hosts_entries() {
  local hosts_file="$1"
  local directory="$2"
  local kept="$3"
  local status=0
  local before
  local after
  PHB_HOSTS_TAG=" # $(run_hosts_tag "$directory")" awk '
    substr($0, length($0) - length(ENVIRON["PHB_HOSTS_TAG"]) + 1) == ENVIRON["PHB_HOSTS_TAG"] { removed++; next }
    { print }
    END { exit (removed > 0 ? 0 : 3) }
  ' "$hosts_file" > "$kept" || status=$?
  (( status == 3 )) && return 0
  (( status == 0 )) || return 1
  before="$(wc -c < "$hosts_file")"
  after="$(wc -c < "$kept")"
  pad_with_comment "$kept" "$(( before - after ))" || return 1
  overwrite_in_place "$kept" "$hosts_file" "$after"
}

# Removes this run's lines from the hosts file under the hosts lock, working on a copy inside the
# run's own specification directory, which the graded command cannot write, so nothing it controls
# can change the bytes between the read and the write-back. Returns failure when the lock, the file
# or the copy cannot be had, so the caller keeps the specification directory and an outer layer can
# try again.
remove_run_hosts_entries() {
  local hosts_file="$1"
  local directory="$2"
  local kept
  kept="$(mktemp "${directory}/${PHB_SPEC_HOSTS_KEPT}.XXXXXX")" || return 1
  if with_hosts_lock strip_run_hosts_entries "$hosts_file" "$directory" "$kept"; then
    rm -f -- "$kept"
    return 0
  fi
  rm -f -- "$kept"
  return 1
}

# Removes the run's lines from the hosts file its record names, when the network layer recorded
# one, and then the record itself. Assumes the directory is one Phobos owns, so the record is one
# the network layer wrote rather than one the graded command could have planted.
remove_recorded_hosts_entries() {
  local directory="$1"
  local record="$directory/${PHB_SPEC_HOSTS_RECORD}"
  local hosts_file
  [[ -f "$record" && ! -L "$record" ]] || return 0
  hosts_file="$(< "$record")"
  if [[ -n "$hosts_file" ]]; then
    remove_run_hosts_entries "$hosts_file" "$directory" || return 1
  fi
  rm -f -- "$record"
}

# Removes a specification directory phobos.sh created, and does nothing to any
# other. Removes the run's hosts-file lines first, and keeps the directory when that fails, so an
# outer layer's clean-up tries again rather than the record being lost with the lines still in
# place. It then deletes any copy of the hosts file a killed clean-up left, the scratch
# subdirectory phobos.sh made, the files write_spec writes and the marker, then the directory itself, so a directory that has gained anything else stays and
# the failure is returned rather than the contents deleted. Assumes the path may be empty,
# missing or not a directory, all of which leave nothing to do.
remove_owned_spec_dir() {
  local directory="$1"
  local name
  [[ -n "$directory" && -d "$directory" && ! -L "$directory" ]] || return 0
  [[ -f "$directory/${PHB_SPEC_MARKER}" && ! -L "$directory/${PHB_SPEC_MARKER}" ]] || return 0
  remove_recorded_hosts_entries "$directory" || return 1
  rm -f -- "$directory/${PHB_SPEC_HOSTS_KEPT}".* || return 1
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
