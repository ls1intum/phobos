#!/usr/bin/env bash
# shellcheck shell=bash
# Turning a parsed policy into the --rights= arguments phobos-landlock takes.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034

# --------------------------------------------------------------------------
# Translating a parsed policy into phobos-landlock arguments.
#
# The filesystem layer builds these arguments, and the tests read them back. They live
# here rather than in the layer so that the translation is stated once: it drifted apart
# when two entry points each carried their own copy.
# --------------------------------------------------------------------------

# The order the usage text lists the letters in, used to normalise a set.
PHB_RIGHTS_ORDER="rwxmdi"

# Answers whether every letter of the first set appears in the second.
rights_subset() {
  local subset="$1"
  local superset="$2"
  local index
  for (( index = 0; index < ${#subset}; index++ )); do
    [[ "$superset" == *"${subset:$index:1}"* ]] || return 1
  done
  return 0
}

# Prints the letters of a set once each, in PHB_RIGHTS_ORDER, so that two
# spellings of one set compare equal and the logged form reads like the manual.
rights_normalise() {
  local wanted="$1"
  local ordered=""
  local index
  local letter
  for (( index = 0; index < ${#PHB_RIGHTS_ORDER}; index++ )); do
    letter="${PHB_RIGHTS_ORDER:$index:1}"
    [[ "$wanted" == *"$letter"* ]] && ordered="${ordered}${letter}"
  done
  printf '%s' "$ordered"
}

# Refuses a path that is a symbolic link with no target. Assumes it is about to
# be materialised: the redirection that creates a missing write path follows such
# a link and writes wherever it points, outside anything the policy named, and
# phobos-landlock only refuses it afterwards.
refuse_dangling_symlink() {
  local candidate="$1"
  [[ -L "$candidate" && ! -e "$candidate" ]] || return 0
  report "Policy invalid: '$candidate' is a symbolic link with no target, so materialising it would write wherever it points. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
}

# Creates a missing write path, because a Landlock rule needs an existing path to
# open. A trailing slash means a directory, as it did before; anything else is
# treated as a file. Assumes the parent may be created too.
materialise_write_path() {
  local target="$1"
  [[ -e "$target" ]] && return 0
  if [[ "$target" == */ ]]; then
    mkdir -p "$target" 2>/dev/null || true
    return 0
  fi
  mkdir -p "$(dirname "$target")" 2>/dev/null || true
  : > "$target" || true
}

# Writes one "letter<TAB>resolved path<TAB>written path" line per policy entry into the named
# table. Takes the five per-right section files. Assumes each holds one path per line.
#
# The changeable paths (write, create, delete) are materialised first, so a path that is also
# read or executed exists by the time its read/execute row is built and keeps that right. A
# non-existent read/execute path is then dropped as a system path absent from this image; a
# non-existent changeable path is kept, so phobos-landlock refuses it with a clear policy
# error rather than the run failing later with EACCES.
collect_rights_table() {
  local table="$1"
  local read_file="$2"
  local execute_file="$3"
  local write_file="$4"
  local create_file="$5"
  local delete_file="$6"
  local changeable
  local entry
  for changeable in "$write_file" "$create_file" "$delete_file"; do
    [[ -n "$changeable" && -s "$changeable" ]] || continue
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      refuse_dangling_symlink "$entry"
      materialise_write_path "$entry"
    done < "$changeable"
  done
  local -a section_files=( "$read_file" "$execute_file" "$write_file" "$create_file" "$delete_file" )
  local -a section_letters=( r x w m d )
  local -a drop_if_missing=( 1 1 0 0 0 )
  local index
  local section_file
  local letter
  : > "$table"
  for (( index = 0; index < ${#section_files[@]}; index++ )); do
    section_file="${section_files[$index]}"
    letter="${section_letters[$index]}"
    [[ -n "$section_file" && -s "$section_file" ]] || continue
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      if (( drop_if_missing[index] )); then
        [[ -e "$entry" ]] || continue
      else
        refuse_dangling_symlink "$entry"
      fi
      printf '%s\t%s\t%s\n' "$letter" "$(printf '%s\n' "$entry" | resolve_symlinks)" "$entry" \
        >> "$table"
    done < "$section_file"
  done
}

# Folds the collected table down to one "rights<TAB>resolved path" line per
# target, unioning the rights of every spelling that names it.
#
# Two spellings can name one tree: /bin is a symlink to /usr/bin in the run-phase
# image. Landlock anchors on the inode, so it sees one target holding both
# entries' rights. Folding first is what lets the hierarchy check see that too;
# without it the two rows skip each other as "the same path" and a conflict
# between them is neither merged nor reported.
fold_table_by_target() {
  local table="$1"
  local folded="$2"
  awk -F'\t' '{ seen[$2] = seen[$2] $1 } END { for (target in seen) printf "%s\t%s\n", seen[target], target }' \
    "$table" > "$folded"
}

# Names every target whose folded rights are wider than one of its spellings
# asked for, so that one entry silently granting more than another is visible.
report_folded_widenings() {
  local table="$1"
  local folded="$2"
  local folded_rights
  local target
  local written_rights
  local written_target
  while IFS=$'\t' read -r folded_rights target; do
    folded_rights="$(rights_normalise "$folded_rights")"
    while IFS=$'\t' read -r written_rights written_target _; do
      [[ "$written_target" == "$target" ]] || continue
      if [[ "$(rights_normalise "$written_rights")" != "$folded_rights" ]]; then
        _log "rights: several policy entries name '$target'; it holds the union '$folded_rights'"
        break
      fi
    done < "$table"
  done < "$folded"
}

# Reads folded "rights<TAB>target" lines, refuses any entry that is a strict
# narrowing of an ancestor, and writes "effective rights<TAB>target" for the rest.
#
# Landlock unions the rights of every rule along a path: a nested rule can only
# add, never take away. So a policy declaring FEWER rights on a nested path states
# a restriction that will not hold, and that is refused. A policy declaring
# DIFFERENT rights, neither side a subset, is the ordinary shape of a workspace
# and stays allowed; its effective set is the union, and the union is what the
# kernel is handed, so the verbose output cannot disagree with what is enforced.
#
# The result goes to a named file rather than to stdout, so that the function is
# called plainly and never in a command substitution, whose subshell a refusal's
# exit would end instead of the run.
resolve_rights_hierarchy() {
  local table="$1"
  local output="$2"
  local ancestor_rights
  local ancestor_path
  local entry_rights
  local entry_path
  local effective
  : > "$output"
  while IFS=$'\t' read -r entry_rights entry_path; do
    [[ -z "$entry_path" ]] && continue
    effective="$entry_rights"
    while IFS=$'\t' read -r ancestor_rights ancestor_path; do
      [[ -z "$ancestor_path" ]] && continue
      [[ "$entry_path" == "$ancestor_path" ]] && continue
      [[ "$entry_path" == "${ancestor_path%/}/"* ]] || continue
      if rights_subset "$entry_rights" "$ancestor_rights" \
         && ! rights_subset "$ancestor_rights" "$entry_rights"; then
        report "Policy unenforceable: '$entry_path' is granted '$entry_rights' but lies beneath '$ancestor_path', which is granted the wider '$ancestor_rights'. Landlock adds the rights of every rule along a path and can never take one away, so the narrower entry would not hold. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
      effective="${effective}${ancestor_rights}"
    done < "$table"
    effective="$(rights_normalise "$effective")"
    if [[ "$effective" != "$(rights_normalise "$entry_rights")" ]]; then
      _log "rights: '$entry_path' is declared '$entry_rights' but lies beneath a wider rule, so it effectively holds '$effective'"
    fi
    printf '%s\t%s\n' "$effective" "$entry_path" >> "$output"
  done < "$table"
}

# Appends one --rights=LETTERS PATH pair per policy entry to the named array,
# carrying the rights that actually hold for that entry's target.
#
# Driven from the collected table rather than the folded one: folding is how two
# spellings are recognised as one tree, but each spelling still needs its own rule,
# and emitting only one would silently drop the other.
emit_rights_arguments() {
  local -n arguments_ref="$1"
  local table="$2"
  local effective_table="$3"
  local written_rights
  local written_target
  local written_path
  local effective
  while IFS=$'\t' read -r written_rights written_target written_path; do
    [[ -n "$written_path" ]] || continue
    effective="$(awk -F'\t' -v target="$written_target" \
                     '$2 == target { print $1; exit }' "$effective_table")"
    arguments_ref+=( "--rights=${effective:-$written_rights}" "$written_path" )
  done < "$table"
}

# Fills the named array with the path rules the policy asks for, after refusing a
# hierarchy Landlock cannot hold. Assumes the three section files hold one path
# per line and that write paths may be created.
#
# Each stage is called plainly, never in a pipe or a process substitution: those
# run it in a subshell, where its exit on an unenforceable policy would end only
# that subshell and leave the run going with no rules at all.
build_path_args() {
  local arguments_name="$1"
  local read_file="$2"
  local execute_file="$3"
  local write_file="$4"
  local create_file="$5"
  local delete_file="$6"
  local table
  local folded_table
  local effective_table
  table="$(new_scratch_file phobos-rights.XXXXXX)"
  folded_table="$(new_scratch_file phobos-rights-f.XXXXXX)"
  effective_table="$(new_scratch_file phobos-rights-e.XXXXXX)"
  collect_rights_table "$table" "$read_file" "$execute_file" "$write_file" "$create_file" "$delete_file"
  fold_table_by_target "$table" "$folded_table"
  report_folded_widenings "$table" "$folded_table"
  resolve_rights_hierarchy "$folded_table" "$effective_table"
  emit_rights_arguments "$arguments_name" "$table" "$effective_table"
  rm -f "$table" "$folded_table" "$effective_table"
}
