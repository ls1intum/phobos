#!/usr/bin/env bash
# shellcheck shell=bash
# This file is a library: every variable it defines is read by the scripts that
# source it, never here, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
set -euo pipefail
PHB_OK=0
PHB_EPOLICY=11
PHB_EMERGE=12
PHB_EBASE=13
PHB_ETIMEOUT=14
PHB_ERUNTIME=15
_log()   { printf '%s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >&2; }
die()    { _log "$1"; exit "${2:-1}"; }
report() { printf '%s\n' "$1"; }
uniq_keep_order() { awk '!seen[$0]++'; }
depth_sort()      { awk '{print gsub(/\//,"/")+1 " " $0}' | sort -k1,1n -k2,2 | cut -d" " -f2-; }
canon_paths() {
  if command -v realpath >/dev/null 2>&1; then
    while IFS= read -r p; do [[ -z "$p" ]] && continue; realpath --canonicalize-missing --no-symlinks "$p" || echo "$p"; done
  else
    cat
  fi
}
allowed_keys() {
  cat <<'EOF'
TIMEOUT_SECONDS
NET_ALLOWLIST_FILE
RO_PATHS_FILE
RW_PATHS_FILE
HIDE_PATHS_FILE
TAIL_FLAGS_FILE
EOF
}
validate_config_file_keys() {
  local file="$1"
  local keys ok unknown=""
  keys=$(sed -E -n 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p' "$file" | sed 's/[[:space:]]//g' | sort -u)
  ok=$(allowed_keys | sort -u)
  while IFS= read -r k; do
    [[ -z "$k" ]] && continue
    if ! grep -qx "$k" <<< "$ok"; then unknown+="$k "; fi
  done <<< "$keys"
  if [[ -n "$unknown" ]]; then
    report "Policy invalid: unknown key(s): ${unknown}. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
}
# Timeout values are seconds: either a whole number, or seconds with
# millisecond precision written as exactly three decimal places.
# GNU timeout receives the value with an explicit seconds suffix, so no unit
# conversion happens after this point.
PHB_TIMEOUT_PATTERN='^[0-9]+(\.[0-9]{3})?$'

# Validates one configured timeout value and stores it in PARSED_TIMEOUT.
# An unusable value is a policy error rather than an ignored line, because
# silently dropping it would run the command with no limit at all.
set_parsed_timeout() {
  local value="$1"
  if [[ ! "$value" =~ $PHB_TIMEOUT_PATTERN ]]; then
    report "Policy invalid: timeout '${value}' must be seconds, either whole or with exactly three decimals. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  # Every accepted spelling of zero (0, 0.000, ...) disables the timeout.
  if [[ -z "${value//[0.]/}" ]]; then
    PARSED_TIMEOUT=""
  else
    PARSED_TIMEOUT="$value"
  fi
}
parse_cfg_policy() {
  local cfg="$1"
  local tdir; tdir="$(mktemp -d -t phobos-cfg.XXXXXX)"
  INI_TMP_DIRS+=" ${tdir}"
  local ro="${tdir}/ro.paths" rw="${tdir}/rw.paths" hide="${tdir}/hide.paths" net="${tdir}/net.rules"
  : >"$ro"; : >"$rw"; : >"$hide"; : >"$net"
  local sec=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="$(echo "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then sec="${BASH_REMATCH[1]}"; continue; fi
    case "$sec" in
      readonly|read) printf '%s\n' "$line" >>"$ro" ;;
      write)         printf '%s\n' "$line" >>"$rw" ;;
      hide|tmpfs)    printf '%s\n' "$line" >>"$hide" ;;
      network)
        if [[ "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
          local target="${BASH_REMATCH[1]}" host port="*"
          if [[ "$target" == *:* ]]; then host="${target%:*}"; port="${target##*:}"; else host="$target"; fi
          host="${host#[}"; host="${host%]}"; printf '%s %s\n' "$host" "$port" >>"$net"
        fi ;;
      limits|timeout)
        # Lines carrying another key (mem_mb=...) stay untouched. An explicit
        # timeout, or a bare value on its own line, is the timeout and is
        # validated; an unusable one is reported rather than ignored.
        if [[ "$line" =~ ^timeout[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_timeout "${BASH_REMATCH[1]}"
        elif [[ "$line" != *=* ]]; then
          set_parsed_timeout "$line"
        fi ;;
      *) ;;
    esac
  done <"$cfg"
  PARSED_RO_FILE="$ro"; PARSED_RW_FILE="$rw"; PARSED_HIDE_FILE="$hide"; PARSED_NET_FILE="$net"; : "${PARSED_TIMEOUT:=}"
}
merge_fs_per_path() {
  local base_ro="$1" base_rw="$2" base_hide="$3"
  local -n cur_ro_ref="$4"; local -n cur_rw_ref="$5"; local -n cur_hide_ref="$6"
  local add_ro="$7" add_rw="$8" add_hide="$9"
  declare -A BASE_RO=() BASE_RW=()
  if [[ -s "$base_ro" ]]; then while IFS= read -r p; do [[ -z "$p" ]] && continue; BASE_RO["$p"]=1; done < <(canon_paths < "$base_ro"); fi
  if [[ -s "$base_rw" ]]; then while IFS= read -r p; do [[ -z "$p" ]] && continue; BASE_RW["$p"]=1; done < <(canon_paths < "$base_rw"); fi
  declare -A CUR_RO=() CUR_RW=() CUR_HIDE=()
  if [[ -s "$cur_ro_ref"  ]]; then while IFS= read -r p; do [[ -z "$p" ]] && continue; CUR_RO["$p"]=1; done < "$cur_ro_ref"; fi
  if [[ -s "$cur_rw_ref"  ]]; then while IFS= read -r p; do [[ -z "$p" ]] && continue; CUR_RW["$p"]=1; done < "$cur_rw_ref"; fi
  if [[ -s "$cur_hide_ref" ]]; then while IFS= read -r p; do [[ -z "$p" ]] && continue; CUR_HIDE["$p"]=1; done < "$cur_hide_ref"; fi
  if [[ -s "$add_hide" ]]; then
    while IFS= read -r p; do [[ -z "$p" ]] && continue; CUR_HIDE["$p"]=1; unset "CUR_RO[$p]"; unset "CUR_RW[$p]"; done < <(canon_paths < "$add_hide" | uniq_keep_order)
  fi
  if [[ -s "$add_ro" ]]; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if [[ -n "${BASE_RO["$p"]:-}" || -n "${BASE_RW["$p"]:-}" ]]; then
        CUR_RO["$p"]=1; unset "CUR_RW[$p]"; unset "CUR_HIDE[$p]"
      else
        report "Policy merge failed: path '$p' requested RO but base does not allow access. (PHB-EMERGE)"; exit "${PHB_EMERGE}"
      fi
    done < <(canon_paths < "$add_ro" | uniq_keep_order)
  fi
  if [[ -s "$add_rw" ]]; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      if [[ -n "${BASE_RW["$p"]:-}" ]]; then
        CUR_RW["$p"]=1; unset "CUR_RO[$p]"; unset "CUR_HIDE[$p]"
      else
        report "Policy merge failed: path '$p' requested RW but base forbids write. (PHB-EMERGE)"; exit "${PHB_EMERGE}"
      fi
    done < <(canon_paths < "$add_rw" | uniq_keep_order)
  fi
  { for k in "${!CUR_RO[@]}"; do echo "$k"; done; } | uniq_keep_order | depth_sort > "$cur_ro_ref" || : > "$cur_ro_ref"
  { for k in "${!CUR_RW[@]}"; do echo "$k"; done; } | uniq_keep_order | depth_sort > "$cur_rw_ref" || : > "$cur_rw_ref"
  { for k in "${!CUR_HIDE[@]}"; do echo "$k"; done; } | uniq_keep_order | depth_sort > "$cur_hide_ref" || : > "$cur_hide_ref"
}
net_union() {
  local out="$1"; shift
  : > "$out"
  declare -A SEEN=()
  for f in "$@"; do
    [[ -n "$f" && -s "$f" ]] || continue
    while IFS= read -r ln; do
      [[ -z "$ln" ]] && continue
      if [[ -z "${SEEN["$ln"]:-}" ]]; then
        echo "$ln" >> "$out"; SEEN["$ln"]=1
      fi
    done < <(sed -E 's/#.*$//' "$f" | sed '/^[[:space:]]*$/d')
  done
}

filter_existing() { while IFS= read -r p; do [[ -n "$p" && -e "$p" ]] && printf '%s\n' "$p"; done; }

write_spec() {
  local spec_dir="$1" ro="$2" rw="$3" hide="$4" net="$5" timeout="$6" tail="$7"
  mkdir -p "$spec_dir"

  if [[ -s "$ro" ]]; then filter_existing < "$ro" > "${spec_dir}/ro.paths"; else : > "${spec_dir}/ro.paths"; fi
  if [[ -s "$hide" ]]; then filter_existing < "$hide" > "${spec_dir}/hide.paths"; else : > "${spec_dir}/hide.paths"; fi

  cp "$rw"   "${spec_dir}/rw.paths"   2>/dev/null || : > "${spec_dir}/rw.paths"

  if [[ -n "$timeout" ]]; then printf '%s\n' "$timeout" > "${spec_dir}/timeout.sec"; else : > "${spec_dir}/timeout.sec"; fi
  if [[ -n "$tail" && -f "$tail" ]]; then sed -E 's/#.*$//' "$tail" | sed '/^[[:space:]]*$/d' > "${spec_dir}/tail.flags"; else : > "${spec_dir}/tail.flags"; fi
  if [[ -n "$net" && -s "$net" ]]; then cp "$net" "${spec_dir}/net.rules"; else : > "${spec_dir}/net.rules"; fi
}
fs_union_files() {
  local out_ro="$1" out_rw="$2" out_hide="$3" in_ro="$4" in_rw="$5" in_hide="$6"
  tmpd="$(mktemp -d)"; trap 'rm -rf "$tmpd"' RETURN
  for k in ro rw hide; do : >"${tmpd}/${k}.all"; done
  [[ -s "$out_ro"   ]] && cat "$out_ro"   >> "${tmpd}/ro.all"
  [[ -s "$out_rw"   ]] && cat "$out_rw"   >> "${tmpd}/rw.all"
  [[ -s "$out_hide" ]] && cat "$out_hide" >> "${tmpd}/hide.all"
  [[ -s "$in_ro"    ]] && cat "$in_ro"    >> "${tmpd}/ro.all"
  [[ -s "$in_rw"    ]] && cat "$in_rw"    >> "${tmpd}/rw.all"
  [[ -s "$in_hide"  ]] && cat "$in_hide"  >> "${tmpd}/hide.all"

  canon_paths < "${tmpd}/ro.all"   | uniq_keep_order | depth_sort > "$out_ro"   || : > "$out_ro"
  canon_paths < "${tmpd}/rw.all"   | uniq_keep_order | depth_sort > "$out_rw"   || : > "$out_rw"
  canon_paths < "${tmpd}/hide.all" | uniq_keep_order | depth_sort > "$out_hide" || : > "$out_hide"
}

# --------------------------------------------------------------------------
# Translating a parsed policy into phobos-landlock arguments.
#
# Both entry points use these, so the two cannot drift apart. That has already
# happened once in this repository, which is why it lives here and not twice.
# --------------------------------------------------------------------------

# Rights each section grants, as the letters phobos-landlock understands.
PHB_RIGHTS_READONLY="r"
PHB_RIGHTS_EXECUTABLE="rx"
PHB_RIGHTS_WRITE="rwmd"

# canon_paths deliberately passes --no-symlinks, because the merge logic
# compares what the policy wrote. The conflict check below needs the opposite:
# Landlock anchors a rule on the inode it opens, so /bin and /usr/bin are one
# tree on a merged-usr system even though they are two lines in the policy.
resolve_symlinks() {
  if command -v realpath >/dev/null 2>&1; then
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      realpath --canonicalize-missing "$p" 2>/dev/null || printf '%s\n' "$p"
    done
  else
    cat
  fi
}

# Landlock unions the rights of every rule along a path: a nested rule can only
# add, never take away. Measured, not assumed.
#
# Two consequences, and they are not the same thing:
#
#   A policy that declares FEWER rights on a nested path states a restriction
#   that will not hold. /usr executable with /usr/share read-only leaves
#   /usr/share executable. That is refused, because the entry would read as a
#   limit and be none.
#
#   A policy that declares DIFFERENT rights, neither side a subset of the other,
#   is normal and stays allowed: a readable, executable tree with one writable
#   directory inside it is the ordinary shape of a build workspace. The nested
#   path still inherits the ancestor's rights on top of its own, so the effective
#   set is the union, and the union is what gets handed to the kernel and logged.
#   Emitting the narrower declaration instead would make the verbose output
#   disagree with what is actually enforced.

# Answers whether every letter of the first string appears in the second.
rights_subset() {
  local a="$1" b="$2" i
  for (( i = 0; i < ${#a}; i++ )); do
    [[ "$b" == *"${a:$i:1}"* ]] || return 1
  done
  return 0
}

# Deduplicates the letters and puts them in the order the usage text lists them,
# so two spellings of one set compare equal and the logged form reads the way the
# documentation does rather than alphabetically.
PHB_RIGHTS_ORDER="rwxmdi"
rights_normalise() {
  local set="$1" out="" i letter
  for (( i = 0; i < ${#PHB_RIGHTS_ORDER}; i++ )); do
    letter="${PHB_RIGHTS_ORDER:$i:1}"
    [[ "$set" == *"$letter"* ]] && out="${out}${letter}"
  done
  printf '%s' "$out"
}

# Reads "rights<TAB>path" lines from the first file, refuses any entry that is a
# strict narrowing of an ancestor, and writes "effective-rights<TAB>path" for the
# rest into the second file.
#
# The result goes to a named file rather than to stdout on purpose: report()
# prints on stdout, so a refusal written while stdout is redirected would land in
# the data file instead of in front of the person the message is for.
resolve_rights_hierarchy() {
  local table="$1" output="$2" a_rights a_path d_rights d_path effective
  : > "$output"
  while IFS=$'\t' read -r d_rights d_path; do
    [[ -z "$d_path" ]] && continue
    effective="$d_rights"
    while IFS=$'\t' read -r a_rights a_path; do
      [[ -z "$a_path" ]] && continue
      [[ "$d_path" == "$a_path" ]] && continue
      [[ "$d_path" == "${a_path%/}/"* ]] || continue
      if rights_subset "$d_rights" "$a_rights" && ! rights_subset "$a_rights" "$d_rights"; then
        report "Policy unenforceable: '$d_path' is granted '$d_rights' but lies beneath '$a_path', which is granted the wider '$a_rights'. Landlock adds the rights of every rule along a path and can never take one away, so the narrower entry would not hold. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
      effective="${effective}${a_rights}"
    done < "$table"
    effective="$(rights_normalise "$effective")"
    if [[ "$effective" != "$(rights_normalise "$d_rights")" ]]; then
      _log "rights: '$d_path' is declared '$d_rights' but lies beneath a wider rule, so it effectively holds '$effective'"
    fi
    printf '%s\t%s\n' "$effective" "$d_path" >> "$output"
  done < "$table"
}

# Fills the named array with one --rights=LETTERS PATH pair per policy entry,
# after refusing a hierarchy that cannot hold. Write paths are materialised
# first, because a Landlock rule needs an existing path to open.
# Usage: build_path_args <array-name> <ro-file> <rx-file> <rw-file>
build_path_args() {
  local -n args_ref="$1"
  local ro="$2" rx="$3" rw="$4"
  local table; table="$(mktemp -t phobos-rights.XXXXXX)"
  local section_file section_rights p

  # Parallel lists rather than "file:rights" strings: a path may contain a colon
  # and splitting on it would quietly cut the file name in half.
  local -a section_files=( "$ro" "$rx" "$rw" )
  local -a section_rights_list=( "${PHB_RIGHTS_READONLY}" "${PHB_RIGHTS_EXECUTABLE}" \
                                 "${PHB_RIGHTS_WRITE}" )
  local section_index
  for (( section_index = 0; section_index < ${#section_files[@]}; section_index++ )); do
    section_file="${section_files[$section_index]}"
    section_rights="${section_rights_list[$section_index]}"
    [[ -n "$section_file" && -s "$section_file" ]] || continue
    while IFS= read -r p; do
      [[ -z "$p" ]] && continue
      # A dangling symlink answers false to -e, and the redirection below would
      # then follow it and create or truncate whatever it points at, outside
      # anything the policy named. phobos-landlock refuses such a path later,
      # but by then the damage is done.
      if [[ -L "$p" && ! -e "$p" ]]; then
        report "Policy invalid: '$p' is a symbolic link with no target, so materialising it would write wherever it points. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
      if [[ "$section_rights" == "${PHB_RIGHTS_WRITE}" && ! -e "$p" ]]; then
        # A trailing slash means "directory" (e.g. target/ after a clean),
        # anything else is treated as a file, as before.
        if [[ "$p" == */ ]]; then
          mkdir -p "$p" 2>/dev/null || true
        else
          mkdir -p "$(dirname "$p")" 2>/dev/null || true
          : > "$p" || true
        fi
      fi
      printf '%s\t%s\t%s\n' "$section_rights" \
             "$(printf '%s\n' "$p" | resolve_symlinks)" "$p" >> "$table"
    done < "$section_file"
  done

  # The hierarchy is judged on resolved paths, so that two spellings of one
  # directory are recognised as the same tree. The kernel is still handed the
  # path the policy wrote: resolving is a comparison, not a rewrite.
  # Two spellings can name one tree: /bin is a symlink to /usr/bin in the run
  # image. Landlock anchors on the inode, so it sees one target with the union of
  # both entries' rights. The table is folded the same way before the hierarchy
  # is judged, otherwise the two rows would skip each other as "the same path"
  # and a conflict between them would be neither merged nor reported.
  local resolved_table; resolved_table="$(mktemp -t phobos-rights-r.XXXXXX)"
  local fold_path fold_rights
  while IFS=$'\t' read -r fold_rights fold_path _; do
    [[ -z "$fold_path" ]] && continue
    printf '%s\t%s\n' "$fold_rights" "$fold_path"
  done < "$table" \
    | awk -F'\t' '{ seen[$2] = seen[$2] $1 } END { for (p in seen) printf "%s\t%s\n", seen[p], p }' \
    > "$resolved_table"
  # Report where the folding actually widened something, so one spelling silently
  # granting more than the other is visible rather than absorbed.
  local folded_rights folded_path original_rights
  while IFS=$'\t' read -r folded_rights folded_path; do
    folded_rights="$(rights_normalise "$folded_rights")"
    while IFS=$'\t' read -r original_rights fold_path _; do
      [[ "$fold_path" == "$folded_path" ]] || continue
      if [[ "$(rights_normalise "$original_rights")" != "$folded_rights" ]]; then
        _log "rights: several policy entries name '$folded_path'; it holds the union '$folded_rights'"
        break
      fi
    done < "$table"
  done < "$resolved_table"
  # Called plainly, neither in a pipe nor in a process substitution: those run the
  # function in a subshell, where its exit on an unenforceable policy would end
  # only that subshell and leave the run going with no rules at all. A refusal has
  # to be able to stop the script it is protecting.
  local effective_table; effective_table="$(mktemp -t phobos-rights-e.XXXXXX)"
  resolve_rights_hierarchy "$resolved_table" "$effective_table"

  # One rule per line the policy wrote, carrying the rights that actually hold
  # for its target. Driving the loop from the folded table instead would emit a
  # single rule for a target two entries name, and silently drop the other
  # spelling.
  local written_rights written_resolved written_path effective
  while IFS=$'\t' read -r written_rights written_resolved written_path; do
    [[ -n "$written_path" ]] || continue
    effective="$(awk -F'\t' -v target="$written_resolved" \
                     '$2 == target { print $1; exit }' "$effective_table")"
    args_ref+=( "--rights=${effective:-$written_rights}" "$written_path" )
  done < "$table"
  rm -f "$effective_table"

  rm -f "$table" "$resolved_table"
}
