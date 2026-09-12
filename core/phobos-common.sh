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

# The order the usage text lists the letters in, used to normalise a set.
PHB_RIGHTS_ORDER="rwxmdi"

# Resolves each path on standard input through its symbolic links and prints it.
# Assumes realpath exists; without it the input is passed through unchanged, which
# makes the hierarchy check compare spellings rather than targets.
#
# canon_paths deliberately passes --no-symlinks, because the merge logic compares
# what the policy wrote. This needs the opposite: Landlock anchors a rule on the
# inode it opens, so /bin and /usr/bin are one tree on a merged-usr system even
# though they are two lines in the policy.
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

# Writes one "rights<TAB>resolved path<TAB>written path" line per policy entry
# into the named table. Assumes the three section files hold one path per line and
# that write paths may be created.
collect_rights_table() {
  local table="$1"
  local readonly_file="$2"
  local executable_file="$3"
  local write_file="$4"
  local -a section_files=( "$readonly_file" "$executable_file" "$write_file" )
  local -a section_rights=( "${PHB_RIGHTS_READONLY}" "${PHB_RIGHTS_EXECUTABLE}" \
                            "${PHB_RIGHTS_WRITE}" )
  local index
  local section_file
  local rights
  local entry
  : > "$table"
  for (( index = 0; index < ${#section_files[@]}; index++ )); do
    section_file="${section_files[$index]}"
    rights="${section_rights[$index]}"
    [[ -n "$section_file" && -s "$section_file" ]] || continue
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      refuse_dangling_symlink "$entry"
      [[ "$rights" == "${PHB_RIGHTS_WRITE}" ]] && materialise_write_path "$entry"
      printf '%s\t%s\t%s\n' "$rights" "$(printf '%s\n' "$entry" | resolve_symlinks)" "$entry" \
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
# The result goes to a named file rather than to stdout, because report() prints
# on stdout and a refusal written while stdout is redirected would land in the
# data file instead of in front of the person the message is for.
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
  local readonly_file="$2"
  local executable_file="$3"
  local write_file="$4"
  local table
  local folded_table
  local effective_table
  table="$(mktemp -t phobos-rights.XXXXXX)"
  folded_table="$(mktemp -t phobos-rights-f.XXXXXX)"
  effective_table="$(mktemp -t phobos-rights-e.XXXXXX)"
  collect_rights_table "$table" "$readonly_file" "$executable_file" "$write_file"
  fold_table_by_target "$table" "$folded_table"
  report_folded_widenings "$table" "$folded_table"
  resolve_rights_hierarchy "$folded_table" "$effective_table"
  emit_rights_arguments "$arguments_name" "$table" "$effective_table"
  rm -f "$table" "$folded_table" "$effective_table"
}

# Refuses a port that is not a number the protocol has. Assumes the caller has
# already decided this rule names a port at all rather than a wildcard.
refuse_unusable_port() {
  local host="$1"
  local port="$2"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) && return 0
  report "Policy invalid: '${host}:${port}' names no usable TCP port. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
}

# Reads a "host port" allow-list, writing the concrete ports it names into the
# second file and the first rule that names none into the third.
#
# Both results go to files rather than to stdout, because report() prints on
# stdout and a refusal raised while stdout is captured would be swallowed.
#
# net.rules holds pairs separated by a space, so the default field splitting is
# what is wanted here: with IFS cleared, read puts the whole line into the first
# variable and leaves the second empty, which makes every rule look like a
# wildcard.
collect_network_ports() {
  local rules="$1"
  local ports_file="$2"
  local wildcard_file="$3"
  local host
  local port
  : > "$ports_file"
  : > "$wildcard_file"
  while read -r host port; do
    [[ -z "$host" ]] && continue
    if [[ "$port" == "*" || -z "$port" ]]; then
      [[ -s "$wildcard_file" ]] || printf '%s:%s\n' "$host" "${port:-*}" > "$wildcard_file"
      continue
    fi
    refuse_unusable_port "$host" "$port"
    printf '%s\n' "$port" >> "$ports_file"
  done < "$rules"
}

# Fills the named array with the TCP port rules Landlock can actually enforce.
#
# The policy language names a host and a port, Landlock knows only ports. A rule
# naming no port therefore cannot be expressed at all: a section made only of
# those leaves the network layer off and says so, which is what the shipped
# policies do. A section mixing one with a concrete port is refused instead,
# because the concrete rule would read as enforced and would not be.
#
# Only an explicit star or an omitted port is that wildcard. "host:0" names no
# port that exists and is a policy mistake, not a licence to switch the layer off.
build_network_args() {
  local arguments_name="$1"
  local rules="$2"
  local -n network_ref="$arguments_name"
  local ports_file
  local wildcard_file
  local port
  [[ -n "$rules" && -s "$rules" ]] || return 0
  ports_file="$(mktemp -t phobos-ports.XXXXXX)"
  wildcard_file="$(mktemp -t phobos-wildcard.XXXXXX)"
  collect_network_ports "$rules" "$ports_file" "$wildcard_file"
  if [[ -s "$wildcard_file" ]] && [[ -s "$ports_file" ]]; then
    report "Policy unenforceable: '$(cat "$wildcard_file")' names no port, so Landlock cannot express it, while other rules do name one. A half-enforced network policy would look stricter than it is. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  if [[ -s "$wildcard_file" ]]; then
    _log "network: '$(cat "$wildcard_file")' names no port; the Landlock network layer stays off and only libnetblocker filters this run"
    rm -f "$ports_file" "$wildcard_file"
    return 0
  fi
  while IFS= read -r port; do
    network_ref+=( --connect-tcp "$port" )
  done < <(sort -n -u "$ports_file")
  rm -f "$ports_file" "$wildcard_file"
}
