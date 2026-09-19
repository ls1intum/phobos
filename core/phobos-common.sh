#!/usr/bin/env bash
# shellcheck shell=bash
# This file is a library: every variable it defines is read by the scripts that
# source it, never here, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
set -euo pipefail
PHB_EPOLICY=11
PHB_ETIMEOUT=14
PHB_ERUNTIME=15
# The filesystem sections, each granting exactly its own phobos-landlock right.
PHB_FS_RIGHTS="read execute write create delete"
# How long the filesystem layer waits, after the command has ended, for the denial counts. A
# process the command left behind can keep its stderr, and so the counter, alive; the layer
# then reports no counts rather than wait for it. Kept below the timeout layer's --kill-after,
# so GNU timeout never escalates to SIGKILL while the layer is still waiting here.
PHB_DENIAL_COUNT_GRACE_SECONDS=2
# The counter's own limits. It runs outside the command's rlimits, so without these a single
# endless stderr line could grow it without bound. A counter that hits them dies, and the run
# then reports no counts; the command's output is never affected.
PHB_DENIAL_COUNTER_MEMORY_KB=65536
PHB_DENIAL_COUNTER_CPU_SECONDS=60
# What the denial report counts in the command's stderr, one extended regular expression each.
PHB_NETWORK_DENIAL_PATTERN='EAI_AGAIN|EAI_FAIL|EAI_NONAME|Network is unreachable|Connection timed out'
PHB_FILESYSTEM_DENIAL_PATTERN='Permission denied|EACCES|EROFS'
_log()   { printf '%s\n' "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*" >&2; }
die()    { _log "$1"; exit "${2:-1}"; }
report() { printf '%s\n' "$1" >&2; }
uniq_keep_order() { awk '!seen[$0]++'; }
depth_sort()      { awk '{print gsub(/\//,"/")+1 " " $0}' | sort -k1,1n -k2,2 | cut -d" " -f2-; }
canon_paths() {
  if command -v realpath >/dev/null 2>&1; then
    while IFS= read -r p; do [[ -z "$p" ]] && continue; realpath --canonicalize-missing --no-symlinks "$p" || echo "$p"; done
  else
    cat
  fi
}
# GNU timeout's own exit statuses: the command ran past its limit and was stopped by the
# SIGTERM, or it ignored the SIGTERM and the --kill-after escalation's SIGKILL ended it
# (128 + 9). A command can end with either status on its own, so neither alone is a timeout.
PHB_TIMEOUT_EXPIRED_EXIT=124
PHB_TIMEOUT_KILLED_EXIT=137
PHB_MICROSECONDS_PER_MILLISECOND=1000
# Timeout values are seconds: either a whole number, or seconds with
# millisecond precision written as exactly three decimal places.
# GNU timeout receives the value with an explicit seconds suffix, so no unit
# conversion happens after this point.
PHB_TIMEOUT_PATTERN='^[0-9]+(\.[0-9]{3})?$'

# A timeout in whole milliseconds, so two spellings of one value compare as numbers rather
# than as text. The pattern guarantees a digit before the point and exactly three after it,
# so both parts are read in base ten, never as octal, and never with an empty field.
timeout_to_ms() {
  local value="$1" integer fraction="000"
  if [[ "$value" == *.* ]]; then integer="${value%%.*}"; fraction="${value#*.}"; else integer="$value"; fi
  printf '%s' "$(( 10#$integer * 1000 + 10#$fraction ))"
}

# The inverse, canonical: whole seconds print without a fraction, so 2 and 2.000 come back as
# the one spelling and the written specification does not depend on which cfg named it.
ms_to_timeout() {
  local ms="$1" seconds fraction
  seconds=$(( ms / 1000 )); fraction=$(( ms % 1000 ))
  if (( fraction == 0 )); then printf '%s' "$seconds"; else printf '%d.%03d' "$seconds" "$fraction"; fi
}

# Prints the given EPOCHREALTIME value in whole microseconds. Every character that is not a
# digit is dropped, because bash writes the decimal separator of the current locale (a comma
# under de_DE), and EPOCHREALTIME always carries exactly six decimals, so the digits that are
# left are the microseconds.
epoch_realtime_microseconds() {
  printf '%s' "${1//[!0-9]/}"
}

# Answers whether a run that ended with the given GNU timeout status after the given number of
# microseconds was stopped by the given timeout. GNU timeout passes the command's own status
# through when it did not time out, and a command killed by someone else, the OOM killer among
# them, ends with the same 137 as the escalation, so the status alone decides nothing: only a
# 124 or a 137 that came no earlier than the timeout is one. The time is the wall clock
# (EPOCHREALTIME), so a clock stepped backwards during a run can make a real expiry look too
# short and be passed through without PHB-ETIMEOUT; the run itself is never extended by it.
run_reached_timeout() {
  local status="$1"
  local elapsed_microseconds="$2"
  local timeout_value="$3"
  local limit_microseconds
  (( status == PHB_TIMEOUT_EXPIRED_EXIT || status == PHB_TIMEOUT_KILLED_EXIT )) || return 1
  limit_microseconds=$(( $(timeout_to_ms "$timeout_value") * PHB_MICROSECONDS_PER_MILLISECOND ))
  (( elapsed_microseconds >= limit_microseconds ))
}

# Merges one configured timeout value into PARSED_TIMEOUT and PARSED_TIMEOUT_DISABLED, which
# parse_cfg_policy resets per call. The rule is the same within a file and across files:
# every spelling of zero disables the timeout and wins over any finite value, and otherwise
# the largest finite value is kept. An unusable value is a policy error rather than an
# ignored line, because silently dropping it would run the command without a limit the
# policy asked for. PARSED_TIMEOUT keeps the raw spelling of the largest finite value so a
# parse test can read it back; the caller canonicalises the effective value.
set_parsed_timeout() {
  local value="$1"
  if [[ ! "$value" =~ $PHB_TIMEOUT_PATTERN ]]; then
    report "Policy invalid: timeout '${value}' must be seconds, either whole or with exactly three decimals. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  # Every accepted spelling of zero (0, 0.000, ...) disables the timeout and wins.
  if [[ -z "${value//[0.]/}" ]]; then
    PARSED_TIMEOUT_DISABLED=1
    return
  fi
  if [[ -z "${PARSED_TIMEOUT:-}" ]] || (( $(timeout_to_ms "$value") > $(timeout_to_ms "$PARSED_TIMEOUT") )); then
    PARSED_TIMEOUT="$value"
  fi
}

# Merges one resource-limit value into the named variable and its "<name>_DISABLED"
# companion, which parse_cfg_policy resets per call. Each value is a non-negative whole
# number; an unusable one is a policy error rather than an ignored line, because silently
# dropping it would run the command without a limit the policy asked for. The rule matches
# the timeout's: zero disables this limit and wins over any finite value, within a file and
# across files, and otherwise the largest finite value is kept.
set_parsed_limit() {
  local -n limit_ref="$1"
  local -n disabled_ref="${1}_DISABLED"
  local key="$2"
  local value="${3//[[:space:]]/}"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    report "Policy invalid: ${key} '${value}' must be a non-negative whole number. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  if (( 10#$value == 0 )); then
    disabled_ref=1
    return
  fi
  if [[ -z "${limit_ref:-}" ]] || (( 10#$value > 10#${limit_ref} )); then
    limit_ref="$value"
  fi
}

# Applies the configured resource limits to this shell, so the command tree it exec's into
# inherits them. Each is optional. rlimits are self-imposed and need no privilege, exactly as
# Landlock is, which is why this works inside the unprivileged container an exercise runs in.
# A configured limit that cannot be set ends the run rather than running without it. Assumes
# it is called plainly, not in a subshell, so the ulimit takes effect for the later exec.
apply_resource_limits() {
  local mem_mb="$1"
  local nproc="$2"
  local nofile="$3"
  local fsize_mb="$4"
  local cpu="$5"
  # A megabyte value is multiplied by 1024 for ulimit's kilobyte argument. Refuse one so
  # large the multiplication would overflow the shell's signed 64-bit arithmetic and wrap to
  # a small or negative limit, rather than setting a limit far tighter than the policy asked.
  local mb_max=8796093022207
  # Zero means the limit is switched off, so it is not applied. Every value is read in base
  # ten, so a leading zero is not taken for octal.
  if [[ -n "$mem_mb" ]] && (( 10#$mem_mb != 0 )); then
    (( 10#$mem_mb <= mb_max )) || die "the memory limit of ${mem_mb} MB is too large to set safely" "${PHB_EPOLICY}"
    ulimit -v "$(( 10#$mem_mb * 1024 ))" || die "cannot set the memory limit of ${mem_mb} MB" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$nproc" ]] && (( 10#$nproc != 0 )); then
    ulimit -u "$(( 10#$nproc ))" || die "cannot set the process limit of ${nproc}" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$nofile" ]] && (( 10#$nofile != 0 )); then
    ulimit -n "$(( 10#$nofile ))" || die "cannot set the open-file limit of ${nofile}" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$fsize_mb" ]] && (( 10#$fsize_mb != 0 )); then
    (( 10#$fsize_mb <= mb_max )) || die "the file-size limit of ${fsize_mb} MB is too large to set safely" "${PHB_EPOLICY}"
    ulimit -f "$(( 10#$fsize_mb * 1024 ))" || die "cannot set the file-size limit of ${fsize_mb} MB" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$cpu" ]] && (( 10#$cpu != 0 )); then
    ulimit -t "$(( 10#$cpu ))" || die "cannot set the CPU-time limit of ${cpu} s" "${PHB_ERUNTIME}"
  fi
}

# Reads the "key=value" lines of a specification's limits.conf into the named associative
# array, one entry per known key, empty for a key the file does not set. Every value that is
# set must be a whole number; anything else ends the run with PHB-EPOLICY rather than being
# dropped, so a malformed value fails closed and no unchecked text reaches the arithmetic in
# apply_resource_limits. Assumes it is called plainly, not in a command substitution, so that
# the refusal ends the run. An absent file sets no limit.
read_limits_conf() {
  local file="$1"
  local -n limits_ref="$2"
  local key
  local value
  limits_ref=( [mem_mb]="" [nproc]="" [nofile]="" [fsize_mb]="" [cpu]="" )
  [[ -f "$file" ]] || return 0
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    [[ -v "limits_ref[$key]" ]] || continue
    limits_ref[$key]="$value"
  done < "$file"
  for key in mem_mb nproc nofile fsize_mb cpu; do
    value="${limits_ref[$key]}"
    if [[ -n "$value" && ! "$value" =~ ^[0-9]+$ ]]; then
      report "Policy invalid: resource limit '${key}=${value}' is not a whole number. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
  done
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
# Splits one [connect] target into a host and a port, writing them through the two named
# variables. IPv4 and a host name take an optional single-colon ":port". An IPv6 address has
# colons of its own, so it must be bracketed to carry a port, [addr]:port, and a bare IPv6
# address with two or more colons and no brackets is the whole host with no port. A "*" port,
# or none, means every port. A bracket that never closes is a policy error rather than a
# guess, so that a mistyped rule is refused instead of read as something else.
parse_network_target() {
  local target="$1"
  local -n host_ref="$2"
  local -n port_ref="$3"
  if [[ "$target" == \[*\]:* ]]; then
    host_ref="${target%]:*}"; host_ref="${host_ref#[}"; port_ref="${target##*:}"
  elif [[ "$target" == \[*\] ]]; then
    host_ref="${target#[}"; host_ref="${host_ref%]}"; port_ref="*"
  elif [[ "$target" == \[* ]]; then
    report "Policy invalid: '${target}' in [connect] opens a bracket it does not close. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  else
    local colons="${target//[^:]/}"
    if (( ${#colons} >= 2 )); then
      host_ref="$target"; port_ref="*"
    elif [[ "$target" == *:* ]]; then
      host_ref="${target%:*}"; port_ref="${target##*:}"
    else
      host_ref="$target"; port_ref="*"
    fi
  fi
}

parse_cfg_policy() {
  local cfg="$1"
  local tdir
  # Under phobos.sh's scratch directory when it set one, so this scratch is removed with
  # the specification directory rather than left in /tmp; otherwise a plain temporary dir.
  if [[ -n "${PHOBOS_SCRATCH:-}" ]]; then
    tdir="$(mktemp -d -p "$PHOBOS_SCRATCH" phobos-cfg.XXXXXX)"
  else
    tdir="$(mktemp -d -t phobos-cfg.XXXXXX)"
  fi
  local rd="${tdir}/read.paths" ex="${tdir}/execute.paths" wr="${tdir}/write.paths" cr="${tdir}/create.paths" de="${tdir}/delete.paths" net="${tdir}/net.rules" bind="${tdir}/bind.rules"
  : >"$rd"; : >"$ex"; : >"$wr"; : >"$cr"; : >"$de"; : >"$net"; : >"$bind"
  local sec=""
  # Reset per call, so a timeout or a resource limit is read from the cfg that sets it and
  # not carried over from an earlier one; the caller merges each across cfgs by the same rule
  # the setters use within a cfg (zero disables and wins, else the largest value).
  PARSED_TIMEOUT=""; PARSED_TIMEOUT_DISABLED=0
  PARSED_LIMIT_MEM_MB=""; PARSED_LIMIT_NPROC=""; PARSED_LIMIT_NOFILE=""
  PARSED_LIMIT_FSIZE_MB=""; PARSED_LIMIT_CPU=""
  PARSED_LIMIT_MEM_MB_DISABLED=0; PARSED_LIMIT_NPROC_DISABLED=0; PARSED_LIMIT_NOFILE_DISABLED=0
  PARSED_LIMIT_FSIZE_MB_DISABLED=0; PARSED_LIMIT_CPU_DISABLED=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="$(echo "$line" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      sec="${BASH_REMATCH[1]}"
      # Validate the section at its header, so an unknown section is refused whether or not it
      # holds any line, rather than being silently ignored.
      case "$sec" in
        read|execute|write|create|delete|connect|bind|limits) ;;
        *) report "Policy invalid: unknown section '[${sec}]' in ${cfg}. (PHB-EPOLICY)"; exit "${PHB_EPOLICY}" ;;
      esac
      continue
    fi
    case "$sec" in
      read)    printf '%s\n' "$line" >>"$rd" ;;
      execute) printf '%s\n' "$line" >>"$ex" ;;
      write)   printf '%s\n' "$line" >>"$wr" ;;
      create)  printf '%s\n' "$line" >>"$cr" ;;
      delete)  printf '%s\n' "$line" >>"$de" ;;
      connect)
        if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
          report "Policy invalid: '${line}' in [connect] is not an 'allow <host>[:<port>]' line. (PHB-EPOLICY)"
          exit "${PHB_EPOLICY}"
        fi
        local target="${BASH_REMATCH[1]}" host="" port="*"
        parse_network_target "$target" host port
        printf '%s %s\n' "$host" "$port" >>"$net" ;;
      bind)
        # [bind] names a local TCP listening endpoint, one 'allow <addr>:<port>' or
        # 'allow <port>' per line. A bare port means any local address. The port is
        # enforced by Landlock (--bind-tcp) and must be concrete, because Landlock's bind
        # right is per-port and cannot express a wildcard; the local address is enforced by
        # libnetblocker's bind hook as defence in depth. IPv6 is bracketed, [::1]:8080.
        if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
          report "Policy invalid: '${line}' in [bind] is not an 'allow <addr>:<port>' line. (PHB-EPOLICY)"
          exit "${PHB_EPOLICY}"
        fi
        local bind_target="${BASH_REMATCH[1]}" bind_host="" bind_port=""
        if [[ "$bind_target" =~ ^[0-9]+$ ]]; then
          bind_host="*"; bind_port="$bind_target"
        else
          parse_network_target "$bind_target" bind_host bind_port
        fi
        if [[ "$bind_port" == "*" || -z "$bind_port" ]]; then
          report "Policy invalid: '${bind_target}' in [bind] names no concrete port. Landlock enforces a bind by port, so name one. (PHB-EPOLICY)"
          exit "${PHB_EPOLICY}"
        fi
        printf '%s %s\n' "$bind_host" "$bind_port" >>"$bind" ;;
      limits)
        # Only the six known keys are accepted; a bare value and an unknown key are refused
        # rather than ignored, so a typo in a limit does not leave the run unrestricted.
        if [[ "$line" =~ ^timeout[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_timeout "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^mem_mb[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_limit PARSED_LIMIT_MEM_MB mem_mb "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^nproc[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_limit PARSED_LIMIT_NPROC nproc "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^nofile[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_limit PARSED_LIMIT_NOFILE nofile "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^fsize_mb[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_limit PARSED_LIMIT_FSIZE_MB fsize_mb "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^cpu[[:space:]]*=[[:space:]]*(.*)$ ]]; then
          set_parsed_limit PARSED_LIMIT_CPU cpu "${BASH_REMATCH[1]}"
        else
          report "Policy invalid: '${line}' in [${sec}] is not a known limit; use timeout=, mem_mb=, nproc=, nofile=, fsize_mb= or cpu=. (PHB-EPOLICY)"
          exit "${PHB_EPOLICY}"
        fi ;;
      "")
        report "Policy invalid: '${line}' appears before any [section] in ${cfg}. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}" ;;
    esac
  done <"$cfg"
  PARSED_FS_DIR="$tdir"; PARSED_NET_FILE="$net"; PARSED_BIND_FILE="$bind"; : "${PARSED_TIMEOUT:=}"
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


write_spec() {
  local spec_dir="$1" fs_dir="$2" net="$3" timeout="$4" tail="$5" bind="$6"
  mkdir -p "$spec_dir"

  local right
  for right in ${PHB_FS_RIGHTS}; do
    if [[ -s "${fs_dir}/${right}.paths" ]]; then cp "${fs_dir}/${right}.paths" "${spec_dir}/${right}.paths"; else : > "${spec_dir}/${right}.paths"; fi
  done

  if [[ -n "$timeout" ]]; then printf '%s\n' "$timeout" > "${spec_dir}/timeout.sec"; else : > "${spec_dir}/timeout.sec"; fi
  if [[ -n "$tail" && -f "$tail" ]]; then sed -E 's/#.*$//' "$tail" | sed '/^[[:space:]]*$/d' > "${spec_dir}/tail.flags"; else : > "${spec_dir}/tail.flags"; fi
  if [[ -n "$net" && -s "$net" ]]; then cp "$net" "${spec_dir}/net.rules"; else : > "${spec_dir}/net.rules"; fi
  if [[ -n "$bind" && -s "$bind" ]]; then cp "$bind" "${spec_dir}/bind.rules"; else : > "${spec_dir}/bind.rules"; fi
}
# Unions the per-right file sets of in_dir into out_dir, canonicalising and de-duplicating
# each right's paths. This is the one additive merge: it builds the base policy from several
# base cfgs, and phobos-policy.sh then folds each exercise cfg in the same way, so the policy
# only ever widens from a deny-all baseline.
fs_union_dir() {
  local out_dir="$1" in_dir="$2"
  local right tmp
  for right in ${PHB_FS_RIGHTS}; do
    tmp="$(mktemp)"
    [[ -s "${out_dir}/${right}.paths" ]] && cat "${out_dir}/${right}.paths" >> "$tmp"
    [[ -s "${in_dir}/${right}.paths"  ]] && cat "${in_dir}/${right}.paths"  >> "$tmp"
    canon_paths < "$tmp" | uniq_keep_order | depth_sort > "${out_dir}/${right}.paths" || : > "${out_dir}/${right}.paths"
    rm -f "$tmp"
  done
}

# --------------------------------------------------------------------------
# Translating a parsed policy into phobos-landlock arguments.
#
# Both entry points use these, so the two cannot drift apart. That has already
# happened once in this repository, which is why it lives here and not twice.
# --------------------------------------------------------------------------

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
  table="$(mktemp -t phobos-rights.XXXXXX)"
  folded_table="$(mktemp -t phobos-rights-f.XXXXXX)"
  effective_table="$(mktemp -t phobos-rights-e.XXXXXX)"
  collect_rights_table "$table" "$read_file" "$execute_file" "$write_file" "$create_file" "$delete_file"
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

# True when the host is the loopback interface. Under the no-network container an exercise
# runs in, loopback is the only network there is, so a loopback rule that names no port is
# tolerated even though Landlock, which enforces ports and not hosts, cannot express it: the
# container, not Landlock, is its boundary. Any other host with no port is refused instead.
is_loopback_host() {
  case "$1" in
    localhost | ::1 | 127.* ) return 0 ;;
    * ) return 1 ;;
  esac
}

# Reads a "host port" allow-list, writing the concrete ports it names into the
# second file and the first rule that names none into the third.
#
# Both results go to files rather than to stdout, so that the function is called
# plainly and never in a command substitution, whose subshell a refusal's exit would
# end instead of the run.
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
      # An external host with no port cannot be enforced: Landlock knows ports, not hosts,
      # so leaving the layer off for it would confine external egress to the preload library,
      # which a submission can step around. Loopback with no port is the one tolerated case.
      if ! is_loopback_host "$host"; then
        report "Policy unenforceable: '${host}' names a host with no port. Landlock enforces TCP ports, not hosts, so an external host with no port cannot be enforced. Name a concrete port, and rely on a no-network container as the outer boundary. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
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
# naming no port therefore cannot be expressed. Only a LOOPBACK host may name no
# port: a section made only of those leaves the network layer off and says so,
# which is what the shipped policies do, and the no-network container is that
# rule's boundary. A non-loopback host with no port is refused in
# collect_network_ports, because leaving the layer off for it would confine
# external egress to the preload library, which a submission can step around. A
# section mixing a loopback wildcard with a concrete port is refused here, because
# the concrete rule would read as enforced while the wildcard would not be.
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

# Fills the named array with the TCP bind-port rules Landlock enforces.
#
# The [bind] section names local TCP ports a submission may listen on. Landlock's bind right
# is per-port and knows no local address, so this emits one --bind-tcp per port. Which local
# address a service may bind to is a separate, stacked change (the libnetblocker bind hook);
# the parser already refuses a [bind] line that names more than a bare port, so every line
# here is a port. A port outside 1..65535 is a policy mistake and ends the run.
build_bind_args() {
  local arguments_name="$1"
  local rules="$2"
  local -n bind_ref="$arguments_name"
  local host
  local port
  local ports_file
  local emitted
  [[ -n "$rules" && -s "$rules" ]] || return 0
  ports_file="$(mktemp -t phobos-bindports.XXXXXX)"
  # Each rule is "addr port"; Landlock enforces the port, so several rules that share a
  # port (different local addresses) collapse to one --bind-tcp. The address is libnetblocker's.
  while read -r host port; do
    [[ -z "$host" ]] && continue
    refuse_unusable_port "$host" "$port"
    printf '%s\n' "$port" >> "$ports_file"
  done < "$rules"
  while IFS= read -r emitted; do
    bind_ref+=( --bind-tcp "$emitted" )
  done < <(sort -n -u "$ports_file")
  rm -f "$ports_file"
}

# --------------------------------------------------------------------------
# Refusing a preload library that would not filter anything.
#
# The loader skips a preload library it cannot use and prints only a warning, and
# the command then runs with no network filtering at all. Both entry points ask
# these functions first, so that such a run ends instead.
# --------------------------------------------------------------------------

# The functions the network layer relies on the preload library defining.
PHB_NETBLOCKER_HOOKS="bind connect getaddrinfo sendmmsg sendmsg sendto"

# Prints the functions a shared object defines with default visibility, one per
# line. Assumes readelf from binutils; prints nothing for a file it cannot read.
defined_library_functions() {
  readelf --dyn-syms --wide "$1" 2>/dev/null \
    | awk '$4 == "FUNC" && $5 == "GLOBAL" && $6 == "DEFAULT" && $7 != "UND" { print $8 }' \
    || true
}

# Runs /bin/true with the named library preloaded and nothing else of the caller's
# environment, printing everything it wrote. Further NAME=VALUE arguments join the
# clean environment. Assumes /usr/bin/env.
#
# env -i alone is not enough: the loader reads LD_* variables while it starts env
# itself, before env has cleared anything, so the subshell removes them first.
run_with_only_preload() {
  local library="$1"
  shift
  (
    unset GLIBC_TUNABLES
    while IFS= read -r name; do
      if [[ "$name" == LD_* ]]; then unset "$name"; fi
    done < <(compgen -e)
    exec /usr/bin/env -i LC_ALL=C LD_BIND_NOW=1 LD_PRELOAD="$library" "$@" /bin/true
  ) 2>&1
}

# Prints why the library cannot act as the network filter, or nothing when it can.
# Assumes the path is already canonical. A space or a colon separates entries in
# LD_PRELOAD, so a path holding one cannot be named there unambiguously.
netblocker_unusable_reason() {
  local library="$1"
  local functions
  local hook
  local output
  if [[ "$library" == *[[:space:]:]* ]]; then
    printf 'holds a space or a colon, which LD_PRELOAD cannot name'
    return 0
  fi
  if [[ ! -f "$library" ]]; then
    printf 'does not exist'
    return 0
  fi
  if ! command -v readelf >/dev/null 2>&1; then
    printf 'cannot be inspected, because readelf is not installed'
    return 0
  fi
  functions="$(defined_library_functions "$library")"
  for hook in ${PHB_NETBLOCKER_HOOKS}; do
    if ! grep -qx -- "$hook" <<<"$functions"; then
      printf 'does not define %s' "$hook"
      return 0
    fi
  done
  if ! output="$(run_with_only_preload "$library")" || [[ -n "$output" ]]; then
    printf 'does not load cleanly: %s' "${output:-a non-zero exit status}"
    return 0
  fi
  if ! output="$(run_with_only_preload "$library" LD_TRACE_LOADED_OBJECTS=1)" \
     || ! awk -v wanted="$library" '$1 == wanted { found = 1 } END { exit !found }' <<<"$output"; then
    printf 'is not among the objects the loader maps'
    return 0
  fi
}

# Ends the run with PHB-ERUNTIME unless the library can act as the network filter.
# Assumes the path is already canonical.
refuse_unusable_netblocker() {
  local library="$1"
  local reason
  reason="$(netblocker_unusable_reason "$library")"
  [[ -z "$reason" ]] && return 0
  report "Network layer unusable: '${library}' ${reason}, so the command would run unfiltered. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
}

# Appends the rules that let the preload library and its rules file be read inside
# the sandbox, and refuses a policy under which either could be changed from inside
# it. Assumes both paths exist and that the write file holds the policy's write
# paths, one per line; the other sections grant no right that changes a file.
#
# Landlock adds the rights of every rule along a path and cannot take one away, so a
# read rule on a file beneath a write path would still leave it writable, and a
# submission could rewrite its network policy or replace the library that enforces
# it before starting another process. Symbolic links are resolved on both sides,
# because Landlock anchors a rule on the inode it opens.
append_netblocker_rules() {
  local -n netblocker_ref="$1"
  local write_file="$2"
  local library="$3"
  local rules="$4"
  local bind_rules="$5"
  local artefact
  local resolved
  local write_path
  local resolved_write
  for artefact in "$library" "$rules" "$bind_rules"; do
    [[ -n "$artefact" ]] || continue
    resolved="$(printf '%s\n' "$artefact" | resolve_symlinks)"
    while IFS= read -r write_path || [[ -n "$write_path" ]]; do
      [[ -z "$write_path" ]] && continue
      resolved_write="$(printf '%s\n' "$write_path" | resolve_symlinks)"
      if [[ "$resolved" == "$resolved_write" || "$resolved" == "${resolved_write%/}/"* ]]; then
        report "Policy unenforceable: '${artefact}' lies beneath the write path '${write_path}', so the sandbox could change the network policy or the library that enforces it. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}"
      fi
    done < <(cat "$write_file" 2>/dev/null)
  done
  netblocker_ref+=( --rights=rx "$library" --rights=r "$rules" )
  # An if, not a "&&", so an empty bind_rules leaves the function returning zero rather than
  # the 1 of a false test, which under the caller's set -e would abort the run silently.
  if [[ -n "$bind_rules" ]]; then
    netblocker_ref+=( --rights=r "$bind_rules" )
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

# Ends the shell with the given status after removing any scratch paths named after
# the directory and then the owned specification directory. A directory that cannot
# be removed is reported, and turns a run that had otherwise succeeded into a
# PHB-ERUNTIME failure rather than leaving a policy behind unnoticed; a run that had
# already failed keeps its own status. Meant for an EXIT trap, which passes $? as the
# first argument, so that it is read before anything else runs. Assumes the scratch
# paths are the shell's own temporary files: one that cannot be removed is reported
# and does not stop the specification directory from being removed.
finish_owned_spec_dir() {
  local status="$1"
  local directory="$2"
  shift 2
  if (( $# > 0 )) && ! rm -rf -- "$@"; then
    _log "cleanup: could not remove the scratch files '$*'"
  fi
  if ! remove_owned_spec_dir "$directory"; then
    _log "cleanup: could not remove the specification directory '${directory}'"
    if (( status == 0 )); then status="${PHB_ERUNTIME}"; fi
  fi
  exit "$status"
}
