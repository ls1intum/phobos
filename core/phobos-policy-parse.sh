#!/usr/bin/env bash
# shellcheck shell=bash
# One policy cfg in, the parsed state and the specification files out.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
# The filesystem sections, each granting exactly its own phobos-landlock right.
PHB_FS_RIGHTS="read execute write create delete"

# Merges one configured timeout value into PARSED_TIMEOUT and PARSED_TIMEOUT_DISABLED, which
# parse_cfg_policy resets per call. The rule is the same within a file and across files:
# every spelling of zero (0, 0.000, ...) disables the timeout and wins over any finite value, and otherwise
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
# A configured limit that cannot be set ends the run rather than running without it. Zero means
# the limit is switched off, so it is not applied. Every value is read in base ten, so a leading
# zero is not taken for octal. Assumes it is called plainly, not in a subshell, so the ulimit
# takes effect for the later exec.
apply_resource_limits() {
  local mem_mb="$1"
  local nproc="$2"
  local nofile="$3"
  local fsize_mb="$4"
  local cpu="$5"
  if [[ -n "$mem_mb" ]] && (( 10#$mem_mb != 0 )); then
    (( 10#$mem_mb <= PHB_LARGEST_MEGABYTES )) || die "the memory limit of ${mem_mb} MB is too large to set safely" "${PHB_EPOLICY}"
    ulimit -v "$(( 10#$mem_mb * PHB_KILOBYTES_PER_MEGABYTE ))" || die "cannot set the memory limit of ${mem_mb} MB" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$nproc" ]] && (( 10#$nproc != 0 )); then
    ulimit -u "$(( 10#$nproc ))" || die "cannot set the process limit of ${nproc}" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$nofile" ]] && (( 10#$nofile != 0 )); then
    ulimit -n "$(( 10#$nofile ))" || die "cannot set the open-file limit of ${nofile}" "${PHB_ERUNTIME}"
  fi
  if [[ -n "$fsize_mb" ]] && (( 10#$fsize_mb != 0 )); then
    (( 10#$fsize_mb <= PHB_LARGEST_MEGABYTES )) || die "the file-size limit of ${fsize_mb} MB is too large to set safely" "${PHB_EPOLICY}"
    ulimit -f "$(( 10#$fsize_mb * PHB_KILOBYTES_PER_MEGABYTE ))" || die "cannot set the file-size limit of ${fsize_mb} MB" "${PHB_ERUNTIME}"
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
    host_ref="${target%]:*}"
    host_ref="${host_ref#[}"
    port_ref="${target##*:}"
  elif [[ "$target" == \[*\] ]]; then
    host_ref="${target#[}"
    host_ref="${host_ref%]}"
    port_ref="*"
  elif [[ "$target" == \[* ]]; then
    report "Policy invalid: '${target}' in [connect] opens a bracket it does not close. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  else
    local colons="${target//[^:]/}"
    if (( ${#colons} >= PHB_IPV6_MINIMUM_COLONS )); then
      host_ref="$target"
      port_ref="*"
    elif [[ "$target" == *:* ]]; then
      host_ref="${target%:*}"
      port_ref="${target##*:}"
    else
      host_ref="$target"
      port_ref="*"
    fi
  fi
}

# Makes the directory one parse_cfg_policy call writes its files into, and prints it. Under
# phobos.sh's scratch directory when it set one, so this scratch is removed with the
# specification directory rather than left in /tmp; otherwise a plain temporary directory.
new_parse_directory() {
  if [[ -n "${PHOBOS_SCRATCH:-}" ]]; then
    mktemp -d -p "$PHOBOS_SCRATCH" phobos-cfg.XXXXXX
  else
    mktemp -d -t phobos-cfg.XXXXXX
  fi
}

# Resets the timeout and the resource limits parse_cfg_policy reads, so each is read from the
# cfg that sets it and not carried over from an earlier one; the caller merges each across cfgs
# by the same rule the setters use within a cfg (zero disables and wins, else the largest value).
reset_parsed_limits() {
  PARSED_TIMEOUT=""
  PARSED_TIMEOUT_DISABLED=0
  PARSED_LIMIT_MEM_MB=""
  PARSED_LIMIT_NPROC=""
  PARSED_LIMIT_NOFILE=""
  PARSED_LIMIT_FSIZE_MB=""
  PARSED_LIMIT_CPU=""
  PARSED_LIMIT_MEM_MB_DISABLED=0
  PARSED_LIMIT_NPROC_DISABLED=0
  PARSED_LIMIT_NOFILE_DISABLED=0
  PARSED_LIMIT_FSIZE_MB_DISABLED=0
  PARSED_LIMIT_CPU_DISABLED=0
}

# Refuses a section the policy format does not have. Asked at the section's header, so an
# unknown section is refused whether or not it holds any line, rather than silently ignored.
# Assumes it is called plainly, not in a subshell, so that the refusal ends the run.
refuse_unknown_section() {
  local section="$1"
  local cfg="$2"
  case "$section" in
    read|execute|write|create|delete|connect|bind|accept|limits) ;;
    *) report "Policy invalid: unknown section '[${section}]' in ${cfg}. (PHB-EPOLICY)"; exit "${PHB_EPOLICY}" ;;
  esac
}

# Appends one [connect] line, "allow <host>[:<port>]", to the rules file as "host port". A line
# of any other shape is refused. Assumes it is called plainly, so that the refusal ends the run.
append_connect_rule() {
  local line="$1"
  local rules="$2"
  local host=""
  local port="*"
  if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
    report "Policy invalid: '${line}' in [connect] is not an 'allow <host>[:<port>]' line. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  parse_network_target "${BASH_REMATCH[1]}" host port
  printf '%s %s\n' "$host" "$port" >>"$rules"
}

# Appends one [bind] line to the rules file as "* port". [bind] names a local TCP listening port,
# one 'allow <port>' per line, and a bare port is the only accepted form. Landlock's bind right is
# per-port and cannot narrow to a local address, so a rule that names an address is refused: a
# listener's reachability is governed by [accept] and the container's network isolation, not by the
# bind address. The stored host is always "*", which build_bind_args ignores. The port range is
# checked downstream by refuse_unusable_port. Assumes it is called plainly, so that a refusal ends
# the run.
append_bind_rule() {
  local line="$1"
  local rules="$2"
  local bind_target
  if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
    report "Policy invalid: '${line}' in [bind] is not an 'allow <port>' line. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  bind_target="${BASH_REMATCH[1]}"
  if [[ ! "$bind_target" =~ ^[0-9]+$ ]]; then
    report "Policy invalid: '${bind_target}' in [bind] is not a bare port; [bind] takes only a port number, because Landlock enforces a bind by port and cannot narrow to a local address. Name the port alone, and govern a listener's reachability with [accept]. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  printf '%s %s\n' "*" "$bind_target" >>"$rules"
}

# Appends one [accept] line, "expose <public-port> to <backend-port> from <source>[, <source>...]",
# to the accept rules file as one "H P src" line per source, or "H P" when the source list is
# empty (a service that is registered but accepts no one). [accept] fronts a student's TCP
# listener with an inbound HAProxy: the public port H is what the container exposes and HAProxy
# filters by source address, the backend port P is the student's own listening port, which [bind]
# must name. Only the port range is checked here; that H is not itself a [bind] port, that P is a
# [bind] port, and that H is a bindable non-privileged port are judged once over the merged
# policy. A source is an IPv4 or IPv6 address or CIDR, validated in full by HAProxy. Assumes it is
# called plainly, so that a refusal ends the run.
append_accept_rule() {
  local line="$1"
  local rules="$2"
  local h
  local p
  local srcs
  local src
  local any=0
  if [[ ! "$line" =~ ^expose[[:space:]]+([0-9]+)[[:space:]]+to[[:space:]]+([0-9]+)[[:space:]]+from[[:space:]]*(.*)$ ]]; then
    report "Policy invalid: '${line}' in [accept] is not an 'expose <public-port> to <backend-port> from <source>[, <source>...]' line. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  h="${BASH_REMATCH[1]}"
  p="${BASH_REMATCH[2]}"
  srcs="${BASH_REMATCH[3]}"
  if [[ ! "$h" =~ ^[1-9][0-9]{0,4}$ || ! "$p" =~ ^[1-9][0-9]{0,4}$ ]] || (( h > 65535 || p > 65535 )); then
    report "Policy invalid: '${line}' in [accept] names a port that is not a whole number from 1 to 65535. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  local IFS=','
  for src in $srcs; do
    src="${src#"${src%%[![:space:]]*}"}"
    src="${src%"${src##*[![:space:]]}"}"
    [[ -z "$src" ]] && continue
    if [[ ! "$src" =~ ^[0-9a-fA-F:./]+$ ]]; then
      report "Policy invalid: '${src}' in [accept] is not an IP address or CIDR. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    printf '%s %s %s\n' "$h" "$p" "$src" >>"$rules"
    any=1
  done
  if (( ! any )); then
    printf '%s %s\n' "$h" "$p" >>"$rules"
  fi
}

# Reads one [limits] line into the PARSED_* values. Only the six known keys are accepted; a bare
# value and an unknown key are refused rather than ignored, so a typo in a limit does not leave
# the run unrestricted. Assumes it is called plainly, so that a refusal ends the run.
read_limits_line() {
  local line="$1"
  local section="$2"
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
    report "Policy invalid: '${line}' in [${section}] is not a known limit; use timeout=, mem_mb=, nproc=, nofile=, fsize_mb= or cpu=. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
}

# Reads one policy cfg. Each filesystem section's paths go into its own "<right>.paths" file,
# the [connect] and [bind] rules into net.rules and bind.rules, all in a fresh directory, and
# the [limits] section into the PARSED_* values. Sets PARSED_FS_DIR, PARSED_NET_FILE and
# PARSED_BIND_FILE to what it wrote. Everything from a "#" is a comment. An unknown section, a
# malformed line and any content before the first section are refused (PHB-EPOLICY). Assumes
# it is called plainly, not in a subshell, so that a refusal ends the run.
parse_cfg_policy() {
  local cfg="$1"
  local tdir
  local line
  local sec=""
  tdir="$(new_parse_directory)"
  local rd="${tdir}/read.paths"
  local ex="${tdir}/execute.paths"
  local wr="${tdir}/write.paths"
  local cr="${tdir}/create.paths"
  local de="${tdir}/delete.paths"
  local net="${tdir}/net.rules"
  local bind="${tdir}/bind.rules"
  local acc="${tdir}/accept.rules"
  : >"$rd"; : >"$ex"; : >"$wr"; : >"$cr"; : >"$de"; : >"$net"; : >"$bind"; : >"$acc"
  reset_parsed_limits
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      sec="${BASH_REMATCH[1]}"
      refuse_unknown_section "$sec" "$cfg"
      continue
    fi
    case "$sec" in
      read)    printf '%s\n' "$line" >>"$rd" ;;
      execute) printf '%s\n' "$line" >>"$ex" ;;
      write)   printf '%s\n' "$line" >>"$wr" ;;
      create)  printf '%s\n' "$line" >>"$cr" ;;
      delete)  printf '%s\n' "$line" >>"$de" ;;
      connect) append_connect_rule "$line" "$net" ;;
      bind)    append_bind_rule "$line" "$bind" ;;
      accept)  append_accept_rule "$line" "$acc" ;;
      limits)  read_limits_line "$line" "$sec" ;;
      "")
        report "Policy invalid: '${line}' appears before any [section] in ${cfg}. (PHB-EPOLICY)"
        exit "${PHB_EPOLICY}" ;;
    esac
  done <"$cfg"
  PARSED_FS_DIR="$tdir"
  PARSED_NET_FILE="$net"
  PARSED_BIND_FILE="$bind"
  PARSED_ACCEPT_FILE="$acc"
}

# Writes into the first file every distinct line of the remaining files, in the order first
# seen, dropping comments and blank lines. Missing or empty files are skipped.
net_union() {
  local out="$1"
  shift
  local file
  local line
  local -A seen=()
  : > "$out"
  for file in "$@"; do
    [[ -n "$file" && -s "$file" ]] || continue
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      if [[ -z "${seen["$line"]:-}" ]]; then
        printf '%s\n' "$line" >> "$out"
        seen["$line"]=1
      fi
    done < <(sed -E 's/#.*$//' "$file" | sed '/^[[:space:]]*$/d')
  done
}


# Writes the run's specification into spec_dir: one "<right>.paths" file per filesystem right
# from fs_dir, net.rules and bind.rules, timeout.sec, and tail.flags without comments or blank
# lines. A part that is empty or absent still gets its file, empty, so every layer can read it.
write_spec() {
  local spec_dir="$1"
  local fs_dir="$2"
  local net="$3"
  local timeout="$4"
  local tail="$5"
  local bind="$6"
  local accept="$7"
  mkdir -p "$spec_dir"

  local right
  for right in ${PHB_FS_RIGHTS}; do
    if [[ -s "${fs_dir}/${right}.paths" ]]; then cp "${fs_dir}/${right}.paths" "${spec_dir}/${right}.paths"; else : > "${spec_dir}/${right}.paths"; fi
  done

  if [[ -n "$timeout" ]]; then printf '%s\n' "$timeout" > "${spec_dir}/timeout.sec"; else : > "${spec_dir}/timeout.sec"; fi
  if [[ -n "$tail" && -f "$tail" ]]; then sed -E 's/#.*$//' "$tail" | sed '/^[[:space:]]*$/d' > "${spec_dir}/tail.flags"; else : > "${spec_dir}/tail.flags"; fi
  if [[ -n "$net" && -s "$net" ]]; then cp "$net" "${spec_dir}/net.rules"; else : > "${spec_dir}/net.rules"; fi
  if [[ -n "$bind" && -s "$bind" ]]; then cp "$bind" "${spec_dir}/bind.rules"; else : > "${spec_dir}/bind.rules"; fi
  if [[ -n "$accept" && -s "$accept" ]]; then cp "$accept" "${spec_dir}/accept.rules"; else : > "${spec_dir}/accept.rules"; fi
}
# Unions the per-right file sets of in_dir into out_dir, canonicalising and de-duplicating
# each right's paths. This is the one additive merge: it builds the base policy from several
# base cfgs, and phobos-policy.sh then folds each exercise cfg in the same way, so the policy
# only ever widens from a deny-all baseline.
fs_union_dir() {
  local out_dir="$1"
  local in_dir="$2"
  local right
  local tmp
  for right in ${PHB_FS_RIGHTS}; do
    tmp="$(new_scratch_file phobos-union.XXXXXX)"
    [[ -s "${out_dir}/${right}.paths" ]] && cat "${out_dir}/${right}.paths" >> "$tmp"
    [[ -s "${in_dir}/${right}.paths"  ]] && cat "${in_dir}/${right}.paths"  >> "$tmp"
    canon_paths < "$tmp" | uniq_keep_order | depth_sort > "${out_dir}/${right}.paths" || : > "${out_dir}/${right}.paths"
    rm -f "$tmp"
  done
}
