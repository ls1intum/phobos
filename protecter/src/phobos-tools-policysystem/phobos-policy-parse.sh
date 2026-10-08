#!/bin/bash
# shellcheck shell=bash
# One policy cfg in, the parsed state and the specification files out.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.
# Every variable here is read by the scripts that source the aggregate, never in
# this file, so SC2034 would fire on all of them by design.
# shellcheck disable=SC2034
# The filesystem buckets, one per phobos-landlock-filesystem-and-networksystem right letter: read (r), execute (x),
# write (w), create (m: regular files and directories), delete (d), ipc (p: sockets and
# named pipes), symlink (l), refer (f: move or rename across directories). The cfg section
# [create-ipc] feeds ipc, [create-symlink] feeds symlink, and [restructure] feeds create,
# delete and refer together, so a policy that names it may rename and move within the tree.
PHB_FS_RIGHTS="read execute write create delete ipc symlink refer"

# Where parse_cfg_policy is, as "<file>, line <number>", while it reads a line; empty otherwise.
PARSE_LOCATION=""

# Ends the run with PHB-EPOLICY and a message that says what is wrong with the line being read and
# where it is, so that a policy of a hundred lines does not have to be searched for the one the
# message quotes. Takes the text without a closing full stop. Assumes it is called plainly, so that
# the refusal ends the run. A line is quoted with ${line@Q}, which shows a control character or a
# byte that is not text as an escape instead of sending it to the terminal.
refuse_cfg() {
  local text="${1%.}"
  if [[ -n "$PARSE_LOCATION" ]]; then
    report "Policy invalid: ${text}. Found in ${PARSE_LOCATION}. (PHB-EPOLICY)"
  else
    report "Policy invalid: ${text}. (PHB-EPOLICY)"
  fi
  exit "${PHB_EPOLICY}"
}

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
    refuse_cfg "timeout ${value@Q} must be seconds, either whole or with exactly three decimals"
  fi
  local seconds="${value%%.*}"
  seconds="${seconds#"${seconds%%[!0]*}"}"
  if (( ${#seconds} > PHB_LARGEST_TIMEOUT_SECOND_DIGITS )); then
    refuse_cfg "timeout ${value@Q} has more than ${PHB_LARGEST_TIMEOUT_SECOND_DIGITS} digits of seconds, which is not a time but a number the arithmetic would read as another one. Write 0 to switch the timeout off"
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
  local value="$3"
  if [[ ! "$value" =~ ^[[:digit:]]+$ ]]; then
    refuse_cfg "${key} ${value@Q} must be a non-negative whole number"
  fi
  local significant="${value#"${value%%[!0]*}"}"
  if (( ${#significant} > PHB_LARGEST_LIMIT_DIGITS )); then
    refuse_cfg "${key} ${value@Q} has more than ${PHB_LARGEST_LIMIT_DIGITS} digits, which is more than a limit can be applied with and which the arithmetic would read as another number. Write 0 to switch the limit off"
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
    if [[ -n "$value" && ! "$value" =~ ^[[:digit:]]+$ ]]; then
      refuse_cfg "resource limit '${key}=${value}' is not a whole number"
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
    refuse_cfg "${target@Q} in [connect] opens a bracket it does not close"
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

# Makes the directory one parse_cfg_policy call writes its files into, under PHOBOS_SCRATCH, and
# prints it, so this scratch is out of the command's reach and is removed with the specification
# directory. Refuses through refuse_missing_scratch when no scratch directory was set.
new_parse_directory() {
  refuse_missing_scratch
  mktemp -d -p "$PHOBOS_SCRATCH" phobos-cfg.XXXXXX
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
  case "$section" in
    read|execute|write|create|delete|create-ipc|create-symlink|restructure|connect|bind|accept|limits) ;;
    *) refuse_cfg "unknown section ${section@Q}; the sections are [read], [execute], [write], [create], [delete], [create-ipc], [create-symlink], [restructure], [connect], [bind], [accept] and [limits]" ;;
  esac
}

# Whether the text is an IPv4 address in dotted-quad form: four decimal numbers from 0 to 255,
# none with a leading zero, which is the one spelling the connect guard reads as an address. Any
# other spelling it reads as a host name and holds to its port alone, so one that merely looks like
# an address, such as 1.2.3 or 127.1, would open the port to every address. Needs no environment.
is_ipv4_literal() {
  local text="$1"
  local octet='(25[012345]|2[01234][[:digit:]]|1[[:digit:]][[:digit:]]|[123456789]?[[:digit:]])'
  [[ "$text" =~ ^${octet}\.${octet}\.${octet}\.${octet}$ ]]
}

# Whether every group of a colon-separated list is one to four hexadecimal digits, the last of them
# an IPv4 address when the second argument says it may be. Takes the list and "yes" or "no" for a
# closing IPv4 address; prints the number of 16-bit groups the list takes, and fails for a list with
# an empty or a malformed group, one that ends in a colon included. Assumes it runs in a command
# substitution.
count_ipv6_groups() {
  local list="$1"
  local last_may_be_ipv4="$2"
  local -a groups=()
  local group
  local total=0
  local position=0
  [[ -z "$list" ]] && { printf '0\n'; return 0; }
  [[ "$list" != *: ]] || return 1
  IFS=: read -ra groups <<< "$list"
  for group in "${groups[@]}"; do
    position=$(( position + 1 ))
    if [[ "$group" =~ ^[[:xdigit:]]{1,4}$ ]]; then
      total=$(( total + 1 ))
    elif [[ "$last_may_be_ipv4" == yes && position -eq ${#groups[@]} ]] && is_ipv4_literal "$group"; then
      total=$(( total + 2 ))
    else
      return 1
    fi
  done
  printf '%s\n' "$total"
}

# Whether the text is an IPv6 address: groups of hexadecimal digits separated by single colons, at
# most one "::" standing for a run of zero groups, and optionally an IPv4 address in the last two
# places. A zone such as %eth0 is not part of the address the guard compares, so it is refused. The
# connect guard reads anything it cannot parse as a host name, so an address that is almost right
# would open the port to every address. Assumes it runs where count_ipv6_groups is defined.
is_ipv6_literal() {
  local text="$1"
  local head
  local tail
  local head_groups
  local tail_groups
  [[ "$text" == *:* && "$text" =~ ^[[:xdigit:]:.]+$ && "$text" != *:::* ]] || return 1
  if [[ "$text" == *::* ]]; then
    head="${text%%::*}"
    tail="${text#*::}"
    [[ "$tail" != *::* ]] || return 1
    head_groups="$(count_ipv6_groups "$head" no)" || return 1
    tail_groups="$(count_ipv6_groups "$tail" yes)" || return 1
    (( head_groups + tail_groups <= 7 ))
  else
    head_groups="$(count_ipv6_groups "$text" yes)" || return 1
    (( head_groups == 8 ))
  fi
}

# Prints the eight 16-bit groups of an IPv6 address that is_ipv6_literal accepted, written out in full
# and separated by spaces, with the "::" filled in with zero groups and a closing IPv4 address turned
# into its two groups. The groups keep the hexadecimal spelling they had. Assumes the address is valid
# and that it runs in a command substitution.
expand_ipv6_groups() {
  local text="${1,,}"
  local head
  local tail
  local -a head_groups=()
  local -a tail_groups=()
  local -a octets=()
  local -a all=()
  if [[ "$text" =~ ^(.*:)([[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+\.[[:digit:]]+)$ ]]; then
    IFS=. read -ra octets <<< "${BASH_REMATCH[2]}"
    text="${BASH_REMATCH[1]}$(printf '%x:%x' $(( octets[0] * 256 + octets[1] )) $(( octets[2] * 256 + octets[3] )))"
  fi
  if [[ "$text" == *::* ]]; then
    head="${text%%::*}"
    tail="${text#*::}"
    [[ -z "$head" ]] || IFS=: read -ra head_groups <<< "$head"
    [[ -z "$tail" ]] || IFS=: read -ra tail_groups <<< "$tail"
    all=( "${head_groups[@]}" )
    while (( ${#all[@]} + ${#tail_groups[@]} < 8 )); do
      all+=( 0 )
    done
    all+=( "${tail_groups[@]}" )
  else
    IFS=: read -ra all <<< "$text"
  fi
  printf '%s\n' "${all[*]}"
}

# Whether an IPv6 address that is_ipv6_literal accepted is an IPv4-mapped one, ::ffff:a.b.c.d in any
# spelling: five zero groups, then ffff. The connect guard keeps a range from such an address only
# when its prefix reaches past those 96 bits. Assumes it runs where expand_ipv6_groups is defined.
is_ipv4_mapped_literal() {
  local -a groups=()
  local index
  read -ra groups <<< "$(expand_ipv6_groups "$1")"
  for index in 0 1 2 3 4; do
    (( 16#${groups[index]} == 0 )) || return 1
  done
  (( 16#${groups[5]} == 16#ffff ))
}

# Refuses a [connect] host that is written like an address but is not one, a prefix length that
# has no meaning, and a port that is missing after its colon, each as a policy error. Without it the
# connect guard drops a bad range or an empty port without a word, so the rule admits nothing, and
# reads a malformed address as a host name, so the rule admits every address on its port. Takes the
# host as parse_network_target left it, the port, and the line for the message. A host name, the
# star, localhost and a well-formed address or range pass. An IPv4-mapped IPv6 range shorter than 96
# bits is refused too, because the guard drops it. Assumes it is called plainly, so that a
# refusal ends the run.
refuse_malformed_address() {
  local host="$1"
  local port="$2"
  local line="$3"
  local address="$host"
  local prefix=""
  local longest=0
  if [[ -z "$port" ]]; then
    refuse_cfg "${line@Q} in [connect] names a host and then no port. Write the port, or * for every port"
  fi
  if [[ "$host" == */* ]]; then
    address="${host%%/*}"
    prefix="${host#*/}"
  fi
  if is_ipv4_literal "$address"; then
    longest=32
  elif is_ipv6_literal "$address"; then
    longest=128
  elif [[ "$host" == */* || "$address" =~ ^[[:digit:].]+$ || "$address" == *:* ]]; then
    refuse_cfg "${address@Q} in [connect] is not a valid address. An IPv4 address is four numbers from 0 to 255 with no leading zero, and an IPv6 address has at most one ::"
  else
    return 0
  fi
  [[ "$host" == */* ]] || return 0
  if [[ ! "$prefix" =~ ^[[:digit:]]+$ ]] || (( ${#prefix} > 3 )) || (( 10#$prefix > longest )); then
    refuse_cfg "the prefix length ${prefix@Q} in ${line@Q} is not a number from 1 to ${longest} for this address"
  fi
  if (( 10#$prefix == 0 )); then
    refuse_cfg "${line@Q} in [connect] has a prefix length of 0, which would mean every address. Write * as the host for that"
  fi
  if (( longest == 128 )) && (( 10#$prefix < 96 )) && is_ipv4_mapped_literal "$address"; then
    refuse_cfg "${line@Q} in [connect] is an IPv4-mapped range with a prefix length below 96, which would reach past the IPv4 addresses and which the connect guard refuses"
  fi
}

# Appends one [connect] line, "allow <host>[:<port>] [udp|tcp]", to the rules file as "host port"
# for TCP, or "host port udp" for UDP. The transport marker is optional and defaults to tcp, so
# every existing rule keeps its two-field form and its meaning. A host with a star in it, other
# than "*" itself, is refused for either transport (refuse_wildcard_host_name). A UDP rule may name an
# exact host name as well as an address, a CIDR, a loopback name or "*": a datagram carries no TLS
# host name for the egress broker to check, so the network layer resolves the name once, before the
# command starts, and holds the rule to the addresses it had then. A line of any other shape, or an
# unknown marker, is refused, and so is a rule that names no port for anything but one loopback
# address (is_loopback_host), because nothing but the connect guard holds such a rule. Assumes
# is_loopback_host is defined, which phobos-common.sh arranges, and that it is called plainly, so
# that the refusal ends the run.
append_connect_rule() {
  local line="$1"
  local rules="$2"
  local host=""
  local port="*"
  if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
    refuse_cfg "${line@Q} in [connect] is not an 'allow <host>[:<port>] [udp|tcp]' line"
  fi
  local -a fields=()
  read -ra fields <<< "${BASH_REMATCH[1]}"
  local target="${fields[0]}"
  local proto="tcp"
  if (( ${#fields[@]} == 2 )); then
    proto="${fields[1]}"
  elif (( ${#fields[@]} > 2 )); then
    refuse_cfg "${line@Q} in [connect] has trailing words; use 'allow <host>[:<port>] [udp|tcp]'"
  fi
  if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
    refuse_cfg "${proto@Q} in [connect] is not a transport; use 'udp' or 'tcp'"
  fi
  parse_network_target "$target" host port
  refuse_wildcard_host_name "$host"
  refuse_malformed_address "$host" "$port" "$line"
  [[ "$port" == "*" ]] || refuse_unusable_port "$host" "$port"
  if [[ "$port" == "*" ]] && ! is_loopback_host "$host"; then
    refuse_cfg "${line@Q} in [connect] names ${host@Q} and no port, and only loopback may name no port: localhost, one address in 127.0.0.0/8, or ::1 or its IPv4-mapped form. A range such as 127.0.0.1/1 reaches far beyond loopback, and a host name is enforced by its port. Name a concrete port"
  fi
  if [[ "$proto" == "udp" ]]; then
    printf '%s %s %s\n' "$host" "$port" "udp" >>"$rules"
  else
    printf '%s %s\n' "$host" "$port" >>"$rules"
  fi
}

# Appends one [bind] line to the rules file as "* port" for TCP, or "* port udp" for UDP. [bind]
# names a local listening port, one 'allow <port> [udp|tcp]' per line, and a bare port is the only
# accepted target. The transport marker is optional and defaults to tcp, so every existing rule
# keeps its two-field form and its meaning. Landlock's bind right is per-port and cannot narrow to a
# local address, so a rule that names an address is refused: a listener's reachability is governed
# by [accept] and the container's network isolation, not by the bind address. The stored host is
# always "*", which build_bind_args ignores. The port range is checked here, so that the refusal names
# the line, and again downstream by refuse_unusable_port. An unknown marker is refused. Assumes it is called plainly, so that a
# refusal ends the run.
append_bind_rule() {
  local line="$1"
  local rules="$2"
  local bind_target
  if [[ ! "$line" =~ ^allow[[:space:]]+(.+)$ ]]; then
    refuse_cfg "${line@Q} in [bind] is not an 'allow <port> [udp|tcp]' line"
  fi
  local -a fields=()
  read -ra fields <<< "${BASH_REMATCH[1]}"
  bind_target="${fields[0]}"
  local proto="tcp"
  if (( ${#fields[@]} == 2 )); then
    proto="${fields[1]}"
  elif (( ${#fields[@]} > 2 )); then
    refuse_cfg "${line@Q} in [bind] has trailing words; use 'allow <port> [udp|tcp]'"
  fi
  if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
    refuse_cfg "${proto@Q} in [bind] is not a transport; use 'udp' or 'tcp'"
  fi
  if [[ ! "$bind_target" =~ ^[[:digit:]]+$ ]]; then
    refuse_cfg "${bind_target@Q} in [bind] is not a bare port; [bind] takes only a port number, because Landlock enforces a bind by port and cannot narrow to a local address. Name the port alone, and govern a listener's reachability with [accept]"
  fi
  refuse_unusable_bind_port "*" "$bind_target"
  if [[ "$proto" == "udp" ]]; then
    printf '%s %s %s\n' "*" "$bind_target" "udp" >>"$rules"
  else
    printf '%s %s\n' "*" "$bind_target" >>"$rules"
  fi
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
  if [[ ! "$line" =~ ^expose[[:space:]]+([[:digit:]]+)[[:space:]]+to[[:space:]]+([[:digit:]]+)[[:space:]]+from[[:space:]]*(.*)$ ]]; then
    refuse_cfg "${line@Q} in [accept] is not an 'expose <public-port> to <backend-port> from <source>[, <source>...]' line"
  fi
  h="${BASH_REMATCH[1]}"
  p="${BASH_REMATCH[2]}"
  srcs="${BASH_REMATCH[3]}"
  if [[ ! "$h" =~ ^[123456789][[:digit:]]{0,4}$ || ! "$p" =~ ^[123456789][[:digit:]]{0,4}$ ]] || (( h > 65535 || p > 65535 )); then
    refuse_cfg "${line@Q} in [accept] names a port that is not a whole number from 1 to 65535"
  fi
  local IFS=','
  for src in $srcs; do
    src="${src#"${src%%[![:space:]]*}"}"
    src="${src%"${src##*[![:space:]]}"}"
    [[ -z "$src" ]] && continue
    if [[ ! "$src" =~ ^[[:xdigit:]:./]+$ ]]; then
      refuse_cfg "${src@Q} in [accept] is not an IP address or CIDR"
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
    refuse_cfg "${line@Q} in [${section}] is not a known limit; use timeout=, mem_mb=, nproc=, nofile=, fsize_mb= or cpu="
  fi
}

# Refuses a path line that does not start with a slash, in a section that names filesystem paths. A
# relative name would be made absolute against whatever directory the run was started in, so the same
# policy would grant different paths from one place to another, and ~, $HOME and quotes are not
# expanded, so they would be taken for the name of a directory. Takes the line and the section.
# Assumes it is called plainly, so that the refusal ends the run.
refuse_relative_path() {
  local line="$1"
  local section="$2"
  [[ "$line" == /* ]] && return 0
  refuse_cfg "${line@Q} in [${section}] is not an absolute path. Write the whole path from /, because ~, variables, quotes and names relative to a directory are not expanded"
}

# Refuses a path line that holds a wildcard character, in a section that names filesystem paths. A
# path is taken as written, so /usr/lib/jvm/* would name one entry whose name is a star, which is
# almost never the set of files the line was written to name, and the rule would grant something
# other than what was meant, without a word. Takes the line and the section. Assumes it is
# called plainly, so that the refusal ends the run.
refuse_wildcard_path() {
  local line="$1"
  local section="$2"
  [[ "$line" != *[\*\?\[]* ]] && return 0
  refuse_cfg "${line@Q} in [${section}] holds a wildcard character, and a path is taken as written, so it would name the one entry with that literal name and not the files it looks like it matches. Name the directory or the file itself"
}

# Refuses a [read] or [execute] path line that names nothing on this system. Landlock can only
# anchor a rule on a path that exists, so the rule for a missing one is left out and the run goes
# on without the access the line was written to give. A typo in a path therefore showed up as a
# command that could not read or execute, far from the line. Asked of exercise configurations
# only: a shipped base policy names paths a given image may not have, and is written to fit more
# than one. The sections that change things are not asked, because the filesystem layer creates
# a missing path they name. The path has to exist when the specification is built, so one that the
# command is meant to create must be made first or reached through an existing parent. Takes the
# line and the section. Assumes it is called plainly, so that the refusal ends the run.
refuse_missing_path() {
  local line="$1"
  local section="$2"
  [[ -e "$line" ]] && return 0
  refuse_cfg "${line@Q} in [${section}] does not exist on this system, so the rule would grant nothing. Check the spelling, or remove the line if the path is not needed here"
}

# Refuses a cfg this program cannot read as a file of lines, before any line is parsed: the path given
# is empty, names nothing, a link to nothing, a directory or another kind of file, or a file this user
# may not read. Each is said as what it is, since "not found" for a directory sends the reader looking
# for a typo that is not there. Takes the path. Assumes it is called plainly, so that the refusal ends
# the run.
refuse_unusable_cfg_file() {
  local cfg="$1"
  if [[ -z "$cfg" ]]; then
    report "Policy invalid: --config was given an empty path, so there is no configuration to read. (PHB-EPOLICY)"
  elif [[ -L "$cfg" && ! -e "$cfg" ]]; then
    report "Policy invalid: the configuration ${cfg@Q} is a symbolic link to nothing. (PHB-EPOLICY)"
  elif [[ ! -e "$cfg" ]]; then
    report "Policy invalid: the configuration ${cfg@Q} does not exist. (PHB-EPOLICY)"
  elif [[ -d "$cfg" ]]; then
    report "Policy invalid: the configuration ${cfg@Q} is a directory, and a configuration is a file. (PHB-EPOLICY)"
  elif [[ ! -f "$cfg" ]]; then
    report "Policy invalid: the configuration ${cfg@Q} is not a regular file. (PHB-EPOLICY)"
  elif [[ ! -r "$cfg" ]]; then
    report "Policy invalid: the configuration ${cfg@Q} cannot be read by this user. (PHB-EPOLICY)"
  else
    return 0
  fi
  exit "${PHB_EPOLICY}"
}

# Refuses a cfg that starts with a UTF-8 byte order mark or holds a NUL byte, which no editor writes
# on purpose into a policy. The mark would make the first header read as text before any section, and
# bash drops a NUL without a word, so a path would be read as one with the byte left out.
# Takes the path of a readable file. Assumes it is called plainly, so that the refusal ends the run.
refuse_binary_cfg() {
  local cfg="$1"
  local first_bytes
  local with_nul
  local without_nul
  if ! { first_bytes="$(head -c 3 < "$cfg" | od -An -tx1 | tr -d ' \n')" \
    && with_nul="$(wc -c < "$cfg")" \
    && without_nul="$(tr -d '\000' < "$cfg" | wc -c)"; } 2>/dev/null; then
    report "Policy invalid: ${cfg@Q} could not be examined with head, od, tr and wc, which this program needs to tell a text file from another. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  if [[ "$first_bytes" == "efbbbf" ]]; then
    report "Policy invalid: ${cfg@Q} starts with a UTF-8 byte order mark. Save the file as UTF-8 without one. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
  if (( with_nul != without_nul )); then
    report "Policy invalid: ${cfg@Q} holds a NUL byte, so it is not a text file. (PHB-EPOLICY)"
    exit "${PHB_EPOLICY}"
  fi
}

# Reads one policy cfg. Each filesystem section's paths go into its own "<right>.paths" file,
# the [connect] and [bind] rules into net.rules and bind.rules, all in a fresh directory, and
# the [limits] section into the PARSED_* values. Sets PARSED_FS_DIR, PARSED_NET_FILE and
# PARSED_BIND_FILE to what it wrote. Everything from a "#" is a comment. An unknown section, a
# malformed line and any content before the first section are refused (PHB-EPOLICY). A second
# argument, any non-empty word, says the cfg is an exercise configuration, whose [read] and [execute] paths must exist.
# Assumes it is called plainly, not in a subshell, so that a refusal ends the run.
parse_cfg_policy() {
  local cfg="$1"
  local exercise="${2:-}"
  local tdir
  local line
  local number=0
  local sec=""
  tdir="$(new_parse_directory)"
  local rd="${tdir}/read.paths"
  local ex="${tdir}/execute.paths"
  local wr="${tdir}/write.paths"
  local cr="${tdir}/create.paths"
  local de="${tdir}/delete.paths"
  local ipc="${tdir}/ipc.paths"
  local sym="${tdir}/symlink.paths"
  local ref="${tdir}/refer.paths"
  local net="${tdir}/net.rules"
  local bind="${tdir}/bind.rules"
  local acc="${tdir}/accept.rules"
  : >"$rd"; : >"$ex"; : >"$wr"; : >"$cr"; : >"$de"; : >"$ipc"; : >"$sym"; : >"$ref"; : >"$net"; : >"$bind"; : >"$acc"
  reset_parsed_limits
  refuse_binary_cfg "$cfg"
  while IFS= read -r line || [[ -n "$line" ]]; do
    number=$(( number + 1 ))
    PARSE_LOCATION="${cfg@Q}, line ${number}"
    if [[ "$line" == *$'\r'* ]]; then
      refuse_cfg "this line contains a carriage return, which a Windows line ending leaves at its end and which would become part of the value. Save the file with LF line endings"
    fi
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^\[(.+)\]$ ]]; then
      sec="${BASH_REMATCH[1]}"
      refuse_unknown_section "$sec"
      continue
    fi
    case "$sec" in
      read|execute|write|create|delete|create-ipc|create-symlink|restructure)
        refuse_relative_path "$line" "$sec"
        refuse_wildcard_path "$line" "$sec"
        if [[ -n "$exercise" && ( "$sec" == "read" || "$sec" == "execute" ) ]]; then refuse_missing_path "$line" "$sec"; fi ;;
    esac
    case "$sec" in
      read)    printf '%s\n' "$line" >>"$rd" ;;
      execute) printf '%s\n' "$line" >>"$ex" ;;
      write)   printf '%s\n' "$line" >>"$wr" ;;
      create)  printf '%s\n' "$line" >>"$cr" ;;
      delete)  printf '%s\n' "$line" >>"$de" ;;
      create-ipc)     printf '%s\n' "$line" >>"$ipc" ;;
      create-symlink) printf '%s\n' "$line" >>"$sym" ;;
      restructure)    printf '%s\n' "$line" >>"$cr"; printf '%s\n' "$line" >>"$de"; printf '%s\n' "$line" >>"$ref" ;;
      connect) append_connect_rule "$line" "$net" ;;
      bind)    append_bind_rule "$line" "$bind" ;;
      accept)  append_accept_rule "$line" "$acc" ;;
      limits)  read_limits_line "$line" "$sec" ;;
      "")
        refuse_cfg "${line@Q} appears before any [section] header" ;;
    esac
  done <"$cfg"
  PARSE_LOCATION=""
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
# base cfgs, and phobos-policysystem.sh then folds each exercise cfg in the same way, so the policy
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
