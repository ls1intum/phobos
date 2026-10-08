#!/bin/bash
# shellcheck shell=bash
# phobos-haproxy.sh -- turn the [connect] allow-list into an haproxy.cfg the egress broker enforces.
#
# Sourced by phobos-networksystem.sh, which starts the broker from a generated config, and by the tests.
# It sets no shell option and sources nothing, so sourcing it more than once keeps doing what it
# did before.
#
# The connect guard hands every allowed stream connection to this broker on loopback, with a
# PROXY protocol version 2 header naming the destination the command meant. The broker reads the
# host name from the TLS ClientHello, which the guard cannot see. For an exact host name it does
# not trust the header's destination at all: it resolves the name itself, through its own
# resolver, and connects to that address, so a command that presents an allowed name but aims at
# some other address is still sent only to where the name resolves. A rule that names an address
# or "*" is enforced by the destination the header carried, unchanged. A wildcard name has no
# address to resolve and is refused before any config is written. net.rules
# holds one "host port" per line, as phobos-policysystem.sh wrote it. The port was already enforced by
# the guard before the redirect, so the broker decides the host alone.

# Classifies one [connect] host into the kinds the broker treats apart: "any" for "*", "invalid"
# for any other host with a star in it, which is tested before the shortcuts below so that a star
# beside a slash or a colon is not taken for an address, "address" for a host with a slash, an IPv6
# colon or only digits and dots, and "exact" for anything else. "localhost" is an address, not an exact name: the guard already
# treats it as the loopback the command connected to, so the broker sends it to the header's
# destination rather than resolve it, and it is never mapped to a placeholder. This is the one
# classifier the config generator and the network layer share, so the two never disagree on what an
# exact name is. It differs by design from the guard's inet_pton test only for a nonsensical
# all-digits token such as "1234", which is an address here and a name there; tests/unit/phobos-tools-networksystem/haproxy_conf.sh
# pins that so the divergence cannot drift.
classify_connect_host() {
  local host="$1"
  if [[ "$host" == "*" ]]; then
    printf 'any\n'
  elif [[ "$host" == *"*"* ]]; then
    printf 'invalid\n'
  elif [[ "$host" == "localhost" || "$host" == *"/"* || "$host" == *:* || "$host" =~ ^[[:digit:].]+$ ]]; then
    printf 'address\n'
  else
    printf 'exact\n'
  fi
}

# Prints, one per line and sorted, the exact host names a net.rules file names in [connect]: the
# hosts classify_connect_host calls "exact". These are the names the broker resolves itself and the
# ones the network layer maps to a placeholder in /etc/hosts. Assumes the file is the "host port"
# form phobos-policysystem.sh writes; a missing file names nothing.
exact_connect_names() {
  local rules="$1"
  local host
  local proto
  while read -r host _ proto; do
    [[ -z "$host" ]] && continue
    [[ "$proto" == "udp" ]] && continue
    [[ "$(classify_connect_host "$host")" == "exact" ]] && printf '%s\n' "$host"
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d') | sort -u
}

# Prints, one per line and sorted, the host names a net.rules file names in [connect] whose match
# depends on the egress broker: the "exact" hosts. The connect guard enforces a
# [connect] rule by address and port alone, so a name-based rule constrains nothing about the onward
# host unless the broker checks the TLS host name; the network layer uses this to refuse a name rule
# when the broker is off, rather than run with a rule the guard would widen to any address on the
# port. An address, "localhost" or "*" rule stays guard-enforced and is not listed. Assumes the file
# is the "host port" form phobos-policysystem.sh writes; a missing file names nothing.
name_connect_rules() {
  local rules="$1"
  local host
  local proto
  while read -r host _ proto; do
    [[ -z "$host" ]] && continue
    [[ "$proto" == "udp" ]] && continue
    [[ "$(classify_connect_host "$host")" == "exact" ]] && printf '%s\n' "$host"
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d') | sort -u
}

# Prints, one per line and sorted, the exact host names the udp rows of a net.rules file name, in
# lower case and once each however they were spelled, since a name is one name whatever its case and
# must lead to one set of addresses. A datagram carries no TLS host name for the egress broker to
# check, so these are not the broker's names: the network layer resolves each one once, before the
# command starts, and holds the rule to the addresses it had then. Assumes the file is the "host port
# [udp]" form phobos-policysystem.sh writes; a missing file names nothing.
udp_connect_names() {
  local rules="$1"
  local host
  local proto
  while read -r host _ proto; do
    [[ -z "$host" ]] && continue
    [[ "$proto" == "udp" ]] || continue
    [[ "$(classify_connect_host "$host")" == "exact" ]] && printf '%s\n' "${host,,}"
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d') | sort -u
}

# Writes the allow-list the connect guard reads when udp rules name hosts: every row of the net.rules
# file, except that a udp row naming an exact host becomes one udp row for each address the host
# resolved to, taken from the "NAME ADDRESS" lines of the resolved file. A name with no line there
# yields no row at all, which denies, so a name that was not resolved can never be read by the guard
# as a host it cannot tie to an address and so as matching its port alone. Takes the net.rules file,
# the resolved file, then the file to write. A name matches without regard to case. Assumes
# phobos-common.sh was sourced.
expand_udp_name_rules() {
  local rules="$1"
  local resolved="$2"
  local out="$3"
  local host
  local port
  local proto
  local name
  local address
  : > "$out" || return 1
  while read -r host port proto; do
    [[ -z "$host" ]] && continue
    if [[ "$proto" == "udp" && "$(classify_connect_host "$host")" == "exact" ]]; then
      while read -r name address; do
        [[ "${name,,}" == "${host,,}" ]] && printf '%s %s udp\n' "$address" "$port" >> "$out"
      done < "$resolved"
    elif [[ -n "$proto" ]]; then
      printf '%s %s %s\n' "$host" "$port" "$proto" >> "$out"
    else
      printf '%s %s\n' "$host" "$port" >> "$out"
    fi
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d')
  return 0
}

# The loopback placeholder every exact [connect] name resolves to for the graded command, so its
# getaddrinfo succeeds without a DNS query the guard would refuse. The command then connects to the
# placeholder, the guard redirects to the broker, and the broker resolves the real address itself
# through its own resolver, which does not consult the hosts file this placeholder lives in. It sits
# inside the loopback range a localhost rule covers, which is harmless, because nothing listens on
# the placeholder itself: a connection to it is bound by the exact name's ClientHello, or, under a
# localhost rule, forwarded to the placeholder where it simply finds nothing.
PHB_BROKER_PLACEHOLDER_IP="127.0.0.2"

# Ends the file with a newline when it has content that does not, so a line appended after it
# starts a line of its own rather than continuing the last one.
ensure_final_newline() {
  local file="$1"
  [[ ! -s "$file" || -z "$(tail -c 1 -- "$file")" ]] && return 0
  printf '\n' >> "$file"
}

# Appends one line per name mapping it to the loopback placeholder, each ending in this run's tag
# as a comment, which the resolver ignores. A name another run or the image already maps still
# gets a line of this run's own, so that run's clean-up cannot take the mapping away from this one;
# the same tagged line is not written twice. A name the file already maps to anything but the
# placeholder is refused with a report, before anything is written, as is a name another run pinned
# to real addresses. Assumes the caller holds the lock on the hosts file.
append_run_hosts_entries() {
  local hosts_file="$1"
  local spec_dir="$2"
  shift 2
  local tag
  local name
  local line
  local wanted=""
  for name in "$@"; do
    wanted+="${name} ${PHB_BROKER_PLACEHOLDER_IP}"$'\n'
  done
  hosts_accepts "$hosts_file" "$wanted" || return 1
  tag="$(run_hosts_tag "$spec_dir")"
  ensure_final_newline "$hosts_file" || return 1
  for name in "$@"; do
    line="${PHB_BROKER_PLACEHOLDER_IP} ${name} # ${tag}"
    grep -qxF -- "$line" "$hosts_file" 2>/dev/null && continue
    printf '%s\n' "$line" >> "$hosts_file" || return 1
  done
  return 0
}

# Maps each given exact [connect] name to the loopback placeholder in the named hosts file, so the
# graded command resolves it with no DNS the guard would refuse. It first records the hosts file in
# the specification directory, so whichever layer removes that directory also removes these lines,
# then appends them under the hosts lock remove_run_hosts_entries takes. Answers non-zero when the
# file cannot be recorded or written, or the lock not had in time, so the caller can refuse rather
# than run with names the command cannot resolve. The network layer passes /etc/hosts and runs this
# before the filesystem layer makes /etc read-only. Assumes phobos-common.sh was sourced and
# flock(1) is present. Takes the hosts file, the specification directory, then the names.
write_broker_hosts() {
  local hosts_file="$1"
  local spec_dir="$2"
  shift 2
  printf '%s\n' "$hosts_file" > "${spec_dir}/${PHB_SPEC_HOSTS_RECORD}" || return 1
  with_hosts_lock append_run_hosts_entries "$hosts_file" "$spec_dir" "$@"
}

# Prints "NAME ADDRESS" for the first name whose addresses in the hosts file are not exactly the ones
# about to be written for it, and answers 0 when there is one, 1 when there is none and 2 when the
# file could not be read. A name the file already maps to something else would be answered to the
# command from that line, while the guard holds the rule to the resolved addresses, so the two would
# disagree and every datagram to the name would be refused; and a name another run has pinned to some
# addresses must not gain more, which that run's command could then be handed although its own guard
# denies them. So a name is fine only where the file holds none of it yet, or exactly the addresses to
# be written, whoever's lines they are: another run's, the image's, a TCP placeholder. Names compare
# without regard to case, as the resolver does, and an IPv6 address is compared in its full form, so
# two spellings of one address are one address. Comments are ignored. Takes the hosts file and the
# "NAME ADDRESS" lines to be written; a missing file has no conflict.
hosts_conflict() {
  local hosts_file="$1"
  local wanted="$2"
  [[ -f "$hosts_file" ]] || return 1
  awk 'function full(address,   tail, at, left, right, head_count, tail_count, heads, tails, out, index_, group, missing) {
         if (address !~ /:/) return address
         address = tolower(address)
         at = match(address, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/)
         if (at) {
           split(substr(address, at), tail, ".")
           address = substr(address, 1, at - 1) sprintf("%x:%x", tail[1] * 256 + tail[2], tail[3] * 256 + tail[4])
         }
         at = index(address, "::")
         if (at) {
           left = substr(address, 1, at - 1)
           right = substr(address, at + 2)
           head_count = (left == "") ? 0 : split(left, heads, ":")
           tail_count = (right == "") ? 0 : split(right, tails, ":")
           missing = 8 - head_count - tail_count
         } else {
           head_count = split(address, heads, ":")
           tail_count = 0
           missing = 0
         }
         out = ""
         for (index_ = 1; index_ <= head_count; index_++) { group = heads[index_]; while (length(group) < 4) group = "0" group; out = out group ":" }
         for (index_ = 1; index_ <= missing; index_++) out = out "0000:"
         for (index_ = 1; index_ <= tail_count; index_++) { group = tails[index_]; while (length(group) < 4) group = "0" group; out = out group ":" }
         return out
       }
       NR == FNR { want[tolower($1), full($2)] = 1; names[tolower($1)] = 1; shown[tolower($1), full($2)] = $2; next }
       { sub(/#.*/, ""); if (NF < 2) next
         for (field = 2; field <= NF; field++) {
           name = tolower($field)
           if (name in names) { present[name, full($1)] = 1; seen[name] = 1; shown[name, full($1)] = $1 }
         } }
       END {
         for (key in present) {
           if (!(key in want)) { split(key, parts, SUBSEP); print parts[1], shown[key]; found = 1; exit }
         }
         for (key in want) {
           split(key, parts, SUBSEP)
           if ((parts[1] in seen) && !(key in present)) { print parts[1], shown[key]; found = 1; exit }
         }
         exit found ? 0 : 1
       }' <(printf '%s\n' "$wanted") "$hosts_file"
}

# Answers 0 when the hosts file may take the "NAME ADDRESS" lines, and otherwise says why and answers
# 1: it maps a name differently, or it could not be read, which is refused too rather than taken for
# no conflict. Takes the hosts file and the lines to be written.
hosts_accepts() {
  local hosts_file="$1"
  local wanted="$2"
  local conflict
  local status
  conflict="$(hosts_conflict "$hosts_file" "$wanted")" && status=0 || status=$?
  case "$status" in
    0)
      report_hosts_conflict "$hosts_file" "$conflict"
      return 1
      ;;
    1)
      return 0
      ;;
  esac
  report "${hosts_file} could not be read to check that it maps no name differently from this run; refusing rather than write to it blind. (PHB-ERUNTIME)"
  return 1
}

# Says that the hosts file maps a name differently from what is about to be written, which ends the
# run, naming the name and one address that only one side has. Takes the hosts file and the
# "NAME ADDRESS" the conflict check printed.
report_hosts_conflict() {
  local hosts_file="$1"
  local conflict="$2"
  report "${hosts_file} maps '${conflict% *}' to a different set of addresses than this run needs (${conflict#* } is on one side only), so the command and the connect guard of one run or another would disagree about where the name leads. (PHB-ERUNTIME)"
}

# Appends one line for every "NAME ADDRESS" line of the resolved file, "ADDRESS NAME # tag", so the
# command resolves a name a udp rule holds to exactly the addresses the guard accepts and needs no
# DNS of its own. Each line ends in this run's tag as a comment, so remove_run_hosts_entries takes it
# away with the run's others, and a line already there is not written twice. Unlike the placeholder
# of a TCP name these are the real addresses: the broker resolves a TCP name itself and ignores the
# one the command used, so a TCP connection to a real address is bound by the name just the same,
# while a datagram has to be sent to a real address to arrive anywhere. Assumes the caller holds the
# lock on the hosts file. A name the file already maps to another address is refused with a report,
# before anything is written. Takes the hosts file, the specification directory and the resolved lines.
append_resolved_hosts_entries() {
  local hosts_file="$1"
  local spec_dir="$2"
  local resolved="$3"
  local tag
  local name
  local address
  local line
  hosts_accepts "$hosts_file" "$resolved" || return 1
  tag="$(run_hosts_tag "$spec_dir")"
  ensure_final_newline "$hosts_file" || return 1
  while read -r name address; do
    [[ -z "$name" ]] && continue
    line="${address} ${name} # ${tag}"
    grep -qxF -- "$line" "$hosts_file" 2>/dev/null && continue
    printf '%s\n' "$line" >> "$hosts_file" || return 1
  done <<< "$resolved"
  return 0
}

# Maps the names of the resolved lines to their addresses in the named hosts file. It records the
# hosts file in the specification directory first, so whichever layer removes that directory also
# removes these lines, then appends them under the hosts lock. Answers non-zero when the file cannot
# be recorded or written, or the lock not had in time, so the caller can refuse rather than run
# with names the command cannot resolve. Assumes phobos-common.sh was sourced and flock(1) is
# present. Takes the hosts file, the specification directory and the "NAME ADDRESS" lines.
write_resolved_hosts() {
  local hosts_file="$1"
  local spec_dir="$2"
  local resolved="$3"
  printf '%s\n' "$hosts_file" > "${spec_dir}/${PHB_SPEC_HOSTS_RECORD}" || return 1
  with_hosts_lock append_resolved_hosts_entries "$hosts_file" "$spec_dir" "$resolved"
}

# How often, and how far apart, stop_haproxy_child checks that an HAProxy it asked to stop is
# gone before it kills it outright, so a stuck HAProxy delays the end of a run by two seconds at most.
PHB_HAPROXY_STOP_ATTEMPTS=40
PHB_HAPROXY_STOP_INTERVAL_SECONDS=0.05

# Answers whether the process id still names a process, polling up to PHB_HAPROXY_STOP_ATTEMPTS
# times, so it answers failure as soon as the process is gone and success only when it outlasted
# every attempt.
outlasts_stop_grace() {
  local pid="$1"
  local attempt
  for (( attempt = 0; attempt < PHB_HAPROXY_STOP_ATTEMPTS; attempt++ )); do
    kill -0 "$pid" 2>/dev/null || return 1
    sleep "$PHB_HAPROXY_STOP_INTERVAL_SECONDS"
  done
  kill -0 "$pid" 2>/dev/null
}

# Stops an HAProxy this shell started in the background and collects its status, so it neither
# outlives the run nor stays behind as a zombie: TERM, a bounded wait, then KILL only when it is
# still there. Bash reaps a background child as soon as it exits, and its process id may then be
# reused, so the id is signalled only while it can still be the HAProxy: once it is found gone it is
# never signalled again. It works from the process id the start function handed back rather than
# from a file, and is meant to be called by the shell that started it, which is outside any
# Landlock domain and so may signal it. An empty process id is nothing to stop.
stop_haproxy_child() {
  local pid="$1"
  [[ -n "$pid" ]] || return 0
  if kill -TERM "$pid" 2>/dev/null && outlasts_stop_grace "$pid"; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

# Prints the frontend allow-list lines for one net.rules file. A host of "*" permits any host. A
# host with a slash, an IPv6 colon or only digits and dots is an address; any other host with a
# star in it ends the run through refuse_wildcard_host_name rather than yield a rule; anything else is an
# exact name. For an exact name the broker resolves the ClientHello's
# host name through the "phobosdns" resolver into a variable, sets the destination to it, and
# refuses when it does not resolve, so the connection can only reach the name's own address; this
# is done only for a connection to the port the rule names, because the broker keeps the
# destination port it was given, and a connection the guard let through on another port, under
# another rule, would otherwise carry that port to the name; names are grouped by port, one acl
# pair for each; this
# needs the resolvers section build_haproxy_conf emits, which the network layer guarantees by
# refusing an exact-name rule with no resolver. Each pair tests the port before the TLS name, and
# the order is load-bearing: HAProxy stops at the first term that is false, while reading the TLS
# name of a connection that has sent nothing waits for its first bytes until the inspect-delay ends.
# Tested first, the port lets a connection to any other port reach the address rules at once, so a
# server that speaks first, as SMTP, MySQL or SSH do, gets its banner to the client without delay.
# On a port a name rule names, the broker cannot tell a TLS client that has not written yet from a
# server that speaks first, so a connection there still waits out the inspect-delay before an
# address rule accepts it. Name matching is case-insensitive. Assumes
# it is called where its output belongs, inside the frontend and after set-dst, and that
# refuse_wildcard_host_name is defined, as it is wherever phobos-common.sh was sourced.
haproxy_allow_rules() {
  local rules="$1"
  local host
  local port
  local proto
  local key
  local tag
  local condition
  local -A names_by_port=()
  local -a conditions=()
  local -a addresses=()
  local any_host=0
  while read -r host port proto; do
    [[ -z "$host" ]] && continue
    [[ "$proto" == "udp" ]] && continue
    case "$(classify_connect_host "$host")" in
      any) any_host=1 ;;
      address)
        if [[ "$host" == "localhost" ]]; then
          addresses+=("127.0.0.0/8" "::1")
        else
          addresses+=("$host")
        fi
        ;;
      invalid) refuse_wildcard_host_name "$host" ;;
      exact) names_by_port["${port:-*}"]+=" ${host}" ;;
    esac
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d')

  if (( any_host )); then
    printf '    tcp-request content accept\n'
    printf '    default_backend to_dst\n'
    return 0
  fi
  while read -r key; do
    [[ -z "$key" ]] && continue
    tag="p${key}"
    [[ "$key" == "*" ]] && tag="pany"
    condition="exact_sni_${tag}"
    printf '    acl exact_sni_%s req.ssl_sni -m str -i %s\n' "$tag" "$(printf '%s\n' ${names_by_port[$key]} | sort -u | tr '\n' ' ' | sed 's/ $//')"
    if [[ "$key" != "*" ]]; then
      printf '    acl exact_port_%s dst_port %s\n' "$tag" "$key"
      condition="exact_port_${tag} exact_sni_${tag}"
    fi
    printf '    tcp-request content do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if %s\n' "$condition"
    printf '    tcp-request content set-dst var(txn.hostip) if %s { var(txn.hostip) -m found }\n' "$condition"
    printf '    tcp-request content reject if %s !{ var(txn.hostip) -m found }\n' "$condition"
    conditions+=("$condition")
  done < <(printf '%s\n' "${!names_by_port[@]}" | sort)
  if (( ${#addresses[@]} > 0 )); then
    printf '    acl allowed_dst dst -m ip %s\n' "$(printf '%s\n' "${addresses[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    printf '    tcp-request content accept if allowed_dst\n'
  fi
  printf '    tcp-request content accept if { req.ssl_hello_type 1 }\n'
  for condition in "${conditions[@]}"; do
    printf '    use_backend to_dst if %s\n' "$condition"
  done
  if (( ${#addresses[@]} > 0 )); then
    printf '    use_backend to_dst if allowed_dst\n'
  fi
  printf '    default_backend refuse\n'
}

# Starts the egress broker for a specification directory, or fails. It generates the broker's
# config from the rules, binds it to a free loopback port, and hands back the "127.0.0.1:port" the
# guard should hand connections to and the broker's process id through the two variables named
# last, so the caller stops it with stop_haproxy_child. It must be called plainly, not in a command
# substitution, so the broker is a child of the caller rather than of a subshell that has already
# ended. haproxy runs in the foreground with -db, so it stays in the run's process group and dies
# with it when a timeout escalates to SIGKILL; it is started with TERM at its default, whatever the
# caller ignores, and its own output goes to a scratch log rather than the command's stdout.
# The broker is trusted infrastructure started before the graded command: its every onward
# connection the guard already vetted by port and the broker itself vets by TLS host name. A port
# that already answers is skipped before the broker binds it; because the broker holds the loopback port
# exclusively, a probe that then answers on a live broker is answering the broker. The upstream
# resolver, "ip" or "ip:port", is the nameserver the broker resolves an exact host name through;
# it is empty when no exact-name rule needs one, and the network layer refuses the run before here
# when one is needed and none was given.
# Assumes phobos-common.sh was sourced, so PHB_SPEC_SCRATCH is set. Takes the specification
# directory, the rules, the haproxy binary, the resolver (empty for none), then the names of the
# variables that receive the endpoint and the process id, and last, optionally, the number of the
# descriptor the broker logs its refusals to. That descriptor is inherited from the caller, which
# opened it, and nothing else is passed: no path is written for the log, so no policy can grant
# the command access to it.
# The two results are only assigned here, through namerefs, and read by the caller, which the
# linter cannot follow, so it reports them as unused.
# shellcheck disable=SC2034
start_egress_broker() {
  local spec_dir="$1"
  local rules="$2"
  local haproxy_bin="$3"
  local resolver="$4"
  local -n endpoint_out="$5"
  local -n pid_out="$6"
  local log_descriptor="${7:-}"
  local scratch="${spec_dir}/${PHB_SPEC_SCRATCH}"
  local cfg
  local log
  local port
  local pid
  mkdir -p "$scratch"
  cfg="${scratch}/broker.cfg"
  log="${scratch}/broker.log"
  for _ in 1 2 3 4 5; do
    port=$(( 20000 + RANDOM % 40000 ))
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      continue
    fi
    build_haproxy_conf "$rules" "$cfg" "127.0.0.1:${port}" "$resolver" "$log_descriptor"
    ( trap - TERM; exec "$haproxy_bin" -f "$cfg" -db ) > "$log" 2>&1 &
    pid=$!
    for _ in $(seq 1 60); do
      kill -0 "$pid" 2>/dev/null || break
      if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        endpoint_out="127.0.0.1:${port}"
        pid_out="$pid"
        return 0
      fi
      sleep 0.05
    done
    stop_haproxy_child "$pid"
  done
  return 1
}

# Emits the "phobosdns" resolvers section the do-resolve of an exact host name queries. Takes the
# upstream nameserver as "ip", to which the default DNS port is added, or as "ip:port" (an IPv6
# nameserver must arrive already bracketed, "[::1]:53"). The short holds and retries turn a
# transient lookup failure into a failed connection the run can see, not a silent stale answer.
# Assumes it is called where a section belongs, at the top of the config.
emit_broker_resolvers() {
  local resolver="$1"
  local server="$resolver"
  [[ "$resolver" == *:* ]] || server="${resolver}:53"
  printf 'resolvers phobosdns\n'
  printf '    nameserver dns1 %s\n' "$server"
  printf '    resolve_retries 3\n'
  printf '    timeout resolve 1s\n'
  printf '    timeout retry 1s\n'
  printf '    hold valid 10s\n'
  printf '    hold obsolete 5s\n'
}

# Writes a complete haproxy.cfg for the egress broker: the "phobosdns" resolvers section when an
# upstream resolver is given, the fixed preamble that keeps it a loopback TCP proxy reading the
# PROXY header and the ClientHello, the allow-list rules haproxy_allow_rules builds, and the two
# backends, one that connects to the destination in force and one that refuses. Takes the
# net.rules file, the output path, the "address:port" the broker listens on, and the upstream
# resolver ("ip" or "ip:port", empty when no exact-name rule needs one), and optionally the number
# of the descriptor to log refusals to. An exact-name rule needs
# the resolvers section; the network layer guarantees a resolver is given whenever one is present.
# With a descriptor, the frontend logs each connection it does not complete normally to it as one
# raw line of machine fields, "PHB-BROKER <backend> <termination state> <hex host name> <address>
# <port>", which the connect guard reads and words as a blocked action. The host name is hex, so
# a name the program chose cannot inject anything into the line, and a connection that completed
# normally is not logged. The name is kept in a variable while the ClientHello is inspected,
# because HAProxy cannot read the request buffer when the line is written, at the end of the
# connection; a connection that sent no name logs a dash.
# A wildcard host name ends the run before anything is written, so a half-written config never
# stands for a refusal. Assumes phobos-common.sh was sourced and that it is called plainly, so
# the refusal ends the run.
build_haproxy_conf() {
  local rules="$1"
  local out="$2"
  local listen="$3"
  local resolver="${4:-}"
  local log_descriptor="${5:-}"
  refuse_wildcard_connect_names "$rules"
  {
    if [[ -n "$resolver" ]]; then
      emit_broker_resolvers "$resolver"
    fi
    printf 'defaults\n'
    printf '    mode tcp\n'
    printf '    timeout connect 5s\n'
    printf '    timeout client 30s\n'
    printf '    timeout server 30s\n'
    if [[ -n "$log_descriptor" ]]; then
      printf '    log fd@%s format raw local0\n' "$log_descriptor"
    fi
    printf 'frontend broker\n'
    if [[ -n "$log_descriptor" ]]; then
      printf '    option dontlog-normal\n'
      printf '    log-format "PHB-BROKER %%b %%ts %%[var(txn.sni),hex] %%[dst] %%[dst_port]"\n'
    fi
    printf '    bind %s accept-proxy\n' "$listen"
    printf '    tcp-request inspect-delay 5s\n'
    printf '    tcp-request content set-dst dst\n'
    printf '    tcp-request content set-dst-port dst_port\n'
    if [[ -n "$log_descriptor" ]]; then
      printf '    tcp-request content set-var(txn.sni) req.ssl_sni\n'
    fi
    haproxy_allow_rules "$rules"
    printf 'backend to_dst\n'
    printf '    server original 0.0.0.0:0\n'
    printf 'backend refuse\n'
    printf '    tcp-request content reject\n'
  } > "$out"
}

# Writes an haproxy.cfg for the inbound filter and the per-port source files it reads, from an
# accept.rules file of "H P [src]" lines. For each public port H it emits a frontend bound
# dual-stack on H that rejects a connection whose source address is not in H's source file, and a
# backend that forwards to the student's backend port P on loopback. A public port with no source
# lines gets an empty source file, so the frontend rejects every peer, fail-closed. Takes the
# accept.rules file, the output config path, and a scratch directory the source files are written
# into and the config references by absolute path.
build_inbound_conf() {
  local accept_rules="$1"
  local out="$2"
  local scratch="$3"
  local h
  local p
  local src
  local -A backend_of=()
  mkdir -p "$scratch"
  while read -r h p src; do
    [[ -z "$h" ]] && continue
    backend_of[$h]="$p"
    [[ -f "${scratch}/in_${h}.src" ]] || : > "${scratch}/in_${h}.src"
    if [[ -n "$src" ]]; then printf '%s\n' "$src" >> "${scratch}/in_${h}.src"; fi
  done < "$accept_rules"
  {
    printf 'defaults\n'
    printf '    mode tcp\n'
    printf '    timeout connect 5s\n'
    printf '    timeout client 30s\n'
    printf '    timeout server 30s\n'
    for h in "${!backend_of[@]}"; do
      printf 'frontend in_%s\n' "$h"
      printf '    bind :::%s v4v6\n' "$h"
      printf '    tcp-request connection reject if !{ src -f %s }\n' "${scratch}/in_${h}.src"
      printf '    default_backend be_%s\n' "$h"
    done
    for h in "${!backend_of[@]}"; do
      printf 'backend be_%s\n' "$h"
      printf '    server s 127.0.0.1:%s\n' "${backend_of[$h]}"
    done
  } > "$out"
}

# Starts the inbound filter for a specification directory and hands its process id back through
# the variable named last, so the caller stops it with stop_haproxy_child and frees the fixed
# public ports. It must be called plainly, not in a command substitution, so the filter is a child
# of the caller. It generates the config and source files, binds haproxy to the public ports the
# accept rules name, and waits for the first of them to answer. haproxy runs in the foreground with
# -db so it stays in the run's process group, started with TERM at its default, its output going
# to a scratch log. It is trusted infrastructure started before the graded command, so it binds a
# public port and connects to the backend on loopback on the run's behalf. Returns non-zero if the
# filter cannot start, having stopped its own attempt, so the caller can refuse the run. Assumes
# phobos-common.sh was sourced, so PHB_SPEC_SCRATCH is set, and that accept_rules is not empty.
# Takes, last and optionally, the number of a descriptor the caller holds that the filter must not
# inherit, such as the pipe the egress broker logs to, and closes it before haproxy starts.
# The result is only assigned here, through a nameref, and read by the caller, which the linter
# cannot follow, so it reports it as unused.
# shellcheck disable=SC2034
start_inbound_haproxy() {
  local spec_dir="$1"
  local accept_rules="$2"
  local haproxy_bin="$3"
  local -n inbound_pid_out="$4"
  local close_descriptor="${5:-}"
  local scratch="${spec_dir}/${PHB_SPEC_SCRATCH}"
  local cfg="${scratch}/inbound.cfg"
  local log="${scratch}/inbound.log"
  local first_port
  local pid
  local _
  mkdir -p "$scratch"
  build_inbound_conf "$accept_rules" "$cfg" "$scratch"
  first_port="$(awk 'NF>=2 {print $1; exit}' "$accept_rules")"
  ( trap - TERM; if [[ -n "$close_descriptor" ]]; then exec {close_descriptor}<&-; fi; exec "$haproxy_bin" -f "$cfg" -db ) > "$log" 2>&1 &
  pid=$!
  for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || break
    if (exec 3<>"/dev/tcp/127.0.0.1/${first_port}") 2>/dev/null; then
      inbound_pid_out="$pid"
      return 0
    fi
    sleep 0.05
  done
  stop_haproxy_child "$pid"
  return 1
}
