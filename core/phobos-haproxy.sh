#!/usr/bin/env bash
# shellcheck shell=bash
# phobos-haproxy.sh -- turn the [connect] allow-list into an haproxy.cfg the egress broker enforces.
#
# Sourced by phobos-network.sh, which starts the broker from a generated config, and by the tests.
# It sets no shell option and sources nothing, so sourcing it more than once keeps doing what it
# did before.
#
# The connect guard hands every allowed stream connection to this broker on loopback, with a
# PROXY protocol version 2 header naming the destination the command meant. The broker reads the
# host name from the TLS ClientHello, which the guard cannot see. For an exact host name it does
# not trust the header's destination at all: it resolves the name itself, through its own
# resolver, and connects to that address, so a command that presents an allowed name but aims at
# some other address is still sent only to where the name resolves. A rule that names an address,
# a name suffix, or "*" is enforced by the destination the header carried, unchanged. net.rules
# holds one "host port" per line, as phobos-policy.sh wrote it. The port was already enforced by
# the guard before the redirect, so the broker decides the host alone.

# Classifies one [connect] host into the four kinds the broker treats apart: "any" for "*",
# "address" for a host with a slash, an IPv6 colon or only digits and dots, "suffix" for "*.name",
# and "exact" for anything else. "localhost" is an address, not an exact name: the guard already
# treats it as the loopback the command connected to, so the broker sends it to the header's
# destination rather than resolve it, and it is never mapped to a placeholder. This is the one
# classifier the config generator and the network layer share, so the two never disagree on what an
# exact name is. It differs by design from the guard's inet_pton test only for a nonsensical
# all-digits token such as "1234", which is an address here and a name there; tests/haproxy_conf.sh
# pins that so the divergence cannot drift.
classify_connect_host() {
  local host="$1"
  if [[ "$host" == "*" ]]; then
    printf 'any\n'
  elif [[ "$host" == "localhost" || "$host" == *"/"* || "$host" == *:* || "$host" =~ ^[0-9.]+$ ]]; then
    printf 'address\n'
  elif [[ "$host" == "*."* ]]; then
    printf 'suffix\n'
  else
    printf 'exact\n'
  fi
}

# Prints, one per line and sorted, the exact host names a net.rules file names in [connect]: the
# hosts classify_connect_host calls "exact". These are the names the broker resolves itself and the
# ones the network layer maps to a placeholder in /etc/hosts. Assumes the file is the "host port"
# form phobos-policy.sh writes; a missing file names nothing.
exact_connect_names() {
  local rules="$1"
  local host
  while read -r host _; do
    [[ -z "$host" ]] && continue
    [[ "$(classify_connect_host "$host")" == "exact" ]] && printf '%s\n' "$host"
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d') | sort -u
}

# The loopback placeholder every exact [connect] name resolves to for the graded command, so its
# getaddrinfo succeeds without a DNS query the guard would refuse. The command then connects to the
# placeholder, the guard redirects to the broker, and the broker resolves the real address itself
# through its own resolver, which does not consult the hosts file this placeholder lives in. It sits
# inside the loopback range a localhost rule covers, which is harmless, because nothing listens on
# the placeholder itself: a connection to it is bound by the exact name's ClientHello, or, under a
# localhost rule, forwarded to the placeholder where it simply finds nothing.
PHB_BROKER_PLACEHOLDER_IP="127.0.0.2"
# The line that marks the entries the network layer adds, so a reader can tell them from an image's.
PHB_BROKER_HOSTS_MARKER="# added by phobos for the egress broker"

# Maps each given exact [connect] name to the loopback placeholder in the named hosts file, so the
# graded command resolves it with no DNS the guard would refuse. Appends only the names not already
# mapped to the placeholder, under one marker line, and answers non-zero when the file cannot be
# written, so the caller can refuse rather than run with names the command cannot resolve. The
# network layer passes /etc/hosts and runs this before the filesystem layer makes /etc read-only.
# Takes the hosts file then the names.
write_broker_hosts() {
  local hosts_file="$1"
  shift
  local name
  local marked=0
  for name in "$@"; do
    grep -qxF "${PHB_BROKER_PLACEHOLDER_IP} ${name}" "$hosts_file" 2>/dev/null && continue
    if (( ! marked )); then
      printf '%s\n' "$PHB_BROKER_HOSTS_MARKER" >> "$hosts_file" || return 1
      marked=1
    fi
    printf '%s %s\n' "$PHB_BROKER_PLACEHOLDER_IP" "$name" >> "$hosts_file" || return 1
  done
  return 0
}

# Prints the frontend allow-list lines for one net.rules file. A host of "*" permits any host. A
# host with a slash, an IPv6 colon or only digits and dots is an address; "*.name" is a name
# suffix; anything else is an exact name. For an exact name the broker resolves the ClientHello's
# host name through the "phobosdns" resolver into a variable, sets the destination to it, and
# refuses when it does not resolve, so the connection can only reach the name's own address; this
# needs the resolvers section build_haproxy_conf emits, which the network layer guarantees by
# refusing an exact-name rule with no resolver. A suffix waits for the ClientHello and is sent to
# the header's destination, the weaker match the name cannot be resolved from. An address rule is
# accepted the moment its destination matches, so a connection with no ClientHello does not wait
# out the inspect-delay. Name matching is case-insensitive, as the preload library's is. Assumes
# it is called where its output belongs, inside the frontend and after set-dst.
haproxy_allow_rules() {
  local rules="$1"
  local host
  local -a names=()
  local -a suffixes=()
  local -a addresses=()
  local any_host=0
  while read -r host _; do
    [[ -z "$host" ]] && continue
    case "$(classify_connect_host "$host")" in
      any) any_host=1 ;;
      address)
        if [[ "$host" == "localhost" ]]; then
          addresses+=("127.0.0.0/8" "::1")
        else
          addresses+=("$host")
        fi
        ;;
      suffix) suffixes+=(".${host#*.}") ;;
      exact) names+=("$host") ;;
    esac
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d')

  if (( any_host )); then
    printf '    tcp-request content accept\n'
    printf '    default_backend to_dst\n'
    return 0
  fi
  if (( ${#names[@]} > 0 )); then
    printf '    acl exact_sni req.ssl_sni -m str -i %s\n' "$(printf '%s\n' "${names[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    printf '    tcp-request content do-resolve(txn.hostip,phobosdns,ipv4) req.ssl_sni if exact_sni\n'
    printf '    tcp-request content set-dst var(txn.hostip) if exact_sni { var(txn.hostip) -m found }\n'
    printf '    tcp-request content reject if exact_sni !{ var(txn.hostip) -m found }\n'
  fi
  if (( ${#suffixes[@]} > 0 )); then
    printf '    acl suffix_sni req.ssl_sni -m end -i %s\n' "$(printf '%s\n' "${suffixes[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
  fi
  if (( ${#addresses[@]} > 0 )); then
    printf '    acl allowed_dst dst -m ip %s\n' "$(printf '%s\n' "${addresses[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    printf '    tcp-request content accept if allowed_dst\n'
  fi
  printf '    tcp-request content accept if { req.ssl_hello_type 1 }\n'
  if (( ${#names[@]} > 0 )); then
    printf '    use_backend to_dst if exact_sni\n'
  fi
  if (( ${#suffixes[@]} > 0 )); then
    printf '    use_backend to_dst if suffix_sni\n'
  fi
  if (( ${#addresses[@]} > 0 )); then
    printf '    use_backend to_dst if allowed_dst\n'
  fi
  printf '    default_backend refuse\n'
}

# Starts the egress broker for a specification directory and prints the "127.0.0.1:port" the
# guard should hand connections to, or fails. It generates the broker's config from the rules,
# binds it to a free loopback port, and records its process id in PHB_SPEC_BROKER_PID under the
# directory, so the layer that ends the run stops it, which the network layer cannot do itself
# because it execs. haproxy runs in the foreground with -db, so it stays a child of the caller
# and in the run's process group, and its own output goes to a scratch log rather than the
# command's stdout, which also keeps the background job from holding a command substitution open.
# The broker is launched with LD_PRELOAD and the libnetblocker configuration stripped: the network
# layer sets those for the graded command, and a child would inherit them, but libnetblocker
# refuses a connect to any address it did not itself resolve from an allowed name, and the broker
# forwards to addresses it never resolved, so under the preload every host-name forward is refused,
# which is the enforcement the broker exists to provide. The broker is trusted infrastructure whose
# every onward connection the guard already vetted by port and the broker itself vets by TLS host
# name, so it is placed outside that in-process filter rather than broken by it. A port that already
# answers is skipped before the broker binds it; because the broker holds the loopback port
# exclusively, a probe that then answers on a live broker is answering the broker. The upstream
# resolver, "ip" or "ip:port", is the nameserver the broker resolves an exact host name through;
# it is empty when no exact-name rule needs one, and the network layer refuses the run before here
# when one is needed and none was given.
# Assumes phobos-common.sh was sourced, so PHB_SPEC_SCRATCH and PHB_SPEC_BROKER_PID are set.
start_egress_broker() {
  local spec_dir="$1"
  local rules="$2"
  local haproxy_bin="$3"
  local resolver="${4:-}"
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
    build_haproxy_conf "$rules" "$cfg" "127.0.0.1:${port}" "$resolver"
    env -u LD_PRELOAD -u NETBLOCKER_CONF -u NETBLOCKER_BIND_CONF "$haproxy_bin" -f "$cfg" -db > "$log" 2>&1 &
    pid=$!
    for _ in $(seq 1 60); do
      kill -0 "$pid" 2>/dev/null || break
      if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        printf '%s\n' "$pid" > "${spec_dir}/${PHB_SPEC_BROKER_PID}"
        printf '127.0.0.1:%s\n' "$port"
        return 0
      fi
      sleep 0.05
    done
    kill "$pid" 2>/dev/null
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
# resolver ("ip" or "ip:port", empty when no exact-name rule needs one). An exact-name rule needs
# the resolvers section; the network layer guarantees a resolver is given whenever one is present.
build_haproxy_conf() {
  local rules="$1"
  local out="$2"
  local listen="$3"
  local resolver="${4:-}"
  {
    if [[ -n "$resolver" ]]; then
      emit_broker_resolvers "$resolver"
    fi
    printf 'defaults\n'
    printf '    mode tcp\n'
    printf '    timeout connect 5s\n'
    printf '    timeout client 30s\n'
    printf '    timeout server 30s\n'
    printf 'frontend broker\n'
    printf '    bind %s accept-proxy\n' "$listen"
    printf '    tcp-request inspect-delay 5s\n'
    printf '    tcp-request content set-dst dst\n'
    printf '    tcp-request content set-dst-port dst_port\n'
    haproxy_allow_rules "$rules"
    printf 'backend to_dst\n'
    printf '    server original 0.0.0.0:0\n'
    printf 'backend refuse\n'
    printf '    tcp-request content reject\n'
  } > "$out"
}
