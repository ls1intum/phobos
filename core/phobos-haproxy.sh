#!/usr/bin/env bash
# shellcheck shell=bash
# phobos-haproxy.sh -- turn the [connect] allow-list into an haproxy.cfg the egress broker enforces.
#
# Not yet sourced by any runtime script; only the tests source it. The next slice wires it into
# the network layer, which will start the broker from a generated config. It sets no shell option
# and sources nothing, so sourcing it more than once keeps doing what it did before.
#
# The connect guard hands every allowed stream connection to this broker on loopback, with a
# PROXY protocol version 2 header naming the destination the command meant. The broker reads the
# host name from the TLS ClientHello, which the guard cannot see, and enforces the allow-list by
# name; a rule that names an address rather than a host is enforced by the destination the header
# carried. net.rules holds one "host port" per line, as phobos-policy.sh wrote it. The port was
# already enforced by the guard before the redirect, so the broker checks the host alone.

# Prints the frontend allow-list lines for one net.rules file: an acl of the permitted TLS host
# names, an acl of the permitted destination addresses, the accepts that end inspection, and the
# use_backend rules that let either through. A host of "*" permits any host. A host with a slash,
# an IPv6 colon or only digits and dots is an address; "*.name" is a name suffix; anything else is
# an exact name. Name matching is case-insensitive, as the preload library's is. An address rule
# is accepted the moment its destination matches, so a connection with no TLS ClientHello does not
# wait out the inspect-delay; a name rule waits for the ClientHello, because the name is in it.
# Assumes it is called where its output belongs, inside the frontend and after set-dst.
haproxy_allow_rules() {
  local rules="$1"
  local host
  local -a names=()
  local -a suffixes=()
  local -a addresses=()
  local any_host=0
  while read -r host _; do
    [[ -z "$host" ]] && continue
    if [[ "$host" == "*" ]]; then
      any_host=1
    elif [[ "$host" == *"/"* || "$host" == *:* || "$host" =~ ^[0-9.]+$ ]]; then
      addresses+=("$host")
    elif [[ "$host" == "*."* ]]; then
      suffixes+=(".${host#*.}")
    else
      names+=("$host")
    fi
  done < <(sed -E 's/#.*$//' "$rules" 2>/dev/null | sed '/^[[:space:]]*$/d')

  if (( any_host )); then
    printf '    tcp-request content accept\n'
    printf '    default_backend to_dst\n'
    return 0
  fi
  if (( ${#names[@]} > 0 )); then
    printf '    acl allowed_sni req.ssl_sni -m str -i %s\n' "$(printf '%s\n' "${names[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
  fi
  if (( ${#suffixes[@]} > 0 )); then
    printf '    acl allowed_sni req.ssl_sni -m end -i %s\n' "$(printf '%s\n' "${suffixes[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
  fi
  if (( ${#addresses[@]} > 0 )); then
    printf '    acl allowed_dst dst -m ip %s\n' "$(printf '%s\n' "${addresses[@]}" | sort -u | tr '\n' ' ' | sed 's/ $//')"
    printf '    tcp-request content accept if allowed_dst\n'
  fi
  printf '    tcp-request content accept if { req.ssl_hello_type 1 }\n'
  if (( ${#names[@]} > 0 || ${#suffixes[@]} > 0 )); then
    printf '    use_backend to_dst if allowed_sni\n'
  fi
  if (( ${#addresses[@]} > 0 )); then
    printf '    use_backend to_dst if allowed_dst\n'
  fi
  printf '    default_backend refuse\n'
}

# Writes a complete haproxy.cfg for the egress broker: the fixed preamble that keeps it a
# loopback TCP proxy reading the PROXY header and the ClientHello, the allow-list rules
# haproxy_allow_rules builds, and the two backends, one that connects to the destination the
# header named and one that refuses. Takes the net.rules file, the output path, and the
# "address:port" the broker listens on.
build_haproxy_conf() {
  local rules="$1"
  local out="$2"
  local listen="$3"
  {
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
