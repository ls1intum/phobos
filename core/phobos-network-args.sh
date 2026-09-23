#!/usr/bin/env bash
# shellcheck shell=bash
# Turning [connect] and [bind] into the TCP port rules Landlock can enforce.
#
# A component of phobos-common.sh, which sources this file after phobos-constants.sh
# and is what every caller sources. It sets no shell option and sources nothing, so
# that sourcing the aggregate twice keeps doing exactly what it did before the split.

# Refuses a port that is not a number the protocol has: a decimal number of at most five
# digits, with no leading zero, from 1 to the highest port. Assumes the caller has already
# decided this rule names a port at all rather than a wildcard. The shape is checked before
# the value, because the shell's arithmetic is 64 bits wide and wraps without a word: a
# twenty-digit port would otherwise come out as a small number and pass.
refuse_unusable_port() {
  local host="$1"
  local port="$2"
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= PHB_HIGHEST_PORT )) && return 0
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
# second file and the first rule that names none into the third. An external host with no port
# is refused, because it cannot be enforced: Landlock knows ports, not hosts, so leaving the
# layer off for it would confine external egress to the connect guard's port check alone, which
# for a portless rule is nothing. Loopback with no port is the one tolerated case.
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

# Refuses a section that mixes a loopback wildcard with a concrete port: the concrete rule
# would read as enforced by the kernel while the wildcard one would not be. Takes the two
# files collect_network_ports wrote. Assumes it is called plainly, so that a refusal ends
# the run.
refuse_mixed_network_wildcard() {
  local ports_file="$1"
  local wildcard_file="$2"
  [[ -s "$wildcard_file" && -s "$ports_file" ]] || return 0
  report "Policy unenforceable: '$(cat "$wildcard_file")' names no port, so Landlock cannot express it, while other rules do name one. A half-enforced network policy would look stricter than it is. (PHB-EPOLICY)"
  exit "${PHB_EPOLICY}"
}

# Refuses every [connect] and [bind] rule that cannot be enforced as written: a port that is
# not one the protocol has, an external host with no port, and a loopback wildcard beside a
# concrete port. phobos-policy.sh asks this once, where the specification is written, so that
# a rule is judged whether or not the layer that would otherwise have judged it is in the
# chain: with --no-networksystem-restriction the network layer is absent, so nobody builds the
# Landlock port rules, and the spec would otherwise carry a rule that is silently dropped.
# Assumes it is called plainly, so that a refusal ends the run.
refuse_unenforceable_network_rules() {
  local net_rules="$1"
  local bind_rules="$2"
  local ports_file
  local wildcard_file
  local host
  local port
  if [[ -n "$net_rules" && -s "$net_rules" ]]; then
    ports_file="$(new_scratch_file phobos-check-ports.XXXXXX)"
    wildcard_file="$(new_scratch_file phobos-check-wildcard.XXXXXX)"
    collect_network_ports "$net_rules" "$ports_file" "$wildcard_file"
    refuse_mixed_network_wildcard "$ports_file" "$wildcard_file"
    rm -f "$ports_file" "$wildcard_file"
  fi
  if [[ -n "$bind_rules" && -s "$bind_rules" ]]; then
    while read -r host port; do
      [[ -z "$host" ]] && continue
      refuse_unusable_port "$host" "$port"
    done < "$bind_rules"
  fi
}

# Refuses every [accept] rule that cannot be enforced against the merged policy: a public port
# below 1024 (unbindable without a capability the run does not have), a public port the graded
# code may itself bind (it could take the port before the inbound HAProxy and receive unfiltered
# connections), a backend port the code may NOT bind (the filter would forward to a listener that
# never comes up), and two rules fronting the same public port with different backends. A public
# port with no source is left alone but warned about, since the filter then rejects every peer.
# bind_rules holds "* port" lines; accept_rules holds "H P [src]" lines. Ports are read base
# ten so a leading zero is not taken as octal. Assumes it is called plainly, so a refusal ends the
# run.
refuse_unenforceable_accept_rules() {
  local accept_rules="$1"
  local bind_rules="$2"
  [[ -n "$accept_rules" && -s "$accept_rules" ]] || return 0
  local -A bound_ports=()
  local host
  local port
  if [[ -n "$bind_rules" && -s "$bind_rules" ]]; then
    while read -r host port; do
      [[ -z "$port" ]] && continue
      bound_ports[$((10#$port))]=1
    done < "$bind_rules"
  fi
  local -A backend_of=()
  local -A has_source=()
  local h
  local p
  local src
  while read -r h p src; do
    [[ -z "$h" ]] && continue
    h=$((10#$h))
    p=$((10#$p))
    if (( h < 1024 )); then
      report "Policy invalid: [accept] public port ${h} is below 1024 and cannot be bound without a capability the run does not have. Use a port at or above 1024. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    if [[ -n "${bound_ports[$h]:-}" ]]; then
      report "Policy invalid: [accept] public port ${h} is also a [bind] port, so the graded code could take it before the inbound filter. Front a port the code may not bind. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    if [[ -z "${bound_ports[$p]:-}" ]]; then
      report "Policy invalid: [accept] backend port ${p} is not a [bind] port, so nothing would listen behind the inbound filter. Name it in [bind]. (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    if [[ -n "${backend_of[$h]:-}" && "${backend_of[$h]}" != "$p" ]]; then
      report "Policy invalid: [accept] fronts public port ${h} with two different backend ports (${backend_of[$h]} and ${p}). (PHB-EPOLICY)"
      exit "${PHB_EPOLICY}"
    fi
    backend_of[$h]="$p"
    [[ -n "$src" ]] && has_source[$h]=1
  done < "$accept_rules"
  for h in "${!backend_of[@]}"; do
    [[ -z "${has_source[$h]:-}" ]] && _log "WARNING: [accept] public port ${h} names no source, so the inbound filter rejects every peer and the service is unreachable."
  done
  return 0
}

# Fills the named array with the TCP port rules Landlock can actually enforce.
#
# The policy language names a host and a port, Landlock knows only ports. A rule naming no
# port therefore cannot be expressed. Only a LOOPBACK host may name no port: a section made
# only of those leaves the network layer off and says so, which is what the shipped policies
# do, and the no-network container is that rule's boundary. Only an explicit star or an
# omitted port is that wildcard; "host:0" names no port that exists and is a policy mistake,
# not a licence to switch the layer off. Every refusal this can reach has already been made
# by refuse_unenforceable_network_rules where the policy was built; it is repeated here so
# that a layer run standalone over a specification is judged too.
build_network_args() {
  local arguments_name="$1"
  local rules="$2"
  local -n network_ref="$arguments_name"
  local ports_file
  local wildcard_file
  local port
  [[ -n "$rules" && -s "$rules" ]] || return 0
  ports_file="$(new_scratch_file phobos-ports.XXXXXX)"
  wildcard_file="$(new_scratch_file phobos-wildcard.XXXXXX)"
  collect_network_ports "$rules" "$ports_file" "$wildcard_file"
  refuse_mixed_network_wildcard "$ports_file" "$wildcard_file"
  if [[ -s "$wildcard_file" ]]; then
    _log "network: '$(cat "$wildcard_file")' names no port; the Landlock network layer stays off, and the connect guard filters this run"
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
# The [bind] section names local TCP ports a submission may listen on. Each rule is "* port";
# Landlock enforces the port, so several rules that share a port collapse to one --bind-tcp.
# Landlock's bind right is per-port and knows no local address, so the parser refuses a [bind]
# rule that names an address and this emits one --bind-tcp per port. The host field is always "*"
# and is ignored here. A port outside 1..65535 is a policy mistake and ends the run.
build_bind_args() {
  local arguments_name="$1"
  local rules="$2"
  local -n bind_ref="$arguments_name"
  local host
  local port
  local ports_file
  local emitted
  [[ -n "$rules" && -s "$rules" ]] || return 0
  ports_file="$(new_scratch_file phobos-bindports.XXXXXX)"
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
