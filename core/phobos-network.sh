#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-common.sh
source "${HERE}/phobos-common.sh"
# shellcheck source=phobos-haproxy.sh
source "${HERE}/phobos-haproxy.sh"

# A generic layer: it does its work and execs the rest of the chain. phobos.sh includes this
# layer only when the network filter is enabled, so there is no enable flag to read.
GUARD_BIN_OPT=""
HAPROXY_BIN_OPT=""
RESOLVER_OPT=""
LANDLOCK_BIN_OPT=""
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --debug) enable_debug_log; shift ;;
    --connect-guard-bin) shift; GUARD_BIN_OPT="${1:-}"; shift ;;
    --haproxy-bin) shift; HAPROXY_BIN_OPT="${1:-}"; shift ;;
    --resolver) shift; RESOLVER_OPT="${1:-}"; shift ;;
    --landlock-bin) shift; LANDLOCK_BIN_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done
[[ $# -ge 3 && "$2" == "--" ]] || { echo "Usage: phobos-network.sh [--debug] [--connect-guard-bin <path>] [--haproxy-bin <path>] [--resolver <ip[:port]>] [--landlock-bin <path>] <SPEC_DIR> -- <cmd...>" >&2; exit "${PHB_EXIT_USAGE}"; }
SPEC_DIR="$1"; shift 2

# Removes the specification phobos.sh created if this layer ends before it hands over,
# for instance because a required piece cannot be started.
trap 'finish_owned_spec_dir "$?" "$SPEC_DIR"' EXIT

RULES="${SPEC_DIR}/net.rules"
# The guard reads this by path; ensure it exists whether or not the policy named any [connect] rule.
[[ -f "$RULES" ]] || : > "$RULES"

# The connect guard enforces a [connect] rule by address and port alone. A rule that names a host
# (an exact name or a "*.name" suffix) constrains nothing about the onward address unless the egress
# broker checks the TLS host name. So the broker is started automatically whenever the allow-list
# names a host, rather than requiring a flag the run could forget and then widen the rule to any
# address on the port. In the default --network none grading container the broker's onward
# connection fails at run time rather than being refused up front, so say loudly that this run now
# assumes a networked container, as the [accept] path does.
want_broker=0
mapfile -t name_rules < <(name_connect_rules "$RULES")
if (( ${#name_rules[@]} > 0 )); then want_broker=1; fi

# The connect guard supervises every connect the command makes and enforces the [connect]
# allow-list by host and port from a place a raw syscall cannot step around. It forks a
# supervisor and execs the rest of the chain, so it goes on the front of what this layer hands
# over. It is refused when missing rather than skipped, so a run cannot lose connect
# supervision unnoticed. When the egress broker is on, the guard is told to hand every allowed
# connection to it, so the broker can enforce by the TLS host name the guard cannot see.
GUARD_BIN="${GUARD_BIN_OPT:-${HERE}/phobos-connect-guard}"
if [[ ! -x "$GUARD_BIN" ]]; then
  report "The connect guard '${GUARD_BIN}' is missing or not executable; refusing to run without connect supervision. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
fi
guard_command=( "$GUARD_BIN" )
if (( PHB_DEBUG_ENABLED )); then guard_command+=( --verbose ); fi
if (( want_broker )); then
  # An exact [connect] name is bound to its own address by the broker, which resolves it through
  # the given resolver, and is mapped to a placeholder in /etc/hosts so the command can resolve it
  # without a DNS query the guard would refuse. Both are refused-closed when they cannot be met, so
  # a run never silently loses the host-name enforcement it asked for.
  mapfile -t exact_names < <(exact_connect_names "$RULES")
  if (( ${#exact_names[@]} > 0 )); then
    if [[ -z "$RESOLVER_OPT" ]]; then
      report "The [connect] allow-list names an exact host, which the egress broker binds by resolving it, but no resolver was given; pass --resolver <ip[:port]>. Refusing rather than run without host-name enforcement. (PHB-ERUNTIME)"
      exit "${PHB_ERUNTIME}"
    fi
    if ! write_broker_hosts /etc/hosts "${exact_names[@]}"; then
      report "Could not write /etc/hosts to map the exact [connect] names for the egress broker; refusing rather than run with names the command cannot resolve. (PHB-ERUNTIME)"
      exit "${PHB_ERUNTIME}"
    fi
  fi
  # Said immediately before the broker starts, matching the [accept] path, so a run refused
  # earlier (missing guard, an exact name without a resolver) does not log a broker that never
  # started. In the default --network none grading container the broker's onward connection fails
  # at run time rather than being refused up front, so say loudly that this run assumes a network.
  _log "NOTICE: the [connect] allow-list names a host (${name_rules[*]}), so the egress broker is started to enforce it by the TLS host name the connect guard cannot see. This assumes a NETWORKED container; in a --network none container the onward connection cannot be made."
  broker_endpoint="$(start_egress_broker "$SPEC_DIR" "$RULES" "${HAPROXY_BIN_OPT:-haproxy}" "$RESOLVER_OPT")" || {
    report "The egress broker could not be started; refusing to run rather than lose the host-name enforcement it was asked for. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  }
  guard_command+=( --broker "$broker_endpoint" )
fi

# Any [accept] rule fronts a student's listener with an inbound filter on a public port. This
# only works in a NETWORKED container, so turning it on removes the --network none default the
# rest of the sandbox relies on, and the run is then contained only by the outer network
# isolation the operator provides. Say so loudly, then start the filter, refusing the run if it
# cannot start rather than leave the listener unfiltered. It is a sibling, so it is started here
# and stopped by whichever layer ends the run, like the egress broker.
ACCEPT_RULES="${SPEC_DIR}/accept.rules"
if [[ -s "$ACCEPT_RULES" ]]; then
  _log "NOTICE: an [accept] rule is present, so this run fronts a listener on a public port and assumes a NETWORKED container with the required isolation (only the public port reachable from outside, no other path to the backend port). This removes the --network none default; the outer network isolation, not Phobos, keeps the backend reachable only through the filter."
  if ! start_inbound_haproxy "$SPEC_DIR" "$ACCEPT_RULES" "${HAPROXY_BIN_OPT:-haproxy}"; then
    report "The inbound filter could not be started; refusing to run rather than expose the listener unfiltered. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
fi
guard_command+=( --rules "$RULES" -- )

# The Landlock TCP-port rules are the kernel-enforced half of the network boundary, and this
# layer applies them itself so that the network restriction is whole here rather than split
# across another layer. They go on a network-only Landlock ruleset (--no-filesystem), which
# leaves the filesystem to the filesystem layer's own ruleset and composes with it by
# intersection. The ruleset is applied inside the connect guard's child lineage, after its
# supervisor has forked, so the supervisor that connects on the command's behalf stays
# unrestricted. When the policy names no TCP port, no ruleset is needed here and the guard alone
# filters the run.
LANDLOCK_BIN="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock}"
command_tail=( "$@" )
port_args=()
build_network_args port_args "$RULES"
build_bind_args port_args "${SPEC_DIR}/bind.rules"
if (( ${#port_args[@]} > 0 )); then
  # Refused when missing rather than left to fail obscurely inside the guard's child, so a run
  # that names a TCP port cannot lose its kernel-enforced port rules without a clear message.
  if [[ ! -x "$LANDLOCK_BIN" ]]; then
    report "The Landlock binary '${LANDLOCK_BIN}' is missing or not executable; refusing to run without the TCP-port rules the [connect]/[bind] policy names. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  landlock_prefix=( "$LANDLOCK_BIN" --no-filesystem )
  if (( PHB_DEBUG_ENABLED )); then landlock_prefix+=( --verbose ); fi
  command_tail=( "${landlock_prefix[@]}" "${port_args[@]}" -- "${command_tail[@]}" )
fi

debug_log network "run" "${guard_command[@]}" "${command_tail[@]}"
exec "${guard_command[@]}" "${command_tail[@]}"
