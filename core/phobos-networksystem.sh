#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=phobos-tools-networksystem/phobos-haproxy.sh
source "${HERE}/phobos-tools-networksystem/phobos-haproxy.sh"

# A layer that runs the rest of the chain as a child and waits for it, rather than exec'ing it
# like the others, because it starts HAProxy processes and maps names in /etc/hosts that must not
# outlive the run, and only a process outside the Landlock domain it sets up can stop them.
# phobos.sh includes this layer only when the network filter is enabled, so there is no enable
# flag to read. Run on its own with one or more --config files instead of a specification
# directory, it builds its own specification through phobos-policysystem.sh and enforces only the
# network.

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the call is refused because it was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos-networksystem.sh - the network layer: supervise what the command may connect to.

It enforces the whole network boundary, runs the rest of the chain and waits for it. That
boundary has three parts: the connect guard, which supervises every connect() from outside
the process; the Landlock port rules, on a network-only ruleset of its own; and, when a
[connect] rule names a host, an egress broker that checks the TLS host name the guard cannot
see. An [accept] rule additionally fronts a listener with an inbound filter.

A udp [connect] rule that names a host cannot be held to it at send time, so the layer resolves
the name once before the command starts, through --resolver, holds the rule to the addresses it
had then and shows the command the same addresses in /etc/hosts.

When the command has ended, it stops the egress broker and the inbound filter it started, and
the lines it added to /etc/hosts for an exact [connect] name are removed with the specification
directory, so a run leaves neither behind.

USAGE
  phobos-networksystem.sh [options] <SPEC_DIR> -- <command> [args...]
  phobos-networksystem.sh [options] --config <file> [--config <file>]... -- <command> [args...]
  phobos-networksystem.sh --help

  Two modes. Given a specification directory it enforces what is written there, which is how
  phobos.sh calls it. Given one or more --config files instead it builds a specification of
  its own through phobos-policysystem.sh, enforces only the network and removes that
  specification again. Everything after -- is the command.

OPTIONS
  --connect-guard-bin <path>  The connect guard
                              (default: "${HERE}/phobos-seccomp-networksystem"). It is
                              refused when missing rather than skipped, so a run cannot lose
                              connect supervision unnoticed.
  --landlock-bin <path>       The enforcer that applies the port rules
                              (default: "${HERE}/phobos-landlock-filesystem-and-networksystem").
  --haproxy-bin <path>        The egress broker and the inbound filter (default: haproxy).
  --resolver <ip[:port]>      The resolver the broker resolves an exact [connect] host name
                              through, and the one a udp [connect] host name is resolved
                              through once at the start, the default DNS port being used when
                              none is given. An exact-name rule without a resolver is refused
                              rather than run without host-name enforcement.
  --config <file>, -c <file>  Standalone mode: an exercise configuration to build a
                              specification from. May be given repeatedly.
  --spec-parent <dir>         Standalone mode only: where that specification directory is
                              made (default: /var/tmp).
  --tail-flags-file <file>    Standalone mode only: the tail flags to build it with.
  --debug, -d                 Report on stderr what this layer runs, and have the guard
                              report verbosely too.
  --help, -h                  Print this manual and end with status 0.

WHAT IT READS FROM THE SPECIFICATION DIRECTORY
  net.rules     the [connect] allow-list, by host, port and transport
  bind.rules    the local ports the command may listen on
  accept.rules  the public ports an inbound filter fronts

  An empty net.rules is a policy, not a gap: it denies every outbound connection.

WHEN A CONTAINER MUST HAVE A NETWORK
  Both the egress broker and the inbound filter need one, so a [connect] rule that names a
  host, or any [accept] rule, removes the --network none posture the rest of the sandbox
  relies on. The layer says so loudly before it starts either. In that posture the outer
  network isolation the operator provides, not Phobos, keeps the backend reachable only
  through the filter.

EXIT STATUS
  0 to 255  the command's own status, passed through unchanged
  2         phobos-networksystem.sh was called the wrong way (PHB_EXIT_USAGE)
  11        the policy is invalid (PHB-EPOLICY)
  15        the guard, the broker or the inbound filter could not be started (PHB-ERUNTIME)

EXAMPLES
  phobos-networksystem.sh --config exercise.cfg -- ./gradlew test
        Enforce only the network, building the policy from one configuration.
  phobos-networksystem.sh --resolver 10.0.0.53 --config exercise.cfg -- ./gradlew test
        The same where a [connect] rule names an exact host, which the broker must resolve.
PHOBOS_HELP
}

# Prints the manual on stdout and ends successfully, for an explicit --help.
show_help() {
  help_text 1
  exit 0
}

# Prints the manual on stderr and ends with PHB_EXIT_USAGE, for a call that was wrong.
usage() {
  help_text 2
  exit "${PHB_EXIT_USAGE}"
}

# Ends the layer with the given status: stops the egress broker and the inbound filter this shell
# started, if it started them, then removes the specification directory through
# finish_owned_spec_dir, which also removes the run's /etc/hosts lines. Meant for the EXIT trap, so
# it runs after the command, after a refusal, and after a timeout's TERM the layer outlived. Assumes
# BROKER_PID and INBOUND_PID are empty or name this shell's own HAProxy children, and SPEC_DIR is set.
end_network_layer() {
  local status="$1"
  stop_haproxy_child "$BROKER_PID"
  stop_haproxy_child "$INBOUND_PID"
  finish_owned_spec_dir "$status" "$SPEC_DIR"
}

GUARD_BIN_OPT=""
HAPROXY_BIN_OPT=""
RESOLVER_OPT=""
LANDLOCK_BIN_OPT=""
CONFIGS=()
SPEC_PARENT="/var/tmp"
TAIL_FLAGS_FILE_OPT=""
LAYER_FLAGS=()
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --help|-h) show_help ;;
    --debug|-d) enable_debug_log; LAYER_FLAGS+=( --debug ); shift ;;
    --connect-guard-bin) shift; GUARD_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --connect-guard-bin "${1:-}" ); shift ;;
    --haproxy-bin) shift; HAPROXY_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --haproxy-bin "${1:-}" ); shift ;;
    --resolver) shift; RESOLVER_OPT="${1:-}"; LAYER_FLAGS+=( --resolver "${1:-}" ); shift ;;
    --landlock-bin) shift; LANDLOCK_BIN_OPT="${1:-}"; LAYER_FLAGS+=( --landlock-bin "${1:-}" ); shift ;;
    --config|-c) shift; CONFIGS+=( "${1:-}" ); shift ;;
    --spec-parent) shift; SPEC_PARENT="${1:-}"; shift ;;
    --tail-flags-file) shift; TAIL_FLAGS_FILE_OPT="${1:-}"; shift ;;
    *) break ;;
  esac
done

# Standalone mode: given one or more --config files instead of a specification directory, this
# layer builds a specification of its own through the one parser, phobos-policysystem.sh, then runs
# itself over that directory in specification-directory mode as a child. The directory is owned
# and removed by this outer shell as well, so it is removed even when the inner run is killed
# before its own clean-up runs.
if (( ${#CONFIGS[@]} > 0 )); then
  [[ "${1:-}" == "--" && $# -ge 2 ]] || usage
  shift
  build_owned_spec_from_configs "$HERE" "$SPEC_PARENT" "$TAIL_FLAGS_FILE_OPT" "${CONFIGS[@]}"
  set +e
  bash "${BASH_SOURCE[0]}" "${LAYER_FLAGS[@]}" "$BUILT_SPEC_DIR" -- "$@"
  rc=$?
  set -e
  exit "$rc"
fi

[[ $# -ge 3 && "$2" == "--" ]] || usage
SPEC_DIR="$1"; shift 2

# The HAProxy children this layer starts, stopped by end_network_layer however the layer ends.
BROKER_PID=""
INBOUND_PID=""
trap 'end_network_layer "$?"' EXIT

# A timeout sends TERM to the whole process group, this layer included. Ignoring it lets the
# layer outlive that TERM and still stop its HAProxy children and remove its /etc/hosts lines;
# every process it starts gets TERM back at its default, so the guard's command, and HAProxy, are
# still ended by it. A SIGKILL escalation ends this layer too, together with HAProxy in the same
# group, and the timeout layer's own clean-up, outside the group, then removes the lines.
trap '' TERM

RULES="${SPEC_DIR}/net.rules"
# The guard reads this by path; ensure it exists whether or not the policy named any [connect] rule.
[[ -f "$RULES" ]] || : > "$RULES"

# The connect guard enforces a [connect] rule by address and port alone. A rule that names a host
# (an exact name) constrains nothing about the onward address unless the egress
# broker checks the TLS host name. So the broker is started automatically whenever the allow-list
# names a host, rather than requiring a flag the run could forget and then widen the rule to any
# address on the port. In the default --network none grading container the broker's onward
# connection fails at run time rather than being refused up front, so say loudly that this run now
# assumes a networked container, as the [accept] path does. A wildcard host name is refused first,
# in this shell and over every row, UDP rows included, because a specification handed to this layer
# on its own may never have met the policy parser, and the helpers below skip UDP rows.
refuse_wildcard_connect_names "$RULES"
want_broker=0
mapfile -t name_rules < <(name_connect_rules "$RULES")
if (( ${#name_rules[@]} > 0 )); then want_broker=1; fi

# The connect guard supervises every connect the command makes and enforces the [connect]
# allow-list by host and port from a place a raw syscall cannot step around. It forks a
# supervisor and execs the rest of the chain, so it goes on the front of what this layer hands
# over. It is refused when missing rather than skipped, so a run cannot lose connect
# supervision unnoticed. When the egress broker is on, the guard is told to hand every allowed
# connection to it, so the broker can enforce by the TLS host name the guard cannot see.
#
# A regular file is required, not merely a name the shell calls executable: this program's C
# sources live in a directory of the same name beside the script, and a directory satisfies -x,
# so a bare checkout would otherwise pass this check and then fail obscurely on the exec.
GUARD_BIN="${GUARD_BIN_OPT:-${HERE}/phobos-seccomp-networksystem}"
if [[ ! -f "$GUARD_BIN" || ! -x "$GUARD_BIN" ]]; then
  report "The connect guard '${GUARD_BIN}' is missing or not executable; refusing to run without connect supervision. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
fi
guard_command=( "$GUARD_BIN" )
if (( PHB_DEBUG_ENABLED )); then guard_command+=( --verbose ); fi

# A udp rule that names a host cannot be held to it at send time, because a datagram carries no TLS
# host name for the egress broker to read. The name is therefore resolved once, now, before the
# command runs, by the guard in its resolve mode and through the resolver given, never through
# /etc/resolv.conf. The guard is handed a rule for each address, and the command is shown the same
# addresses in /etc/hosts, so the two cannot disagree about where the name leads. The answer is a
# snapshot for the run: an address the name gains afterwards is not followed. Every step is refused
# when it cannot be met, so a run never keeps a name rule it could not tie to an address: a name
# that does not resolve, more rules than the guard keeps, and an /etc/hosts line that maps the name
# somewhere the lookup did not.
GUARD_RULES="$RULES"
mapfile -t udp_names < <(udp_connect_names "$RULES")
if (( ${#udp_names[@]} > 0 )); then
  if [[ -z "$RESOLVER_OPT" ]]; then
    report "A udp [connect] rule names a host (${udp_names[*]}), which is resolved once before the command starts, but no resolver was given; pass --resolver <ip[:port]>. Refusing rather than run with a name rule that holds to nothing. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  _log "NOTICE: a udp [connect] rule names a host (${udp_names[*]}), so it is resolved once now through ${RESOLVER_OPT} and the rule is held to the addresses it has now. This assumes a NETWORKED container; in a --network none container the lookup cannot be made."
  resolve_flags=()
  if (( PHB_DEBUG_ENABLED )); then resolve_flags+=( --verbose ); fi
  if ! udp_resolved="$("$GUARD_BIN" "${resolve_flags[@]}" --resolve --resolver "$RESOLVER_OPT" -- "${udp_names[@]}")"; then
    report "A udp [connect] host name could not be resolved through ${RESOLVER_OPT}; refusing rather than run with a name rule that holds to nothing. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  GUARD_RULES="${SPEC_DIR}/${PHB_SPEC_GUARD_RULES}"
  udp_resolved_file="$(new_scratch_file phobos-udp-resolved.XXXXXX)"
  printf '%s\n' "$udp_resolved" > "$udp_resolved_file"
  expand_udp_name_rules "$RULES" "$udp_resolved_file" "$GUARD_RULES"
  rm -f "$udp_resolved_file"
  guard_rule_count="$(grep -c . "$GUARD_RULES" || true)"
  if (( guard_rule_count > PHB_GUARD_RULES_MAXIMUM )); then
    report "Resolving the udp [connect] host names gives ${guard_rule_count} rules, and the connect guard keeps ${PHB_GUARD_RULES_MAXIMUM}; the rest would be dropped without a word. Name fewer hosts or ports. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  if ! write_resolved_hosts /etc/hosts "$SPEC_DIR" "$udp_resolved"; then
    report "Could not write /etc/hosts to map the udp [connect] names to the addresses they resolved to; refusing rather than run with names the command cannot resolve. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
fi
if (( want_broker )); then
  # An exact [connect] name is bound to its own address by the broker, which resolves it through
  # the given resolver, and is mapped to a placeholder in /etc/hosts so the command can resolve it
  # without a DNS query the guard would refuse. Both are refused-closed when they cannot be met, so
  # a run never silently loses the host-name enforcement it asked for.
  mapfile -t exact_names < <(exact_connect_names "$RULES")
  # A name a udp rule holds is mapped to its real addresses above, and a placeholder for the same
  # name would make a datagram sent to it go nowhere, so it gets no placeholder. A TCP connection
  # to a real address is bound by the name as well, since the broker resolves it itself. Names are
  # compared without regard to case, as a hosts lookup does.
  declare -A udp_held=()
  for name in "${udp_names[@]}"; do udp_held["${name,,}"]=1; done
  tcp_only_names=()
  for name in "${exact_names[@]}"; do
    [[ -n "${udp_held[${name,,}]:-}" ]] || tcp_only_names+=( "$name" )
  done
  exact_names=( "${tcp_only_names[@]}" )
  if (( ${#exact_names[@]} > 0 )); then
    if [[ -z "$RESOLVER_OPT" ]]; then
      report "The [connect] allow-list names an exact host, which the egress broker binds by resolving it, but no resolver was given; pass --resolver <ip[:port]>. Refusing rather than run without host-name enforcement. (PHB-ERUNTIME)"
      exit "${PHB_ERUNTIME}"
    fi
    if ! write_broker_hosts /etc/hosts "$SPEC_DIR" "${exact_names[@]}"; then
      report "Could not write /etc/hosts to map the exact [connect] names for the egress broker; refusing rather than run with names the command cannot resolve. (PHB-ERUNTIME)"
      exit "${PHB_ERUNTIME}"
    fi
  fi
  # Said immediately before the broker starts, matching the [accept] path, so a run refused
  # earlier (missing guard, an exact name without a resolver) does not log a broker that never
  # started. In the default --network none grading container the broker's onward connection fails
  # at run time rather than being refused up front, so say loudly that this run assumes a network.
  _log "NOTICE: the [connect] allow-list names a host (${name_rules[*]}), so the egress broker is started to enforce it by the TLS host name the connect guard cannot see. This assumes a NETWORKED container; in a --network none container the onward connection cannot be made."
  broker_endpoint=""
  if ! start_egress_broker "$SPEC_DIR" "$RULES" "${HAPROXY_BIN_OPT:-haproxy}" "$RESOLVER_OPT" broker_endpoint BROKER_PID; then
    report "The egress broker could not be started; refusing to run rather than lose the host-name enforcement it was asked for. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  guard_command+=( --broker "$broker_endpoint" )
fi

# Any [accept] rule fronts a student's listener with an inbound filter on a public port. This
# only works in a NETWORKED container, so turning it on removes the --network none default the
# rest of the sandbox relies on, and the run is then contained only by the outer network
# isolation the operator provides. Say so loudly, then start the filter, refusing the run if it
# cannot start rather than leave the listener unfiltered. It is a sibling of the command, so it is
# started here and stopped by end_network_layer, like the egress broker.
ACCEPT_RULES="${SPEC_DIR}/accept.rules"
if [[ -s "$ACCEPT_RULES" ]]; then
  _log "NOTICE: an [accept] rule is present, so this run fronts a listener on a public port and assumes a NETWORKED container with the required isolation (only the public port reachable from outside, no other path to the backend port). This removes the --network none default; the outer network isolation, not Phobos, keeps the backend reachable only through the filter."
  if ! start_inbound_haproxy "$SPEC_DIR" "$ACCEPT_RULES" "${HAPROXY_BIN_OPT:-haproxy}" INBOUND_PID; then
    report "The inbound filter could not be started; refusing to run rather than expose the listener unfiltered. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
fi
if bind_rules_grant_ephemeral_tcp "${SPEC_DIR}/bind.rules"; then
  guard_command+=( --allow-ephemeral-listen )
fi
if ephemeral_udp_bind_granted "${SPEC_DIR}/bind.rules" "$RULES"; then
  guard_command+=( --allow-ephemeral-udp-bind )
fi
guard_command+=( --rules "$GUARD_RULES" -- )

# The Landlock port rules are the kernel-enforced half of the network boundary, and this
# layer applies them itself so that the network restriction is whole here rather than split
# across another layer. They go on a network-only Landlock ruleset (--no-filesystem), which
# leaves the filesystem to the filesystem layer's own ruleset and composes with it by
# intersection. The ruleset is applied inside the connect guard's child lineage, after its
# supervisor has forked, so the supervisor that connects on the command's behalf stays
# unrestricted.
#
# Bind is closed by default: --close-bind hands the kernel the bind directions with nothing
# granted, so only a [bind] row opens a port, and a row for port 0 opens only the kernel's own
# choice of port. The ruleset is therefore applied on every run, also when the policy names no
# port at all and in a run given no --config, where it is what keeps a bare run from listening.
LANDLOCK_BIN="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock-filesystem-and-networksystem}"
command_tail=( "$@" )
port_args=( --close-bind )
build_network_args port_args "$RULES"
build_bind_args port_args "${SPEC_DIR}/bind.rules"
# An allowed datagram send needs a source port, which the kernel auto-binds and BIND_UDP now
# gates, so a UDP [connect] rule brings the ephemeral grant with it. Added after both builders
# because it reads the connect rules, not the arguments they made.
add_udp_ephemeral_bind_if_needed port_args "$RULES"
# Refused when missing rather than left to fail obscurely inside the guard's child, so a run
# cannot lose the kernel-enforced port rules and the closed bind without a clear message.
if [[ ! -f "$LANDLOCK_BIN" || ! -x "$LANDLOCK_BIN" ]]; then
  report "The Landlock binary '${LANDLOCK_BIN}' is missing or not executable; refusing to run without the port rules and the closed bind. (PHB-ERUNTIME)"
  exit "${PHB_ERUNTIME}"
fi
landlock_prefix=( "$LANDLOCK_BIN" --no-filesystem )
if (( PHB_DEBUG_ENABLED )); then landlock_prefix+=( --verbose ); fi
# The operator's --minimum-landlock-version lives in the tail flags, which only the filesystem
# layer reads, so it is read here too, or a kernel too old to close bind could not be refused.
minimum_landlock_version="$(tail_minimum_landlock_version "${SPEC_DIR}/tail.flags")"
if [[ -n "$minimum_landlock_version" ]]; then
  landlock_prefix+=( --minimum-landlock-version "$minimum_landlock_version" )
fi
command_tail=( "${landlock_prefix[@]}" "${port_args[@]}" -- "${command_tail[@]}" )

# The guard runs as a child rather than replacing this shell, so the EXIT trap is still here to
# clean up once it ends; its status, the command's own, is passed through unchanged.
debug_log network "run" "${guard_command[@]}" "${command_tail[@]}"
set +e
( trap - TERM; exec "${guard_command[@]}" "${command_tail[@]}" )
rc=$?
set -e
exit "$rc"
