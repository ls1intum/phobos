#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=phobos-tools-common/phobos-common.sh
source "${HERE}/phobos-tools-common/phobos-common.sh"
# shellcheck source=phobos-tools-networksystem/phobos-haproxy.sh
source "${HERE}/phobos-tools-networksystem/phobos-haproxy.sh"

# A generic layer: it does its work and execs the rest of the chain. phobos.sh includes this
# layer only when the network filter is enabled, so there is no enable flag to read. Run on its
# own with one or more --config files instead of a specification directory, it builds its own
# specification through phobos-policysystem.sh and enforces only the network.

# Prints the whole manual on the file descriptor named by $1, which is stdout when the
# manual was asked for and stderr when the call is refused because it was wrong.
help_text() {
  cat >&"$1" <<PHOBOS_HELP
phobos-networksystem.sh - the network layer: supervise what the command may connect to.

It enforces the whole network boundary and then hands the rest of the chain on. That
boundary has three parts: the connect guard, which supervises every connect() from outside
the process; the Landlock port rules, on a network-only ruleset of its own; and, when a
[connect] rule names a host, an egress broker that checks the TLS host name the guard cannot
see. An [accept] rule additionally fronts a listener with an inbound filter.

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
                              through, the default DNS port being used when none is given.
                              An exact-name rule without a resolver is refused rather than
                              run without host-name enforcement.
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
# and removed by this outer shell, because the specification-directory run execs the guard and so
# leaves no waiter of its own to remove it.
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
LANDLOCK_BIN="${LANDLOCK_BIN_OPT:-${HERE}/phobos-landlock-filesystem-and-networksystem}"
command_tail=( "$@" )
port_args=()
build_network_args port_args "$RULES"
build_bind_args port_args "${SPEC_DIR}/bind.rules"
# When the policy handles both UDP directions, the kernel gates an outgoing datagram's ephemeral
# source-port auto-bind by BIND_UDP, so a "--bind-udp 0" is added or an allowed send is denied its
# source. Added here, after both builders, because it depends on connect and bind rules together.
add_udp_ephemeral_bind_if_needed port_args
if (( ${#port_args[@]} > 0 )); then
  # Refused when missing rather than left to fail obscurely inside the guard's child, so a run
  # that names a TCP port cannot lose its kernel-enforced port rules without a clear message.
  if [[ ! -f "$LANDLOCK_BIN" || ! -x "$LANDLOCK_BIN" ]]; then
    report "The Landlock binary '${LANDLOCK_BIN}' is missing or not executable; refusing to run without the TCP-port rules the [connect]/[bind] policy names. (PHB-ERUNTIME)"
    exit "${PHB_ERUNTIME}"
  fi
  landlock_prefix=( "$LANDLOCK_BIN" --no-filesystem )
  if (( PHB_DEBUG_ENABLED )); then landlock_prefix+=( --verbose ); fi
  command_tail=( "${landlock_prefix[@]}" "${port_args[@]}" -- "${command_tail[@]}" )
fi

debug_log network "run" "${guard_command[@]}" "${command_tail[@]}"
exec "${guard_command[@]}" "${command_tail[@]}"
