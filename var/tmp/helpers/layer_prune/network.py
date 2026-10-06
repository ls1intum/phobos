"""[connect] and [bind] rules from the network refusals of an observed run (A.6.5, "Network").

A record holds addresses, never names, so an external destination is never granted from one: it is
returned as refused, and the stage aborts with "needs external network". The only external rules a
prune writes are the hosts an exercise declares in prune.json (decision 11), seeded by seed_rules and
kept only when the minimisation finds them needed.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re

from layer_prune import attribute, strace_parse
from layer_prune.record import LAYER_NETWORK, Denial

# One declared host in prune.json: a DNS name, a port, and an optional transport marker.
DECLARED_HOST = re.compile(
    r"^(?P<name>(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])"
    r":(?P<port>[1-9][0-9]{0,4})(?: (?P<transport>tcp|udp))?$"
)
# The highest port number.
PORT_MAXIMUM = 65535
# The calls whose success names a local port the run holds.
BINDING_CALLS = frozenset({"bind", "getsockname"})


@dataclasses.dataclass(frozen=True)
class NetworkDecision:
    """What one observed run's network refusals ask for.

    `connect` and `bind` are rules to add; `refused_external` the external destinations, as
    "<address>:<port> <transport>", that no rule may grant; `reported` the refusals left ungranted for
    another reason, each with that reason.
    """

    connect: tuple[str, ...]
    bind: tuple[str, ...]
    refused_external: tuple[str, ...]
    reported: tuple[str, ...]


def family_of(address: str) -> str:
    """AF_INET6 for an address with a colon, AF_INET otherwise, as strace's socket addresses spell them."""
    return "AF_INET6" if ":" in address else "AF_INET"


def is_loopback(address: str) -> bool:
    """Whether an address is loopback: 127.0.0.0/8, ::1, or an IPv4-mapped loopback address."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(parsed, "ipv4_mapped", None)
    return parsed.is_loopback or (mapped is not None and mapped.is_loopback)


def transport_marker(transport: str | None) -> str:
    """The suffix a rule carries for its transport: " udp", or nothing for tcp, the default."""
    return " udp" if transport == "udp" else ""


def loopback_wildcard(families: frozenset[str], transport: str | None) -> str:
    """The rule that opens every loopback port of the given families for one transport (A.6.5)."""
    if families >= {"AF_INET", "AF_INET6"}:
        return "allow localhost" + transport_marker(transport)
    if families == {"AF_INET6"}:
        return "allow [::1]" + transport_marker(transport)
    return "allow 127.0.0.1:*" + transport_marker(transport)


def exact_loopback(address: str, port: int, transport: str | None) -> str:
    """The rule naming one loopback destination exactly, an IPv6 address in brackets."""
    host = f"[{address}]" if ":" in address else address
    return f"allow {host}:{port}" + transport_marker(transport)


def bound_ports(trace: strace_parse.Trace) -> frozenset[tuple[str, int, str]]:
    """Every (family, port, transport) a process of the run held, from successful bind and getsockname.

    Only calls inside the command's domain count. A bind to port 0 names no port; the getsockname
    that follows it reports the port the kernel chose.
    """
    state = attribute.RunState(trace, "/")
    held: set[tuple[str, int, str]] = set()
    for index, call in enumerate(trace.syscalls):
        if call.errno is not None:
            continue
        state.follow(call)
        if call.name not in BINDING_CALLS or call.result != 0 or not trace.in_domain(index):
            continue
        family, _, port = attribute.parse_address(strace_parse.argument(call, 1) or "")
        transport = state.transport(call)
        if family in attribute.INET_FAMILIES and port and transport is not None:
            held.add((family, port, transport))
    return frozenset(held)


def decide_connect(denial: Denial, bound: frozenset[tuple[str, int, str]],
                   wildcards: set[tuple[str, str]], exact: set[tuple[str, str, str]], refused: list[str],
                   reported: list[str]) -> None:
    """Sorts one refused connect or datagram into the collections network_rules builds its decision from.

    `wildcards` collects (family, transport) pairs that need every loopback port, `exact` the
    (family, transport, rule) of each loopback destination granted exactly.
    """
    if denial.address is None or denial.port is None:
        return
    transport = denial.transport or "tcp"
    destination = f"{denial.address}:{denial.port} {transport}"
    if not is_loopback(denial.address):
        refused.append(destination)
        return
    family = family_of(denial.address)
    if (family, denial.port, transport) in bound:
        wildcards.add((family, transport))
        return
    exact.add((family, transport, exact_loopback(denial.address, denial.port, transport)))
    reported.append(f"loopback {destination}: no process of the run bound that port; granted exactly")


def decide_bind(denial: Denial, binds: set[str], reported: list[str]) -> None:
    """Sorts one refused bind or listen into the bind rules or the reported refusals."""
    if denial.port == 0:
        binds.add("allow 0" + transport_marker(denial.transport))
    elif denial.port is not None and denial.address is not None and is_loopback(denial.address):
        binds.add(f"allow {denial.port}" + transport_marker(denial.transport))
    else:
        reported.append(f"bind of port {denial.port} on {denial.address}: not a loopback service; not granted")


def network_rules(denials: list[Denial], bound: frozenset[tuple[str, int, str]],
                  declared_hosts: tuple[str, ...]) -> NetworkDecision:
    """The rules one run's network refusals ask for, by A.6.5.

    A refused loopback destination on a port the run bound itself becomes that family's loopback
    wildcard (both families: localhost); one on a port nobody bound is granted exactly and reported,
    unless a wildcard of its family and transport already covers it. A refused bind of port 0, or a
    listen on an unbound socket, becomes `allow 0`; an explicit port only for a loopback address. An
    external destination is never granted, whatever the declared hosts: a declared host is a name,
    a record holds addresses, and the guard holds a name rule to its port, so a destination it
    refused is one no declared rule names. `declared_hosts` is named in the report when it is.
    """
    wildcards: set[tuple[str, str]] = set()
    exact: set[tuple[str, str, str]] = set()
    binds: set[str] = set()
    refused: list[str] = []
    reported: list[str] = []
    for denial in denials:
        if denial.layer != LAYER_NETWORK:
            continue
        if attribute.SECTION_BIND in denial.sections:
            decide_bind(denial, binds, reported)
        else:
            decide_connect(denial, bound, wildcards, exact, refused, reported)
    transports = {transport for _, transport in wildcards}
    connect = {loopback_wildcard(frozenset(family for family, kind in wildcards if kind == transport), transport)
               for transport in transports}
    connect.update(rule for family, transport, rule in exact if (family, transport) not in wildcards)
    if refused and declared_hosts:
        reported.append("declared hosts are names and match no refused address: " + ", ".join(declared_hosts))
    return NetworkDecision(connect=tuple(sorted(connect)), bind=tuple(sorted(binds)),
                           refused_external=tuple(sorted(set(refused))), reported=tuple(reported))


def seed_rules(declared_hosts: tuple[str, ...]) -> tuple[str, ...]:
    """One `allow <name>:<port>` rule per host prune.json declares, with ` udp` where declared (decision 11).

    Raises ValueError for an entry that is not a lower-case DNS name, a port from 1 to 65535 and an
    optional tcp or udp marker, so nothing but a well-formed name ever reaches a rule.
    """
    rules: list[str] = []
    for entry in declared_hosts:
        match = DECLARED_HOST.match(entry)
        if match is None or int(match.group("port")) > PORT_MAXIMUM:
            raise ValueError(f"declared host {entry!r} is not <name>:<port> with an optional tcp or udp")
        rules.append(f"allow {match.group('name')}:{match.group('port')}" + transport_marker(match.group("transport")))
    return tuple(rules)
