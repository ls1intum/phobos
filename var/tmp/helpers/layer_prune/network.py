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
    r"(?P<name>(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9])"
    r":(?P<port>[1-9][0-9]{0,4})(?: (?P<transport>tcp|udp))?"
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


def loopback_kind(address: str) -> str | None:
    """"inet" for a 127.0.0.0/8 address, "inet6" for ::1, "mapped" for an IPv4-mapped loopback, None otherwise."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    mapped = getattr(parsed, "ipv4_mapped", None)
    if mapped is not None:
        return "mapped" if mapped.is_loopback else None
    if not parsed.is_loopback:
        return None
    return "inet6" if parsed.version == 6 else "inet"


def is_loopback(address: str) -> bool:
    """Whether an address is loopback in any spelling: 127.0.0.0/8, ::1, or an IPv4-mapped loopback address."""
    return loopback_kind(address) is not None


def transport_marker(transport: str | None) -> str:
    """The suffix a rule carries for its transport: " udp", or nothing for tcp, the default."""
    return " udp" if transport == "udp" else ""


def address_wildcard(address: str, transport: str) -> str:
    """The rule that opens every port of one loopback address for one transport, as the guard holds it."""
    if ":" in address:
        return f"allow [{address}]" + transport_marker(transport)
    return f"allow {address}:*" + transport_marker(transport)


def exact_loopback(address: str, port: int, transport: str | None) -> str:
    """The rule naming one loopback destination exactly, an IPv6 address in brackets."""
    host = f"[{address}]" if ":" in address else address
    return f"allow {host}:{port}" + transport_marker(transport)


def bound_ports(trace: strace_parse.Trace) -> frozenset[tuple[str, int, str]]:
    """Every (family, port, transport) a server of the run held, from successful bind, listen and getsockname.

    Only calls inside the command's domain count, and getsockname only on a socket the run bound or
    listened on, since a client socket's port is an ephemeral one that says nothing about a server.
    A bind to port 0 names no port; the getsockname that follows it reports the port the kernel chose.
    """
    state = attribute.RunState(trace, "/")
    servers: set[tuple[int, str]] = set()
    held: set[tuple[str, int, str]] = set()
    for index, call in enumerate(trace.syscalls):
        if call.errno is not None:
            continue
        state.follow(call)
        if call.result != 0 or not trace.in_domain(index):
            continue
        socket_key = (state.group(call.pid), (strace_parse.argument(call, 0) or "").split("<", 1)[0])
        if call.name in ("bind", "listen"):
            servers.add(socket_key)
        if call.name not in BINDING_CALLS or socket_key not in servers:
            continue
        family, _, port = attribute.parse_address(strace_parse.argument(call, 1) or "")
        transport = state.transport(call)
        if family in attribute.INET_FAMILIES and port and transport is not None:
            held.add((family, port, transport))
    return frozenset(held)


@dataclasses.dataclass
class Collected:
    """What network_rules gathers from one run's refusals before it writes rules."""

    wildcards: set[tuple[str, str]] = dataclasses.field(default_factory=set)
    exact: set[tuple[str, str, str]] = dataclasses.field(default_factory=set)
    binds: set[str] = dataclasses.field(default_factory=set)
    refused: list[str] = dataclasses.field(default_factory=list)
    reported: list[str] = dataclasses.field(default_factory=list)


def decide_connect(denial: Denial, bound: frozenset[tuple[str, int, str]], collected: Collected) -> None:
    """Sorts one refused connect or datagram: an external refusal, a loopback wildcard or exact rule, or a report.

    A server is recognised by port and transport alone, so a dual-stack server bound to :: matches a
    client that connects over IPv4. An IPv4-mapped loopback destination is the IPv4 endpoint it maps,
    as the guard judges it, so it is sorted as that address.
    """
    if denial.address is None or denial.port is None:
        return
    destination = f"{denial.address}:{denial.port} {denial.transport or 'unknown transport'}"
    kind = loopback_kind(denial.address)
    if kind is None:
        collected.refused.append(destination)
        return
    if denial.transport is None:
        collected.reported.append(f"loopback {destination}: the socket's transport is unknown; not granted")
        return
    if kind == "mapped":
        denial = dataclasses.replace(denial, address=str(ipaddress.ip_address(denial.address).ipv4_mapped))
    if any(port == denial.port and transport == denial.transport for _, port, transport in bound):
        collected.wildcards.add((denial.address, denial.transport))
        return
    collected.exact.add((denial.address, denial.transport, exact_loopback(denial.address, denial.port, denial.transport)))
    collected.reported.append(f"loopback {destination}: no process of the run bound that port; granted exactly")


def decide_bind(denial: Denial, collected: Collected) -> None:
    """Sorts one refused bind or listen into the bind rules or the reported refusals."""
    if denial.transport is None:
        collected.reported.append(f"bind of port {denial.port}: the socket's transport is unknown; not granted")
    elif denial.port == 0:
        collected.binds.add("allow 0" + transport_marker(denial.transport))
    elif denial.port is not None and denial.address is not None and loopback_kind(denial.address) in ("inet", "inet6"):
        collected.binds.add(f"allow {denial.port}" + transport_marker(denial.transport))
    else:
        collected.reported.append(f"bind of port {denial.port} on {denial.address}: not a loopback service; not granted")


def connect_rules(collected: Collected) -> set[str]:
    """The [connect] rules: localhost where both families need every port, otherwise one wildcard per address,
    and every exact rule no wildcard of its address and transport covers."""
    rules: set[str] = set()
    covered: set[tuple[str, str]] = set()
    for transport in sorted({kind for _, kind in collected.wildcards}):
        addresses = {address for address, kind in collected.wildcards if kind == transport}
        if {loopback_kind(address) for address in addresses} == {"inet", "inet6"}:
            rules.add("allow localhost" + transport_marker(transport))
            covered.add(("*", transport))
            continue
        rules.update(address_wildcard(address, transport) for address in addresses)
        covered.update((address, transport) for address in addresses)
    rules.update(rule for address, transport, rule in collected.exact
                 if (address, transport) not in covered and ("*", transport) not in covered)
    return rules


def network_rules(denials: list[Denial], bound: frozenset[tuple[str, int, str]],
                  declared_hosts: tuple[str, ...]) -> NetworkDecision:
    """The rules one run's network refusals ask for, by A.6.5.

    A refused loopback destination on a port a server of the run held becomes a wildcard for that
    address (localhost when both families need it); one on a port nobody held is granted exactly and
    reported. A refused bind of port 0, or a listen on an unbound socket, becomes `allow 0`; an
    explicit port only for a loopback address. A refusal whose transport is unknown is reported. An
    external destination is never granted, whatever the declared hosts: a declared host is a name, a
    record holds addresses, and the guard holds a name rule to its port, so a destination it refused
    is one no declared rule names. `declared_hosts` is named in the report when it is.
    """
    collected = Collected()
    for denial in denials:
        if denial.layer != LAYER_NETWORK:
            continue
        if attribute.SECTION_BIND in denial.sections:
            decide_bind(denial, collected)
        else:
            decide_connect(denial, bound, collected)
    if collected.refused and declared_hosts:
        collected.reported.append("declared hosts are names and match no refused address: " + ", ".join(declared_hosts))
    return NetworkDecision(connect=tuple(sorted(connect_rules(collected))), bind=tuple(sorted(collected.binds)),
                           refused_external=tuple(sorted(set(collected.refused))), reported=tuple(collected.reported))


def seed_rules(declared_hosts: tuple[str, ...]) -> tuple[str, ...]:
    """One `allow <name>:<port>` rule per host prune.json declares, with ` udp` where declared (decision 11).

    Raises ValueError for an entry that is not a lower-case DNS name, a port from 1 to 65535 and an
    optional tcp or udp marker, so nothing but a well-formed name ever reaches a rule.
    """
    rules: list[str] = []
    for entry in declared_hosts:
        match = DECLARED_HOST.fullmatch(entry)
        if match is None or int(match.group("port")) > PORT_MAXIMUM:
            raise ValueError(f"declared host {entry!r} is not <name>:<port> with an optional tcp or udp")
        rules.append(f"allow {match.group('name')}:{match.group('port')}" + transport_marker(match.group("transport")))
    return tuple(rules)
