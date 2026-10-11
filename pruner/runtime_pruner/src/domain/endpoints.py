"""The network endpoints a recorded session reached, and the [connect] and [bind] rules they ask for.

The syscalls only show addresses, so this module reads three more things from the trace: which
connections completed (a non-blocking connect answers EINPROGRESS and is judged by what is seen
afterwards), which ports a process of the session held (only an explicit bind or a listen makes one),
and the names behind the addresses (the TLS host name of the ClientHello, DNS answers, the container's
hosts file). Rules follow plan A.8.2. Everything observed is untrusted text: a host name becomes a rule
only when names.rule_hostname accepts it, and every comment is escaped when the policy is rendered.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from collections.abc import Iterable

from runtime_pruner.src.domain import names, needs
from shared.src.domain import attribute, cfgfile, network, strace_parse
from shared.src.domain.record import Syscall

DNS_PORT = 53
# The calls that deliver a datagram or a segment, and the ones that receive one.
SEND_CALLS = frozenset({"write", "send", "sendto", "sendmsg", "sendmmsg"})
RECEIVE_CALLS = frozenset({"recvfrom", "recvmsg", "recvmmsg"})
ACCEPT_CALLS = frozenset({"accept", "accept4"})
# The comments the rules carry; named once so the suites and the documentation quote the same words.
UNBOUND_LOOPBACK_COMMENT = ("a service outside the session listened on this port while recording; "
                            "it must exist at grading time too")
TLS_NAME_COMMENT = "TLS host name of the session's ClientHello; grading needs --resolver, the egress broker holds the name"
ADDRESS_COMMENT = "no TLS host name was seen, so the address is held; it may change, and a name rule needs one"
UDP_COMMENT = "an explicit UDP port rule needs Landlock ABI 10"
LOOKUP_COMMENT = "the session resolved a name it then reached by address; grading resolves it again"
IOV_BASE = re.compile(r'iov_base="((?:[^"\\]|\\.)*)"')


@dataclasses.dataclass(frozen=True)
class Endpoint:
    """One destination a session reached: a numeric address, a port, `tcp` or `udp`, and the call."""

    address: str
    port: int
    transport: str
    call: str


@dataclasses.dataclass
class NetworkNeeds:
    """What one session did on the network, before any rule.

    `connected` holds the destinations of stream connections that completed, `incomplete` those that
    answered EINPROGRESS and were never seen to complete, `sent` the destinations a datagram was
    sent to, and `unsent` the datagram connects that sent nothing (glibc ranks addresses that way).
    `held` is every (transport, port) a process of the session bound explicitly or listened on,
    `binds` every (transport, requested port) it asked to bind, `accepted` every peer an accepted
    connection came from with the local port, `server_names` the TLS host name seen on a connection
    to a destination, and `dns_names` the name a DNS answer gave an address.
    """

    connected: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    incomplete: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    sent: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    unsent: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    held: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    binds: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    accepted: set[tuple[str, int]] = dataclasses.field(default_factory=set)
    server_names: dict[tuple[str, int], str] = dataclasses.field(default_factory=dict)
    dns_names: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class NetworkRules:
    """The rules the sessions ask for: [connect] and [bind] rules with their comments, and the notes.

    `notes` are the endpoints left out, each with the reason; `needs_resolver` is set when a rule
    names a host, which grading serves only with --resolver; `rejected_names` are the observed names
    that failed the DNS grammar and so shaped no rule; `reached` is every destination a rule or a
    note was made for, for the comparison with an existing policy.
    """

    connect: tuple[cfgfile.Rule, ...]
    bind: tuple[cfgfile.Rule, ...]
    notes: tuple[str, ...]
    needs_resolver: bool
    rejected_names: tuple[str, ...]
    reached: tuple[Endpoint, ...]


def observe(calls: Iterable[Syscall]) -> NetworkNeeds:
    """What the calls of one session did on the network; assumes they are in log order, whole.

    Every call is read, the failed ones too, since a non-blocking connect that answered EINPROGRESS
    is the beginning of a connection. Descriptors are followed per thread group, so a descriptor
    number reused in another process or after a close is never taken for the earlier socket.
    """
    walk = _Walk()
    for call in calls:
        walk.see(call)
    return walk.found


def rules(sessions: list[NetworkNeeds], hosts: dict[str, str]) -> NetworkRules:
    """The [connect] and [bind] rules the sessions ask for, with the notes of what was left out.

    `hosts` maps an address to the name the container's hosts file gives it. A loopback destination
    on a (transport, port) some process of the sessions held becomes the loopback wildcard, any
    other an exact rule with a comment; an external stream destination becomes `allow <TLS name>:<port>`
    when a ClientHello named it and `allow <address>:<port>` otherwise; a datagram destination is named
    by DNS when the answer was seen. Lookups of the resolver are granted only when a rule by address
    needs the session's name again. Assumes the sessions were recorded in containers of one image.
    """
    merged = _merge(sessions)
    owned = _owned(sessions)
    notes: list[str] = []
    rejected: set[str] = set()
    reached: list[Endpoint] = []
    connect: dict[str, cfgfile.Rule] = {}
    wildcards: dict[str, set[str]] = {}
    exact: list[tuple[str, str, cfgfile.Rule]] = []
    lookups: list[Endpoint] = []
    address_rules_with_lookup = False
    needs_resolver = False
    destinations = [Endpoint(address, port, "tcp", "connect") for address, port in sorted(merged.connected)]
    destinations += [Endpoint(address, port, "udp", "sendto") for address, port in sorted(merged.sent)]
    for endpoint in destinations:
        reached.append(endpoint)
        kind = network.loopback_kind(endpoint.address)
        if endpoint.transport == "udp" and endpoint.port == DNS_PORT:
            lookups.append(endpoint)
        elif kind is not None:
            _loopback(endpoint, kind, owned, wildcards, exact)
        elif endpoint.transport == "tcp":
            rule, by_address = _external_stream(endpoint, merged, hosts, rejected)
            connect.setdefault(rule.text, rule)
            needs_resolver = needs_resolver or not by_address
            address_rules_with_lookup = address_rules_with_lookup or (by_address and endpoint.address in merged.dns_names)
        else:
            rule, named = _external_datagram(endpoint, merged, hosts, rejected)
            connect.setdefault(rule.text, rule)
            needs_resolver = needs_resolver or named
    ordered = [*_wildcard_rules(wildcards), *_exact_rules(exact, wildcards), *connect.values()]
    ordered += _lookup_rules(lookups, address_rules_with_lookup)
    notes += [f"datagram connect to {_text(address, port)} udp sent nothing; not granted (glibc ranks the addresses "
              "of a name this way)" for address, port in sorted(merged.unsent)]
    notes += [f"connect to {_text(address, port)} tcp was attempted and never completed; not granted"
              for address, port in sorted(merged.incomplete)]
    notes += [f"[accept] not generated: accept from {address} on port {port}; choose the public port and write the "
              "rule by hand" for address, port in sorted(merged.accepted) if network.loopback_kind(address) is None]
    return NetworkRules(connect=tuple(ordered), bind=tuple(_bind_rules(merged.binds)), notes=tuple(notes),
                        needs_resolver=needs_resolver, rejected_names=tuple(sorted(rejected)), reached=tuple(reached))


def _merge(sessions: list[NetworkNeeds]) -> NetworkNeeds:
    """The union of what every session did; the first name seen for a destination or an address wins."""
    merged = NetworkNeeds()
    for session in sessions:
        merged.connected |= session.connected
        merged.incomplete |= session.incomplete
        merged.sent |= session.sent
        merged.unsent |= session.unsent
        merged.binds |= session.binds
        merged.accepted |= session.accepted
        for destination, name in session.server_names.items():
            merged.server_names.setdefault(destination, name)
        for address, name in session.dns_names.items():
            merged.dns_names.setdefault(address, name)
    merged.incomplete -= merged.connected
    merged.unsent -= merged.sent
    return merged


def _owned(sessions: list[NetworkNeeds]) -> set[tuple[str, int, str]]:
    """Every loopback destination (address, port, transport) that a session reached on a port it held itself.

    A port one session held does not make another session's connection to the same number the
    session's own server: that one is a service outside it.
    """
    owned: set[tuple[str, int, str]] = set()
    for session in sessions:
        owned.update((address, port, "tcp") for address, port in session.connected if ("tcp", port) in session.held)
        owned.update((address, port, "udp") for address, port in session.sent if ("udp", port) in session.held)
    return owned


def _loopback(endpoint: Endpoint, kind: str, owned: set[tuple[str, int, str]], wildcards: dict[str, set[str]],
              exact: list[tuple[str, str, cfgfile.Rule]]) -> None:
    """Sorts a loopback destination into a wildcard of its transport or an exact rule with its comment."""
    if (endpoint.address, endpoint.port, endpoint.transport) in owned:
        wildcards.setdefault(endpoint.transport, set()).add(kind)
        return
    rule = cfgfile.Rule(network.exact_loopback(endpoint.address, endpoint.port, endpoint.transport),
                        UNBOUND_LOOPBACK_COMMENT)
    exact.append((endpoint.transport, kind, rule))


def _wildcard_rules(wildcards: dict[str, set[str]]) -> list[cfgfile.Rule]:
    """One loopback wildcard per transport: both families together are localhost."""
    return [cfgfile.Rule(network.loopback_wildcard(frozenset(kinds), transport))
            for transport, kinds in sorted(wildcards.items())]


def _exact_rules(exact: list[tuple[str, str, cfgfile.Rule]], wildcards: dict[str, set[str]]) -> list[cfgfile.Rule]:
    """The exact loopback rules no wildcard of the same transport and family already covers, once each."""
    found: dict[str, cfgfile.Rule] = {}
    for transport, kind, rule in exact:
        if kind not in wildcards.get(transport, set()):
            found.setdefault(rule.text, rule)
    return list(found.values())


def _external_stream(endpoint: Endpoint, merged: NetworkNeeds, hosts: dict[str, str],
                     rejected: set[str]) -> tuple[cfgfile.Rule, bool]:
    """The rule for an external stream destination, and whether it is by address (True) or by name (False)."""
    seen = merged.server_names.get((endpoint.address, endpoint.port))
    if seen is not None:
        name = names.rule_hostname(seen)
        if name is not None:
            return cfgfile.Rule(f"allow {name}:{endpoint.port}", TLS_NAME_COMMENT), False
        rejected.add(seen)
    return cfgfile.Rule(f"allow {_text(endpoint.address, endpoint.port)}", _address_comment(endpoint.address, merged,
                                                                                            hosts, rejected)), True


def _external_datagram(endpoint: Endpoint, merged: NetworkNeeds, hosts: dict[str, str],
                       rejected: set[str]) -> tuple[cfgfile.Rule, bool]:
    """The rule for an external datagram destination, and whether it names a host."""
    given = merged.dns_names.get(endpoint.address) or hosts.get(endpoint.address)
    if given is not None:
        name = names.rule_hostname(given)
        if name is not None:
            return cfgfile.Rule(f"allow {name}:{endpoint.port} udp", UDP_COMMENT), True
        rejected.add(given)
    return cfgfile.Rule(f"allow {_text(endpoint.address, endpoint.port)} udp", UDP_COMMENT), False


def _address_comment(address: str, merged: NetworkNeeds, hosts: dict[str, str], rejected: set[str]) -> str:
    """The comment above a rule by address: the name DNS or the hosts file gave it, if any."""
    given = merged.dns_names.get(address) or hosts.get(address)
    if given is None:
        return ADDRESS_COMMENT
    if names.rule_hostname(given) is None:
        rejected.add(given)
    return f"{ADDRESS_COMMENT}; the session reached it as {given}"


def _lookup_rules(lookups: list[Endpoint], needed: bool) -> list[cfgfile.Rule]:
    """The resolver lookups: rules when a rule by address needs the name again, commented out otherwise."""
    found: list[cfgfile.Rule] = []
    for endpoint in lookups:
        text = f"allow {_text(endpoint.address, endpoint.port)} udp"
        if needed:
            found.append(cfgfile.Rule(text, LOOKUP_COMMENT))
        else:
            found.append(cfgfile.Rule(f"# not granted: {text} (the network layer maps names in /etc/hosts)"))
    return found


def _bind_rules(binds: set[tuple[str, int]]) -> list[cfgfile.Rule]:
    """The [bind] rules: `allow 0` for the kernel's choice, `allow <port>` for an explicit one."""
    found: list[cfgfile.Rule] = []
    for transport, port in sorted(binds):
        comment = UDP_COMMENT if transport == "udp" and port != 0 else ""
        found.append(cfgfile.Rule(f"allow {port}" + network.transport_marker(transport), comment))
    return found


def _text(address: str, port: int) -> str:
    """An address and port as a rule spells them: an IPv6 address in brackets."""
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


class _Walk:
    """The state of reading one session: thread groups, sockets bound without a known port, results.

    A stream connection counts only when the session made it: `connect` returned 0, or answered
    EINPROGRESS and a later call showed that remote end (`pending`). A connection the session accepted
    shows a remote end too, and is never one it made. A TLS host name is read from the first payload
    sent to a destination only, so a CONNECT to a proxy cannot name the host behind it."""

    def __init__(self) -> None:
        """Starts with no thread known and nothing found."""
        self.found = NetworkNeeds()
        self.groups: dict[int, int] = {}
        self.unnamed: dict[tuple[int, str], tuple[str, str]] = {}
        self.pending: set[tuple[str, int]] = set()
        self.payloads: set[tuple[str, int]] = set()

    def group(self, pid: int) -> int:
        """The thread group of a thread; a thread not seen created is its own group."""
        return self.groups.get(pid, pid)

    def see(self, call: Syscall) -> None:
        """Reads one call: first its effect on the process tree, then what it did on the network."""
        child = strace_parse.forked_child(call)
        if child is not None:
            self._forked(call, child)
        if call.name == "close" and call.errno is None:
            self.unnamed.pop(self._key(call), None)
            return
        pending = call.name == "connect" and call.errno == "EINPROGRESS"
        if call.errno is not None and not pending:
            return
        socket_text = strace_parse.argument(call, 0) or ""
        local, remote = needs.socket_ends(socket_text)
        transport = needs.transport_of(socket_text)
        if remote is not None and transport == "tcp" and _normal(remote) in self.pending:
            self.found.connected.add(_normal(remote))
        self._named(call, socket_text, local, transport)
        if call.name == "bind":
            self._bind(call, socket_text, transport)
        elif call.name == "listen":
            self._listen(call, socket_text, local, transport)
        elif call.name == "connect":
            self._connect(call, transport, pending)
        elif call.name in ACCEPT_CALLS:
            self._accept(call, local)
        elif call.name in RECEIVE_CALLS:
            self._receive(call, remote)
        elif call.name in SEND_CALLS:
            self._send(call, remote, transport)

    def _forked(self, call: Syscall, child: int) -> None:
        """Gives a created process the unnamed sockets of its parent; a thread shares its group."""
        parent = self.group(call.pid)
        if strace_parse.is_thread(call):
            self.groups[child] = parent
            return
        self.groups[child] = child
        for (owner, number), pending in list(self.unnamed.items()):
            if owner == parent:
                self.unnamed[(child, number)] = pending

    def _key(self, call: Syscall) -> tuple[int, str]:
        """The socket a call's first argument names: the calling thread group and the descriptor number."""
        match = needs.DESCRIPTOR_ARGUMENT.match(strace_parse.argument(call, 0) or "")
        return self.group(call.pid), match.group("number") if match else ""

    def _named(self, call: Syscall, socket_text: str, local: tuple[str, int] | None, transport: str | None) -> None:
        """Makes a bound socket's port held once a decoration shows the port the kernel chose."""
        key = self._key(call)
        if local is None or key not in self.unnamed or transport is None:
            return
        self.unnamed.pop(key)
        self.found.held.add((transport, local[1]))

    def _bind(self, call: Syscall, socket_text: str, transport: str | None) -> None:
        """An explicit bind holds its port; a bind to port 0 holds the port the kernel chooses, seen later."""
        family, _, port = _address(strace_parse.argument(call, 1) or "")
        if family is None or port is None or transport is None:
            return
        self.found.binds.add((transport, port))
        if port == 0:
            self.unnamed[self._key(call)] = (transport, socket_text)
        else:
            self.found.held.add((transport, port))

    def _listen(self, call: Syscall, socket_text: str, local: tuple[str, int] | None, transport: str | None) -> None:
        """A listen holds the socket's port; on a socket never bound it is an ephemeral bind."""
        if transport is None:
            return
        if local is None:
            self.found.binds.add((transport, 0))
            self.unnamed[self._key(call)] = (transport, socket_text)
        else:
            self.found.held.add((transport, local[1]))

    def _connect(self, call: Syscall, transport: str | None, pending: bool) -> None:
        """A stream connect that finished, or began and awaits its completion; a datagram connect awaits a send."""
        family, address, port = _address(attribute.destination_text(call))
        if family not in attribute.INET_FAMILIES or address is None or port is None or transport is None:
            return
        destination = _normal((address, port))
        if transport == "tcp":
            if pending:
                self.pending.add(destination)
                self.found.incomplete.add(destination)
            else:
                self.found.connected.add(destination)
        else:
            self.found.unsent.add(destination)

    def _accept(self, call: Syscall, local: tuple[str, int] | None) -> None:
        """An accepted connection: the peer's address and the local port it came to."""
        _, address, _ = _address(strace_parse.argument(call, 1) or "")
        if address is not None and local is not None:
            self.found.accepted.add((_normal((address, 0))[0], local[1]))

    def _send(self, call: Syscall, remote: tuple[str, int] | None, transport: str | None) -> None:
        """A datagram sent counts its destination; the first bytes of a stream may be a ClientHello."""
        if transport == "udp":
            family, address, port = _address(attribute.destination_text(call))
            if family in attribute.INET_FAMILIES and address is not None and port is not None:
                self._sent(_normal((address, port)))
            elif remote is not None:
                self._sent(_normal(remote))
        elif transport == "tcp" and remote is not None and _normal(remote) not in self.payloads:
            self.payloads.add(_normal(remote))
            hello = names.client_hello_server_name(_buffer(call))
            if hello is not None:
                self.found.server_names[_normal(remote)] = hello

    def _sent(self, destination: tuple[str, int]) -> None:
        """Counts a datagram to the destination, which also makes a datagram connect to it count."""
        self.found.sent.add(destination)
        self.found.unsent.discard(destination)

    def _receive(self, call: Syscall, remote: tuple[str, int] | None) -> None:
        """Reads the DNS answers a resolver socket received: each address maps to the name asked."""
        text = (strace_parse.argument(call, 4) or "") if call.name == "recvfrom" else call.arguments
        _, source, source_port = _address(text)
        if not (remote is not None and remote[1] == DNS_PORT) and not (source is not None and source_port == DNS_PORT):
            return
        for address, asked in names.dns_answers(_buffer(call)):
            self.found.dns_names.setdefault(_normal((address, 0))[0], asked)


def _address(text: str) -> tuple[str | None, str | None, int | None]:
    """The family, address and port of a socket address strace printed, each None where absent."""
    return attribute.parse_address(text)


def _normal(destination: tuple[str, int]) -> tuple[str, int]:
    """A destination spelt once: an IPv4-mapped IPv6 address written as IPv4, others as ipaddress writes them."""
    address, port = destination
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address, port
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return str(parsed), port


def _buffer(call: Syscall) -> bytes:
    """The bytes strace printed for the data of a send or receive; empty where none can be read.

    A `write`, `send` or `sendto` prints the buffer as its second argument; a `recvfrom` as its
    second argument too; a message call prints it as the iov_base of the first vector. Assumes -x,
    which writes every byte as \\xHH, so nothing is lost to a printable character.
    """
    if call.name in ("sendmsg", "recvmsg", "sendmmsg", "recvmmsg"):
        match = IOV_BASE.search(call.arguments)
        text = match.group(1) if match else ""
    else:
        argument = strace_parse.argument(call, 1) or ""
        text = argument[1:-1] if argument.startswith('"') and argument.endswith('"') else ""
    return strace_parse.unescape(text).encode("utf-8", "surrogateescape")
