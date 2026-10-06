"""Checks how refused connects, datagrams and binds become [connect] and [bind] rules (A.6.5, decision 11)."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import attribute, network, record, strace_parse


def network_denial(section: str, address: str | None, port: int | None, transport: str | None,
                   operation: str = "connect") -> record.Denial:
    """A network denial as attribute.denials builds it."""
    return record.Denial(pid=300, layer=record.LAYER_NETWORK, operation=operation, objects=(),
                         sections=frozenset({section}), address=address, port=port, transport=transport,
                         errno="EACCES")


def connect(address: str, port: int, transport: str) -> record.Denial:
    """A refused connect or datagram to one destination."""
    return network_denial(attribute.SECTION_CONNECT, address, port, transport)


def bind(port: int, transport: str, address: str = "0.0.0.0") -> record.Denial:
    """A refused bind of one local port."""
    return network_denial(attribute.SECTION_BIND, address, port, transport, operation="bind")


def listen_unbound(transport: str) -> record.Denial:
    """A refused listen on a socket bound to no port, as attribute.denials builds it."""
    return network_denial(attribute.SECTION_BIND, None, 0, transport, operation="listen")


def test_a_loopback_port_the_run_bound_becomes_the_loopback_wildcard():
    decision = network.network_rules([connect("127.0.0.1", 43521, "tcp")], frozenset({("AF_INET", 43521, "tcp")}), ())
    assert decision.connect == ("allow 127.0.0.1:*",)


def test_both_loopback_families_become_localhost():
    decision = network.network_rules([connect("127.0.0.1", 40000, "tcp"), connect("::1", 40001, "tcp")],
                                     frozenset({("AF_INET", 40000, "tcp"), ("AF_INET6", 40001, "tcp")}), ())
    assert decision.connect == ("allow localhost",)


def test_an_ipv6_loopback_server_alone_becomes_the_ipv6_wildcard_and_udp_keeps_its_marker():
    decision = network.network_rules([connect("::1", 40001, "udp")], frozenset({("AF_INET6", 40001, "udp")}), ())
    assert decision.connect == ("allow [::1] udp",)


def test_a_loopback_port_nobody_bound_is_granted_exactly_and_reported():
    decision = network.network_rules([connect("127.0.0.1", 5432, "tcp")], frozenset(), ())
    assert decision.connect == ("allow 127.0.0.1:5432",)
    assert decision.reported and "no process of the run bound" in decision.reported[0]


def test_an_exact_loopback_rule_is_dropped_beside_a_wildcard_of_its_family():
    decision = network.network_rules([connect("127.0.0.1", 5432, "tcp"), connect("127.0.0.1", 43521, "tcp")],
                                     frozenset({("AF_INET", 43521, "tcp")}), ())
    assert decision.connect == ("allow 127.0.0.1:*",)


def test_an_external_address_is_never_granted():
    decision = network.network_rules([connect("10.0.0.1", 80, "tcp")], frozenset(), ())
    assert decision.connect == ()
    assert decision.refused_external == ("10.0.0.1:80 tcp",)


def test_a_refused_ephemeral_bind_becomes_allow_zero():
    decision = network.network_rules([bind(0, "tcp")], frozenset(), ())
    assert decision.bind == ("allow 0",)


def test_a_refused_listen_on_an_unbound_socket_becomes_allow_zero():
    decision = network.network_rules([listen_unbound("tcp")], frozenset(), ())
    assert decision.bind == ("allow 0",)


def test_a_datagram_bind_on_port_zero_becomes_allow_zero_udp():
    decision = network.network_rules([bind(0, "udp")], frozenset(), ())
    assert decision.bind == ("allow 0 udp",)


def test_an_explicit_port_is_granted_only_for_a_loopback_service():
    loopback = network.network_rules([bind(8080, "tcp", address="127.0.0.1")], frozenset(), ())
    anywhere = network.network_rules([bind(8080, "tcp")], frozenset(), ())
    assert loopback.bind == ("allow 8080",)
    assert anywhere.bind == ()
    assert anywhere.reported


def test_declared_hosts_seed_exactly_their_rules():
    assert network.seed_rules(("api.example.org:443", "ntp.example.org:123 udp")) == (
        "allow api.example.org:443", "allow ntp.example.org:123 udp")


@pytest.mark.parametrize("entry", ["*.example.org:443", "api.example.org", "api.example.org:0",
                                   "api.example.org:70000", "API.example.org:443", "10.0.0.1:443",
                                   "api.example.org:443\n[write]", "api.example.org:443 sctp"])
def test_a_malformed_declared_host_never_becomes_a_rule(entry):
    with pytest.raises(ValueError):
        network.seed_rules((entry,))


def test_an_undeclared_external_destination_is_refused_even_beside_declared_hosts():
    decision = network.network_rules([connect("192.0.2.7", 443, "tcp")], frozenset(), ("api.example.org:443",))
    assert decision.connect == ()
    assert decision.refused_external == ("192.0.2.7:443 tcp",)


def test_bound_ports_come_from_successful_binds_and_getsockname_inside_the_domain():
    lines = [
        "300 landlock_restrict_self(3, 0) = 0",
        "300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4<socket:[1]>",
        '300 bind(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        "300 listen(4<socket:[1]>, 50) = 0",
        ('300 getsockname(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(43521), sin_addr=inet_addr("127.0.0.1")}, '
         "[16]) = 0"),
        "200 socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 5<socket:[2]>",
        ('200 bind(5<socket:[2]>, {sa_family=AF_INET6, sin6_port=htons(5000), sin6_flowinfo=htonl(0), '
         'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0'),
    ]
    assert network.bound_ports(strace_parse.parse_trace(lines)) == frozenset({("AF_INET", 43521, "tcp")})
