"""Checks how the endpoints a recorded session reached become [connect] and [bind] rules (plan A.8).

Each case reads strace lines through endpoints.observe and endpoints.rules, the way generate does,
and pairs the call that asks for a rule with the neighbouring one that does not: a recorder that
grants too little fails a correct run, one that grants too much widens the sandbox unseen.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))
sys.path.insert(0, str(REPO_ROOT / "pruner" / "runtime_pruner" / "test" / "unit" / "domain"))

from runtime_pruner.src.domain import endpoints
from shared.src.domain import cfgfile, strace_parse
from test_layer_record_names import client_hello_with_server_name, dns_response

FIXTURES = REPO_ROOT / "pruner" / "runtime_pruner" / "test" / "unit" / "domain" / "fixtures" / "record"


def quoted(data: bytes) -> str:
    """Bytes as strace -x prints a buffer: every byte as \\xHH, in double quotes."""
    return '"' + "".join(f"\\x{byte:02x}" for byte in data) + '"'


def hello_argument(name: str) -> str:
    """The buffer argument of a write that sends a ClientHello for the given server name."""
    return quoted(client_hello_with_server_name(name.encode("utf-8")))


def observed(*lines: str) -> endpoints.NetworkNeeds:
    """What the trace lines did on the network."""
    return endpoints.observe(strace_parse.iter_calls(lines))


def rules_of(*lines: str, hosts: dict[str, str] | None = None) -> endpoints.NetworkRules:
    """The rules one session made of the trace lines asks for."""
    return endpoints.rules([observed(*lines)], hosts or {})


def texts(rules: tuple[cfgfile.Rule, ...]) -> tuple[str, ...]:
    """The rules as plain text."""
    return tuple(rule.text for rule in rules)


def inet(address: str, port: int) -> str:
    """The sockaddr strace prints for an IPv4 destination."""
    return f'{{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{address}")}}'


def test_a_loopback_port_the_session_bound_becomes_the_loopback_wildcard():
    rules = rules_of(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 0)}, 16) = 0",
                     "16 listen(3<TCP:[127.0.0.1:40623]>, 128) = 0",
                     f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 40623)}, 16) = 0")
    assert texts(rules.connect) == ("allow 127.0.0.1:*",)
    assert texts(rules.bind) == ("allow 0",)


def test_a_loopback_port_nobody_in_the_session_bound_is_exact_and_explained():
    rules = rules_of(f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 5432)}, 16) = 0")
    assert texts(rules.connect) == ("allow 127.0.0.1:5432",)
    assert "must exist at grading time" in rules.connect[0].comment


def test_a_server_bound_to_a_port_the_kernel_chose_is_held_when_a_later_call_shows_the_port():
    rules = rules_of(f"16 bind(3<UDP:[1]>, {inet('127.0.0.1', 0)}, 16) = 0",
                     f"16 getsockname(3<UDP:[127.0.0.1:44444]>, {inet('127.0.0.1', 44444)}, [128 => 16]) = 0",
                     f"16 sendto(4<UDP:[2]>, \"x\", 1, 0, {inet('127.0.0.1', 44444)}, 16) = 1")
    assert texts(rules.connect) == ("allow 127.0.0.1:* udp",)
    assert texts(rules.bind) == ("allow 0 udp",)


def test_both_loopback_families_together_are_localhost():
    inet6 = 'sin6_port=htons(40000), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0'
    rules = rules_of(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 40000)}, 16) = 0",
                     f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 40000)}, 16) = 0",
                     f"17 connect(5<TCPv6:[3]>, {{sa_family=AF_INET6, {inet6}}}, 28) = 0")
    assert texts(rules.connect) == ("allow localhost",)


def test_a_datagram_connect_that_sent_nothing_is_not_granted():
    rules = rules_of(f"16 connect(5<UDP:[3]>, {inet('104.20.26.136', 443)}, 16) = 0")
    assert rules.connect == ()
    assert any("104.20.26.136:443" in note for note in rules.notes)


def test_a_datagram_connect_followed_by_a_send_is_granted_by_name_when_dns_gave_one():
    answer = dns_response(b"time", "198.51.100.5")
    rules = rules_of(f"16 recvfrom(5<UDP:[10.0.0.2:40000->10.0.0.1:53]>, {quoted(answer)}, 2048, 0, "
                     f"{inet('10.0.0.1', 53)}, [128 => 16]) = {len(answer)}",
                     f"17 connect(6<UDP:[4]>, {inet('198.51.100.5', 123)}, 16) = 0",
                     "17 send(6<UDP:[10.0.0.2:41000->198.51.100.5:123]>, \"x\", 1, 0) = 1")
    assert texts(rules.connect) == ("allow time:123 udp",)
    assert rules.needs_resolver
    assert "ABI 10" in rules.connect[0].comment


def test_a_tls_server_name_becomes_a_name_rule_and_asks_for_a_resolver():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('172.66.157.237', 443)}, 16) = -1 EINPROGRESS "
                     "(Operation now in progress)",
                     "16 write(3<TCP:[172.17.0.2:32972->172.66.157.237:443]>, "
                     f"{hello_argument('example.org')}, 517) = 517")
    assert texts(rules.connect) == ("allow example.org:443",)
    assert rules.needs_resolver


def test_the_fixture_client_hello_of_a_real_handshake_gives_its_name():
    hello = quoted((FIXTURES / "hello-sni.bin").read_bytes())
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('93.184.216.34', 443)}, 16) = 0",
                     f"16 sendto(3<TCP:[172.17.0.2:32972->93.184.216.34:443]>, {hello}, 517, 0, NULL, 0) = 517")
    assert texts(rules.connect) == ("allow example.org:443",)


def test_without_tls_the_address_is_granted_and_the_name_dns_gave_it_is_a_comment():
    answer = dns_response(b"plain", "192.0.2.7")
    rules = rules_of(f"16 recvfrom(5<UDP:[10.0.0.2:40000->10.0.0.1:53]>, {quoted(answer)}, 2048, 0, "
                     f"{inet('10.0.0.1', 53)}, [128 => 16]) = {len(answer)}",
                     f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = 0")
    assert "allow 192.0.2.7:80" in texts(rules.connect)
    comment = next(rule.comment for rule in rules.connect if rule.text == "allow 192.0.2.7:80")
    assert "plain" in comment
    assert not rules.needs_resolver


def test_the_lookup_of_a_name_reached_by_address_is_granted_and_otherwise_commented_out():
    answer = dns_response(b"plain", "192.0.2.7")
    lookup = [f"16 connect(5<UDP:[9]>, {inet('10.0.0.1', 53)}, 16) = 0",
              "16 send(5<UDP:[10.0.0.2:40000->10.0.0.1:53]>, \"q\", 1, 0) = 1",
              (f"16 recvfrom(5<UDP:[10.0.0.2:40000->10.0.0.1:53]>, {quoted(answer)}, 2048, 0, "
               f"{inet('10.0.0.1', 53)}, [128 => 16]) = {len(answer)}")]
    by_address = rules_of(*lookup, f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = 0")
    assert "allow 10.0.0.1:53 udp" in texts(by_address.connect)
    by_name = rules_of(*lookup, f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 443)}, 16) = 0",
                       "16 write(3<TCP:[10.0.0.2:50000->192.0.2.7:443]>, "
                       f"{hello_argument('plain.example.org')}, 517) = 517")
    assert "allow 10.0.0.1:53 udp" not in texts(by_name.connect)
    assert any(text.startswith("# not granted: allow 10.0.0.1:53 udp") for text in texts(by_name.connect))


def test_an_ipv4_mapped_destination_is_written_as_ipv4():
    mapped = ('sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:192.0.2.7", &sin6_addr), '
              'sin6_scope_id=0')
    rules = rules_of(f"16 connect(3<TCPv6:[1]>, {{sa_family=AF_INET6, {mapped}}}, 28) = 0")
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)


def test_a_udp_bind_does_not_make_a_tcp_connection_to_the_same_port_look_owned():
    rules = rules_of(f"16 bind(3<UDP:[1]>, {inet('127.0.0.1', 40000)}, 16) = 0",
                     f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 40000)}, 16) = 0")
    assert texts(rules.connect) == ("allow 127.0.0.1:40000",)


def test_a_client_sockets_own_port_is_not_held():
    rules = rules_of(f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 5432)}, 16) = 0",
                     f"17 getsockname(4<TCP:[127.0.0.1:41000->127.0.0.1:5432]>, {inet('127.0.0.1', 41000)}, "
                     "[128 => 16]) = 0",
                     f"18 connect(5<TCP:[3]>, {inet('127.0.0.1', 41000)}, 16) = 0")
    assert "allow 127.0.0.1:*" not in texts(rules.connect)
    assert "allow 127.0.0.1:41000" in texts(rules.connect)


def test_a_non_blocking_connect_never_seen_to_complete_is_not_granted():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = -1 EINPROGRESS "
                     "(Operation now in progress)",
                     "16 getsockopt(3<TCP:[1]>, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0")
    assert rules.connect == ()
    assert any("never completed" in note for note in rules.notes)


def test_a_non_blocking_connect_that_completed_is_granted():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = -1 EINPROGRESS "
                     "(Operation now in progress)",
                     "16 getsockopt(3<TCP:[172.17.0.2:50000->192.0.2.7:80]>, SOL_SOCKET, SO_ERROR, [0], [4]) = 0")
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)
    assert rules.notes == ()


def test_completion_seen_in_a_child_after_fork_counts():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = -1 EINPROGRESS "
                     "(Operation now in progress)",
                     "16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
                     "17 write(3<TCP:[172.17.0.2:50000->192.0.2.7:80]>, \"GET / HTTP/1.0\\r\\n\\r\\n\", 18) = 18")
    assert texts(rules.connect) == ("allow 192.0.2.7:80",)


def test_a_reused_descriptor_number_does_not_complete_another_connect():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = -1 EINPROGRESS "
                     "(Operation now in progress)",
                     "16 close(3<TCP:[1]>) = 0",
                     f"16 connect(3<TCP:[2]>, {inet('192.0.2.8', 443)}, 16) = 0",
                     "16 getsockopt(3<TCP:[172.17.0.2:50001->192.0.2.8:443]>, SOL_SOCKET, SO_ERROR, [0], [4]) = 0")
    assert "allow 192.0.2.7:80" not in texts(rules.connect)
    assert "allow 192.0.2.8:443" in texts(rules.connect)


def test_an_invalid_server_name_falls_back_to_the_address_and_is_listed_as_rejected():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 443)}, 16) = 0",
                     "16 write(3<TCP:[172.17.0.2:32972->192.0.2.7:443]>, "
                     f"{hello_argument('x' + chr(10) + '[write]' + chr(10) + '/')}, 517) = 517")
    assert texts(rules.connect) == ("allow 192.0.2.7:443",)
    assert not rules.needs_resolver
    assert rules.rejected_names == ("x\n[write]\n/",)


def test_a_dns_name_that_is_an_injection_shapes_no_rule_and_no_section_of_the_rendered_policy():
    answer = dns_response(b"x\n[write]\n/", "192.0.2.7")
    rules = rules_of(f"16 recvfrom(5<UDP:[10.0.0.2:40000->10.0.0.1:53]>, {quoted(answer)}, 2048, 0, "
                     f"{inet('10.0.0.1', 53)}, [128 => 16]) = {len(answer)}",
                     f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = 0")
    policy = cfgfile.Policy(fs={}, connect=rules.connect, bind=rules.bind, limits={})
    text = cfgfile.render(policy)
    assert "allow 192.0.2.7:80" in text
    assert cfgfile.read_policy(text).fs == {}
    assert "x\\x0a[write]\\x0a/" in text


def test_an_outside_peer_becomes_an_accept_note_and_no_rule():
    rules = rules_of(f"16 accept4(3<TCP:[0.0.0.0:8080]>, {inet('203.0.113.9', 51000)}, [16], SOCK_CLOEXEC) = 4")
    assert any(note.startswith("[accept] not generated") and "203.0.113.9" in note and "8080" in note
               for note in rules.notes)
    assert rules.connect == ()


def test_a_loopback_peer_is_the_sessions_own_client_and_needs_no_note():
    rules = rules_of(f"16 accept4(3<TCP:[127.0.0.1:8080]>, {inet('127.0.0.1', 51000)}, [16], SOCK_CLOEXEC) = 4")
    assert rules.notes == ()


def test_an_explicit_bind_port_is_a_rule_and_a_udp_one_says_it_needs_abi_10():
    rules = rules_of(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 8080)}, 16) = 0",
                     f"16 bind(4<UDP:[2]>, {inet('127.0.0.1', 9090)}, 16) = 0")
    assert texts(rules.bind) == ("allow 8080", "allow 9090 udp")
    assert "ABI 10" in rules.bind[1].comment
    assert rules.bind[0].comment == ""


def test_a_failed_bind_asks_for_nothing():
    rules = rules_of(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 80)}, 16) = -1 EACCES (Permission denied)")
    assert rules.bind == ()


def test_a_listen_on_a_socket_never_bound_is_an_ephemeral_bind():
    rules = rules_of("16 listen(3<TCP:[1]>, 128) = 0",
                     "16 getsockname(3<TCP:[0.0.0.0:36000]>, {sa_family=AF_INET, sin_port=htons(36000), "
                     "sin_addr=inet_addr(\"0.0.0.0\")}, [128 => 16]) = 0",
                     f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 36000)}, 16) = 0")
    assert texts(rules.bind) == ("allow 0",)
    assert texts(rules.connect) == ("allow 127.0.0.1:*",)


def test_the_sessions_of_one_recording_are_merged_and_a_connection_completing_in_another_is_not_incomplete():
    first = observed(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = -1 EINPROGRESS (Operation now in progress)")
    second = observed(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 80)}, 16) = 0")
    merged = endpoints.rules([first, second], {})
    assert texts(merged.connect) == ("allow 192.0.2.7:80",)
    assert merged.notes == ()


@pytest.mark.parametrize("call", [
    "16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path=\"/run/x\"}, 110) = 0",
    "16 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[1]>",
])
def test_a_call_that_reaches_no_internet_endpoint_asks_for_no_rule(call):
    rules = rules_of(call)
    assert rules.connect == ()
    assert rules.bind == ()


def test_a_loopback_resolver_is_a_lookup_like_any_other_and_not_an_exact_loopback_rule():
    rules = rules_of(f"16 connect(5<UDP:[9]>, {inet('127.0.0.11', 53)}, 16) = 0",
                     "16 send(5<UDP:[10.0.0.2:40000->127.0.0.11:53]>, \"q\", 1, 0) = 1")
    assert "allow 127.0.0.11:53 udp" not in texts(rules.connect)
    assert any(text.startswith("# not granted: allow 127.0.0.11:53 udp") for text in texts(rules.connect))


def test_a_connection_the_session_accepted_is_never_one_it_made():
    peer = inet("172.17.0.1", 51000)
    rules = rules_of(f"16 accept4(3<TCP:[0.0.0.0:5000]>, {peer}, [16], SOCK_CLOEXEC) = 4<TCP:[172.17.0.2:5000->172.17.0.1:51000]>",
                     "16 write(4<TCP:[172.17.0.2:5000->172.17.0.1:51000]>, \"HTTP/1.1 200 OK\", 15) = 15",
                     "16 setsockopt(4<TCP:[172.17.0.2:5000->172.17.0.1:51000]>, SOL_TCP, TCP_NODELAY, [1], 4) = 0")
    assert rules.connect == ()
    assert any(note.startswith("[accept] not generated") for note in rules.notes)


def test_a_loopback_client_the_session_accepted_gets_no_exact_rule_for_its_ephemeral_port():
    peer = inet("127.0.0.1", 51000)
    rules = rules_of(f"16 accept4(3<TCP:[127.0.0.1:5000]>, {peer}, [16], SOCK_CLOEXEC) = 4<TCP:[127.0.0.1:5000->127.0.0.1:51000]>",
                     "16 write(4<TCP:[127.0.0.1:5000->127.0.0.1:51000]>, \"x\", 1) = 1")
    assert rules.connect == ()


def test_a_port_one_session_held_does_not_own_another_sessions_connection_to_the_same_number():
    first = observed(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 8080)}, 16) = 0")
    second = observed(f"17 connect(4<TCP:[2]>, {inet('127.0.0.1', 8080)}, 16) = 0")
    rules = endpoints.rules([first, second], {})
    assert texts(rules.connect) == ("allow 127.0.0.1:8080",)
    assert "must exist at grading time" in rules.connect[0].comment


def test_a_hello_after_a_connect_to_a_proxy_does_not_name_the_host_behind_it():
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('198.51.100.9', 3128)}, 16) = 0",
                     "16 write(3<TCP:[10.0.0.2:40000->198.51.100.9:3128]>, \"CONNECT example.org:443 HTTP/1.1\\r\\n\\r\\n\", 34) = 34",
                     f"16 write(3<TCP:[10.0.0.2:40000->198.51.100.9:3128]>, {hello_argument('example.org')}, 517) = 517")
    assert texts(rules.connect) == ("allow 198.51.100.9:3128",)


@pytest.mark.parametrize("name", ["localhost", "api.localhost", "0x7f.0x0.0x0.0x1", "2130706433"])
def test_a_server_name_that_means_the_loopback_or_an_address_shapes_no_rule(name):
    rules = rules_of(f"16 connect(3<TCP:[1]>, {inet('192.0.2.7', 443)}, 16) = 0",
                     f"16 write(3<TCP:[10.0.0.2:40000->192.0.2.7:443]>, {hello_argument(name)}, 517) = 517")
    assert texts(rules.connect) == ("allow 192.0.2.7:443",)


def test_a_port_bound_by_a_parent_and_named_by_its_child_after_a_fork_is_held():
    rules = rules_of(f"16 bind(3<TCP:[1]>, {inet('127.0.0.1', 0)}, 16) = 0",
                     "16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
                     "17 listen(3<TCP:[127.0.0.1:40623]>, 128) = 0",
                     f"18 connect(4<TCP:[2]>, {inet('127.0.0.1', 40623)}, 16) = 0")
    assert texts(rules.connect) == ("allow 127.0.0.1:*",)


def test_a_datagram_sent_through_a_message_call_names_its_destination():
    data = quoted(b"u")
    rules = rules_of(f"16 sendmsg(5<UDP:[3]>, {{msg_name={inet('198.51.100.5', 123)}, msg_namelen=16, "
                     f"msg_iov=[{{iov_base={data}, iov_len=1}}], msg_iovlen=1}}, 0) = 1")
    assert texts(rules.connect) == ("allow 198.51.100.5:123 udp",)
