"""Checks how the recorder recovers host names from what a recorded session sent and received.

The system calls a session makes only show addresses. A name comes from the TLS host name the
program sent, from a DNS answer it read, or from the hosts file. All three are written by the
program or by the network, so every parser here must survive malformed input without raising,
and no observed name may become a rule unless it is a plain DNS name.

The DNS fixtures are responses captured from a public resolver on 2026-10-06 (example.org, A
and AAAA; docs.python.org, A behind a CNAME). The ClientHello fixtures were produced by
Python's ssl module with OpenSSL 3.6 through a memory BIO, so no network was involved: one with
the host name example.org and TLS 1.3, one limited to TLS 1.2, and one without a host name.
"""

from __future__ import annotations

import pathlib
import struct
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from runtime_pruner.src.domain import names

FIXTURES = REPO_ROOT / "pruner" / "runtime_pruner" / "test" / "unit" / "domain" / "fixtures" / "record"


def dns_name(*labels: bytes) -> bytes:
    """The wire form of a DNS name from its labels, uncompressed."""
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def dns_response(question: bytes, address: str, answers: list[bytes] | None = None) -> bytes:
    """A response asking one name with one label, answered by one A record for that name.

    The answer's owner is a compression pointer to the question, as resolvers write it. Further
    answer records may be given whole, in wire form, to build chains and malformed messages.
    """
    records = answers if answers is not None else [
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(part) for part in address.split("."))]
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(records), 0, 0)
    return header + dns_name(question) + struct.pack("!HH", 1, 1) + b"".join(records)


def client_hello_with_server_name(name: bytes) -> bytes:
    """A minimal TLS 1.2 ClientHello whose server name extension carries the given bytes."""
    server_name = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(server_name)) + server_name
    body = (b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x00\x2f" + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_a_and_aaaa_answers_map_to_the_name_asked():
    answers = names.dns_answers((FIXTURES / "dns-example-org-a.bin").read_bytes())
    answers += names.dns_answers((FIXTURES / "dns-example-org-aaaa.bin").read_bytes())
    assert ("172.66.157.237", "example.org") in answers
    assert ("2606:4700:10::ac42:9ded", "example.org") in answers
    assert len(answers) == 4
    assert all(name == "example.org" for _, name in answers)


def test_a_cname_chain_maps_to_the_name_asked_not_the_alias():
    answers = names.dns_answers((FIXTURES / "dns-cname.bin").read_bytes())
    assert {name for _, name in answers} == {"docs.python.org"}
    assert ("151.101.0.223", "docs.python.org") in answers
    assert len(answers) == 4


def test_an_address_owned_by_a_name_outside_the_chain_is_not_attributed():
    stray = dns_name(b"elsewhere", b"test") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 99])
    own = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
    answers = names.dns_answers(dns_response(b"asked", "192.0.2.7", answers=[stray, own]))
    assert answers == [("192.0.2.7", "asked")]


def test_a_query_is_not_an_answer():
    assert names.dns_answers(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00") == []


def test_a_truncated_message_gives_no_answer_and_no_exception():
    assert names.dns_answers((FIXTURES / "dns-example-org-a.bin").read_bytes()[:20]) == []


@pytest.mark.parametrize("cut", range(61))
def test_every_truncation_of_a_response_is_survived_and_keeps_only_whole_answers(cut):
    whole = names.dns_answers((FIXTURES / "dns-example-org-a.bin").read_bytes())
    partial = names.dns_answers((FIXTURES / "dns-example-org-a.bin").read_bytes()[:cut])
    assert set(partial) <= set(whole)


def test_a_compression_loop_gives_no_answer_and_no_exception():
    looping = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
    message = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1) + looping
    assert names.dns_answers(message) == []


def test_a_forward_compression_pointer_gives_no_answer():
    message = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x20" + struct.pack("!HH", 1, 1) + bytes(40)
    assert names.dns_answers(message) == []


def test_two_questions_are_ambiguous_and_give_no_answer():
    message = dns_response(b"one", "192.0.2.7")
    message = message[:4] + struct.pack("!H", 2) + message[6:]
    assert names.dns_answers(message) == []


def test_the_server_name_of_a_client_hello():
    assert names.client_hello_server_name((FIXTURES / "hello-sni.bin").read_bytes()) == "example.org"


def test_the_server_name_of_a_tls_1_2_client_hello():
    assert names.client_hello_server_name((FIXTURES / "hello-tls12-sni.bin").read_bytes()) == "example.org"


def test_a_client_hello_without_a_server_name():
    assert names.client_hello_server_name((FIXTURES / "hello-no-sni.bin").read_bytes()) is None


def test_application_data_is_not_a_client_hello():
    assert names.client_hello_server_name(b"\x17\x03\x03\x00\x05hello") is None


@pytest.mark.parametrize("cut", range(183))
def test_every_truncation_of_a_client_hello_is_survived(cut):
    name = names.client_hello_server_name((FIXTURES / "hello-tls12-sni.bin").read_bytes()[:cut])
    assert name in (None, "example.org")


def test_a_server_name_cut_by_the_end_of_the_record_is_not_returned():
    hello = client_hello_with_server_name(b"example.org")
    assert names.client_hello_server_name(hello[:-3]) is None


@pytest.mark.parametrize("fixture", ["dns-example-org-a.bin", "dns-cname.bin", "hello-sni.bin", "hello-tls12-sni.bin"])
def test_no_single_corrupted_byte_makes_a_parser_raise(fixture):
    original = (FIXTURES / fixture).read_bytes()
    for index in range(len(original)):
        for value in (0x00, 0x3F, 0xC0, 0xFF):
            corrupted = original[:index] + bytes([value]) + original[index + 1:]
            assert isinstance(names.dns_answers(corrupted), list)
            assert names.client_hello_server_name(corrupted) is None or \
                isinstance(names.client_hello_server_name(corrupted), str)


@pytest.mark.parametrize("name", ["api.phobos.test", "API.Phobos.Test", "a-b.example.org", "localhost", "x1.org"])
def test_a_dns_name_is_a_valid_host_name(name):
    assert names.valid_hostname(name) == name.lower()


@pytest.mark.parametrize("name", ["evil\n[write]\n/", "a..b", "-a.example.org", "a-.example.org", "a" * 64 + ".org",
                                  "192.0.2.7", "::1", "a b.org", "", "*.example.org", "example.org.",
                                  "1.2.3", "127.1", "a.b.c.d" + ".e" * 124, "exa\\.mple.org", "caf\xe9.org",
                                  "under_score.org", ".example.org"])
def test_anything_else_is_not(name):
    assert names.valid_hostname(name) is None


def test_a_dns_answer_for_an_injected_name_yields_a_name_that_is_never_valid():
    answers = names.dns_answers(dns_response(question=b"x\n[write]\n/", address="192.0.2.7"))
    assert answers == [("192.0.2.7", "x\n[write]\n/")]
    assert names.valid_hostname(answers[0][1]) is None


def test_a_dot_inside_one_label_cannot_pass_for_two_labels():
    answers = names.dns_answers(dns_response(question=b"evil.example", address="192.0.2.7"))
    assert answers == [("192.0.2.7", "evil\\.example")]
    assert names.valid_hostname(answers[0][1]) is None


def test_a_client_hello_naming_an_injection_yields_a_name_that_is_never_valid():
    name = names.client_hello_server_name(client_hello_with_server_name(b"x\n[write]\n/"))
    assert name == "x\n[write]\n/"
    assert names.valid_hostname(name) is None


def test_the_hosts_file_maps_each_address_to_its_first_name():
    text = ("# comment\n127.0.0.1\tlocalhost\n::1 localhost ip6-localhost\n192.0.2.7 api.phobos.test api # tail\n"
            "192.0.2.7 second.phobos.test\n\n")
    assert names.hosts_file(text) == {"127.0.0.1": "localhost", "::1": "localhost", "192.0.2.7": "api.phobos.test"}


def test_a_malformed_hosts_line_is_skipped():
    text = "not-an-address name\n192.0.2.300 bad\n192.0.2.8\n192.0.2.9 good\n"
    assert names.hosts_file(text) == {"192.0.2.9": "good"}


def test_an_address_in_the_hosts_file_is_written_as_the_recorder_writes_it():
    assert names.hosts_file("2001:DB8:0:0:0:0:0:1 v6.phobos.test\n") == {"2001:db8::1": "v6.phobos.test"}
