"""Checks the audit observer: records read as denials, the cross-check with strace, and the ABI 10 rows.

The fixture under fixtures/audit/ is written in the layout the kernel documents for the Landlock audit
records (Linux 6.15 and later), not captured: the KVM run uploads the raw lines it read, and they replace
this file once the first run has produced them. What these tests pin is this module's reading of that
layout, in both directions: an agreeing pair passes, a mismatched one is reported.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import audit, record

FIXTURE = REPO_ROOT / "tests" / "python" / "fixtures" / "audit" / "records.txt"


def strace_denial(path: str, *sections: str) -> record.Denial:
    """A Landlock filesystem denial as strace's attribution builds it."""
    return record.Denial(pid=7, layer=record.LAYER_FILESYSTEM, operation="openat", objects=(path,),
                         sections=frozenset(sections), address=None, port=None, transport=None, errno="EACCES")


@pytest.fixture(name="parsed")
def parsed_fixture():
    """The records and the unparsed lines of the fixture."""
    return audit.parse(FIXTURE.read_text().splitlines())


def test_each_kind_of_record_is_read_as_what_the_kernel_says_it_refused(parsed):
    records, unparsed = parsed
    by_blocker = {item.blockers: item for item in records}
    assert by_blocker[("fs.read_file",)].path in ("/etc/hostname", "/srv/with space/file")
    assert by_blocker[("fs.read_file", "fs.write_file")].path == "/srv/data/both.txt"
    assert by_blocker[("fs.make_reg",)].path == "/srv/data"
    assert by_blocker[("net.bind_udp",)].port == 5000
    assert by_blocker[("net.connect_tcp",)].port == 80
    assert len(records) == 8
    assert len(unparsed) == 1 and "damaged" in unparsed[0]


def test_a_path_with_an_unprintable_byte_is_decoded_from_its_hex(parsed):
    records, _ = parsed
    assert "/srv/with space/file" in [item.path for item in records]


def test_a_domain_record_and_other_lines_are_not_access_records():
    records, unparsed = audit.parse(['audit: type=1424 audit(1.0:1): domain=a status=allocated',
                                     "audit: type=1300 audit(1.0:2): arch=c000003e syscall=257",
                                     "some other kernel line"])
    assert records == [] and unparsed == []


def test_blockers_map_to_the_sections_of_the_call_table(parsed):
    records, _ = parsed
    sections = {item.blockers: audit.sections_of(item) for item in records}
    assert sections[("fs.read_file", "fs.write_file")] == {"read", "write"}
    assert sections[("fs.make_reg",)] == {"create"}
    assert sections[("fs.ioctl_dev",)] == frozenset()
    assert sections[("net.bind_udp",)] == frozenset()


def test_an_audit_record_that_agrees_with_the_strace_denial_leaves_no_mismatch(parsed):
    records, _ = parsed
    result = audit.cross_check([strace_denial("/etc/hostname", "read"),
                                strace_denial("/srv/data/both.txt", "read", "write"),
                                strace_denial("/srv/data", "create")], audit.denials(records))
    assert result["mismatches"] == []


def test_a_write_the_policy_already_half_held_agrees_because_audit_names_only_the_missing_right():
    records, _ = audit.parse(['audit: type=1423 audit(1.0:1): domain=a blockers=fs.write_file path="/srv/x"'])
    assert audit.cross_check([strace_denial("/srv/x", "read", "write")], audit.denials(records))["mismatches"] == []


def test_an_audit_record_for_another_right_or_another_object_is_a_mismatch(parsed):
    records, _ = parsed
    wrong_right = audit.cross_check([strace_denial("/etc/hostname", "write")], audit.denials(records))
    assert [item["objects"] for item in wrong_right["mismatches"]] == [["/etc/hostname"]]
    assert wrong_right["mismatches"][0]["audit_for_object"] == [["read"]]
    no_record = audit.cross_check([strace_denial("/never/refused", "read")], audit.denials(records))
    assert no_record["mismatches"][0]["audit_for_object"] == []


def test_a_deliberately_wrong_entry_in_the_mapping_makes_the_cross_check_fail(parsed, monkeypatch):
    records, _ = parsed
    attributed = [strace_denial("/etc/hostname", "read")]
    assert audit.cross_check(attributed, audit.denials(records))["mismatches"] == []
    monkeypatch.setitem(audit.FILESYSTEM_SECTIONS, "fs.read_file", frozenset({"write"}))
    assert len(audit.cross_check(attributed, audit.denials(records))["mismatches"]) == 1


def test_audit_denials_strace_did_not_attribute_are_reported_and_not_matched_twice(parsed):
    records, _ = parsed
    result = audit.cross_check([strace_denial("/etc/hostname", "read"), strace_denial("/etc/hostname", "read")],
                               audit.denials(records))
    assert len(result["mismatches"]) == 1
    leftover = [item["objects"] for item in result["audit_only"]]
    assert ["/srv/data/out.txt"] in leftover and ["/dev/null"] in leftover


def test_a_udp_bind_the_kernel_names_gives_exactly_one_row(parsed):
    records, _ = parsed
    rows, other = audit.abi10_rows(["allow 5000 udp"], records, [])
    assert rows == ["allow 5000 udp"] and other == []


def test_a_rule_the_kernel_did_not_name_or_that_is_not_a_udp_bind_is_never_a_row(parsed):
    records, _ = parsed
    rows, other = audit.abi10_rows(["allow 6000 udp", "allow 5000", "allow 127.0.0.1:*", "allow 0 udp"], records, [])
    assert rows == []
    assert other == ["allow 6000 udp", "allow 5000", "allow 127.0.0.1:*", "allow 0 udp"]


def test_a_row_the_policy_already_holds_is_not_added_again(parsed):
    records, _ = parsed
    assert audit.abi10_rows(["allow 5000 udp"], records, ["allow 5000 udp"]) == ([], [])


def test_a_quoted_path_is_taken_as_written_and_only_a_bare_one_is_decoded_from_hex():
    quoted, _ = audit.parse(['audit: type=1423 audit(1.0:1): domain=a blockers=fs.read_file path="AB"'])
    bare, _ = audit.parse(["audit: type=1423 audit(1.0:2): domain=a blockers=fs.read_file path=2F657463"])
    assert quoted[0].path == "AB" and bare[0].path == "/etc"


@pytest.mark.parametrize("rule", ["allow 0 udp", "allow 65536 udp", "allow 99999 udp", "allow 007 udp",
                                  "allow \u0665000 udp", "allow 5000 tcp", "allow 5000", "allow 5000 udp extra"])
def test_a_rule_that_is_not_a_udp_bind_on_a_port_from_1_to_65535_is_never_a_row_even_when_the_kernel_names_it(rule):
    records, _ = audit.parse(["audit: type=1423 audit(1.0:1): domain=a blockers=net.bind_udp lport=5000",
                              "audit: type=1423 audit(1.0:2): domain=a blockers=net.bind_udp lport=0",
                              "audit: type=1423 audit(1.0:3): domain=a blockers=net.bind_udp lport=65536"])
    rows, other = audit.abi10_rows([rule], records, [])
    assert rows == [] and other == [rule]


def test_the_largest_port_is_a_row_when_the_kernel_names_it():
    records, _ = audit.parse(["audit: type=1423 audit(1.0:1): domain=a blockers=net.bind_udp lport=65535"])
    assert audit.abi10_rows(["allow 65535 udp"], records, []) == (["allow 65535 udp"], [])


def test_a_strace_denial_that_asks_for_more_does_not_take_the_record_meant_for_one_that_asks_for_less():
    records, _ = audit.parse(['audit: type=1423 audit(1.0:1): domain=a blockers=fs.read_file path="/x"',
                              'audit: type=1423 audit(1.0:2): domain=a blockers=fs.read_file,fs.write_file path="/x"'])
    result = audit.cross_check([strace_denial("/x", "read", "write"), strace_denial("/x", "read")],
                               audit.denials(records))
    assert result["mismatches"] == [] and result["audit_only"] == []
