"""Checks the comparison of recorded sessions with an existing policy: what is missing, unused or covered (plan A.12)."""

from __future__ import annotations

import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))
sys.path.insert(0, str(REPO_ROOT / "tests" / "python"))

from layer_prune import cfgfile
from layer_record import diff, generate
from test_layer_record_generate import listing_of, recording_directory

HOSTNAME = '16 openat(AT_FDCWD</opt/w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'
LIBRARY = '16 openat(AT_FDCWD</opt/w>, "/usr/lib/x.so", O_RDONLY) = 3</usr/lib/x.so>'


def report_of(tmp_path: pathlib.Path, policy_text: str, *lines: str) -> diff.Report:
    """The comparison of a one-session recording of the trace lines with the policy text."""
    listing = listing_of("/etc/hostname", "/usr/lib/x.so", directories=("/etc", "/usr", "/usr/lib", "/opt", "/opt/w"))
    recording = generate.load(recording_directory(tmp_path, list(lines), listing=listing))
    return diff.compare([recording], cfgfile.read_policy(policy_text))


def test_a_need_no_rule_covers_is_missing(tmp_path):
    report = report_of(tmp_path, "[read]\n/usr\n", HOSTNAME)
    assert report.missing == ["[read] /etc/hostname"]


def test_an_ancestor_rule_covers_a_need(tmp_path):
    assert report_of(tmp_path, "[read]\n/usr\n", LIBRARY).missing == []


def test_a_rule_no_session_touched_is_unused(tmp_path):
    report = report_of(tmp_path, "[read]\n/usr\n/opt\n", LIBRARY)
    assert report.unused == ["[read] /opt"]


def test_a_rule_an_ancestor_covers_is_marked_and_not_called_unused(tmp_path):
    report = report_of(tmp_path, "[read]\n/usr\n/usr/lib\n", LIBRARY)
    assert "[read] /usr/lib" in report.covered_by_ancestor
    assert "[read] /usr/lib" not in report.unused


def test_a_section_whose_rights_were_not_asked_for_is_unused_beside_one_that_was(tmp_path):
    report = report_of(tmp_path, "[read]\n/usr\n[execute]\n/usr\n", LIBRARY)
    assert report.unused == ["[execute] /usr"]


def test_an_endpoint_no_rule_admits_is_missing(tmp_path):
    connect = ['16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = 0']
    report = report_of(tmp_path, "[connect]\nallow 127.0.0.1:*\n", *connect)
    assert report.missing == ["[connect] allow 192.0.2.7:80"]
    assert report.unused == ["[connect] allow 127.0.0.1:*"]


def test_a_loopback_wildcard_covers_a_loopback_endpoint_and_is_used_by_it(tmp_path):
    lines = ['16 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(40000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
             '17 connect(4<TCP:[2]>, {sa_family=AF_INET, sin_port=htons(40000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0']
    report = report_of(tmp_path, "[connect]\nallow localhost\n[bind]\nallow 40000\n", *lines)
    assert report.missing == []
    assert report.unused == []


def test_the_report_names_all_three_lists(tmp_path):
    text = diff.render(report_of(tmp_path, "[read]\n/usr\n/opt\n", HOSTNAME, LIBRARY))
    assert "Needed by a session, not granted by the policy: 1" in text
    assert "Granted by the policy, used by no session: 1" in text
    assert "covered by an ancestor entry" in text


def test_an_ipv4_wildcard_does_not_cover_an_ipv6_loopback_need(tmp_path):
    address = ('{sa_family=AF_INET6, sin6_port=htons(40000), sin6_flowinfo=htonl(0), '
               'inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}')
    lines = [f"16 bind(3<TCP:[1]>, {address}, 28) = 0", f"17 connect(4<TCPv6:[2]>, {address}, 28) = 0"]
    report = report_of(tmp_path, "[connect]\nallow 127.0.0.1:*\n", *lines)
    assert "[connect] allow [::1]" in report.missing


def test_a_range_rule_is_never_called_unused(tmp_path):
    connect = ['16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = 0']
    report = report_of(tmp_path, "[connect]\nallow 192.0.2.0/24:80\n", *connect)
    assert not any("192.0.2.0/24" in row for row in report.unused)
