"""Checks the listing of every path that existed before a recorded session.

The snapshot decides two things later: whether a path the session touched existed before it
(only then may it become a [read] or [execute] row), and whether a replay container starts in
the recording's state. Both go wrong silently if a path is lost or misread, so the format is
checked to round-trip names that a line-based file could otherwise break.
"""

from __future__ import annotations

import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "pruner" / "src"))

from layer_record import snapshot


def test_the_snapshot_lists_the_tree_and_keeps_the_hosts_file_beside_it(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hosts").write_text("192.0.2.7 api.phobos.test\n")
    (root / "proc").mkdir()
    (root / "proc" / "1").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    snapshot.take(out / "c.txt", root=root)
    listing = (out / "c.txt").read_text().splitlines()
    assert any(line.startswith("f ") and line.endswith("\t/etc/hosts") for line in listing)
    assert not any(line.endswith("\t/proc/1") for line in listing)
    assert (out / "c.hosts").read_text() == "192.0.2.7 api.phobos.test\n"


def test_the_snapshot_counts_what_it_wrote_and_skips_the_kernel_trees_and_the_recordings(tmp_path):
    root = tmp_path / "root"
    (root / "sys" / "kernel").mkdir(parents=True)
    (root / "var" / "tmp" / "recordings" / "s").mkdir(parents=True)
    (root / "var" / "tmp" / "kept").write_text("x")
    written = snapshot.take(tmp_path / "c.txt", root=root)
    listing = snapshot.read_listing(tmp_path / "c.txt")
    assert written == len(listing)
    assert "/var/tmp/kept" in listing
    assert "/var/tmp" in listing
    assert "/sys" not in listing
    assert not any(path.startswith("/var/tmp/recordings") for path in listing)


def test_each_kind_of_path_gets_its_fingerprint(tmp_path):
    root = tmp_path / "root"
    (root / "d").mkdir(parents=True)
    (root / "d").chmod(0o750)
    (root / "d" / "f").write_text("abc")
    (root / "d" / "f").chmod(0o640)
    os.utime(root / "d" / "f", ns=(1_700_000_000_000_000_000, 1_700_000_000_123_456_789))
    (root / "d" / "l").symlink_to("f")
    os.mkfifo(root / "d" / "p", 0o600)
    listing = snapshot.fingerprint(root=root)
    assert listing["/d"] == "d 0750"
    assert listing["/d/f"] == "f 0640 3 1700000000123456789"
    assert listing["/d/l"] == "l f"
    assert listing["/d/p"] == "o 0600"


def test_a_symbolic_link_to_a_directory_is_listed_and_not_followed(tmp_path):
    root = tmp_path / "root"
    (root / "real").mkdir(parents=True)
    (root / "real" / "inside").write_text("x")
    (root / "alias").symlink_to("real")
    listing = snapshot.fingerprint(root=root)
    assert listing["/alias"] == "l real"
    assert "/alias/inside" not in listing
    assert "/real/inside" in listing


def test_a_pseudo_terminal_is_a_per_run_name_and_left_out(tmp_path):
    root = tmp_path / "root"
    (root / "dev" / "pts").mkdir(parents=True)
    (root / "dev" / "pts" / "0").write_text("")
    (root / "dev" / "pts" / "ptmx").write_text("")
    listing = snapshot.fingerprint(root=root)
    assert "/dev/pts/0" not in listing
    assert "/dev/pts/ptmx" in listing


def test_names_that_would_break_a_line_round_trip(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    awkward = ["tab\there", "new\nline", "carriage\rreturn", "back\\slash", "\\t literally"]
    for name in awkward:
        (root / name).write_text("x")
    (root / "link").symlink_to("target\twith\na break")
    snapshot.take(tmp_path / "c.txt", root=root)
    listing = snapshot.read_listing(tmp_path / "c.txt")
    for name in awkward:
        assert "/" + name in listing
    assert listing["/link"] == "l target\twith\na break"
    assert len((tmp_path / "c.txt").read_bytes().split(b"\n")) == len(listing) + 1


def test_the_listing_read_back_equals_the_fingerprint_with_the_docker_files(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hostname").write_text("one\n")
    (root / "etc" / "os-release").write_text("A\n")
    snapshot.take(tmp_path / "c.txt", root=root)
    listing = snapshot.read_listing(tmp_path / "c.txt")
    assert "/etc/hostname" in listing
    assert {path: value for path, value in listing.items() if path not in snapshot.DOCKER_MANAGED} \
        == snapshot.fingerprint(root=root)


def test_what_docker_creates_per_container_does_not_tell_two_fresh_containers_apart(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root, stamp in ((first, 1_791_260_710_613_437_001), (second, 1_791_260_712_120_437_002)):
        (root / "etc").mkdir(parents=True)
        (root / "dev").mkdir()
        (root / "etc" / "os-release").write_text("A\n")
        os.utime(root / "etc" / "os-release", ns=(stamp, 1_700_000_000_000_000_000))
        (root / ".dockerenv").write_text("")
        os.utime(root / ".dockerenv", ns=(stamp, stamp))
    (second / "dev" / "console").write_text("")
    assert snapshot.fingerprint(root=first) == snapshot.fingerprint(root=second)
    assert "/etc/os-release" in snapshot.fingerprint(root=first)


def test_no_hosts_copy_is_written_when_the_root_has_no_hosts_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    snapshot.take(tmp_path / "c.txt", root=root)
    assert not (tmp_path / "c.hosts").exists()
