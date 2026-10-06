"""Checks how the replay check decides whether it runs in a fresh container.

A replay in the recording's own container, or in one that something changed, can pass on what
was left behind. The check therefore compares the container's starting state with the
recording's instead of taking freshness on trust, and refuses a container that is not fresh
unless the caller explicitly opts in (Markus's decision 12 in the plan).
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_record import (
    check,
    guard,
    snapshot,
)

START = {"/": "d 0755", "/etc": "d 0755", "/etc/os-release": "f 0644 386 1700000000000000000",
         "/var/tmp/testing-dir": "d 0755", "/var/tmp/testing-dir/old.txt": "f 0644 4 1700000000000000000"}


def recording_with_session(directory: pathlib.Path, container_id: str, fingerprint: dict[str, str],
                           number: int = 1) -> pathlib.Path:
    """Writes a recording directory holding one session recorded in the given container.

    The snapshot also lists the three files Docker writes into every container, as a real one
    taken by snapshot.take does, so the comparison has to leave them out to call a container
    fresh.
    """
    recording = directory / "recording"
    session = recording / "sessions" / str(number)
    session.mkdir(parents=True)
    (recording / "snapshots").mkdir(exist_ok=True)
    listed = fingerprint | {path: "f 0644 12 1700000000000000000" for path in snapshot.DOCKER_MANAGED}
    lines = "".join(f"{value}\t{path}\n" for path, value in sorted(listed.items()))
    (recording / "snapshots" / f"{container_id}.txt").write_text(lines)
    meta = {"container_id": container_id, "snapshot": f"snapshots/{container_id}.txt"}
    (session / "session.json").write_text(json.dumps(meta))
    return recording


def test_another_container_with_the_recordings_starting_state_is_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "bbb", START, same_container=False) == "fresh-container"


def test_a_fresh_container_stays_fresh_with_the_opt_in(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "bbb", START, same_container=True) == "fresh-container"


def test_an_added_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/var/tmp/testing-dir/out.txt": "f 0644 1 1700000000000000001"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "/var/tmp/testing-dir/out.txt" in refused.value.message
    assert check.mode(recording, "bbb", changed, same_container=True) == "changed-container"


def test_a_removed_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = {path: value for path, value in START.items() if path != "/var/tmp/testing-dir/old.txt"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/var/tmp/testing-dir/old.txt" in refused.value.message


def test_a_modified_file_at_an_existing_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/etc/os-release": "f 0644 391 1700000000500000000"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/etc/os-release" in refused.value.message


def test_at_most_twenty_differences_are_named(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {f"/var/tmp/leftover-{number:02d}": "f 0644 1 1" for number in range(25)}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/var/tmp/leftover-19" in refused.value.message
    assert "/var/tmp/leftover-20" not in refused.value.message
    assert "5 more" in refused.value.message


def test_the_fingerprint_sees_contents_change_through_size_and_time_and_skips_docker_files(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text("A\n")
    (root / "etc" / "hostname").write_text("one\n")
    before = snapshot.fingerprint(root=root)
    (root / "etc" / "os-release").write_text("AB\n")
    (root / "etc" / "hostname").write_text("another\n")
    after = snapshot.fingerprint(root=root)
    assert before["/etc/os-release"] != after["/etc/os-release"]
    assert "/etc/hostname" not in before


def test_the_recordings_own_container_is_refused_without_the_opt_in(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "aaa", START, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "aaa" in refused.value.message


def test_a_container_any_session_ran_in_is_the_recordings_own(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    recording_with_session(tmp_path, container_id="ccc", fingerprint=START, number=2)
    with pytest.raises(guard.Refused):
        check.mode(recording, "ccc", START, same_container=False)


def test_the_opt_in_runs_in_the_same_container_and_says_so(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "aaa", START, same_container=True) == "same-container"
    assert "can make it pass where a fresh container would fail" in check.NOT_FRESH_WARNING


def test_the_first_session_decides_the_starting_state(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    later = START | {"/var/tmp/testing-dir/out.txt": "f 0644 1 1"}
    recording_with_session(tmp_path, container_id="ccc", fingerprint=later, number=10)
    assert check.mode(recording, "bbb", START, same_container=False) == "fresh-container"


def test_a_recording_without_a_session_is_refused(tmp_path):
    (tmp_path / "empty" / "sessions").mkdir(parents=True)
    with pytest.raises(guard.Refused) as refused:
        check.mode(tmp_path / "empty", "bbb", START, same_container=False)
    assert refused.value.status == guard.EXIT_USAGE
