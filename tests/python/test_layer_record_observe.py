"""Checks how one session is recorded: where it runs, what it starts from, and that its trace is whole.

Recording under strace needs ptrace of the recorder's own children, which the prune image allows
and a developer's machine may not; those tests skip without strace. The same ground is covered in
the prune image by tests/integration/record_interactive.sh and record_replay.sh, through the
recorder's command line rather than these functions.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_record import (
    observe,
    snapshot,
)

NEEDS_STRACE = pytest.mark.skipif(shutil.which("strace") is None or sys.platform != "linux",
                                  reason="strace is only in the prune image")


def test_the_working_directory_is_the_tails(tmp_path):
    tail = tmp_path / "TailPhobos.cfg"
    tail.write_text("# comment\n--chdir /var/tmp/testing-dir\n")
    assert observe.tail_chdir(tail) == pathlib.Path("/var/tmp/testing-dir")


def test_tail_flags_without_a_working_directory_are_refused(tmp_path):
    tail = tmp_path / "TailPhobos.cfg"
    tail.write_text("--minimum-landlock-version 5\n")
    with pytest.raises(ValueError, match="--chdir"):
        observe.tail_chdir(tail)


def test_the_exercise_is_copied_with_its_times_and_replaces_files_of_the_same_name(tmp_path):
    exercise = tmp_path / "exercise"
    (exercise / "src").mkdir(parents=True)
    (exercise / "src" / "a.txt").write_text("new")
    os.utime(exercise / "src" / "a.txt", ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    workdir = tmp_path / "work"
    (workdir / "src").mkdir(parents=True)
    (workdir / "src" / "a.txt").write_text("old")
    observe.copy_exercise(exercise, workdir)
    assert (workdir / "src" / "a.txt").read_text() == "new"
    assert (workdir / "src" / "a.txt").stat().st_mtime_ns == 1_700_000_000_000_000_000


def test_without_an_exercise_only_the_working_directory_is_made(tmp_path):
    observe.copy_exercise(None, tmp_path / "work")
    assert (tmp_path / "work").is_dir()
    assert list((tmp_path / "work").iterdir()) == []


def test_a_container_is_listed_once_before_its_first_session_and_after_the_exercise_copy(tmp_path):
    root = tmp_path / "root"
    workdir = root / "work"
    exercise = tmp_path / "exercise"
    exercise.mkdir()
    (exercise / "old.txt").write_text("x")
    recording = tmp_path / "recording"
    listing = observe.prepare_container(recording, workdir, exercise, root=root)
    assert "/work/old.txt" in snapshot.read_listing(listing)
    (workdir / "later.txt").write_text("y")
    assert observe.prepare_container(recording, workdir, exercise, root=root) == listing
    assert "/work/later.txt" not in snapshot.read_listing(listing)


@NEEDS_STRACE
def test_a_recorded_session_keeps_the_commands_status_and_a_complete_trace(tmp_path):
    result = observe.record_session(["sh", "-c", "cat /etc/hostname > /dev/null; exit 7"], tmp_path, tmp_path, None)
    assert result.status == 7
    directory = tmp_path / "sessions" / str(result.number)
    trace = (directory / "trace").read_text()
    assert '"/etc/hostname"' in trace
    assert "exit_group(7)" in trace
    meta = json.loads((directory / "session.json").read_text())
    assert meta["status"] == 7
    assert meta["container_id"]
    assert meta["scripted"] is False


@NEEDS_STRACE
def test_a_child_that_outlives_the_command_is_still_in_the_trace(tmp_path):
    result = observe.record_session(["sh", "-c", "sleep 1 & exit 0"], tmp_path, tmp_path, None)
    assert result.status == 0
    trace = (tmp_path / "sessions" / str(result.number) / "trace").read_text()
    assert trace.count("exit_group(0)") >= 2


@NEEDS_STRACE
def test_a_scripted_session_runs_in_a_terminal_and_records_whether_its_expectations_held(tmp_path):
    script = tmp_path / "s.script"
    script.write_text('send import sys; print("OK-" + str(sys.stdin.isatty()))\nexpect OK-True\nsend exit()\n')
    result = observe.record_session([sys.executable, "-q", "-i"], tmp_path, tmp_path, script)
    assert result.status == 0
    assert result.expectations_met is True
    meta = json.loads((tmp_path / "sessions" / str(result.number) / "session.json").read_text())
    assert meta["interactive"] is True
    assert meta["script_sha256"] == observe.script_digest(script)


@NEEDS_STRACE
def test_a_process_the_session_leaves_running_is_stopped_and_named(tmp_path, monkeypatch):
    monkeypatch.setattr(observe, "LINGER_SECONDS", 1.0)
    result = observe.record_session(["sh", "-c", "sleep 60 & exit 0"], tmp_path, tmp_path, None)
    meta = json.loads((tmp_path / "sessions" / str(result.number) / "session.json").read_text())
    assert result.status == 0
    assert any(entry.endswith(" sleep") for entry in meta["stopped_leftovers"])


@NEEDS_STRACE
def test_a_command_ended_by_a_signal_reports_it(tmp_path):
    result = observe.record_session(["sh", "-c", "kill -TERM $$"], tmp_path, tmp_path, None)
    assert result.status == 128 + 15
    assert result.signal == 15
