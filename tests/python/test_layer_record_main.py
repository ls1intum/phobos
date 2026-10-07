"""Checks the recorder's command line: its warning, and every refusal before anything is recorded.

Each refusal happens before a session starts, so these run anywhere: PHOBOS_HOME points at a
directory the test shapes like the prune image or like the run-phase image.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_record import (
    guard,
    main,
)


@pytest.fixture
def prune_home(tmp_path, monkeypatch):
    """A PHOBOS_HOME with the prune image's shape."""
    home = tmp_path / "core"
    home.mkdir()
    (home / "BasePrune.cfg").write_text("# grants nothing\n")
    (home / "TailPhobos.cfg").write_text("--chdir /var/tmp/testing-dir\n")
    (home / "phobos.sh").write_text("#!/bin/sh\n")
    monkeypatch.setenv("PHOBOS_HOME", str(home))
    monkeypatch.setattr(main, "_own_status", lambda: "TracerPid:\t0\n")
    return home


def test_the_help_begins_with_the_warning(capsys):
    with pytest.raises(SystemExit):
        main.main(["--help"])
    assert capsys.readouterr().out.startswith("Records the reference program of an exercise. While it records, "
                                              "the program runs with no sandbox at all")


@pytest.mark.parametrize("arguments", [["record", "--config", "x.cfg", "--", "true"],
                                       ["record", "--resolver", "192.0.2.53", "--", "true"],
                                       ["check", "--config", "x.cfg", "--", "true"],
                                       ["record", "-nnr", "--", "true"]])
def test_a_grading_option_is_refused_with_the_usage_status(prune_home, arguments, capsys):
    assert main.main(arguments) == guard.EXIT_USAGE
    assert "does not grade" in capsys.readouterr().err


def test_the_layers_as_the_command_are_refused(prune_home):
    assert main.main(["record", "--", str(prune_home / "phobos.sh"), "--", "true"]) == guard.EXIT_USAGE
    assert main.main(["record", "--", "sh", str(prune_home / "phobos.sh")]) == guard.EXIT_USAGE


def test_the_run_phase_image_is_refused_with_the_environment_status(tmp_path, monkeypatch, capsys):
    home = tmp_path / "core"
    home.mkdir()
    (home / "BaseLanguage-java.cfg").write_text("[read]\n/usr\n")
    monkeypatch.setenv("PHOBOS_HOME", str(home))
    assert main.main(["record", "--", "true"]) == guard.EXIT_ENVIRONMENT
    assert "prune image" in capsys.readouterr().err


def test_a_traced_recorder_is_refused(prune_home, monkeypatch):
    monkeypatch.setattr(main, "_own_status", lambda: "TracerPid:\t42\n")
    assert main.main(["record", "--", "true"]) == guard.EXIT_ENVIRONMENT


def test_a_missing_command_is_a_usage_error(prune_home):
    assert main.main(["record"]) == guard.EXIT_USAGE


@pytest.mark.parametrize("name", ["../escape", "a/b", ".hidden", ""])
def test_a_recording_name_that_could_leave_the_recordings_is_refused(prune_home, name):
    assert main.main(["record", "--name", name, "--", "true"]) == guard.EXIT_USAGE


def test_check_takes_a_resolver_and_still_needs_a_generated_policy(prune_home, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(main, "RECORDINGS", tmp_path / "recordings")
    assert main.main(["check", "--resolver", "192.0.2.53", "--", "true"]) == guard.EXIT_USAGE
    assert "policy.cfg" in capsys.readouterr().err


def test_an_abbreviated_option_is_never_taken_for_another(prune_home):
    with pytest.raises(SystemExit) as ended:
        main.main(["record", "--na", "x", "--", "true"])
    assert ended.value.code == 2


def test_a_malformed_script_is_refused_before_anything_is_recorded(prune_home, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "RECORDINGS", tmp_path / "recordings")
    script = tmp_path / "bad.script"
    script.write_text("type x\n")
    assert main.main(["record", "--script", str(script), "--", "true"]) == guard.EXIT_USAGE
    assert not (tmp_path / "recordings").exists()


def test_an_exercise_that_is_not_a_directory_is_refused(prune_home, tmp_path):
    assert main.main(["record", "--exercise", str(tmp_path / "missing"), "--", "true"]) == guard.EXIT_USAGE


def test_the_layers_named_relative_to_the_working_directory_are_refused(tmp_path):
    home = tmp_path / "core"
    home.mkdir()
    (home / "phobos.sh").write_text("#!/bin/sh\n")
    work = tmp_path / "work"
    work.mkdir()
    (work / "run").symlink_to(home / "phobos.sh")
    with pytest.raises(guard.Refused):
        guard.refuse_layer_command(["./run"], home, work)
