"""Checks the recorder's refusals: it must never look like grading or run where grading runs.

The recorder grants everything while it records, so the one thing worse than a recorder that
fails is one that is taken for the sandbox. These refusals are safeguards against that mistake,
not containment, and each is tested in both directions: the refused case and its neighbour that
is accepted.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_record import guard


def test_a_config_option_is_refused_as_grading():
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_grading_options(["--config", "exercise.cfg", "--", "python3"])
    assert refused.value.status == guard.EXIT_USAGE
    assert "does not grade" in refused.value.message


@pytest.mark.parametrize("option", ["-c", "--resolver", "-nnr", "--no-filesystem-restriction", "-nr",
                                    "--no-timeoutsystem-restriction", "-ntr", "--no-networksystem-restriction",
                                    "--no-resourcesystem-restriction", "-nrr", "-nfr", "--no-restriction"])
def test_every_grading_switch_is_refused(option):
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_grading_options([option, "x", "--", "python3"])
    assert refused.value.status == guard.EXIT_USAGE


@pytest.mark.parametrize("option", ["--config=exercise.cfg", "--resolver=192.0.2.53"])
def test_a_grading_option_with_its_value_attached_is_refused_too(option):
    with pytest.raises(guard.Refused):
        guard.refuse_grading_options(["record", option, "--", "python3"])


def test_arguments_after_the_separator_belong_to_the_command():
    guard.refuse_grading_options(["--", "python3", "--config", "x"])


def test_the_recorders_own_options_are_accepted():
    guard.refuse_grading_options(["record", "--name", "s", "--script", "session.script", "--", "python3"])


def test_the_run_phase_image_is_refused(tmp_path):
    (tmp_path / "BaseLanguage-java.cfg").write_text("[read]\n/usr\n")
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_outside_prune_image(tmp_path)
    assert refused.value.status == guard.EXIT_ENVIRONMENT


def test_a_prune_base_beside_another_base_is_refused(tmp_path):
    (tmp_path / "BasePrune.cfg").write_text("# grants nothing\n")
    (tmp_path / "BaseLanguage-java.cfg").write_text("[read]\n/usr\n")
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_outside_prune_image(tmp_path)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "BaseLanguage-java.cfg" in refused.value.message


def test_the_prune_image_is_accepted(tmp_path):
    (tmp_path / "BasePrune.cfg").write_text("# grants nothing\n")
    guard.refuse_outside_prune_image(tmp_path)


def test_the_layers_themselves_cannot_be_recorded(tmp_path):
    (tmp_path / "phobos.sh").write_text("#!/bin/sh\n")
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_layer_command([str(tmp_path / "phobos.sh"), "--config", "x"], tmp_path)
    assert refused.value.status == guard.EXIT_USAGE


def test_the_layers_started_through_an_interpreter_are_refused_too(tmp_path):
    (tmp_path / "phobos.sh").write_text("#!/bin/sh\n")
    with pytest.raises(guard.Refused):
        guard.refuse_layer_command(["sh", str(tmp_path / "phobos.sh"), "--", "true"], tmp_path)


def test_the_layers_found_through_the_path_are_refused_too(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "phobos.sh").write_text("#!/bin/sh\n")
    (home / "phobos.sh").chmod(0o755)
    bin_directory = tmp_path / "bin"
    bin_directory.mkdir()
    (bin_directory / "phobos").symlink_to(home / "phobos.sh")
    monkeypatch.setenv("PATH", str(bin_directory))
    with pytest.raises(guard.Refused):
        guard.refuse_layer_command(["phobos", "--", "true"], home)


def test_a_program_outside_the_layers_is_accepted(tmp_path):
    guard.refuse_layer_command(["python3", "-q"], tmp_path)


def test_a_file_beside_the_layers_but_outside_their_directory_is_accepted(tmp_path):
    home = tmp_path / "core"
    home.mkdir()
    (tmp_path / "core-notes.txt").write_text("not part of Phobos\n")
    guard.refuse_layer_command(["cat", str(tmp_path / "core-notes.txt")], home)


def test_a_traced_recorder_refuses():
    with pytest.raises(guard.Refused) as refused:
        guard.refuse_when_traced("Name:\tpython3\nTracerPid:\t42\n")
    assert refused.value.status == guard.EXIT_ENVIRONMENT


def test_an_untraced_recorder_is_accepted():
    guard.refuse_when_traced("Name:\tpython3\nTracerPid:\t0\n")
