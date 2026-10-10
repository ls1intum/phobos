"""Checks which exercises belong to a key: the family fallback, the declared key, and what ends a run."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "pruner" / "src"))

from layer_prune import cfgfile, discovery, generalise, main, search, stages

ORIGIN = {"pruner": "phobos layer pruner", "kernel": "7.0", "architecture": "aarch64", "landlock_abi": 8, "uid": 0,
          "strace": "strace -- version 6.8", "date": "2026-10-06T00:00:00Z"}


def exercise(root: pathlib.Path, family: str, name: str, settings: object = None) -> pathlib.Path:
    """One exercise with a build script, and a prune.json holding settings when settings is not None."""
    directory = root / family / name
    directory.mkdir(parents=True)
    (directory / "build_script.sh").write_text("#!/bin/bash\nexit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    if settings is not None:
        (directory / "prune.json").write_text(settings if isinstance(settings, str) else json.dumps(settings))
    return directory


def names(directories: list[pathlib.Path]) -> list[str]:
    """The family and the name of each directory."""
    return [f"{directory.parent.name}/{directory.name}" for directory in directories]


def test_an_exercise_without_a_key_belongs_to_its_family(tmp_path):
    exercise(tmp_path, "python", "sorting")
    exercise(tmp_path, "java", "fixture")
    assert names(discovery.exercises_of(tmp_path, "python")) == ["python/sorting"]
    assert names(discovery.exercises_of(tmp_path, "java")) == ["java/fixture"]


def test_a_declared_key_wins_over_the_family(tmp_path):
    exercise(tmp_path, "java", "gradle-reference", {"key": "java-gradle"})
    exercise(tmp_path, "java", "maven-reference", {"key": "java-maven"})
    assert names(discovery.exercises_of(tmp_path, "java-gradle")) == ["java/gradle-reference"]
    assert names(discovery.exercises_of(tmp_path, "java-maven")) == ["java/maven-reference"]
    assert discovery.exercises_of(tmp_path, "java") == []


def test_one_key_can_gather_exercises_from_two_families(tmp_path):
    exercise(tmp_path, "java-gradle", "fixture")
    exercise(tmp_path, "java", "gradle-reference", {"key": "java-gradle"})
    assert names(discovery.exercises_of(tmp_path, "java-gradle")) == ["java/gradle-reference", "java-gradle/fixture"]


def test_hidden_folders_are_not_exercises(tmp_path):
    exercise(tmp_path, "java", ".git")
    exercise(tmp_path, ".cache", "alpha")
    exercise(tmp_path, "java", "alpha")
    assert names(discovery.exercises_of(tmp_path, "java")) == ["java/alpha"]


def test_a_setting_other_than_the_key_does_not_matter_here(tmp_path):
    exercise(tmp_path, "java", "alpha", {"declared_hosts": "not a list", "key": "java-gradle"})
    exercise(tmp_path, "java", "beta", {"declared_hosts": "not a list"})
    assert names(discovery.exercises_of(tmp_path, "java-gradle")) == ["java/alpha"]
    assert names(discovery.exercises_of(tmp_path, "java")) == ["java/beta"]


@pytest.mark.parametrize("text", ["{not json", "[]", "null", '"text"', '{"key": 3}', '{"key": ""}', '{"key": "Java"}',
                                  '{"key": "java_gradle"}', '{"key": "-java"}', '{"key": "java--gradle"}'])
def test_a_prune_json_that_names_no_usable_key_is_refused(tmp_path, text):
    exercise(tmp_path, "java", "alpha", text)
    with pytest.raises(discovery.DiscoveryRefused):
        discovery.exercises_of(tmp_path, "python")


def test_a_prune_json_that_is_not_text_is_refused(tmp_path):
    directory = exercise(tmp_path, "java", "alpha")
    (directory / "prune.json").write_bytes(b"\xff\xfe")
    with pytest.raises(discovery.DiscoveryRefused):
        discovery.exercises_of(tmp_path, "java")


def test_a_prune_json_that_is_not_a_file_is_refused_rather_than_taken_for_absent(tmp_path):
    directory = exercise(tmp_path, "java", "alpha")
    (directory / "prune.json").mkdir()
    with pytest.raises(discovery.DiscoveryRefused):
        discovery.exercises_of(tmp_path, "java")
    (directory / "prune.json").rmdir()
    (directory / "prune.json").symlink_to(tmp_path / "nowhere.json")
    with pytest.raises(discovery.DiscoveryRefused):
        discovery.exercises_of(tmp_path, "java")


def test_two_exercises_of_one_key_with_one_name_are_refused_naming_both(tmp_path):
    first = exercise(tmp_path, "java", "reference", {"key": "java-gradle"})
    second = exercise(tmp_path, "other", "reference", {"key": "java-gradle"})
    with pytest.raises(discovery.DiscoveryRefused) as refusal:
        discovery.exercises_of(tmp_path, "java-gradle")
    assert str(first) in str(refusal.value)
    assert str(second) in str(refusal.value)


def test_one_name_under_two_keys_is_not_a_clash(tmp_path):
    exercise(tmp_path, "java", "reference", {"key": "java-gradle"})
    exercise(tmp_path, "other", "reference", {"key": "java-maven"})
    assert names(discovery.exercises_of(tmp_path, "java-gradle")) == ["java/reference"]
    assert names(discovery.exercises_of(tmp_path, "java-maven")) == ["other/reference"]


@pytest.fixture
def pruned(monkeypatch):
    """Replaces the pipeline, so only discovery and the writing of artefacts are measured."""
    monkeypatch.setattr(stages, "prune_exercise", lambda exercise, budget, environment, stage, pristine: (
        cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={"cpu": 30}), [{"stage": stage}]))
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)


def test_the_artefacts_carry_the_declared_key(tmp_path, pruned):
    exercise(tmp_path / "exercises", "java", "gradle-reference", {"key": "java-gradle"})
    exercise(tmp_path / "exercises", "java", "maven-reference", {"key": "java-maven"})
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(tmp_path / "exercises"), "--output-dir", str(output), "java-gradle"]) == 0
    assert sorted(path.name for path in output.iterdir()) == ["java-gradle_gradle-reference.cfg",
                                                              "java-gradle_gradle-reference.json"]


def test_a_refused_discovery_writes_nothing_and_removes_nothing(tmp_path, pruned, capsys):
    exercise(tmp_path / "exercises", "java", "alpha", {"key": "java-gradle"})
    exercise(tmp_path / "exercises", "python", "broken", "{not json")
    output = tmp_path / "out"
    output.mkdir()
    (output / "java-gradle_old.cfg").write_text("kept")
    assert main.main(["--testing-root", str(tmp_path / "exercises"), "--output-dir", str(output), "java-gradle"]) == 1
    assert sorted(path.name for path in output.iterdir()) == ["java-gradle_old.cfg"]
    assert "nothing was written" in capsys.readouterr().err


def test_a_key_no_exercise_has_ends_the_run(tmp_path, pruned, capsys):
    exercise(tmp_path / "exercises", "java", "alpha", {"key": "java-gradle"})
    assert main.main(["--testing-root", str(tmp_path / "exercises"), "--output-dir", str(tmp_path / "out"), "java"]) == 1
    assert "no exercise under" in capsys.readouterr().err


def test_a_search_abort_is_still_one_exercises_alone(tmp_path, monkeypatch, pruned):
    def fake(exercise, budget, environment, stage, pristine):
        if exercise.name == "broken":
            raise search.PruneAbort("flaky reference", {"record": [{"stage": "baseline"}]})
        return cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={"cpu": 30}), [{"stage": stage}]
    monkeypatch.setattr(stages, "prune_exercise", fake)
    exercise(tmp_path / "exercises", "java", "alpha", {"key": "java-gradle"})
    exercise(tmp_path / "exercises", "java", "broken", {"key": "java-gradle"})
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(tmp_path / "exercises"), "--output-dir", str(output), "java-gradle"]) == 1
    assert (output / "java-gradle_alpha.cfg").exists()
    assert (output / "java-gradle_broken.aborted.json").exists()
