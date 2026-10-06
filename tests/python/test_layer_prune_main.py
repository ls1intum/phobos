"""Checks the pruner's command line: artefact names, stale removal, the record's hash and the exit contract."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, main, search, stages

ORIGIN = {"pruner": "phobos layer pruner", "kernel": "7.0", "architecture": "aarch64", "landlock_abi": 8, "uid": 0,
          "strace": "strace -- version 6.8", "date": "2026-10-06T00:00:00Z"}


def exercise_tree(root: pathlib.Path, *names: str) -> pathlib.Path:
    """A testing root with one exercise per name under the key java, each with a build script."""
    for name in names:
        directory = root / "java" / name
        directory.mkdir(parents=True)
        (directory / "build_script.sh").write_text("#!/bin/bash\nexit 0\n")
        (directory / "build_script.sh").chmod(0o755)
    return root


@pytest.fixture
def pruned(monkeypatch):
    """Replaces the pipeline: an exercise named "broken" aborts, any other gets a small policy."""
    def fake(exercise, budget, environment, stage):
        if exercise.name == "broken":
            raise search.PruneAbort("flaky reference", {"record": [{"stage": "baseline"}]})
        return cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={"cpu": 30}), [{"stage": stage}]
    monkeypatch.setattr(stages, "prune_exercise", fake)
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)


def test_every_exercise_gets_a_cfg_and_a_record_whose_hash_is_the_cfgs(tmp_path, pruned):
    root = exercise_tree(tmp_path / "exercises", "alpha")
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "java"]) == 0
    cfg = (output / "java_alpha.cfg").read_text()
    record = json.loads((output / "java_alpha.json").read_text())
    assert cfg.startswith("# Pruned by the phobos layer pruner for java/alpha")
    assert "[read]\n/usr\n" in cfg
    assert record["cfg_sha256"] == hashlib.sha256(cfg.encode()).hexdigest()
    assert record["schema_version"] == main.SCHEMA_VERSION


def test_earlier_artefacts_of_the_key_are_removed_and_other_keys_kept(tmp_path, pruned):
    root = exercise_tree(tmp_path / "exercises", "alpha")
    output = tmp_path / "out"
    output.mkdir()
    (output / "java_gone.cfg").write_text("[read]\n/x\n")
    (output / "java_gone.json").write_text("{}")
    (output / "python_kept.cfg").write_text("[read]\n/x\n")
    main.main(["--testing-root", str(root), "--output-dir", str(output), "java"])
    assert sorted(path.name for path in output.iterdir()) == ["java_alpha.cfg", "java_alpha.json", "python_kept.cfg"]


def test_an_aborted_exercise_writes_no_cfg_and_the_command_names_it(tmp_path, pruned, capsys):
    root = exercise_tree(tmp_path / "exercises", "alpha", "broken")
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "java"]) == main.EXIT_ABORTED
    assert not (output / "java_broken.cfg").exists()
    aborted = json.loads((output / "java_broken.aborted.json").read_text())
    assert aborted["aborted"] == "flaky reference"
    assert "java/broken: aborted: flaky reference" in capsys.readouterr().out
    assert (output / "java_alpha.cfg").exists()


def test_a_key_without_exercises_is_an_abort(tmp_path, pruned):
    root = tmp_path / "exercises"
    (root / "java").mkdir(parents=True)
    assert main.main(["--testing-root", str(root), "--output-dir", str(tmp_path / "out"), "java"]) == main.EXIT_ABORTED
