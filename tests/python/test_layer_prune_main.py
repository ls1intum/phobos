"""Checks the pruner's command line: artefact names, stale removal, the record's hash and the exit contract."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, generalise, main, runner, search, stages

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
    def fake(exercise, budget, environment, stage, pristine):
        if exercise.name == "broken":
            raise search.PruneAbort("flaky reference", {"record": [{"stage": "baseline"}]})
        return cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={"cpu": 30}), [{"stage": stage}]
    monkeypatch.setattr(stages, "prune_exercise", fake)
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
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


def test_any_other_failure_is_written_as_a_defect_and_the_next_exercise_is_still_pruned(tmp_path, pruned, monkeypatch):
    def fake(exercise, budget, environment, stage, pristine):
        if exercise.name == "alpha":
            raise OSError("the trace file vanished")
        if exercise.name == "beta":
            raise runner.PrunerDefect(15, pathlib.Path("/var/tmp/layer-prune-logs/run-0001-layers.log"), "stopped")
        return cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={}), []
    monkeypatch.setattr(stages, "prune_exercise", fake)
    root = exercise_tree(tmp_path / "exercises", "alpha", "beta", "gamma")
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "java"]) == main.EXIT_ABORTED
    alpha = json.loads((output / "java_alpha.aborted.json").read_text())
    beta = json.loads((output / "java_beta.aborted.json").read_text())
    assert alpha["aborted"] == "a defect of the pruner: OSError: the trace file vanished"
    assert beta["evidence"] == {"status": 15, "log": "/var/tmp/layer-prune-logs/run-0001-layers.log"}
    assert (output / "java_gamma.cfg").exists()


def test_a_malformed_prune_json_aborts_its_exercise_only(tmp_path, pruned):
    root = exercise_tree(tmp_path / "exercises", "alpha", "beta")
    (root / "java" / "alpha" / "prune.json").write_text('{"declared_hosts": ["*.example.org:443"]}')
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "java"]) == main.EXIT_ABORTED
    aborted = json.loads((output / "java_alpha.aborted.json").read_text())
    assert aborted["aborted"].startswith("the exercise was refused:")
    assert (output / "java_beta.cfg").exists()


def test_a_stage_short_of_all_writes_under_partial_and_says_it_is_not_to_ship(tmp_path, pruned):
    root = exercise_tree(tmp_path / "exercises", "alpha")
    output = tmp_path / "out"
    assert main.main(["--stage", "filesystem", "--testing-root", str(root), "--output-dir", str(output), "java"]) == 0
    assert not (output / "java_alpha.cfg").exists()
    partial = (output / main.PARTIAL_DIRECTORY / "java_alpha.cfg").read_text()
    assert "stage filesystem" in partial
    assert "not a policy to ship" in partial


def test_a_testing_root_that_overlaps_the_working_directory_is_refused(tmp_path, pruned, capsys):
    working = runner.Environment().testing_dir
    assert main.main(["--testing-root", working, "--output-dir", str(tmp_path / "out"), "java"]) == main.EXIT_ABORTED
    assert "overlaps" in capsys.readouterr().err


def test_a_missing_key_is_named_and_a_hidden_directory_is_no_exercise(tmp_path, pruned, capsys):
    root = exercise_tree(tmp_path / "exercises", "alpha")
    (root / "java" / ".git").mkdir()
    output = tmp_path / "out"
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "python"]) == main.EXIT_ABORTED
    assert "no exercise under" in capsys.readouterr().err
    assert main.main(["--testing-root", str(root), "--output-dir", str(output), "java"]) == 0
    assert not list(output.glob("java_.git*"))


def test_an_output_directory_that_overlaps_the_working_directory_is_refused(tmp_path, pruned, capsys):
    root = exercise_tree(tmp_path / "exercises", "alpha")
    working = runner.Environment().testing_dir
    assert main.main(["--testing-root", str(root), "--output-dir", working + "/out", "java"]) == main.EXIT_ABORTED
    assert "output directory" in capsys.readouterr().err
