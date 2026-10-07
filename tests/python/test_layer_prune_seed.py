"""Checks the per-language seed: what a seed may name, how it starts the filesystem stage, what the policy says
about it, and that nothing else under /tmp or elsewhere is ever write-granted by a refusal (decision 7)."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, generalise, record, runner, search, seed, stages

SHIPPED = REPO_ROOT / "docker" / "prune_phase" / "layers" / "seeds"


def seed_file(directory: pathlib.Path, text: str, name: str = "java.cfg") -> pathlib.Path:
    """Writes a seed into a directory; the directory."""
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(text)
    return directory


@pytest.mark.parametrize("name", ["java.cfg", "java-2.cfg", "a_b.c.cfg"])
def test_a_plain_cfg_file_name_is_a_seed_name(name):
    assert seed.parse_name(name, "prune.json") == name


@pytest.mark.parametrize("name", ["../java.cfg", "/etc/java.cfg", "java", "java.cfg/", ".java.cfg", "a b.cfg", "",
                                  "java.cfg\n", 1, None, ["java.cfg"]])
def test_anything_else_is_refused_as_a_seed_name(name):
    with pytest.raises(ValueError):
        seed.parse_name(name, "prune.json")


def test_the_shipped_java_seed_names_only_the_scratch_directory_and_is_a_seed_the_loader_accepts():
    loaded = seed.load("java.cfg", str(SHIPPED))
    assert loaded.fs == {"/tmp": frozenset({"read", "write", "create", "delete"})}
    assert not (loaded.connect or loaded.bind or loaded.limits)


@pytest.mark.parametrize("text, why", [
    ("", "names no row"),
    ("[connect]\nallow 10.0.0.1:80\n", "more than filesystem rows"),
    ("[limits]\ntimeout=5\n", "more than filesystem rows"),
    ("[execute]\n/tmp\n", "which a seed may not"),
    ("[write]\n/\n", "the root"),
    ("[write]\n/var/tmp\n", "specification directory"),
    ("[create]\n/var\n", "specification directory"),
    ("[write]\n/tmp/does-not-exist-for-a-seed\n", "not an existing real directory"),
    ("[write]\n/etc/hostname\n", "not an existing real directory"),
    ("not a policy\n", "cannot be read"),
])
def test_a_seed_that_names_more_than_scratch_rows_on_existing_directories_is_refused(tmp_path, text, why):
    with pytest.raises(ValueError, match=why):
        seed.load("java.cfg", str(seed_file(tmp_path / "seeds", text)))


def test_a_missing_or_linked_seed_is_refused(tmp_path):
    with pytest.raises(ValueError, match="is not a file"):
        seed.load("java.cfg", str(tmp_path))
    real = tmp_path / "real.cfg"
    real.write_text("[write]\n/tmp\n")
    (tmp_path / "java.cfg").symlink_to(real)
    with pytest.raises(ValueError, match="is not a file"):
        seed.load("java.cfg", str(tmp_path))


def test_the_comment_above_a_seed_row_says_where_it_comes_from_and_that_the_shipped_base_grants_it():
    loaded = seed.load("java.cfg", str(SHIPPED))
    text = cfgfile.render(cfgfile.Policy(fs=loaded.fs, connect=(), bind=(), limits={},
                                         comments=seed.comments_for("java.cfg", loaded)))
    assert "# seed: [create], [delete], [read], [write] on /tmp come from the java.cfg seed" in text
    assert "the shipped base grants them already" in text
    assert cfgfile.read_policy(text).fs == loaded.fs


def pruning_for(tmp_path: pathlib.Path, seed_name: str | None) -> stages.Pruning:
    """A pruning of a minimal exercise whose prune.json names `seed_name`."""
    directory = tmp_path / "exercise"
    directory.mkdir()
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    if seed_name is not None:
        (directory / "prune.json").write_text(json.dumps({"seed": seed_name}))
    return stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                          environment=runner.Environment())


def test_the_filesystem_stage_starts_from_the_seed_rows_and_keeps_their_comment_and_the_record(tmp_path):
    found = pruning_for(tmp_path, "java.cfg")
    started = stages.seed_policy(found, str(SHIPPED))
    assert started.fs == {"/tmp": frozenset({"read", "write", "create", "delete"})}
    assert "from the java.cfg seed" in found.comments["/tmp"]
    assert found.log[-1] == {"stage": "seed", "name": "java.cfg",
                             "rows": {"/tmp": ["create", "delete", "read", "write"]}}


def test_an_exercise_without_a_seed_starts_empty_as_before(tmp_path):
    found = pruning_for(tmp_path, None)
    assert stages.seed_policy(found, str(SHIPPED)).fs == {}
    assert found.comments == {} and found.log == []


def test_an_exercise_that_names_a_seed_that_is_not_there_aborts_instead_of_starting_without_it(tmp_path):
    found = pruning_for(tmp_path, "absent.cfg")
    with pytest.raises(search.PruneAbort, match="language seed cannot be used"):
        stages.seed_policy(found, str(tmp_path))


def test_prune_json_carries_the_seed_name_and_refuses_one_that_is_not_a_plain_name(tmp_path):
    assert pruning_for(tmp_path, "java.cfg").exercise.seed == "java.cfg"
    directory = tmp_path / "other"
    directory.mkdir()
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    for bad in ("../java.cfg", 7):
        (directory / "prune.json").write_text(json.dumps({"seed": bad}))
        with pytest.raises(runner.ExerciseRefused):
            runner.read_exercise(directory)


def denial(path: str, section: str) -> record.Denial:
    """A refused access of one section on one path."""
    return record.Denial(pid=300, layer=record.LAYER_FILESYSTEM, operation="openat", objects=(path,),
                         sections=frozenset({section}), address=None, port=None, transport=None, errno="EACCES",
                         run=1, tid=300)


SNAPSHOT = generalise.Snapshot(existing=frozenset({"/var/tmp/testing-dir", "/srv/data"}),
                               directories=frozenset({"/var/tmp/testing-dir", "/srv/data"}),
                               scanned=("/var/tmp/testing-dir", "/srv/data"))


@pytest.mark.parametrize("path", ["/tmp/EssentialPackages_123.yaml", "/tmp/surefire-root/stdout-1_4deferred",
                                  "/srv/other/new-name-456"])
@pytest.mark.parametrize("section", ["write", "create", "delete"])
def test_a_refusal_on_a_name_outside_the_scanned_roots_is_never_given_a_write_class_grant_by_a_refusal(path, section):
    grants, notes = generalise.grants_and_notes([denial(path, section)], SNAPSHOT, generalise.DEFAULT_FINE_ROOTS)
    assert grants == {}
    assert notes.reported[0]["section"] == section


def test_a_name_under_a_directory_the_run_created_in_is_still_only_reported_even_beside_the_seed_rows(tmp_path):
    """The seed starts the policy; it does not change what a refusal may ask for."""
    started = seed.load("java.cfg", str(SHIPPED))
    grants, _ = generalise.grants_and_notes([denial("/srv/other/new-name-456", "write")], SNAPSHOT,
                                            generalise.DEFAULT_FINE_ROOTS, started.fs)
    assert grants == {}
