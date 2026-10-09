"""Checks the per-language seed: what a seed may name, how it starts the filesystem stage, what the policy says
about it, and that a seed never widens what a refusal may ask for (decision 7).

The seeds name directories that must be real on the host the tests run on, so the cases build their own
seed directory under a resolved temporary path instead of relying on /tmp, which is a link on some systems.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "pruner" / "src"))

from layer_prune import cfgfile, generalise, record, runner, search, seed, stages

SHIPPED = REPO_ROOT / "docker" / "pruner" / "layers" / "seeds"
NOTHING = ()


@pytest.fixture(name="scratch")
def scratch_fixture(tmp_path):
    """A resolved scratch directory the seed may name, and the seed directory beside it."""
    base = pathlib.Path(os.path.realpath(tmp_path))
    (base / "scratch").mkdir()
    (base / "seeds").mkdir()
    return base


def write_seed(base: pathlib.Path, text: str, name: str = "java.cfg") -> str:
    """Writes a seed into the seed directory of `base`; the directory."""
    (base / "seeds" / name).write_text(text)
    return str(base / "seeds")


def rows(base: pathlib.Path, *sections: str) -> str:
    """Seed text naming the scratch directory in each section."""
    return "".join(f"[{section}]\n{base / 'scratch'}\n\n" for section in sections)


@pytest.mark.parametrize("name", ["java.cfg", "java-2.cfg", "a_b.c.cfg"])
def test_a_plain_cfg_file_name_is_a_seed_name(name):
    assert seed.parse_name(name, "prune.json") == name


@pytest.mark.parametrize("name", ["../java.cfg", "/etc/java.cfg", "java", "java.cfg/", ".java.cfg", "a b.cfg", "",
                                  "java.cfg\n", 1, None, ["java.cfg"]])
def test_anything_else_is_refused_as_a_seed_name(name):
    with pytest.raises(ValueError):
        seed.parse_name(name, "prune.json")


def test_the_shipped_java_seed_names_only_the_scratch_directory_with_the_four_sections_a_seed_may_name():
    shipped = cfgfile.read_policy((SHIPPED / "java.cfg").read_text())
    assert shipped.fs == {"/tmp": frozenset({"read", "write", "create", "delete"})}
    assert not (shipped.connect or shipped.bind or shipped.limits)
    assert all(sections <= seed.SEED_SECTIONS for sections in shipped.fs.values())


def test_a_seed_with_the_scratch_rows_is_read_back_as_a_policy(scratch):
    directory = write_seed(scratch, rows(scratch, "read", "write", "create", "delete"))
    loaded = seed.load("java.cfg", directory, NOTHING)
    assert loaded.fs == {str(scratch / "scratch"): frozenset({"read", "write", "create", "delete"})}


@pytest.mark.parametrize("section", ["execute", "restructure", "create-ipc", "create-symlink"])
def test_a_section_beyond_read_write_create_and_delete_is_refused(scratch, section):
    with pytest.raises(ValueError, match="which a seed may not"):
        seed.load("java.cfg", write_seed(scratch, rows(scratch, section)), NOTHING)


def test_a_seed_that_names_more_than_scratch_rows_on_existing_real_directories_is_refused(scratch):
    for text, why in (("", "names no row"), ("[connect]\nallow 10.0.0.1:80\n", "more than filesystem rows"),
                      ("[limits]\ntimeout=5\n", "more than filesystem rows"), ("[write]\n/\n", "the root"),
                      (f"[write]\n{scratch}/scratch/absent\n", "not an existing real directory"),
                      ("[write]\n/etc/hostname\n", "not an existing real directory"),
                      ("not a policy\n", "cannot be read")):
        with pytest.raises(ValueError, match=why):
            seed.load("java.cfg", write_seed(scratch, text), NOTHING)


def test_a_row_on_a_directory_the_pruner_owns_or_above_or_beneath_one_is_refused(scratch):
    owned = scratch / "scratch" / "owned"
    (owned / "inside").mkdir(parents=True)
    for entry in (scratch / "scratch", owned, owned / "inside", scratch):
        with pytest.raises(ValueError, match="pruner owns"):
            seed.load("java.cfg", write_seed(scratch, f"[write]\n{entry}\n"), (str(owned),))
    seed.load("java.cfg", write_seed(scratch, rows(scratch, "write")), (str(scratch / "elsewhere"),))


def test_an_entry_beneath_a_linked_parent_or_a_linked_seed_or_seed_directory_is_refused(scratch):
    (scratch / "link").symlink_to(scratch / "scratch")
    with pytest.raises(ValueError, match="not an existing real directory"):
        seed.load("java.cfg", write_seed(scratch, f"[write]\n{scratch / 'link'}\n"), NOTHING)
    good = write_seed(scratch, rows(scratch, "write"))
    (scratch / "linked-seeds").symlink_to(scratch / "seeds")
    with pytest.raises(ValueError, match="not a real file"):
        seed.load("java.cfg", str(scratch / "linked-seeds"), NOTHING)
    (scratch / "seeds" / "other.cfg").symlink_to(scratch / "seeds" / "java.cfg")
    with pytest.raises(ValueError, match="not a real file"):
        seed.load("other.cfg", good, NOTHING)
    with pytest.raises(ValueError, match="not a real file"):
        seed.load("absent.cfg", good, NOTHING)


def test_an_unreadable_seed_is_refused(scratch):
    directory = write_seed(scratch, rows(scratch, "write"))
    (scratch / "seeds" / "java.cfg").write_bytes(b"\xff\xfe not text")
    with pytest.raises(ValueError, match="cannot be read"):
        seed.load("java.cfg", directory, NOTHING)


def test_the_comment_names_only_the_sections_given_and_renders_and_parses_back():
    comment = seed.comment_for("java.cfg", "/tmp", {"write", "read"})
    assert comment == "seed: [read], [write] on /tmp come from the java.cfg seed of the prune image, not from a refusal"
    text = cfgfile.render(cfgfile.Policy(fs={"/tmp": frozenset({"read", "write"})}, connect=(), bind=(), limits={},
                                         comments={"/tmp": comment}))
    assert f"# {comment}\n/tmp\n" in text
    assert cfgfile.read_policy(text).fs == {"/tmp": frozenset({"read", "write"})}


def pruning_for(base: pathlib.Path, seed_name: str | None) -> stages.Pruning:
    """A pruning of a minimal exercise whose prune.json names `seed_name`."""
    directory = base / "exercise"
    directory.mkdir(exist_ok=True)
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    if seed_name is not None:
        (directory / "prune.json").write_text(json.dumps({"seed": seed_name}))
    return stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                          environment=runner.Environment(testing_dir=str(base / "testing"),
                                                         log_dir=str(base / "logs")))


def test_the_filesystem_stage_starts_from_the_seed_rows_and_the_record_says_which(scratch):
    found = pruning_for(scratch, "java.cfg")
    started = stages.seed_policy(found, write_seed(scratch, rows(scratch, "read", "write")))
    target = str(scratch / "scratch")
    assert started.fs == {target: frozenset({"read", "write"})}
    assert found.seeded == {target: frozenset({"read", "write"})}
    assert found.log[-1] == {"stage": "seed", "name": "java.cfg", "rows": {target: ["read", "write"]}}


def test_an_exercise_without_a_seed_starts_empty_as_before(scratch):
    found = pruning_for(scratch, None)
    assert stages.seed_policy(found, str(scratch / "seeds")).fs == {}
    assert found.seeded == {} and found.log == []


def test_a_named_seed_that_is_missing_or_names_a_directory_the_pruner_owns_aborts(scratch):
    found = pruning_for(scratch, "absent.cfg")
    with pytest.raises(search.PruneAbort, match="language seed cannot be used"):
        stages.seed_policy(found, str(scratch / "seeds"))
    owned = pruning_for(scratch, "java.cfg")
    (scratch / "testing").mkdir()
    with pytest.raises(search.PruneAbort, match="pruner owns"):
        stages.seed_policy(owned, write_seed(scratch, f"[write]\n{scratch / 'testing'}\n"))


def test_the_seed_is_read_before_the_first_run_of_the_pruning(scratch, monkeypatch):
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(stages, "baseline", lambda pruning: pytest.fail("the baseline ran before the seed was read"))
    found = pruning_for(scratch, "absent.cfg")
    index = generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    original = stages.seed_policy
    monkeypatch.setattr(stages, "seed_policy", lambda pruning: original(pruning, str(scratch / "seeds")))
    with pytest.raises(search.PruneAbort, match="language seed cannot be used"):
        stages.prune_exercise(found.exercise, stages.Budget(), found.environment, "filesystem", index)


def test_prune_json_carries_the_seed_name_and_refuses_one_that_is_not_a_plain_name(scratch):
    assert pruning_for(scratch, "java.cfg").exercise.seed == "java.cfg"
    directory = scratch / "other"
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


def snapshot_beneath(scratch: pathlib.Path, seeded: bool) -> generalise.Snapshot:
    """What snapshot_for builds when the pristine index holds the scratch directory and a subdirectory of it."""
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    found.pristine = generalise.Snapshot(existing=frozenset({target, target + "/sub"}),
                                         directories=frozenset({target, target + "/sub"}), scanned=("/",))
    if seeded:
        found.seeded = {target: frozenset({"write", "create"})}
    policy = cfgfile.Policy(fs={target: frozenset({"write", "create"})}, connect=(), bind=(), limits={})
    return stages.snapshot_for(found, policy)


@pytest.mark.parametrize("section", ["create-ipc", "create-symlink", "restructure"])
def test_a_directory_only_a_seed_write_grants_is_not_climbed_from_so_a_refusal_cannot_ask_more_beneath_it(scratch,
                                                                                                          section):
    target = str(scratch / "scratch")
    request = denial(target + "/sub/new", section)
    seeded, _ = generalise.grants_and_notes([request], snapshot_beneath(scratch, True), generalise.DEFAULT_FINE_ROOTS)
    assert seeded == {}
    refused, _ = generalise.grants_and_notes([request], snapshot_beneath(scratch, False), generalise.DEFAULT_FINE_ROOTS)
    assert refused == {target + "/sub": frozenset({section})}, "a directory a refusal granted is climbed from as before"


def run_prune_filesystem(monkeypatch, found: stages.Pruning, start: cfgfile.Policy, kept: dict[str, frozenset[str]]):
    """prune_filesystem with the runs replaced: the grow returns `start` and the minimisation keeps `kept`."""
    monkeypatch.setattr(stages, "grow_filesystem", lambda pruning, policy: policy)
    monkeypatch.setattr(stages, "minimise_policy_fs",
                        lambda pruning, policy, stage: cfgfile.Policy(fs=kept, connect=(), bind=(), limits={}))
    monkeypatch.setattr(stages, "widenings", lambda pruning, policy: [])
    return stages.seed_comments(found, stages.prune_filesystem(found, start))


def test_the_seed_comment_follows_the_policy_the_prune_ends_with_not_the_first_minimisation(scratch, monkeypatch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    stages.seed_policy(found, write_seed(scratch, rows(scratch, "read", "write", "create")))
    later = cfgfile.Policy(fs={target: frozenset({"read"})}, connect=(), bind=(), limits={})
    assert stages.seed_comments(found, later).comments[target].startswith(f"seed: [read] on {target} come from")
    assert stages.seed_comments(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={})).comments == {}


def test_the_seed_comment_names_only_the_sections_that_survived_the_minimisation(scratch, monkeypatch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    started = stages.seed_policy(found, write_seed(scratch, rows(scratch, "read", "write", "create", "delete")))
    policy = run_prune_filesystem(monkeypatch, found, started, {target: frozenset({"write", "create"})})
    assert policy.comments[target] == (f"seed: [create], [write] on {target} come from the java.cfg seed of the prune "
                                       "image, not from a refusal")


def test_nothing_is_said_about_a_seed_none_of_whose_rows_survived(scratch, monkeypatch):
    found = pruning_for(scratch, "java.cfg")
    started = stages.seed_policy(found, write_seed(scratch, rows(scratch, "write")))
    assert run_prune_filesystem(monkeypatch, found, started, {}).comments == {}


def test_a_comment_another_rule_put_on_the_same_path_is_kept_beside_the_seed_comment(scratch, monkeypatch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    started = stages.seed_policy(found, write_seed(scratch, rows(scratch, "read", "write")))
    found.comments[target] = "per-run: some other reason"
    policy = run_prune_filesystem(monkeypatch, found, started, {target: frozenset({"read"})})
    assert policy.comments[target].startswith("per-run: some other reason; seed: [read] on")


def test_a_seeded_row_is_marked_in_the_widenings_list(scratch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    stages.seed_policy(found, write_seed(scratch, rows(scratch, "read", "write")))
    listed = stages.widenings(found, cfgfile.Policy(fs={target: frozenset({"read", "write", "create"})}, connect=(),
                                                    bind=(), limits={}))
    assert listed[0]["seeded"] == ["read", "write"] and listed[0]["observed_count"] == 0


def test_a_seed_row_on_a_pinned_read_root_is_refused_before_any_run(scratch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    started = stages.seed_policy(found, write_seed(scratch, rows(scratch, "write")))
    found.pinned_roots[target] = "pinned"
    with pytest.raises(search.PruneAbort, match="pinned read root"):
        stages.check_pinned_grants(found, started)


def test_a_path_is_below_a_seed_by_components_and_not_by_text(scratch):
    found = pruning_for(scratch, "java.cfg")
    found.seeded = {"/tmp": frozenset({"write"})}
    assert stages.at_or_below_seed(found, "/tmp")
    assert stages.at_or_below_seed(found, "/tmp/tools")
    assert not stages.at_or_below_seed(found, "/tmp2")
    assert not stages.at_or_below_seed(found, "/")
    assert not stages.at_or_below_seed(pruning_for(scratch, None), "/tmp/tools")


def test_a_directory_below_a_seeded_one_that_holds_its_rights_is_not_climbed_from(scratch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    found.pristine = generalise.Snapshot(existing=frozenset({target, target + "/sub"}),
                                         directories=frozenset({target, target + "/sub"}), scanned=("/",))
    found.seeded = {target: frozenset({"write", "create"})}
    below = cfgfile.Policy(fs={target: frozenset({"write", "create"}), target + "/sub": frozenset({"write", "create"})},
                           connect=(), bind=(), limits={})
    assert target not in stages.snapshot_for(found, below).scanned
    assert target + "/sub" not in stages.snapshot_for(found, below).scanned, "the hierarchy rule copies the rights down"
    elsewhere = cfgfile.Policy(fs={target + "/sub": frozenset({"write"})}, connect=(), bind=(), limits={})
    found.seeded = {}
    assert target + "/sub" in stages.snapshot_for(found, elsewhere).scanned, "without a seed it is climbed from as before"


def test_rights_a_directory_holds_only_because_the_seed_has_them_on_its_ancestor_say_so(scratch):
    found = pruning_for(scratch, "java.cfg")
    target = str(scratch / "scratch")
    found.seed_name = "java.cfg"
    found.seeded = {target: frozenset({"read", "write"})}
    policy = cfgfile.Policy(fs={target: frozenset({"read", "write"}), target + "/tools": frozenset({"read", "write", "create"})},
                            connect=(), bind=(), limits={})
    comments = stages.seed_comments(found, policy).comments
    assert comments[target].startswith(f"seed: [read], [write] on {target} come from")
    assert comments[target + "/tools"] == (f"seed: [read], [write] on {target}/tools are the java.cfg seed's rights on "
                                           f"{target}, copied down by the hierarchy rule")
    unrelated = cfgfile.Policy(fs={target + "/tools": frozenset({"create"})}, connect=(), bind=(), limits={})
    assert stages.seed_comments(found, unrelated).comments == {}, "a right the seed does not have is not blamed on it"
