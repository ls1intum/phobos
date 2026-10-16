"""Checks the kept seed: what it may name, that no minimisation removes its rows, that it is no root a refusal climbs
from, what the policy says about it, and that the KVM cross-check keeps its rows (seed.py).

The rows must name real paths on the host the tests run on, so the cases build their own seed directory under a
resolved temporary path, and use /dev/null and /dev/urandom, which every host has, for a character device.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.application import kvm, search, stages
from exercise_pruner.src.domain import seed, verdict
from exercise_pruner.src.infrastructure import runner
from shared.src.domain import cfgfile, generalise, strace_parse

SHIPPED = REPO_ROOT / "pruner" / "config" / "seeds"
NOTHING = ()
PASSED = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
URANDOM = "/dev/urandom"


@pytest.fixture(name="scratch")
def scratch_fixture(tmp_path):
    """A resolved scratch directory a kept row may name, and the seed directory beside it."""
    base = pathlib.Path(os.path.realpath(tmp_path))
    (base / "scratch").mkdir()
    (base / "seeds").mkdir()
    return base


def write_kept(base: pathlib.Path, text: str, name: str = "swift-kept.cfg") -> str:
    """Writes a kept seed into the seed directory of `base`; the directory."""
    (base / "seeds" / name).write_text(text)
    return str(base / "seeds")


def exercise_with(base: pathlib.Path, settings: dict) -> stages.Pruning:
    """A pruning of a minimal exercise whose prune.json holds `settings`, with the reference already known."""
    directory = base / "exercise"
    directory.mkdir(exist_ok=True)
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    (directory / "prune.json").write_text(json.dumps(settings))
    found = stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                           environment=runner.Environment(testing_dir=str(base / "testing"), log_dir=str(base / "logs")))
    found.reference = PASSED
    return found


def passing(monkeypatch) -> list[cfgfile.Policy]:
    """Makes every layered run pass; the policies it was asked to run."""
    asked: list[cfgfile.Policy] = []

    def fake(exercise, policy, shape, environment):
        asked.append(policy)
        return runner.RunResult(verdict=PASSED, status=0, trace=strace_parse.parse_trace([]), samples=None,
                                wall_seconds=0.1, log_path=pathlib.Path("/tmp/run.log"))
    monkeypatch.setattr(runner, "run_layers", fake)
    return asked


def test_the_shipped_swift_kept_seed_names_only_reading_dev_urandom_and_loads_on_this_host():
    assert cfgfile.read_policy((SHIPPED / "swift-kept.cfg").read_text()).fs == {URANDOM: frozenset({"read"})}
    assert seed.load_kept("swift-kept.cfg", str(SHIPPED), NOTHING).fs == {URANDOM: frozenset({"read"})}


def test_the_swift_reference_names_the_kept_seed_beside_its_seed():
    exercise = runner.read_exercise(REPO_ROOT / "exercises" / "swift" / "swift-reference")
    assert exercise.seed == "swift.cfg" and exercise.kept_seed == "swift-kept.cfg"


def test_a_kept_row_may_name_a_directory_a_regular_file_or_a_character_device(scratch):
    (scratch / "scratch" / "file").write_text("x")
    text = (f"[read]\n{scratch / 'scratch'}\n{scratch / 'scratch' / 'file'}\n{URANDOM}\n\n"
            f"[write]\n{scratch / 'scratch'}\n{scratch / 'scratch' / 'file'}\n/dev/null\n\n"
            f"[create]\n{scratch / 'scratch'}\n\n[delete]\n{scratch / 'scratch'}\n")
    loaded = seed.load_kept("swift-kept.cfg", write_kept(scratch, text), NOTHING)
    assert loaded.fs[str(scratch / "scratch")] == frozenset({"read", "write", "create", "delete"})
    assert loaded.fs[str(scratch / "scratch" / "file")] == frozenset({"read", "write"})
    assert loaded.fs["/dev/null"] == frozenset({"write"})


def test_a_kept_row_on_anything_but_an_existing_real_directory_file_or_character_device_is_refused(scratch):
    (scratch / "link").symlink_to(scratch / "scratch")
    os.mkfifo(scratch / "fifo")
    for entry, why in ((scratch / "absent", "does not exist"), (scratch / "link", "not a real path"),
                       (scratch / "fifo", "no directory, regular file or character device")):
        with pytest.raises(ValueError, match=why):
            seed.load_kept("swift-kept.cfg", write_kept(scratch, f"[read]\n{entry}\n"), NOTHING)


@pytest.mark.parametrize("section", ["create", "delete"])
def test_a_file_or_device_takes_only_read_and_write(scratch, section):
    (scratch / "scratch" / "file").write_text("x")
    for entry in (scratch / "scratch" / "file", URANDOM):
        with pytest.raises(ValueError, match="a file or device"):
            seed.load_kept("swift-kept.cfg", write_kept(scratch, f"[{section}]\n{entry}\n"), NOTHING)


def test_no_write_class_section_sits_on_or_beneath_a_pseudo_file_system_and_dev_writes_only_a_device(scratch,
                                                                                                    monkeypatch):
    pseudo = scratch / "scratch" / "pseudo"
    (pseudo / "inside").mkdir(parents=True)
    monkeypatch.setattr(seed, "UNWRITABLE_ROOTS", (str(pseudo),))
    for entry in (pseudo, pseudo / "inside"):
        with pytest.raises(ValueError, match="takes no"):
            seed.load_kept("swift-kept.cfg", write_kept(scratch, f"[write]\n{entry}\n"), NOTHING)
    assert seed.load_kept("swift-kept.cfg", write_kept(scratch, f"[read]\n{pseudo}\n"), NOTHING).fs
    with pytest.raises(ValueError, match="no character device"):
        seed.load_kept("swift-kept.cfg", write_kept(scratch, "[write]\n/dev\n"), NOTHING)


def test_a_kept_seed_is_held_to_every_rule_a_seed_file_is(scratch):
    owned = scratch / "scratch" / "owned"
    owned.mkdir()
    for text, why in (("", "names no row"), ("[connect]\nallow 10.0.0.1:80\n", "more than filesystem rows"),
                      ("[read]\n/\n", "the root"), (f"[execute]\n{scratch / 'scratch'}\n", "which a seed may not"),
                      (f"[read]\n{owned}\n", "pruner owns"), ("not a policy\n", "cannot be read")):
        with pytest.raises(ValueError, match=why):
            seed.load_kept("swift-kept.cfg", write_kept(scratch, text), (str(owned),))
    with pytest.raises(ValueError, match="not a real file"):
        seed.load_kept("absent.cfg", str(scratch / "seeds"), NOTHING)
    with pytest.raises(ValueError):
        seed.load_kept("../swift-kept.cfg", str(scratch / "seeds"), NOTHING)


def test_prune_json_carries_a_kept_seed_without_a_seed_and_refuses_one_that_is_not_a_plain_name(scratch):
    assert exercise_with(scratch, {"kept_seed": "swift-kept.cfg"}).exercise.kept_seed == "swift-kept.cfg"
    directory = scratch / "exercise"
    for bad in ("../swift-kept.cfg", 7):
        (directory / "prune.json").write_text(json.dumps({"kept_seed": bad}))
        with pytest.raises(runner.ExerciseRefused):
            runner.read_exercise(directory)


def test_the_filesystem_stage_starts_from_the_union_of_both_seeds_and_the_record_names_each(scratch):
    target = str(scratch / "scratch")
    directory = write_kept(scratch, f"[read]\n{URANDOM}\n\n[write]\n{target}\n")
    (scratch / "seeds" / "swift.cfg").write_text(f"[read]\n{target}\n")
    found = exercise_with(scratch, {"seed": "swift.cfg", "kept_seed": "swift-kept.cfg"})
    started = stages.seed_policy(found, directory)
    assert started.fs == {target: frozenset({"read", "write"}), URANDOM: frozenset({"read"})}
    assert found.seeded == {target: frozenset({"read"})}
    assert found.kept_seed_rows == {target: frozenset({"write"}), URANDOM: frozenset({"read"})}
    assert [entry["stage"] for entry in found.log] == ["seed", "kept seed"]
    assert found.log[-1] == {"stage": "kept seed", "name": "swift-kept.cfg",
                             "rows": {target: ["write"], URANDOM: ["read"]}}


def test_a_kept_seed_alone_starts_the_stage_and_one_that_cannot_be_used_aborts(scratch):
    found = exercise_with(scratch, {"kept_seed": "swift-kept.cfg"})
    assert stages.seed_policy(found, write_kept(scratch, f"[read]\n{URANDOM}\n")).fs == {URANDOM: frozenset({"read"})}
    absent = exercise_with(scratch, {"kept_seed": "absent.cfg"})
    with pytest.raises(search.PruneAbort, match="kept seed cannot be used"):
        stages.seed_policy(absent, str(scratch / "seeds"))


def test_the_minimisation_removes_what_no_run_needs_but_never_a_kept_row(scratch, monkeypatch):
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {URANDOM: frozenset({"read"})}
    asked = passing(monkeypatch)
    policy = cfgfile.Policy(fs={"/usr": frozenset({"read"}), "/opt": frozenset({"read"}), URANDOM: frozenset({"read"})},
                            connect=(), bind=(), limits={})
    final = stages.minimise_policy_fs(found, policy, "filesystem")
    assert final.fs == {URANDOM: frozenset({"read"})}
    assert asked and all("read" in run.fs.get(URANDOM, ()) for run in asked), "every run holds the kept row"
    removed = next(entry for entry in found.log if entry["stage"] == "filesystem minimisation")["removed"]
    assert [URANDOM, "read"] not in removed and ["/usr", "read"] in removed


def test_a_kept_row_the_compaction_folded_into_its_parent_is_back_on_its_own_path(scratch, monkeypatch):
    target = str(scratch / "scratch")
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {target + "/a": frozenset({"read"})}
    asked = passing(monkeypatch)
    compacted = cfgfile.Policy(fs={target: frozenset({"read"})}, connect=(), bind=(), limits={})
    final = stages.minimise_policy_fs(found, compacted, "filesystem")
    assert final.fs == {target + "/a": frozenset({"read"})}
    assert all("read" in run.fs.get(target + "/a", ()) for run in asked)


def test_under_the_final_network_rules_the_kept_row_stays_too(scratch, monkeypatch):
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {URANDOM: frozenset({"read"})}
    passing(monkeypatch)
    policy = cfgfile.Policy(fs={"/usr": frozenset({"read"}), URANDOM: frozenset({"read"})},
                            connect=("allow 127.0.0.1:*",), bind=(), limits={})
    assert stages.minimise_policy_fs(found, policy, "filesystem after network", final_network=True).fs == {
        URANDOM: frozenset({"read"})}


def test_a_routed_filesystem_stage_and_a_restored_minimisation_keep_the_row(scratch, monkeypatch):
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {URANDOM: frozenset({"read"})}
    passing(monkeypatch)
    monkeypatch.setattr(stages, "grow_filesystem", lambda pruning, policy: policy)
    routed = cfgfile.Policy(fs={"/usr": frozenset({"read"}), URANDOM: frozenset({"read"})}, connect=(), bind=(),
                            limits={})
    after = stages.prune_filesystem(found, routed)
    assert after.fs == {URANDOM: frozenset({"read"})}
    assert stages.unminimised(found, after).fs == {"/usr": frozenset({"read"}), URANDOM: frozenset({"read"})}


def test_sections_the_hierarchy_adds_beside_a_kept_row_are_no_loss_and_a_missing_one_is(scratch):
    target = str(scratch / "scratch")
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {target + "/a": frozenset({"read"}), URANDOM: frozenset({"read"})}
    raised = cfgfile.Policy(fs=generalise.normalise_hierarchy({target: frozenset({"read", "write"}),
                                                               target + "/a": frozenset({"read"}),
                                                               URANDOM: frozenset({"read"})}),
                            connect=(), bind=(), limits={})
    assert raised.fs[target + "/a"] == frozenset({"read", "write"})
    assert stages.missing_kept_pairs(found, raised) == []
    lacking = cfgfile.Policy(fs={target: frozenset({"read"})}, connect=(), bind=(), limits={})
    assert stages.missing_kept_pairs(found, lacking) == sorted([(target + "/a", "read"), (URANDOM, "read")])


def test_a_prune_that_ends_without_a_kept_row_aborts_as_a_defect(scratch, monkeypatch):
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(stages, "permissive_run", lambda pruning: None)
    monkeypatch.setattr(stages, "prune_filesystem", lambda pruning, policy: cfgfile.Policy(fs={}, connect=(), bind=(),
                                                                                          limits={}))
    directory = write_kept(scratch, f"[read]\n{URANDOM}\n")
    original = stages.seed_policy
    monkeypatch.setattr(stages, "seed_policy", lambda pruning: original(pruning, directory))
    found = exercise_with(scratch, {"kept_seed": "swift-kept.cfg"})
    index = generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    with pytest.raises(search.PruneAbort, match="lacks rows of the kept seed") as aborted:
        stages.prune_exercise(found.exercise, stages.Budget(), found.environment, "filesystem", index)
    assert aborted.value.evidence["missing"] == [[URANDOM, "read"]]
    assert "record" in aborted.value.evidence


def test_the_permissive_run_holds_the_kept_rows(scratch, monkeypatch):
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {URANDOM: frozenset({"read"})}
    asked = passing(monkeypatch)
    stages.permissive_run(found)
    assert "read" in asked[0].fs[URANDOM] and asked[0].fs["/"] == frozenset({"read", "execute"})


def test_a_directory_only_a_kept_seed_write_grants_is_not_climbed_from(scratch):
    target = str(scratch / "scratch")
    found = exercise_with(scratch, {})
    found.pristine = generalise.Snapshot(existing=frozenset({target, target + "/sub"}),
                                         directories=frozenset({target, target + "/sub"}), scanned=("/",))
    policy = cfgfile.Policy(fs={target: frozenset({"write", "create"}), target + "/sub": frozenset({"write", "create"})},
                            connect=(), bind=(), limits={})
    assert target in stages.snapshot_for(found, policy).scanned, "a directory a refusal granted is climbed from"
    found.kept_seed_rows = {target: frozenset({"write", "create"})}
    assert stages.at_or_below_seed(found, target + "/sub") and not stages.at_or_below_seed(found, target + "2")
    scanned = stages.snapshot_for(found, policy).scanned
    assert target not in scanned and target + "/sub" not in scanned


def test_a_kept_row_and_a_path_holding_a_kept_directorys_rights_say_where_they_come_from(scratch):
    target = str(scratch / "scratch")
    found = exercise_with(scratch, {})
    found.kept_seed_name = "swift-kept.cfg"
    found.kept_seed_rows = {URANDOM: frozenset({"read"}), target: frozenset({"write"})}
    policy = cfgfile.Policy(fs={URANDOM: frozenset({"read"}), target: frozenset({"read", "write"}),
                                target + "/tools": frozenset({"read", "write"})}, connect=(), bind=(), limits={},
                            comments={URANDOM: "per-run: another reason"})
    comments = stages.seed_comments(found, policy).comments
    assert comments[URANDOM] == ("per-run: another reason; kept: [read] on /dev/urandom come from the swift-kept.cfg "
                                 "kept seed of the prune image, which no minimisation removes; that file says why")
    assert comments[target].startswith(f"kept: [write] on {target} come from")
    assert comments[target + "/tools"] == (f"kept: [write] on {target}/tools are the swift-kept.cfg kept seed's rights "
                                           f"on {target}, copied down by the hierarchy rule")
    text = cfgfile.render(stages.seed_comments(found, policy))
    assert cfgfile.read_policy(text).fs == policy.fs


def test_the_cross_check_keeps_a_kept_row_the_policy_holds_and_adds_none_it_does_not():
    policy = cfgfile.Policy(fs={"/a": frozenset({"read"}), "/b": frozenset({"read"}), "/c": frozenset({"read"})},
                            connect=(), bind=(), limits={})
    assert sorted(kvm.narrowed(policy).fs) == ["/a", "/c"]
    assert sorted(kvm.narrowed(policy, {"/b"}).fs) == ["/a", "/b", "/c"]
    assert sorted(kvm.narrowed(policy, {"/d"}).fs) == ["/a", "/c"]


def test_the_cross_check_of_the_shipped_swift_base_drops_dev_urandom_unless_it_is_kept():
    base = cfgfile.read_policy((REPO_ROOT / "protecter" / "src" / "config" / "BaseLanguage-swift.cfg").read_text())
    assert URANDOM not in kvm.narrowed(base).fs, "the path order puts /dev/urandom among the removed entries"
    kept = kvm.narrowed(base, {URANDOM})
    assert URANDOM in kept.fs and len(kept.fs) < len(base.fs)


def guest_verification(scratch: pathlib.Path, monkeypatch, settings: dict) -> tuple[dict, str | None, dict]:
    """verify_exercise over a policy of /a and /dev/urandom whose cross-check is refused nothing; the record, the
    reason and the kept rows the cross-check was given."""
    monkeypatch.setattr(seed, "SEED_DIRECTORY", write_kept(scratch, f"[read]\n{URANDOM}\n"))
    exercise = scratch / "fixture"
    exercise.mkdir()
    (exercise / "build_script.sh").write_text("exit 0\n")
    (exercise / "build_script.sh").chmod(0o755)
    (exercise / "prune.json").write_text(json.dumps(settings))
    output = scratch / "out"
    output.mkdir()
    text = f"[read]\n/a\n{URANDOM}\n"
    (output / "java_fixture.cfg").write_text(text)
    (output / "java_fixture.json").write_text(json.dumps({"cfg_sha256": kvm.hashlib.sha256(text.encode()).hexdigest()}))
    seen: dict = {}

    def cross(pruning, policy, capture):
        seen.update(pruning.kept_seed_rows)
        return {"mismatches": [], "audit_only": [], "strace_denials": 0, "verdict": {"exit_class": "success"}}
    monkeypatch.setattr(stages, "baseline", lambda pruning, inspect: PASSED)
    monkeypatch.setattr(kvm, "cross_check_run", cross)
    monkeypatch.setattr(kvm, "abi10_phase", lambda *arguments: (None, []))
    entry, _, reason = kvm.verify_exercise(exercise, "java", runner.Environment(), output, None, {"landlock_abi": 10},
                                           None, lambda failure: {"aborted": str(failure), "evidence": {}})
    return entry, reason, seen


def test_the_guest_loads_the_kept_seed_and_says_when_the_narrowing_then_removed_nothing(scratch, monkeypatch):
    entry, reason, seen = guest_verification(scratch, monkeypatch, {"kept_seed": "swift-kept.cfg"})
    assert seen == {URANDOM: frozenset({"read"})}
    assert entry["verified"] is False and "the narrowing removed none" in reason


def test_without_a_kept_seed_the_cross_check_still_runs_without_every_second_grant(tmp_path, monkeypatch):
    scratch = pathlib.Path(os.path.realpath(tmp_path))
    (scratch / "seeds").mkdir()
    entry, reason, seen = guest_verification(scratch, monkeypatch, {})
    assert seen == {}
    assert entry["verified"] is False and "although it ran without 1 grant(s)" in reason


def test_a_kept_row_on_a_socket_is_refused(scratch, monkeypatch):
    monkeypatch.chdir(scratch)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind("socket")
        with pytest.raises(ValueError, match="no directory, regular file or character device"):
            seed.load_kept("swift-kept.cfg", write_kept(scratch, f"[read]\n{scratch / 'socket'}\n"), NOTHING)
    finally:
        listener.close()


def test_all_four_sections_of_a_kept_directory_survive_the_normalisation(scratch):
    target = str(scratch / "scratch")
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {target: frozenset({"read", "write", "create", "delete"})}
    policy = cfgfile.Policy(fs={target: frozenset({"read", "write", "create", "delete"}), "/usr": frozenset({"read"})},
                            connect=(), bind=(), limits={})
    assert stages.missing_kept_pairs(found, stages.normalised(found, policy)) == []


def test_the_real_cross_check_runs_with_the_kept_rows_the_policy_holds(scratch, monkeypatch):
    found = exercise_with(scratch, {})
    found.kept_seed_rows = {URANDOM: frozenset({"read"})}
    asked: list[cfgfile.Policy] = []

    def run(self, policy, shape, stage):
        asked.append(policy)
        return runner.RunResult(verdict=PASSED, status=0, trace=None, samples=None, wall_seconds=0.1,
                                log_path=pathlib.Path("/tmp/run.log"))

    class Silent:
        """A capture of a kernel that writes nothing."""

        def collect(self) -> list[str]:
            """Nothing was written."""
            return []
    monkeypatch.setattr(stages.Pruning, "run", run)
    policy = cfgfile.Policy(fs={"/a": frozenset({"read"}), URANDOM: frozenset({"read"}), "/usr": frozenset({"read"})},
                            connect=(), bind=(), limits={})
    kvm.cross_check_run(found, policy, Silent())
    found.kept_seed_rows = {}
    kvm.cross_check_run(found, policy, Silent())
    assert sorted(asked[0].fs) == ["/a", URANDOM, "/usr"]
    assert sorted(asked[1].fs) == ["/a", "/usr"], "without a kept seed every second entry goes, /dev/urandom among them"
