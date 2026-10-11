"""Checks the stage logic of A.6.4 with a fake runner: the baseline, the permissive run and the network stage."""

from __future__ import annotations

import dataclasses
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.application import search, stages
from exercise_pruner.src.domain import verdict
from exercise_pruner.src.infrastructure import runner
from shared.src.domain import cfgfile, record, strace_parse

PASSED = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
FAILED = verdict.Verdict(exit_class="tests-failed", tests=(("T.a", "failed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
RESTRICT = "300 landlock_restrict_self(3, 0) = 0"


def result(found: verdict.Verdict, *lines: str) -> runner.RunResult:
    """A run result with the given verdict and a trace of the given strace lines."""
    return runner.RunResult(verdict=found, status=0, trace=strace_parse.parse_trace([RESTRICT, *lines]), samples=None,
                            wall_seconds=0.1, log_path=pathlib.Path("/tmp/run.log"))


def pruning(tmp_path: pathlib.Path) -> stages.Pruning:
    """A pruning of a minimal exercise, with the reference already known."""
    directory = tmp_path / "fixture"
    directory.mkdir(exist_ok=True)
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    found = stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                           environment=runner.Environment())
    found.reference = PASSED
    return found


def feed(monkeypatch, *results: runner.RunResult) -> list[cfgfile.Policy]:
    """Makes run_layers answer with the given results in turn; returns the policies it was asked to run."""
    asked: list[cfgfile.Policy] = []
    pending = list(results)

    def fake(exercise, policy, shape, environment):
        asked.append(policy)
        return pending.pop(0) if len(pending) > 1 else pending[0]
    monkeypatch.setattr(runner, "run_layers", fake)
    return asked


SETSID = "300 setsid() = -1 EPERM (Operation not permitted)"
UNIX = '300 connect(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 EACCES (Permission denied)'
EXTERNAL = ("300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4<socket:[1]>",
            ('300 connect(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) '
             "= -1 EACCES (Permission denied)"))


def test_the_permissive_run_names_a_fixed_rule_before_an_external_destination(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED, SETSID, UNIX, *EXTERNAL))
    with pytest.raises(search.PruneAbort, match="incompatible with a fixed rule"):
        stages.permissive_run(pruning(tmp_path))


def test_the_permissive_run_names_an_external_destination_when_only_unix_lookups_are_beside_it(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED, UNIX, *EXTERNAL))
    with pytest.raises(search.PruneAbort, match="needs external network: undeclared 10.0.0.1:80 tcp"):
        stages.permissive_run(pruning(tmp_path))


def test_a_permissive_run_that_matches_passes_whatever_it_was_refused(tmp_path, monkeypatch):
    feed(monkeypatch, result(PASSED, SETSID, *EXTERNAL))
    stages.permissive_run(pruning(tmp_path))


def test_the_compiled_programs_root_is_the_assignment_directory_unless_the_exercise_names_another(tmp_path):
    found = pruning(tmp_path)
    assert stages.compiled_roots(found) == ()
    found.exercise = runner.Exercise(**{**found.exercise.__dict__, "runs_compiled_programs": True})
    assert stages.compiled_roots(found) == ("/var/tmp/testing-dir/assignment",)
    found.exercise = runner.Exercise(**{**found.exercise.__dict__, "compiled_programs_directory": "test"})
    assert stages.compiled_roots(found) == ("/var/tmp/testing-dir/test",)


def test_the_baseline_aborts_on_a_flaky_reference_and_on_a_run_without_tests(tmp_path, monkeypatch):
    outcomes = iter([PASSED, FAILED])
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: runner.RunResult(
        verdict=next(outcomes), status=0, trace=None, samples=None, wall_seconds=0.1, log_path=pathlib.Path("/tmp/x")))
    with pytest.raises(search.PruneAbort, match="flaky reference"):
        stages.baseline(pruning(tmp_path))
    empty = verdict.Verdict(exit_class="success", tests=(), tests_ran=False, no_source=True, infra_failure=False)
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: runner.RunResult(
        verdict=empty, status=0, trace=None, samples=None, wall_seconds=0.1, log_path=pathlib.Path("/tmp/x")))
    with pytest.raises(search.PruneAbort, match="ran no tests"):
        stages.baseline(pruning(tmp_path))


def test_the_network_stage_grants_loopback_beside_a_refused_external_attempt_and_leaves_that_refused(tmp_path, monkeypatch):
    server = ("300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 5<socket:[2]>",
              '300 bind(5<socket:[2]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
              "300 listen(5<socket:[2]>, 1) = 0",
              ('300 getsockname(5<socket:[2]>, {sa_family=AF_INET, sin_port=htons(43000), sin_addr=inet_addr("127.0.0.1")}, '
               "[16]) = 0"),
              "300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 6<socket:[3]>",
              ('300 connect(6<socket:[3]>, {sa_family=AF_INET, sin_port=htons(43000), sin_addr=inet_addr("127.0.0.1")}, 16) '
               "= -1 EACCES (Permission denied)"))
    asked = feed(monkeypatch, result(FAILED, *server, *EXTERNAL), result(PASSED, *EXTERNAL))
    final = stages.prune_network(pruning(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    assert asked[1].connect == ("allow 127.0.0.1:*",)
    assert final.connect == ()


def test_the_network_stage_aborts_when_only_an_external_destination_is_left(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED, *EXTERNAL))
    with pytest.raises(search.PruneAbort, match="needs external network"):
        stages.prune_network(pruning(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))


def test_the_network_stage_aborts_on_a_failure_without_a_network_denial(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        stages.prune_network(pruning(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))


def test_a_path_under_proc_or_dev_is_never_resolved_by_the_pruner():
    assert stages.canonical("/proc/self/status") == "/proc/self/status"
    assert stages.canonical("/dev/stdout") == "/dev/stdout"


def proc_denial(path: str, section: str, pid: int = 412) -> record.Denial:
    """A Landlock filesystem denial of one section on a path, by the process `pid`."""
    return record.Denial(pid=pid, layer=record.LAYER_FILESYSTEM, operation="openat", objects=(path,),
                         sections=frozenset({section}), address=None, port=None, transport=None, errno="EACCES",
                         run=1, tid=pid)


def test_a_write_on_a_per_run_name_is_reported_and_only_a_read_is_granted_on_its_stable_directory(tmp_path,
                                                                                                    monkeypatch):
    monkeypatch.setattr(stages.control, "landlock_caused", lambda denial, *rest: True)
    found = pruning(tmp_path)
    snapshot = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    written = stages.filesystem_grants(found, [proc_denial("/proc/412/oom_score_adj", "write")], snapshot, {})
    assert written == {}
    assert found.log[-1]["reported"][0]["section"] == "write"
    read = stages.filesystem_grants(found, [proc_denial("/proc/413/status", "read", pid=413)], snapshot, {})
    assert read == {"/proc": frozenset({"read"})}


def test_the_pristine_index_leaves_out_the_pseudo_filesystems_links_and_the_pruners_own_directories(tmp_path):
    root = tmp_path / "root"
    for directory in ("proc/1", "srv/data", "exercises/build", "var/tmp/logs"):
        (root / directory).mkdir(parents=True)
    (root / "srv" / "data" / "x").write_text("x")
    (root / "bin").symlink_to("srv")
    environment = runner.Environment(testing_dir=str(root / "exercises"), log_dir=str(root / "var/tmp/logs"),
                                     candidate_dir=str(root / "run/layer-prune"))
    index = stages.pristine_index(environment, root)
    real = os.path.realpath(root)
    assert f"{real}/srv/data/x" in index.existing
    assert f"{real}/var/tmp" in index.directories
    assert not any(path.startswith((f"{real}/proc", f"{real}/var/tmp/testing-dir", f"{real}/var/tmp/logs", f"{real}/bin"))
                   for path in index.existing)


def test_a_snapshot_answers_from_the_pristine_index_not_from_what_earlier_runs_left(tmp_path):
    found = pruning(tmp_path)
    leftover = tmp_path / "leftover"
    leftover.mkdir()
    found.pristine = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=(str(tmp_path),))
    snapshot = stages.snapshot_for(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    assert not snapshot.existed(str(leftover))
    assert snapshot.existed(stages.runner.TESTING_DIR + "/build_script.sh")


def test_the_joint_verification_routes_a_new_grant_at_most_twice_and_then_aborts(tmp_path, monkeypatch):
    found = pruning(tmp_path)
    routed = []
    monkeypatch.setattr(stages, "joint_runs", lambda pruning, policy: False)
    monkeypatch.setattr(stages, "unminimised", lambda pruning, policy: policy)
    monkeypatch.setattr(stages, "denials_of", lambda pruning, result: [])
    monkeypatch.setattr(stages, "filesystem_grants",
                        lambda pruning, denials, snapshot, held: {f"/srv/{len(routed)}": frozenset({"read"})})
    monkeypatch.setattr(stages, "snapshot_for", lambda pruning, policy: None)
    monkeypatch.setattr(stages, "prune_filesystem", lambda pruning, seed: routed.append(seed) or seed)
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="did not settle"):
        stages.verify(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    assert len(routed) == stages.ROUTING_ROUNDS
    assert routed[0].fs == {"/srv/0": frozenset({"read"})}


def test_the_joint_verification_aborts_when_no_stage_would_grant_anything_new(tmp_path, monkeypatch):
    found = pruning(tmp_path)
    held = {"/srv/data": frozenset({"read"})}
    monkeypatch.setattr(stages, "joint_runs", lambda pruning, policy: False)
    monkeypatch.setattr(stages, "unminimised", lambda pruning, policy: policy)
    monkeypatch.setattr(stages, "denials_of", lambda pruning, result: [])
    monkeypatch.setattr(stages, "filesystem_grants", lambda pruning, denials, snapshot, policy: dict(held))
    monkeypatch.setattr(stages, "snapshot_for", lambda pruning, policy: None)
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="without a denial a stage owns"):
        stages.verify(found, cfgfile.Policy(fs=dict(held), connect=(), bind=(), limits={}))


def sampled(found: verdict.Verdict, samples: list[dict] | None) -> runner.RunResult:
    """A run result with the given verdict and samples and no trace."""
    return runner.RunResult(verdict=found, status=0, trace=None, samples=samples, wall_seconds=1.0,
                            log_path=pathlib.Path("/tmp/run.log"))


SAMPLE = [{"time": 0.1, "pid": 9, "vm_peak_mb": 10.0, "cpu_seconds": 1.0, "highest_descriptor": 9, "tasks": 3}]


def test_every_raised_limit_is_verified_and_a_fourth_doubling_aborts(tmp_path, monkeypatch):
    found = pruning(tmp_path)
    verified = []

    def run(policy, shape, stage):
        if shape == stages.SAMPLED:
            return sampled(PASSED, SAMPLE)
        if shape == stages.LIMITED:
            verified.append(policy.limits["timeout"])
        return sampled(FAILED, SAMPLE)
    monkeypatch.setattr(found, "run", run)
    monkeypatch.setattr(stages.limits, "limit_signature", lambda *arguments: "timeout")
    monkeypatch.setattr(stages, "limit_denials", lambda pruning, result: [])
    with pytest.raises(search.PruneAbort, match="limits did not settle"):
        stages.prune_limits(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    first = verified[0]
    assert sorted(set(verified)) == [first, first * 2, first * 4, first * 8]


def test_a_failure_under_limits_without_a_signature_aborts_and_a_sampled_run_without_samples_is_a_defect(tmp_path,
                                                                                                          monkeypatch):
    found = pruning(tmp_path)
    monkeypatch.setattr(found, "run", lambda policy, shape, stage: sampled(PASSED if shape == stages.SAMPLED else FAILED,
                                                                         SAMPLE))
    monkeypatch.setattr(stages.limits, "limit_signature", lambda *arguments: None)
    monkeypatch.setattr(stages, "limit_denials", lambda pruning, result: [])
    with pytest.raises(search.PruneAbort, match="without a limit signature"):
        stages.prune_limits(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    monkeypatch.setattr(found, "run", lambda policy, shape, stage: sampled(PASSED, []))
    with pytest.raises(runner.PrunerDefect, match="no sample"):
        stages.prune_limits(found, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))


def test_unminimised_puts_back_every_grant_and_rule_the_minimisations_removed(tmp_path):
    found = pruning(tmp_path)
    found.removed_pairs = {("/srv/data", "read")}
    found.removed_rules = {("connect", "allow 127.0.0.1:*"), ("bind", "allow 0")}
    restored = stages.unminimised(found, cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=(), bind=(), limits={}))
    assert restored.fs == {"/usr": frozenset({"read"}), "/srv/data": frozenset({"read"})}
    assert restored.connect == ("allow 127.0.0.1:*",)
    assert restored.bind == ("allow 0",)


@pytest.mark.parametrize(("stage", "ran"), [("filesystem", ["filesystem"]),
                                            ("network", ["filesystem", "network"]),
                                            ("limits", ["filesystem", "network", "limits"]),
                                            ("all", ["filesystem", "network", "limits", "verify", "containment"])])
def test_each_stage_runs_only_the_stages_up_to_it(tmp_path, monkeypatch, stage, ran):
    calls = []
    empty = cfgfile.Policy(fs={}, connect=(), bind=(), limits={})
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(stages, "permissive_run", lambda pruning: None)
    for name in ("filesystem", "network", "limits"):
        monkeypatch.setattr(stages, f"prune_{name}", lambda pruning, policy, name=name: calls.append(name) or empty)
    monkeypatch.setattr(stages, "verify", lambda pruning, policy: calls.append("verify") or empty)
    monkeypatch.setattr(stages.containment, "run_checks", lambda policy, environment: calls.append("containment") or [])
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    stages.prune_exercise(pruning(tmp_path).exercise, stages.Budget(), runner.Environment(), stage, index)
    assert calls == ran


def test_a_kernel_that_refuses_the_subreaper_is_a_pruner_defect(tmp_path, monkeypatch):
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: False)
    with pytest.raises(runner.PrunerDefect, match="subreaper"):
        stages.prune_exercise(pruning(tmp_path).exercise, stages.Budget(), runner.Environment())


def test_the_permissive_run_without_any_refusal_is_one_without_an_attributable_denial(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        stages.permissive_run(pruning(tmp_path))


def test_outside_the_prune_container_the_pruner_refuses_to_run(tmp_path, monkeypatch):
    monkeypatch.delenv(stages.PRUNE_CONTAINER_VARIABLE, raising=False)
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: pytest.fail("nothing may be planted"))
    with pytest.raises(runner.PrunerDefect, match="only in the prune container"):
        stages.prune_exercise(pruning(tmp_path).exercise, stages.Budget(), runner.Environment())


def test_what_earlier_runs_left_is_removed_before_a_layered_run_and_what_was_there_or_is_kept_stays(tmp_path,
                                                                                                     monkeypatch):
    root = tmp_path / "root"
    (root / "tmp").mkdir(parents=True)
    (root / "srv" / "data").mkdir(parents=True)
    (root / "srv" / "data" / "kept.txt").write_text("x")
    (root / "out").mkdir()
    environment = runner.Environment(testing_dir=str(root / "work"), log_dir=str(root / "logs"),
                                     candidate_dir=str(root / "run"), kept=(str(root / "out"),))
    found = pruning(tmp_path)
    found.environment = environment
    found.pristine = stages.pristine_index(environment, root)
    (root / "tmp" / "hsperfdata_root").mkdir()
    (root / "tmp" / "hsperfdata_root" / "123").write_text("x")
    (root / "srv" / "data" / "cache.bin").write_text("x")
    (root / "srv" / "link").symlink_to(root / "srv" / "data")
    (root / "out" / "java_fixture.cfg").write_text("[read]\n/usr\n")
    (root / "logs").mkdir()
    (root / "logs" / "run-0001-layers.log").write_text("x")
    feed(monkeypatch, result(PASSED))
    found.run(cfgfile.Policy(fs={}, connect=(), bind=(), limits={}), stages.JOINT, "verification")
    real = pathlib.Path(os.path.realpath(root))
    assert not (real / "tmp" / "hsperfdata_root").exists()
    assert not (real / "srv" / "data" / "cache.bin").exists()
    assert not (real / "srv" / "link").is_symlink()
    assert (real / "srv" / "data" / "kept.txt").exists()
    assert (real / "out" / "java_fixture.cfg").exists()
    assert (real / "logs" / "run-0001-layers.log").exists()
    restored = next(entry for entry in found.log if entry["stage"] == "restored")
    assert restored["count"] == 3


def test_the_merged_verification_runs_every_layer_under_the_files_as_given_and_aborts_on_a_mismatch(tmp_path,
                                                                                                    monkeypatch):
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    configs = (tmp_path / "BaseLanguage-java.cfg", tmp_path / "java_fixture.cfg")
    shapes = []
    outcomes = iter([PASSED, FAILED])
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: shapes.append("subreaper") or True)
    monkeypatch.setattr(runner, "gate_configs", lambda given, environment, log: shapes.append(("gate", given)))
    monkeypatch.setattr(runner, "run_configured", lambda exercise, given, shape, environment, files: (
        shapes.append((shape, given)) or sampled(next(outcomes), None)))
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    exercise = pruning(tmp_path).exercise
    with pytest.raises(search.PruneAbort, match="did not match the reference"):
        stages.verify_merged(exercise, configs, runner.Environment(log_dir=str(tmp_path / "logs")), index)
    assert shapes == ["subreaper", ("gate", configs), (stages.JOINT, configs), (stages.JOINT, configs)]
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: False)
    with pytest.raises(runner.PrunerDefect, match="subreaper"):
        stages.verify_merged(exercise, configs, runner.Environment(log_dir=str(tmp_path / "logs")), index)


def test_the_merged_verification_stops_at_a_baseline_that_fails_with_the_record_and_restores_before_each_run(
        tmp_path, monkeypatch):
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    configs = (tmp_path / "BaseLanguage-java.cfg", tmp_path / "java_fixture.cfg")
    restored = []
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    exercise = pruning(tmp_path).exercise
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(runner, "gate_configs", lambda *arguments: pytest.fail("the baseline fails first"))

    def refuse(pruning):
        pruning.note("baseline", attempt=1)
        raise search.PruneAbort("flaky reference")
    monkeypatch.setattr(stages, "baseline", refuse)
    with pytest.raises(search.PruneAbort, match="flaky reference") as raised:
        stages.verify_merged(exercise, configs, runner.Environment(log_dir=str(tmp_path / "logs")), index)
    assert raised.value.evidence["record"] == [{"stage": "baseline", "attempt": 1}]
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(runner, "gate_configs", lambda *arguments: None)
    monkeypatch.setattr(stages, "restore_pristine", lambda pruning: restored.append("restore") or [])
    monkeypatch.setattr(runner, "run_configured", lambda *arguments: restored.append("run") or sampled(PASSED, None))
    stages.verify_merged(exercise, configs, runner.Environment(log_dir=str(tmp_path / "logs")), index)
    assert restored == ["restore", "run"] * stages.Budget().verification_runs


def test_the_filesystem_stage_of_an_exercise_with_declared_hosts_keeps_the_network_open_to_them(tmp_path,
                                                                                                  monkeypatch):
    asked = feed(monkeypatch, result(PASSED))
    plain = pruning(tmp_path)
    stages.filesystem_run(plain, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}), True, "filesystem")
    assert plain.log[-1]["shape"] == dataclasses.asdict(stages.OBSERVED_FILESYSTEM)
    declared = pruning(tmp_path)
    declared.exercise = runner.Exercise(**{**declared.exercise.__dict__, "declared_hosts": ("api.example.org:443",)})
    shapes = []
    monkeypatch.setattr(runner, "run_layers", lambda exercise, policy, shape, environment: (
        asked.append(policy), shapes.append(shape), result(PASSED))[-1])
    stages.filesystem_run(declared, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}), True, "filesystem")
    assert asked[0].connect == ()
    assert asked[1].connect == (*cfgfile.PERMISSIVE_CONNECT, "allow api.example.org:443")
    assert asked[1].bind == cfgfile.PERMISSIVE_BIND
    assert shapes == [stages.OBSERVED_NETWORK]


def declared_pruning(tmp_path: pathlib.Path) -> stages.Pruning:
    """A pruning of the minimal exercise with one declared host."""
    found = pruning(tmp_path)
    found.exercise = runner.Exercise(**{**found.exercise.__dict__, "declared_hosts": ("api.example.org:443",)})
    return found


def test_the_filesystem_stage_of_an_exercise_with_declared_hosts_hands_back_no_network_rule(tmp_path, monkeypatch):
    feed(monkeypatch, result(PASSED))
    grown = stages.prune_filesystem(declared_pruning(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
    assert (grown.connect, grown.bind) == ((), ())


def test_a_declared_host_the_network_stage_drops_makes_the_filesystem_minimised_again_under_the_final_rules(
        tmp_path, monkeypatch):
    found = declared_pruning(tmp_path)
    minimised = []
    final = cfgfile.Policy(fs={"/srv/cache": frozenset({"write"})}, connect=("allow 127.0.0.1:*",), bind=(), limits={})
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(stages, "permissive_run", lambda pruning: None)
    monkeypatch.setattr(stages, "prune_filesystem", lambda pruning, policy: policy)
    monkeypatch.setattr(stages, "prune_network", lambda pruning, policy: final)
    monkeypatch.setattr(stages, "minimise_policy_fs", lambda pruning, policy, stage, final_network=False: (
        minimised.append((policy.connect, stage, final_network)), policy)[-1])
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    stages.prune_exercise(found.exercise, stages.Budget(), runner.Environment(), "network", index)
    assert minimised == [(("allow 127.0.0.1:*",), "filesystem after network", True)]


def test_a_declared_host_reference_that_fails_its_tests_names_the_undeclared_destination(tmp_path, monkeypatch):
    found = declared_pruning(tmp_path)
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: sampled(FAILED, None))
    feed(monkeypatch, result(FAILED, *EXTERNAL))
    with pytest.raises(search.PruneAbort, match="needs external network: undeclared 10.0.0.1:80 tcp"):
        stages.baseline(found)
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="fails its own tests, also under the layers"):
        stages.baseline(declared_pruning(tmp_path))
    feed(monkeypatch, result(PASSED))
    with pytest.raises(search.PruneAbort, match="the diagnosis run did not match it"):
        stages.baseline(declared_pruning(tmp_path))


SKIPPED = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"), ("T.b", "skipped")), tests_ran=True,
                          no_source=False, infra_failure=False)


def test_a_declared_host_reference_with_a_skipped_test_is_taken_as_it_is_without_a_diagnosis(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: sampled(SKIPPED, None))
    monkeypatch.setattr(stages, "diagnose_declared_reference", lambda *arguments: pytest.fail("nothing failed"))
    assert stages.baseline(declared_pruning(tmp_path)) == SKIPPED


def test_a_declared_host_reference_that_passes_needs_no_diagnosis(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: sampled(PASSED, None))
    monkeypatch.setattr(stages, "diagnose_declared_reference", lambda *arguments: pytest.fail("nothing failed"))
    assert stages.baseline(declared_pruning(tmp_path)) == PASSED


def test_merged_verification_runs_only_in_the_prune_container(tmp_path, monkeypatch):
    monkeypatch.delenv(stages.PRUNE_CONTAINER_VARIABLE, raising=False)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: pytest.fail("must not get that far"))
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    with pytest.raises(runner.PrunerDefect, match="only in the prune container"):
        stages.verify_merged(pruning(tmp_path).exercise, (), runner.Environment(), index)


def test_a_minimisation_under_the_final_network_rules_first_needs_the_whole_policy_to_pass(tmp_path, monkeypatch):
    found = declared_pruning(tmp_path)
    found.reference = PASSED
    feed(monkeypatch, result(FAILED))
    policy = cfgfile.Policy(fs={"/usr": frozenset({"read"})}, connect=("allow 127.0.0.1:*",), bind=(), limits={})
    with pytest.raises(search.PruneAbort, match="do not pass under the final network rules"):
        stages.minimise_policy_fs(found, policy, "filesystem after network", final_network=True)


def test_a_reference_without_declared_hosts_may_fail_tests_as_long_as_it_does_so_every_time(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: sampled(FAILED, None))
    assert stages.baseline(pruning(tmp_path)) == FAILED


def test_when_every_declared_host_is_kept_the_filesystem_is_not_minimised_again(tmp_path, monkeypatch):
    found = declared_pruning(tmp_path)
    kept = cfgfile.Policy(fs={}, connect=("allow api.example.org:443",), bind=(), limits={})
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: True)
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(stages, "permissive_run", lambda pruning: None)
    monkeypatch.setattr(stages, "prune_filesystem", lambda pruning, policy: policy)
    monkeypatch.setattr(stages, "prune_network", lambda pruning, policy: kept)
    monkeypatch.setattr(stages, "minimise_policy_fs", lambda *arguments, **keywords: pytest.fail("not again"))
    index = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    assert stages.prune_exercise(found.exercise, stages.Budget(), runner.Environment(), "network", index)[0] == kept


def pty_denial(path: str, sections: frozenset[str], detail: str = "") -> record.Denial:
    """A Landlock filesystem denial on a pseudo-terminal device, as the ioctl and the open of one produce."""
    return record.Denial(pid=500, layer=record.LAYER_FILESYSTEM, operation="ioctl" if detail else "openat",
                         objects=(path,), sections=sections, address=None, port=None, transport=None,
                         errno="EACCES", run=1, tid=500, detail=detail)


PTY_RUN = [pty_denial("/dev/ptmx", frozenset({"read", "write"})),
           pty_denial("/dev/pts/ptmx", frozenset({"read", "write"})),
           pty_denial("/dev/pts/ptmx", frozenset({"ioctl"}), "TIOCSPTLCK"),
           pty_denial("/dev/pts/3", frozenset({"read", "write"})),
           pty_denial("/dev/pts/3", frozenset({"ioctl"}), "TCGETS")]


def terminal_pruning(tmp_path: pathlib.Path, declared: bool) -> stages.Pruning:
    """A pruning of an exercise that does or does not declare uses_pseudo_terminals."""
    found = pruning(tmp_path)
    found.exercise = dataclasses.replace(found.exercise, uses_pseudo_terminals=declared)
    return found


def test_a_declared_exercise_gets_the_one_directory_read_written_and_open_to_ioctl(tmp_path, monkeypatch):
    monkeypatch.setattr(stages.control, "landlock_caused", lambda denial, *rest: True)
    snapshot = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    grants = stages.filesystem_grants(terminal_pruning(tmp_path, True), PTY_RUN, snapshot, {})
    assert grants == {"/dev/pts": frozenset({"read", "write", "ioctl"})}


def test_an_undeclared_exercise_gets_no_ioctl_grant_from_the_same_run(tmp_path, monkeypatch):
    monkeypatch.setattr(stages.control, "landlock_caused", lambda denial, *rest: True)
    snapshot = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    grants = stages.filesystem_grants(terminal_pruning(tmp_path, False), PTY_RUN, snapshot, {})
    assert not any("ioctl" in sections for sections in grants.values())
    assert "/dev/pts" not in grants


def test_an_ioctl_denial_alone_does_not_grant_the_directory_to_an_undeclared_exercise(tmp_path, monkeypatch):
    monkeypatch.setattr(stages.control, "landlock_caused", lambda denial, *rest: True)
    snapshot = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    only_ioctl = [pty_denial("/dev/pts/ptmx", frozenset({"ioctl"}), "TIOCGPTN")]
    assert stages.filesystem_grants(terminal_pruning(tmp_path, False), only_ioctl, snapshot, {}) == {}


def test_the_permissive_policy_of_a_declared_exercise_holds_the_terminal_directory_and_no_other_device():
    declared = cfgfile.permissive_policy(pathlib.Path("/"), (), True)
    undeclared = cfgfile.permissive_policy(pathlib.Path("/"), (), False)
    assert declared.fs["/dev/pts"] == frozenset({"read", "write", "ioctl"})
    assert "/dev/pts" not in undeclared.fs
    assert {path for path, sections in declared.fs.items() if "ioctl" in sections} == {"/dev/pts"}
