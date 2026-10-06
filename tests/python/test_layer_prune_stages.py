"""Checks the stage logic of A.6.4 with a fake runner: the baseline, the permissive run and the network stage."""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, record, runner, search, stages, strace_parse, verdict

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
    monkeypatch.setattr(stages.control, "landlock_caused", lambda denial: True)
    found = pruning(tmp_path)
    snapshot = stages.generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=())
    written = stages.filesystem_grants(found, [proc_denial("/proc/412/oom_score_adj", "write")], snapshot, {})
    assert written == {}
    assert found.log[-1]["reported"][0]["section"] == "write"
    read = stages.filesystem_grants(found, [proc_denial("/proc/413/status", "read", pid=413)], snapshot, {})
    assert read == {"/proc": frozenset({"read"})}


def test_the_pristine_index_leaves_out_the_pseudo_filesystems_links_and_the_pruners_own_directories(tmp_path):
    root = tmp_path / "root"
    for directory in ("proc/1", "srv/data", "var/tmp/testing-dir/build", "var/tmp/logs"):
        (root / directory).mkdir(parents=True)
    (root / "srv" / "data" / "x").write_text("x")
    (root / "bin").symlink_to("srv")
    environment = runner.Environment(testing_dir=str(root / "var/tmp/testing-dir"), log_dir=str(root / "var/tmp/logs"),
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
    monkeypatch.setattr(stages.containment, "plant_canaries", lambda: None)
    monkeypatch.setattr(stages.sampler, "become_subreaper", lambda: False)
    with pytest.raises(runner.PrunerDefect, match="subreaper"):
        stages.prune_exercise(pruning(tmp_path).exercise, stages.Budget(), runner.Environment())


def test_the_permissive_run_without_any_refusal_is_one_without_an_attributable_denial(tmp_path, monkeypatch):
    feed(monkeypatch, result(FAILED))
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        stages.permissive_run(pruning(tmp_path))
