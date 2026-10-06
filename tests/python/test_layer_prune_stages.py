"""Checks the stage logic of A.6.4 with a fake runner: the baseline, the permissive run and the network stage."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, runner, search, stages, strace_parse, verdict

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
