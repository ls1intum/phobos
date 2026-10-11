"""Checks which containment checks a policy gets and how a probe's output is judged (A.6.4, Task 7.2)."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.application import containment, search
from exercise_pruner.src.infrastructure import runner
from shared.src.domain import cfgfile


def policy(fs: dict[str, set[str]] | None = None, connect: tuple[str, ...] = (), bind: tuple[str, ...] = (),
           limits: dict[str, int] | None = None) -> cfgfile.Policy:
    """A policy from plain sets."""
    return cfgfile.Policy(fs={path: frozenset(sections) for path, sections in (fs or {}).items()},
                          connect=connect, bind=bind, limits=limits or {})


def names(found: list[containment.ContainmentCheck]) -> list[str]:
    """The names of the checks."""
    return [check.name for check in found]


def test_every_canary_is_checked_even_under_a_policy_that_grants_its_directory():
    found = names(containment.checks(policy({"/srv": {"read"}})))
    assert all(f"canary {canary}" in found for canary in containment.CANARIES)


def test_a_named_destination_or_port_is_not_checked_and_an_unnamed_one_is():
    plain = names(containment.checks(policy()))
    named = names(containment.checks(policy(connect=("allow 10.0.0.1:80",), bind=("allow 8080",))))
    assert "connect 10.0.0.1:80" in plain
    assert "bind 8080" in plain
    assert "connect 10.0.0.1:80" not in named
    assert "bind 8080" not in named


def test_each_derived_limit_the_probe_can_exceed_gets_a_check(tmp_path):
    found = names(containment.checks(policy({str(tmp_path): {"write", "create"}},
                                            limits={"nofile": 256, "nproc": 64, "fsize_mb": 16, "timeout": 60, "cpu": 30})))
    assert {"nofile", "nproc", "fsize_mb", "timeout", "cpu"} <= set(found)
    assert "mem_mb" not in found
    beyond = names(containment.checks(policy(limits={"timeout": 600, "nofile": 100000})))
    assert "timeout" not in beyond
    assert "nofile" not in beyond


def test_a_read_only_grant_gets_a_write_check_and_one_beneath_a_writable_grant_does_not(tmp_path):
    readable = tmp_path / "data"
    readable.mkdir()
    only_read = containment.checks(policy({str(readable): {"read"}}))
    beneath = containment.checks(policy({str(readable): {"read"}, str(tmp_path): {"write", "create"}}))
    assert any(check.name.startswith("write into") for check in only_read)
    assert not any(check.name.startswith("write into") for check in beneath)


def test_the_probe_runs_with_only_itself_and_dev_null_added():
    base = policy({"/usr": {"read", "execute"}})
    added = containment.probe_policy(base)
    assert set(added.fs) - set(base.fs) == {containment.PROBE, "/dev/null"}
    assert added.fs["/dev/null"] == frozenset({"read"})


@pytest.mark.parametrize(("output", "status", "expected"), [
    ("OP open ret=-1 errno=EACCES\n", 0, True),
    ("OP open ret=3 errno=0\nOP read ret=6 errno=0\n", 0, False),
    ("OP open ret=-1 errno=ENOENT\n", 0, False),
])
def test_a_check_is_refused_only_by_the_errno_it_names(output, status, expected):
    check = containment.ContainmentCheck("canary", ("read", "/x"), frozenset({"EACCES"}))
    assert containment.refused(check, status, output) is expected


def test_a_limit_check_is_refused_by_its_status_or_its_line():
    timeout = containment.ContainmentCheck("timeout", ("sleep", "65"), frozenset({"status:14"}))
    nofile = containment.ContainmentCheck("nofile", ("openfiles", "257"), frozenset({"EMFILE"}), "errno=EMFILE")
    assert containment.refused(timeout, 14, "SLEEPING 65\n")
    assert not containment.refused(timeout, 0, "SLEPT\n")
    assert containment.refused(nofile, 1, "OPENED 253 of 257 errno=EMFILE\n")
    assert not containment.refused(nofile, 0, "OPENED 257 of 257 errno=0\n")


def environment_in(tmp_path: pathlib.Path, monkeypatch) -> runner.Environment:
    """An environment under tmp_path whose gate accepts every candidate."""
    monkeypatch.setattr(runner, "gate", lambda text, cfg, environment, log_path: runner.write_candidate(text, cfg, log_path))
    return runner.Environment(candidate_dir=str(tmp_path / "run"), log_dir=str(tmp_path / "logs"))


def test_a_check_the_probe_passes_aborts_the_exercise(tmp_path, monkeypatch):
    monkeypatch.setattr(containment, "run_check", lambda check, cfg, environment, log: {"name": check.name,
                                                                                         "refused": False})
    with pytest.raises(search.PruneAbort, match="containment check passed"):
        containment.run_checks(policy({"/srv": {"read"}}), environment_in(tmp_path, monkeypatch))


def test_a_limit_no_check_can_exceed_is_recorded_unchecked_and_never_aborts(tmp_path, monkeypatch):
    monkeypatch.setattr(containment, "run_check", lambda check, cfg, environment, log: {"name": check.name,
                                                                                         "refused": True})
    results = containment.run_checks(policy(limits={"timeout": 600, "nofile": 100000}),
                                     environment_in(tmp_path, monkeypatch))
    unchecked = {result["name"]: result["unchecked"] for result in results if "unchecked" in result}
    assert set(unchecked) >= {"timeout", "nofile"}


def test_nproc_is_unchecked_as_root_and_checked_otherwise(monkeypatch):
    monkeypatch.setattr(containment.os, "geteuid", lambda: 0)
    assert "nproc" not in names(containment.checks(policy(limits={"nproc": 64})))
    assert containment.unchecked(policy(limits={"nproc": 64}))[0]["unchecked"].startswith("uid 0")
    monkeypatch.setattr(containment.os, "geteuid", lambda: 1000)
    assert "nproc" in names(containment.checks(policy(limits={"nproc": 64})))
    assert containment.unchecked(policy(limits={"nproc": 64})) == []


def test_a_check_whose_control_is_refused_too_is_unproven_and_aborts(tmp_path, monkeypatch):
    def probe(argv, check):
        refused_everywhere = "START\nOP open ret=-1 errno=EACCES\n"
        return containment.ProbeRun(status=0, output=refused_everywhere)
    monkeypatch.setattr(containment, "run_probe", probe)
    canary = containment.checks(policy())[0]
    assert containment.run_check(canary, tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")["refused"] is None
    monkeypatch.setattr(containment, "checks", lambda final: [canary])
    with pytest.raises(search.PruneAbort, match="unproven"):
        containment.run_checks(policy(), environment_in(tmp_path, monkeypatch))


def test_a_check_counts_as_refused_only_under_phobos_after_its_control_succeeded(tmp_path, monkeypatch):
    def probe(argv, check):
        sandboxed = argv[0].endswith("phobos.sh")
        line = "OP open ret=-1 errno=EACCES" if sandboxed else "OP open ret=3 errno=0"
        return containment.ProbeRun(status=0, output=f"START\n{line}\n")
    monkeypatch.setattr(containment, "run_probe", probe)
    entry = containment.run_check(containment.checks(policy())[0], tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")
    assert entry["refused"] is True
    assert entry["control"]["evidence"] == ["OP open ret=3 errno=0"]


def test_a_probe_that_did_not_start_without_phobos_is_unproven(tmp_path, monkeypatch):
    monkeypatch.setattr(containment, "run_probe", lambda argv, check: containment.ProbeRun(status=127, output=""))
    entry = containment.run_check(containment.checks(policy())[0], tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")
    assert entry["refused"] is None


def test_a_phobos_stop_before_the_probe_started_is_a_pruner_defect(tmp_path, monkeypatch):
    def probe(argv, check):
        if argv[0].endswith("phobos.sh"):
            return containment.ProbeRun(status=11, output="Policy invalid. (PHB-EPOLICY)\n")
        return containment.ProbeRun(status=0, output="START\nOP open ret=3 errno=0\n")
    monkeypatch.setattr(containment, "run_probe", probe)
    with pytest.raises(runner.PrunerDefect, match="PHB-EPOLICY"):
        containment.run_check(containment.checks(policy())[0], tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")


def test_the_write_check_never_truncates_and_a_new_name_is_removed_afterwards(tmp_path):
    existing = tmp_path / "data.txt"
    existing.write_text("keep\n")
    on_file = containment.write_check(str(existing))
    assert on_file.probe_arguments == ("open", str(existing), "w")
    assert on_file.leaves is None
    in_directory = containment.write_check(str(tmp_path / containment.WRITE_CHECK_FILE))
    assert in_directory.probe_arguments[2] == "excl"
    assert in_directory.leaves == str(tmp_path / containment.WRITE_CHECK_FILE)


def test_a_rule_names_the_tcp_check_only_for_tcp_or_both_transports():
    assert containment.names_connect(policy(connect=("allow 10.0.0.1",)), "10.0.0.1", "80")
    assert containment.names_connect(policy(connect=("allow 10.0.0.1:* tcp",)), "10.0.0.1", "80")
    assert not containment.names_connect(policy(connect=("allow 10.0.0.1:80 udp",)), "10.0.0.1", "80")
    assert not containment.names_connect(policy(connect=("allow 10.0.0.2:80",)), "10.0.0.1", "80")
    assert containment.names_bind(policy(bind=("allow 8080",)), "8080")
    assert not containment.names_bind(policy(bind=("allow 8080 udp",)), "8080")


def test_a_cpu_limit_the_timeout_reaches_first_and_a_file_size_without_a_directory_are_unchecked():
    found = {entry["name"]: entry["unchecked"] for entry in containment.unchecked(policy(limits={"cpu": 60, "timeout": 30,
                                                                                                "fsize_mb": 16}))}
    assert found["cpu"].startswith("the timeout ends")
    assert found["fsize_mb"].startswith("the policy grants no directory")


def test_the_probe_policy_is_normalised_so_render_accepts_it():
    final = policy({"/usr/local/libexec": {"read", "execute", "write"}})
    cfgfile.render(containment.probe_policy(final))


def test_the_write_check_never_reaches_a_pseudo_filesystem(tmp_path):
    readable = tmp_path / "data"
    readable.mkdir()
    found = containment.checks(policy({"/proc": {"read"}, "/sys": {"read"}, "/dev/null": {"read"},
                                       str(readable): {"read"}}))
    writes = [check for check in found if check.name.startswith("write into")]
    assert [check.probe_arguments[1] for check in writes] == [str(readable / containment.WRITE_CHECK_FILE)]


def test_a_control_that_fails_for_another_reason_leaves_a_file_check_unproven(tmp_path, monkeypatch):
    def probe(argv, check):
        if argv[0].endswith("phobos.sh"):
            return containment.ProbeRun(status=0, output="START\nOP open ret=-1 errno=EACCES\n")
        return containment.ProbeRun(status=0, output="START\nOP open ret=-1 errno=ENOENT\n")
    monkeypatch.setattr(containment, "run_probe", probe)
    entry = containment.run_check(containment.checks(policy())[0], tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")
    assert entry["refused"] is None


def test_a_network_check_needs_only_a_control_not_refused_the_same_way(tmp_path, monkeypatch):
    def probe(argv, check):
        if argv[0].endswith("phobos.sh"):
            return containment.ProbeRun(status=0, output="START\nOP connect ret=-1 errno=EACCES\n")
        return containment.ProbeRun(status=0, output="START\nOP connect ret=-1 errno=ENETUNREACH\n")
    monkeypatch.setattr(containment, "run_probe", probe)
    connect = next(check for check in containment.checks(policy()) if check.name.startswith("connect"))
    assert containment.run_check(connect, tmp_path / "x.cfg", runner.Environment(), tmp_path / "log")["refused"] is True
