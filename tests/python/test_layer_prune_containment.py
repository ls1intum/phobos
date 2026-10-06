"""Checks which containment checks a policy gets and how a probe's output is judged (A.6.4, Task 7.2)."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, containment, search


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


def test_a_check_the_probe_passes_aborts_the_exercise(tmp_path, monkeypatch):
    monkeypatch.setattr(containment, "run_check", lambda check, cfg, phobos: {"name": check.name, "refused": False})
    with pytest.raises(search.PruneAbort, match="containment check passed"):
        containment.run_checks(policy({"/srv": {"read"}}), candidate_dir=str(tmp_path))


def test_a_limit_no_check_can_exceed_is_recorded_unchecked_and_never_aborts(tmp_path, monkeypatch):
    monkeypatch.setattr(containment, "run_check", lambda check, cfg, phobos: {"name": check.name, "refused": True})
    results = containment.run_checks(policy(limits={"timeout": 600, "nofile": 100000}), candidate_dir=str(tmp_path))
    unchecked = {result["name"]: result["unchecked"] for result in results if "unchecked" in result}
    assert set(unchecked) >= {"timeout", "nofile"}


def test_nproc_is_unchecked_as_root_and_checked_otherwise(monkeypatch):
    monkeypatch.setattr(containment.os, "geteuid", lambda: 0)
    assert "nproc" not in names(containment.checks(policy(limits={"nproc": 64})))
    assert containment.unchecked(policy(limits={"nproc": 64}))[0]["unchecked"].startswith("uid 0")
    monkeypatch.setattr(containment.os, "geteuid", lambda: 1000)
    assert "nproc" in names(containment.checks(policy(limits={"nproc": 64})))
    assert containment.unchecked(policy(limits={"nproc": 64})) == []
