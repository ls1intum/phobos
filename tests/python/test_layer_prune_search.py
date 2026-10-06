"""Checks the grow loop and the minimisation of A.6.4 on synthetic runs, both directions and their bounds."""

from __future__ import annotations

import dataclasses
import itertools
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, search, verdict

PASSING = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                          infra_failure=False)
FAILING = verdict.Verdict(exit_class="tests-failed", tests=(("T.a", "failed"),), tests_ran=True, no_source=False,
                          infra_failure=False)


@dataclasses.dataclass(frozen=True)
class FakeRun:
    """A run result as grow reads it: a verdict and the grants its denials would ask for."""

    verdict: verdict.Verdict
    asks: dict[str, frozenset[str]]


def empty_policy() -> cfgfile.Policy:
    """A policy that grants nothing."""
    return cfgfile.Policy(fs={}, connect=(), bind=(), limits={})


def asks_of(result: FakeRun) -> dict[str, frozenset[str]]:
    """The derive function of the fakes: whatever the fake run says its denials ask for."""
    return result.asks


def needs(*paths: str):
    """A run that fails, asking for read on each path the policy lacks, until it grants them all."""
    def run(policy: cfgfile.Policy) -> FakeRun:
        missing = {path: frozenset({"read"}) for path in paths if "read" not in policy.fs.get(path, frozenset())}
        return FakeRun(verdict=FAILING if missing else PASSING, asks=dict(list(missing.items())[:1]))
    return run


def test_minimise_keeps_exactly_the_needed_items():
    needed = {"b", "e"}
    result = search.minimise(list("abcdefgh"), lambda subset: needed <= set(subset))
    assert set(result.kept) == needed


def test_minimise_keeps_the_original_order_and_equal_items_apart():
    result = search.minimise(["x", "y", "x"], lambda subset: subset.count("x") == 2)
    assert result.kept == ["x", "x"]


def test_minimise_stays_within_four_n_minus_two_runs():
    for size in range(1, 40):
        items = list(range(size))
        needed = set(items[::3])
        result = search.minimise(items, lambda subset, needed=needed: needed <= set(subset))
        assert result.trials <= 2 * size - 1
        assert result.runs <= 4 * size - 2
        assert set(result.kept) == needed


def test_a_flaky_oracle_cannot_make_minimise_retry_or_remove_on_one_pass():
    outcomes = itertools.cycle([True, False])
    tried = []

    def flaky(subset):
        tried.append(frozenset(subset))
        return next(outcomes)

    result = search.minimise(list("abcd"), flaky)
    assert result.kept == list("abcd")
    assert len(set(tried)) == result.trials
    assert result.trials <= 7


def test_minimise_of_nothing_makes_no_run():
    result = search.minimise([], lambda subset: pytest.fail("no run expected"))
    assert (result.kept, result.trials, result.runs) == ([], 0, 0)


def test_grow_grants_round_by_round_until_the_run_passes():
    policy = search.grow(run=needs("/a", "/b"), seed=empty_policy(), reference=PASSING, rounds=5, derive=asks_of)
    assert policy.fs == {"/a": frozenset({"read"}), "/b": frozenset({"read"})}


def test_grow_aborts_on_a_failure_without_a_denial():
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        search.grow(run=lambda policy: FakeRun(FAILING, {}), seed=empty_policy(), reference=PASSING, rounds=5,
                    derive=asks_of)


def test_grow_goes_on_when_the_unobserved_rerun_matches_and_aborts_when_it_does_not():
    calls = iter([FakeRun(FAILING, {}), FakeRun(FAILING, {"/a": frozenset({"read"})}), FakeRun(PASSING, {})])
    policy = search.grow(run=lambda policy: next(calls), seed=empty_policy(), reference=PASSING, rounds=5,
                         derive=asks_of, rerun=lambda policy: FakeRun(PASSING, {}))
    assert policy.fs == {"/a": frozenset({"read"})}
    with pytest.raises(search.PruneAbort, match="without an attributable denial"):
        search.grow(run=lambda policy: FakeRun(FAILING, {}), seed=empty_policy(), reference=PASSING, rounds=5,
                    derive=asks_of, rerun=lambda policy: FakeRun(FAILING, {}))


def test_grow_withdraws_a_grant_that_did_not_take_effect_and_aborts():
    with pytest.raises(search.PruneAbort, match="survived its own grant") as aborted:
        search.grow(run=lambda policy: FakeRun(FAILING, {"/a": frozenset({"read"})}), seed=empty_policy(),
                    reference=PASSING, rounds=5, derive=asks_of)
    assert aborted.value.evidence["grants"] == {"/a": ["read"]}


def test_grow_stops_when_the_verdict_matches_and_leaves_harmless_denials_ungranted():
    policy = search.grow(run=lambda policy: FakeRun(PASSING, {"/maybe": frozenset({"read"})}), seed=empty_policy(),
                         reference=PASSING, rounds=5, derive=asks_of)
    assert policy.fs == {}


def test_grow_aborts_when_the_budget_runs_out():
    with pytest.raises(search.PruneAbort, match="did not converge"):
        search.grow(run=needs("/a", "/b", "/c"), seed=empty_policy(), reference=PASSING, rounds=2, derive=asks_of)
