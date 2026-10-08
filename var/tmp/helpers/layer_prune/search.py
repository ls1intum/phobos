"""The grow loop and the minimisation of A.6.4: grant what refusals prove, then remove what was not needed.

Both work on the run as a black box. `grow` asks an observed run what it was refused and grants that,
round by round, until the run matches the reference; it never turns a failure without an attributed
denial into a grant, and it aborts when a grant does not make its own refusal disappear. `minimise`
removes grants by a binary split, keeping a removal only after two passing runs; every decision is
final, so it ends after at most 2n - 1 trials and 4n - 2 runs (decision 10: no run budget).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any, Generic, TypeVar

from layer_prune import cfgfile, verdict

Item = TypeVar("Item")


class PruneAbort(Exception):
    """The exercise cannot be pruned for the stated reason; no configuration is written for it.

    `evidence` carries what the record should show about why, for example the denials that
    survived their grant or the run that failed without one.
    """

    def __init__(self, reason: str, evidence: dict[str, Any] | None = None) -> None:
        """Keeps the reason as the message and the evidence beside it."""
        super().__init__(reason)
        self.reason = reason
        self.evidence = evidence or {}


@dataclasses.dataclass(frozen=True)
class MinimiseResult(Generic[Item]):
    """What minimise kept, how many trials it made (nodes tested) and how many runs they took."""

    kept: list[Item]
    trials: int
    runs: int


@dataclasses.dataclass
class MinimiseState:
    """The running state of one minimisation: the positions of the items kept so far, and the counts."""

    kept: list[int]
    trials: int = 0
    runs: int = 0


def try_removal(node: list[int], items: list[Item], passes: Callable[[list[Item]], bool], state: MinimiseState) -> None:
    """Tries removing one node of the split tree, a list of positions; on failure, its halves in turn.

    The removal is kept only when two runs in a row pass, and once kept or refused it is never tried again.
    """
    removed = set(node)
    candidate = [position for position in state.kept if position not in removed]
    state.trials += 1
    state.runs += 1
    if passes([items[position] for position in candidate]):
        state.runs += 1
        if passes([items[position] for position in candidate]):
            state.kept = candidate
            return
    if len(node) > 1:
        middle = len(node) // 2
        try_removal(node[:middle], items, passes, state)
        try_removal(node[middle:], items, passes, state)


def minimise(items: list[Item], passes: Callable[[list[Item]], bool]) -> MinimiseResult[Item]:
    """Removes every item the runs show is not needed, by A.6.4's binary split, every decision final.

    `passes` makes one run with the given items granted and answers whether it matched the reference.
    The result keeps the items in their original order. Its 1-minimality rests on monotone outcomes,
    as A.6.4 states; it terminates within its bound either way.
    """
    state = MinimiseState(kept=list(range(len(items))))
    if items:
        try_removal(list(state.kept), items, passes, state)
    return MinimiseResult(kept=[items[position] for position in state.kept], trials=state.trials, runs=state.runs)


def with_grants(policy: cfgfile.Policy, grants: dict[str, frozenset[str]]) -> cfgfile.Policy:
    """The policy with the grants added to its filesystem sections, path by path."""
    fs = dict(policy.fs)
    for path, sections in grants.items():
        fs[path] = fs.get(path, frozenset()) | sections
    return dataclasses.replace(policy, fs=fs)


def already_granted(policy: cfgfile.Policy, grants: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """The grants that add nothing to the policy: a refusal that asks for one survived its own grant.

    A grant adds nothing when the policy already holds every right it names on its path, through an
    entry on the path itself or on an ancestor, since Landlock unions the rights along a path. A grant
    that overlaps the policy but adds a right (write beside a read already held) is not one.
    """
    return {path: sections for path, sections in grants.items()
            if cfgfile.rights_of(sections) <= cfgfile.covered_rights(path, policy)}


def grow(run: Callable[[cfgfile.Policy], Any], seed: cfgfile.Policy, reference: verdict.Verdict, rounds: int,
         derive: Callable[[Any], dict[str, frozenset[str]]],
         rerun: Callable[[cfgfile.Policy], Any] | None = None) -> cfgfile.Policy:
    """Grows the policy from the refusals of observed runs until a run matches the reference (A.6.4).

    `run` makes one observed run and returns a result with a `verdict`; `derive` turns a result into the
    grants its attributed, Landlock-caused denials ask for. A run that matches the reference ends the
    loop, and the denials it still had are left ungranted. A failing run that asks for nothing is made
    once more with `rerun` (unobserved): when that rerun matches, the failure was the observer's, and the
    policy is returned as it stands, since grading runs unobserved; otherwise it aborts. A run whose
    grants all add nothing to the policy aborts: the policy already held every right it asked for, so
    its refusals were not caused by their absence. A round that asks for something new as well goes on,
    since one refused call names several objects (an execve the program and its loader), of which only
    some may lack a right; a refusal that keeps surviving beside new grants ends at the budget. An
    exhausted budget aborts too.
    """
    policy = seed
    for _ in range(rounds):
        result = run(policy)
        if verdict.same_outcome(result.verdict, reference):
            return policy
        grants = derive(result)
        survived = already_granted(policy, grants)
        if grants and len(survived) == len(grants):
            raise PruneAbort("a refusal survived its own grant", {"grants": {path: sorted(sections) for path, sections
                                                                              in survived.items()}})
        if not grants:
            if rerun is not None and verdict.same_outcome(rerun(policy).verdict, reference):
                return policy
            raise PruneAbort("failed without an attributable denial", {"verdict": dataclasses.asdict(result.verdict)})
        policy = with_grants(policy, grants)
    raise PruneAbort("did not converge within the grow budget", {"rounds": rounds, "grants": len(policy.fs)})
