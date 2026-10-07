"""The per-exercise pipeline of A.6.4: baseline, permissive run, filesystem, network, limits, verification.

Each stage has one layer that can deny, which keeps attribution unambiguous: the filesystem stage runs
with the network layer and the limits off (except for the declared hosts of an exercise that names
some, see filesystem_run), the network stage with the filesystem fixed, the limits stage under both. The joint verification is the only run shape that matters for grading, and a denial
found there goes back to the stage that owns it. Everything a stage concludes is appended to the
record, so a reviewer of the generated policy sees why each grant is there and what was left out.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import shutil
from typing import Any

from layer_prune import (
    attribute,
    cfgfile,
    containment,
    control,
    generalise,
    limits,
    network,
    pinned,
    record,
    runner,
    sampler,
    search,
    verdict,
)

# How many times each run of the baseline is made, and how often a failing joint verification may send
# a denial back to its stage.
BASELINE_RUNS = 3
ROUTING_ROUNDS = 2
# How often each limit may be doubled after a run ended at it (A.6.5).
LIMIT_RAISES = 3
# The calls by which a fixed refusal of a UNIX-domain destination shows, which nearly every run has.
UNIX_SENDS = frozenset({"connect", "sendto", "sendmsg", "sendmmsg"})
# How many observed objects a widening lists, and the most entries beneath a directory it counts.
WIDENING_EXAMPLES = 10
WIDENING_COUNT_LIMIT = 100000
# Bytes per megabyte, for the largest file a run wrote.
BYTES_PER_MEGABYTE = 1024 * 1024
# The pseudo filesystems the index of what existed before the first run leaves out: what exists there
# is the kernel's answer at the moment, never a run's leftover.
UNINDEXED_ROOTS = ("/proc", "/sys")
# What restore_pristine never removes although the index does not hold it: the device nodes the kernel
# makes, and the canaries the containment checks read.
NEVER_CLEANED = ("/dev", "/srv/phobos-prune-canary", "/root/phobos-prune-canary")
# The environment variable the prune image sets: removing what runs leave behind is only safe in a
# container that exists for the prune.
PRUNE_CONTAINER_VARIABLE = "PHOBOS_PRUNE_CONTAINER"
# The run shapes of the stages (A.6.4).
OBSERVED_FILESYSTEM = runner.RunShape(observe=True, network=False, limits=False, sample=False)
UNOBSERVED_FILESYSTEM = runner.RunShape(observe=False, network=False, limits=False, sample=False)
OBSERVED_NETWORK = runner.RunShape(observe=True, network=True, limits=False, sample=False)
UNOBSERVED_NETWORK = runner.RunShape(observe=False, network=True, limits=False, sample=False)
SAMPLED = runner.RunShape(observe=False, network=True, limits=False, sample=True)
LIMITED = runner.RunShape(observe=False, network=True, limits=True, sample=True)
OBSERVED_LIMITED = runner.RunShape(observe=True, network=True, limits=True, sample=False)
JOINT = runner.RunShape(observe=False, network=True, limits=True, sample=False)
OBSERVED_JOINT = runner.RunShape(observe=True, network=True, limits=True, sample=False)


@dataclasses.dataclass(frozen=True)
class Budget:
    """The abort conditions of A.6.4; there is no minimisation budget (decision 10)."""

    grow_rounds: int = 40
    network_rounds: int = 10
    verification_runs: int = 3
    run_seconds: int = 1800


@dataclasses.dataclass
class Pruning:
    """One exercise's pruning: its inputs, the runs made so far, the denials seen, and the record."""

    exercise: runner.Exercise
    budget: Budget
    environment: runner.Environment
    reference: verdict.Verdict | None = None
    observed_runs: int = 0
    history: list[record.Denial] = dataclasses.field(default_factory=list)
    log: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    removed_pairs: set[tuple[str, str]] = dataclasses.field(default_factory=set)
    removed_rules: set[tuple[str, str]] = dataclasses.field(default_factory=set)
    comments: dict[str, str] = dataclasses.field(default_factory=dict)
    pinned_roots: dict[str, str] = dataclasses.field(default_factory=dict)
    pristine: generalise.Snapshot = dataclasses.field(
        default_factory=lambda: generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=()))

    def note(self, stage: str, **details: Any) -> None:
        """Appends one entry to the record."""
        self.log.append({"stage": stage, **details})

    def run(self, policy: cfgfile.Policy, shape: runner.RunShape, stage: str) -> runner.RunResult:
        """One layered run from the state the index records, recorded with its shape and outcome."""
        removed = restore_pristine(self)
        if removed:
            self.note("restored", removed=removed[:WIDENING_EXAMPLES], count=len(removed))
        result = runner.run_layers(self.exercise, policy, shape, self.environment)
        self.note(stage, run=result.log_path.name, shape=dataclasses.asdict(shape), status=result.status,
                  verdict=dataclasses.asdict(result.verdict), seconds=round(result.wall_seconds, 3))
        return result

    def matches(self, result: runner.RunResult) -> bool:
        """Whether a run agrees with the reference."""
        return self.reference is not None and verdict.same_outcome(result.verdict, self.reference)


def denials_of(pruning: Pruning, result: runner.RunResult) -> list[record.Denial]:
    """The denials of one observed run, numbered by run, with /proc/self rewritten and paths canonical.

    A path under /proc or /dev is never resolved by the pruner, which would resolve its own magic
    links; any other path is resolved with os.path.realpath, since Landlock anchors on the inode.
    """
    if result.trace is None:
        return []
    pruning.observed_runs += 1
    found = []
    for denial in attribute.denials(result.trace, runner.TESTING_DIR):
        objects = tuple(canonical(generalise.rewrite_self(path, denial.pid, denial.tid)) for path in denial.objects)
        found.append(dataclasses.replace(denial, objects=objects, run=pruning.observed_runs))
    return found


def canonical(path: str) -> str:
    """The path Landlock would see: resolved outside /proc and /dev, as written inside them."""
    if path.startswith(("/proc/", "/dev/")) or path in ("/proc", "/dev"):
        return path
    return os.path.realpath(path)


# The outcomes of a test that mean it did not pass; a skipped test is neither passed nor failed.
FAILING_OUTCOMES = (verdict.FAILED, verdict.UNREADABLE)


def baseline(pruning: Pruning) -> verdict.Verdict:
    """Three reference runs that ran tests, without NO-SOURCE or an infrastructure failure, all alike (A.8)."""
    reference = None
    for attempt in range(BASELINE_RUNS):
        result = runner.run_reference(pruning.exercise, pruning.environment)
        pruning.note("baseline", attempt=attempt + 1, status=result.status, verdict=dataclasses.asdict(result.verdict))
        found = result.verdict
        if not found.tests_ran or found.no_source or found.infra_failure:
            raise search.PruneAbort("the reference run ran no tests or failed for an infrastructure reason",
                                    {"verdict": dataclasses.asdict(found)})
        if reference is not None and not verdict.same_outcome(found, reference):
            raise search.PruneAbort("flaky reference", {"first": dataclasses.asdict(reference),
                                                        "later": dataclasses.asdict(found)})
        reference = found
    if pruning.exercise.declared_hosts and any(outcome in FAILING_OUTCOMES for _, outcome in reference.tests):
        diagnose_declared_reference(pruning, reference)
    return reference


def diagnose_declared_reference(pruning: Pruning, reference: verdict.Verdict) -> None:
    """Says why the reference of an exercise that declares hosts fails tests under the layers; always raises PruneAbort.

    Such a reference runs under the layers with its declared hosts as its only external rules, so a
    host it needs but did not declare makes it fail its own tests, consistently, and the baseline
    would take that failure as the outcome to reproduce. One observed run names the undeclared
    destination ("needs external network", A.6.5); without one, the reference is not one to prune from.
    This errs restrictive: a reference that declares hosts and fails a test by design is not pruned,
    while one without declared hosts may fail as long as it fails the same way every time. A skipped
    test is not a failure and never starts this diagnosis. A diagnosis run that matches the reference
    is reported as such, since then the failure is not the layers' doing.
    """
    policy = cfgfile.permissive_policy(pathlib.Path("/"), pruning.exercise.declared_hosts)
    result = pruning.run(policy, OBSERVED_NETWORK, "reference diagnosis")
    external = network.network_rules(denials_of(pruning, result), frozenset(),
                                     pruning.exercise.declared_hosts).refused_external
    if external:
        raise search.PruneAbort("needs external network: undeclared " + ", ".join(external),
                                {"refused_external": list(external)})
    if verdict.same_outcome(result.verdict, reference):
        raise search.PruneAbort("the reference fails its own tests, also under the layers with only its declared hosts",
                                {"verdict": dataclasses.asdict(result.verdict)})
    raise search.PruneAbort("the reference fails its own tests under the layers with only its declared hosts, "
                            "and the diagnosis run did not match it",
                            {"verdict": dataclasses.asdict(result.verdict)})


def permissive_run(pruning: Pruning) -> None:
    """The permissive layered run: every layer on, everything granted that a policy may grant.

    A difference is named by its likeliest cause, in this order: a fixed rule of the layers other
    than a refused UNIX-domain connect (a setsid the timeout's group lock refuses, a raw socket); then
    a refused external destination, since the run grants no external host but the declared ones
    ("needs external network", A.6.5). Any other failure is one without an attributable denial: the run
    held everything a policy may grant, so no refusal it still met is one a grant could undo. A refused
    UNIX-domain connect comes after the external destination because nearly every run makes one (an
    nscd lookup) and does without it.
    """
    policy = cfgfile.permissive_policy(pathlib.Path("/"), pruning.exercise.declared_hosts)
    result = pruning.run(policy, OBSERVED_NETWORK, "permissive")
    if pruning.matches(result):
        return
    denials = denials_of(pruning, result)
    refusals = jsonable([dataclasses.asdict(denial) for denial in denials
                         if denial.layer in (record.LAYER_FIXED, record.LAYER_OTHER)])
    if any(denial.layer == record.LAYER_FIXED and denial.operation not in UNIX_SENDS for denial in denials):
        raise search.PruneAbort("incompatible with a fixed rule of the layers", {"refusals": refusals})
    external = network.network_rules(denials, frozenset(), pruning.exercise.declared_hosts).refused_external
    if external:
        raise search.PruneAbort("needs external network: undeclared " + ", ".join(external),
                                {"refused_external": list(external)})
    raise search.PruneAbort("the permissive layered run failed without an attributable denial",
                            {"run": result.log_path.name,
                             "denials": jsonable([dataclasses.asdict(denial) for denial in denials])})


def jsonable(value: Any) -> Any:
    """The value with every set and frozenset as a sorted list and every tuple as a list, for the record."""
    if isinstance(value, (set, frozenset)):
        return sorted(jsonable(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    return value


def pristine_index(environment: runner.Environment, root: pathlib.Path = pathlib.Path("/")) -> generalise.Snapshot:
    """Everything that exists before the first run, outside the pseudo filesystems and the pruner's own directories.

    The runs leave files behind outside the working directory, which alone is restored between them,
    and the unsandboxed baseline does so without any restriction. Taken once, before the baseline, the
    index is what grading's fresh container holds; a later snapshot answers from it rather than from
    the filesystem as the earlier runs left it. `root` stands for `/`, so a test can pass a tree.
    """
    roots = [str(entry) for entry in sorted(root.iterdir())
             if entry.is_dir() and not entry.is_symlink() and "/" + entry.name not in UNINDEXED_ROOTS]
    excluded = tuple(os.path.realpath(path) for path in
                     (environment.testing_dir, environment.log_dir, environment.candidate_dir))
    return generalise.Snapshot.take(roots, excluded)


def kept_from_cleaning(environment: runner.Environment) -> tuple[str, ...]:
    """What restore_pristine leaves alone: the pruner's own directories, its output, and NEVER_CLEANED."""
    own = (environment.testing_dir, environment.log_dir, environment.candidate_dir, *environment.kept)
    return tuple(os.path.realpath(path) for path in own) + NEVER_CLEANED


def removed_entry(path: str) -> None:
    """Removes one entry a run left: a directory with what it holds, anything else (a link included) by itself."""
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def restore_pristine(pruning: Pruning) -> list[str]:
    """Removes every entry under the indexed roots that the index does not hold, so a run starts as grading does.

    The unsandboxed baseline and the earlier layered runs leave files outside the working directory,
    which runner.restore alone renews: a fixed-name directory under /tmp, a cache. A later run would
    find it there, where a fresh grading container would have to create it, and its creation would
    never be observed. Only entries the runs added are removed; a file they changed in place stays as
    they left it. The baseline runs are not preceded by this, so a reference that depends on what an
    earlier run of it left still shows as flaky. Runs only in the prune container (PRUNE_CONTAINER_VARIABLE).
    """
    index = pruning.pristine
    kept = kept_from_cleaning(pruning.environment)
    removed: list[str] = []
    for root in index.scanned:
        for current, subdirectories, files in os.walk(root):
            for name in list(subdirectories):
                full = os.path.join(current, name)
                if generalise.within(full, kept) or full in index.existing:
                    if generalise.within(full, kept):
                        subdirectories.remove(name)
                    continue
                subdirectories.remove(name)
                removed_entry(full)
                removed.append(full)
            for name in files:
                full = os.path.join(current, name)
                if full not in index.existing and not generalise.within(full, kept):
                    removed_entry(full)
                    removed.append(full)
    return removed


def snapshot_for(pruning: Pruning, policy: cfgfile.Policy) -> generalise.Snapshot:
    """What existed before the runs: the pristine exercise at the working directory, and the index of the rest.

    Only the working directory and the write-granted directories are climbed from (A.6.5); every other
    path is answered from the index taken before the first run.
    """
    existing: set[str] = set()
    directories: set[str] = set()
    workdir = pruning.exercise.workdir
    for current, subdirectories, files in os.walk(workdir):
        mapped = runner.TESTING_DIR + current[len(str(workdir)):]
        directories.add(mapped)
        existing.add(mapped)
        existing.update(os.path.join(mapped, name) for name in files + subdirectories)
        directories.update(os.path.join(mapped, name) for name in subdirectories)
    roots = sorted(path for path, sections in policy.fs.items() if sections & set(cfgfile.WRITE_SECTIONS)
                   and pruning.pristine.is_directory(path) and not within_testing_dir(path))
    return generalise.Snapshot(existing=frozenset(existing) | pruning.pristine.existing,
                               directories=frozenset(directories) | pruning.pristine.directories,
                               scanned=(runner.TESTING_DIR, *roots), indexed=pruning.pristine.scanned)


def within_testing_dir(path: str) -> bool:
    """Whether a path is the working directory or lies beneath it."""
    return path == runner.TESTING_DIR or cfgfile.is_beneath(path, runner.TESTING_DIR)


def filesystem_grants(pruning: Pruning, current: list[record.Denial], snapshot: generalise.Snapshot,
                      held: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """The grants one run's Landlock-caused filesystem denials ask for, per-run names judged against every run so far.

    `held` is the policy the run held, whose write-class rights the narrowing of [execute] counts too.
    """
    confirmed = [denial for denial in current if denial.layer == record.LAYER_FILESYSTEM and control.landlock_caused(denial)]
    combined = pruning.history + confirmed
    taken = generalise.classify_per_run(combined)
    offset = len(pruning.history)
    grants: dict[str, set[str]] = {}
    remaining = []
    per_run_reported = []
    for position, denial in enumerate(confirmed):
        kept = []
        for path in denial.objects:
            if (offset + position, path) in taken:
                readable = denial.sections & generalise.READ_CLASS
                if readable:
                    grants.setdefault(taken[(offset + position, path)][0], set()).update(readable)
                per_run_reported.extend({"path": path, "section": section,
                                         "reason": "a write-class right on a per-run name is never widened"}
                                        for section in sorted(denial.sections - generalise.READ_CLASS))
            else:
                kept.append(path)
        if kept:
            remaining.append(dataclasses.replace(denial, objects=tuple(kept)))
    found, notes = generalise.grants_and_notes(remaining, snapshot, generalise.DEFAULT_FINE_ROOTS, held,
                                               pruning.pinned_roots)
    notes.reported.extend(per_run_reported)
    for path, sections in found.items():
        grants.setdefault(path, set()).update(sections)
    pruning.comments.update(notes.comments)
    pruning.history.extend(confirmed)
    pruning.note("denials", run=pruning.observed_runs, reported=notes.reported,
                 confirmed=jsonable([dataclasses.asdict(denial) for denial in confirmed]),
                 not_landlock=jsonable([dataclasses.asdict(denial) for denial in current if denial not in confirmed]))
    return {path: frozenset(sections) for path, sections in grants.items()}


def normalised(pruning: Pruning, policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy as it is run: [execute] narrowed, and every nested strict subset raised so render accepts it.

    A write-class right one round grants can land beside an [execute] an earlier round put on a
    directory, so generalise.narrow_execute is applied to the whole policy, with every file the runs
    so far were refused executing, and the comments it writes are kept for the record.
    """
    notes = generalise.Notes()
    executed = sorted({path for denial in pruning.history if "execute" in denial.sections for path in denial.objects})
    narrowed = generalise.narrow_execute(generalise.normalise_hierarchy(policy.fs), executed,
                                         snapshot_for(pruning, policy), notes)
    pruning.comments.update(notes.comments)
    return dataclasses.replace(policy, fs=generalise.normalise_hierarchy(narrowed))


def filesystem_run(pruning: Pruning, policy: cfgfile.Policy, observe: bool, stage: str) -> runner.RunResult:
    """One run of the filesystem stage: the network layer off, so only the filesystem can refuse.

    An exercise that declares hosts can reach them only through the network layer, which maps each
    name and starts the egress broker, so its filesystem runs keep that layer on with exactly the
    network rules of the permissive run (cfgfile.with_permissive_network); the stage's grants still
    come from filesystem refusals only. This errs permissive in one way: a file the build touches only
    while a declared host answers is granted, and prune_exercise minimises the filesystem once more
    under the final rules when the network stage drops a declared host.
    """
    if not pruning.exercise.declared_hosts:
        return pruning.run(policy, OBSERVED_FILESYSTEM if observe else UNOBSERVED_FILESYSTEM, stage)
    open_network = cfgfile.with_permissive_network(policy, pruning.exercise.declared_hosts)
    return pruning.run(open_network, OBSERVED_NETWORK if observe else UNOBSERVED_NETWORK, stage)


def grow_filesystem(pruning: Pruning, seed: cfgfile.Policy) -> cfgfile.Policy:
    """Stage 1's grow loop from a seed policy (A.6.4)."""
    snapshots: list[tuple[generalise.Snapshot, cfgfile.Policy]] = []

    def observed(policy: cfgfile.Policy) -> runner.RunResult:
        """One observed filesystem run, with the snapshot taken before it."""
        snapshots.append((snapshot_for(pruning, policy), policy))
        return filesystem_run(pruning, normalised(pruning, policy), True, "filesystem")

    def derive(result: runner.RunResult) -> dict[str, frozenset[str]]:
        """The grants of one run's denials, generalised against the snapshot taken before it."""
        return filesystem_grants(pruning, denials_of(pruning, result), snapshots[-1][0], snapshots[-1][1].fs)

    def unobserved(policy: cfgfile.Policy) -> runner.RunResult:
        """The same run without the observer."""
        return filesystem_run(pruning, normalised(pruning, policy), False, "filesystem rerun")

    grown = search.grow(observed, seed, pruning.reference, pruning.budget.grow_rounds, derive, unobserved)
    pruning.note("grow", rounds=len(snapshots), grants=len(grown.fs))
    return grown


def minimise_policy_fs(pruning: Pruning, policy: cfgfile.Policy, stage: str,
                       final_network: bool = False) -> cfgfile.Policy:
    """Removes every (path, section) grant two unobserved runs show is not needed (A.6.4, decision 10).

    The runs are filesystem runs (filesystem_run), or with `final_network` runs under the policy's own
    [connect] and [bind] rules with the network layer on; those first prove that the whole policy passes
    under them, since a minimisation from a policy that does not pass would keep everything and fail later
    for a reason it did not name.
    """
    pairs = sorted((path, section) for path, sections in policy.fs.items() for section in sections)

    def passes(kept: list[tuple[str, str]]) -> bool:
        """One unobserved run with only the kept grants."""
        candidate = normalised(pruning, with_pairs(policy, kept))
        if final_network:
            return pruning.matches(pruning.run(candidate, UNOBSERVED_NETWORK, stage))
        return pruning.matches(filesystem_run(pruning, candidate, False, stage))

    if final_network and not passes(pairs):
        raise search.PruneAbort("the filesystem grants do not pass under the final network rules, so there is nothing "
                                "to minimise from")
    result = search.minimise(pairs, passes)
    final = normalised(pruning, with_pairs(policy, result.kept))
    removed = set(pairs) - {(path, section) for path, sections in final.fs.items() for section in sections}
    pruning.removed_pairs.update(removed)
    pruning.note(f"{stage} minimisation", before=len(pairs), kept=len(result.kept), trials=result.trials,
                 runs=result.runs, removed=jsonable(sorted(removed)))
    return final


def with_pairs(policy: cfgfile.Policy, pairs: list[tuple[str, str]]) -> cfgfile.Policy:
    """The policy whose filesystem sections are exactly the given (path, section) pairs."""
    fs: dict[str, set[str]] = {}
    for path, section in pairs:
        fs.setdefault(path, set()).add(section)
    return dataclasses.replace(policy, fs={path: frozenset(sections) for path, sections in fs.items()})


def prune_filesystem(pruning: Pruning, seed: cfgfile.Policy) -> cfgfile.Policy:
    """Stage 1: grow from denials, compact, normalise, minimise, with the network layer and the limits off.

    The network layer stays on for the declared hosts of an exercise that names some (filesystem_run).
    """
    grown = grow_filesystem(pruning, seed)
    compacted = generalise.compact(grown.fs, generalise.DEFAULT_COMPACTION_THRESHOLD, generalise.DEFAULT_FINE_ROOTS)
    pruning.note("compaction", before=sorted(grown.fs), after=sorted(compacted))
    minimised = minimise_policy_fs(pruning, normalised(pruning, dataclasses.replace(grown, fs=compacted)), "filesystem")
    comments = {**pruning.comments, **generalise.per_run_grants(pruning.history)[1]}
    pruning.note("widenings", grants=widenings(pruning, minimised))
    return dataclasses.replace(minimised, comments={path: text for path, text in comments.items() if path in minimised.fs})


def widenings(pruning: Pruning, policy: cfgfile.Policy) -> list[dict[str, Any]]:
    """Every directory grant of the policy with the observed objects behind it and how many entries it covers (A.6.5).

    A directory grant covers its siblings of the observed objects by construction; this list is how
    a reviewer sees exactly where the policy is wider than the observation.
    """
    observed = sorted({path for denial in pruning.history for path in denial.objects})
    found = []
    for path, sections in sorted(policy.fs.items()):
        if not os.path.isdir(path):
            continue
        behind = [item for item in observed if item == path or cfgfile.is_beneath(item, path)]
        found.append({"path": path, "sections": sorted(sections), "observed": behind[:WIDENING_EXAMPLES],
                      "observed_count": len(behind), "covers": entries_beneath(path)})
    return found


def entries_beneath(path: str) -> int:
    """How many entries lie beneath a directory, counted up to WIDENING_COUNT_LIMIT."""
    count = 0
    for _, subdirectories, files in os.walk(path):
        count += len(subdirectories) + len(files)
        if count >= WIDENING_COUNT_LIMIT:
            return WIDENING_COUNT_LIMIT
    return count


def network_decision(pruning: Pruning, result: runner.RunResult) -> network.NetworkDecision:
    """The network rules one observed run's Landlock- or guard-caused network denials ask for."""
    current = [denial for denial in denials_of(pruning, result)
               if denial.layer == record.LAYER_NETWORK and control.landlock_caused(denial)]
    decision = network.network_rules(current, network.bound_ports(result.trace), pruning.exercise.declared_hosts)
    pruning.note("network denials", decision=jsonable(dataclasses.asdict(decision)))
    return decision


def prune_network(pruning: Pruning, policy: cfgfile.Policy, seed_connect: tuple[str, ...] = (),
                  seed_bind: tuple[str, ...] = ()) -> cfgfile.Policy:
    """Stage 2: grow [connect] and [bind] from denials with the filesystem fixed, then minimise every rule (A.6.4).

    The grow starts from the declared hosts' rules plus the seeds the joint verification routes back.
    A refused external destination is never granted. It ends the stage as "needs external network"
    only when the round has nothing else to grant, so an attempt the build does without, beside a
    loopback rule it does need, is recorded and left refused rather than aborting the exercise. A
    failure with nothing to grant is made once more unobserved, as in the filesystem stage, and the
    rules stand when that run matches.
    """
    seeded = network.seed_rules(pruning.exercise.declared_hosts) + seed_connect
    current = dataclasses.replace(policy, connect=tuple(dict.fromkeys(seeded)), bind=tuple(dict.fromkeys(seed_bind)))
    for _ in range(pruning.budget.network_rounds):
        result = pruning.run(current, OBSERVED_NETWORK, "network")
        if pruning.matches(result):
            break
        decision = network_decision(pruning, result)
        connect = tuple(dict.fromkeys(current.connect + decision.connect))
        bind = tuple(dict.fromkeys(current.bind + decision.bind))
        if (connect, bind) == (current.connect, current.bind):
            if decision.refused_external:
                raise search.PruneAbort("needs external network: undeclared " + ", ".join(decision.refused_external),
                                        {"decision": jsonable(dataclasses.asdict(decision))})
            if pruning.matches(pruning.run(current, UNOBSERVED_NETWORK, "network rerun")):
                break
            raise search.PruneAbort("network stage failed without an attributable denial", {"run": result.log_path.name})
        current = dataclasses.replace(current, connect=connect, bind=bind)
    else:
        raise search.PruneAbort("the network stage did not converge within its budget")
    rules = [("connect", rule) for rule in current.connect] + [("bind", rule) for rule in current.bind]

    def passes(kept: list[tuple[str, str]]) -> bool:
        """One unobserved run with only the kept rules."""
        candidate = dataclasses.replace(current, connect=tuple(rule for kind, rule in kept if kind == "connect"),
                                        bind=tuple(rule for kind, rule in kept if kind == "bind"))
        return pruning.matches(pruning.run(candidate, UNOBSERVED_NETWORK, "network minimisation"))

    result = search.minimise(rules, passes)
    pruning.removed_rules.update(set(rules) - set(result.kept))
    pruning.note("network minimisation", before=jsonable(rules), kept=jsonable(result.kept), runs=result.runs)
    return dataclasses.replace(current, connect=tuple(rule for kind, rule in result.kept if kind == "connect"),
                               bind=tuple(rule for kind, rule in result.kept if kind == "bind"))


def largest_file_mb(policy: cfgfile.Policy) -> float:
    """The largest file under the policy's write grants after a run, in megabytes (what `ulimit -f` bounds)."""
    largest = 0
    for path, sections in policy.fs.items():
        if not sections & set(cfgfile.WRITE_SECTIONS):
            continue
        if os.path.isfile(path):
            largest = max(largest, os.path.getsize(path))
        for current, _, files in os.walk(path):
            for name in files:
                full = os.path.join(current, name)
                if os.path.isfile(full) and not os.path.islink(full):
                    largest = max(largest, os.path.getsize(full))
    return largest / BYTES_PER_MEGABYTE


def measure(result: runner.RunResult, policy: cfgfile.Policy) -> limits.Measurement:
    """One sampled run's peaks: wall clock, the CPU time of the busiest process, address space, tasks, descriptors, file."""
    samples = result.samples or []
    last: dict[int, dict] = {}
    for sample in samples:
        last[sample["pid"]] = sample
    return limits.Measurement(
        wall_seconds=result.wall_seconds,
        cpu_seconds=max((sample["cpu_seconds"] for sample in last.values()), default=0.0),
        vm_peak_mb=max((sample["vm_peak_mb"] for sample in samples), default=0.0),
        tasks=max((sample["tasks"] for sample in samples), default=0),
        highest_descriptor=max((sample["highest_descriptor"] for sample in samples), default=0),
        largest_file_mb=largest_file_mb(policy),
    )


def last_samples(result: runner.RunResult) -> list[dict]:
    """The last sample of each process of a sampled run."""
    last: dict[int, dict] = {}
    for sample in result.samples or []:
        last[sample["pid"]] = sample
    return list(last.values())


def limit_denials(pruning: Pruning, result: runner.RunResult) -> list[record.Denial]:
    """The exhausted-resource refusals of one observed run."""
    return [denial for denial in denials_of(pruning, result) if denial.layer == record.LAYER_LIMIT]


def measured_run(pruning: Pruning, policy: cfgfile.Policy) -> limits.Measurement:
    """One sampled run with every limit off, measured at once, before the next run restores the working directory."""
    result = pruning.run(policy, SAMPLED, "limits measurement")
    if not pruning.matches(result):
        raise search.PruneAbort("a run with every limit off did not match the reference")
    if not result.samples:
        raise runner.PrunerDefect(result.status, result.log_path, "a sampled run yielded no sample of its processes")
    return measure(result, policy)


def prune_limits(pruning: Pruning, policy: cfgfile.Policy) -> cfgfile.Policy:
    """Stage 3: measure with the limits off, put the margins on, raise a limit only on its own signature (A.6.5).

    Every raised value is verified; a limit that would need more than LIMIT_RAISES doublings aborts.
    """
    measurements = [measured_run(pruning, policy) for _ in range(BASELINE_RUNS)]
    derived = limits.margins(measurements, limits.Margins(), pruning.exercise.heap_pinned)
    pruning.note("limits", measurements=[dataclasses.asdict(item) for item in measurements], derived=dict(derived),
                 mem_mb="derived" if pruning.exercise.heap_pinned else "left to the default: the heap is not pinned")
    raises: dict[str, int] = {}
    while True:
        current = dataclasses.replace(policy, limits=dict(derived))
        runs = [pruning.run(current, LIMITED, "limits verification") for _ in range(pruning.budget.verification_runs)]
        failed = next((result for result in runs if not pruning.matches(result)), None)
        if failed is None:
            return current
        diagnosis = limit_denials(pruning, pruning.run(current, OBSERVED_LIMITED, "limits diagnosis"))
        unlimited = limit_denials(pruning, pruning.run(policy, OBSERVED_NETWORK, "limits control"))
        signature = limits.limit_signature(failed.status, last_samples(failed), derived, diagnosis, unlimited)
        if signature is None:
            raise search.PruneAbort("failed under limits without a limit signature", {"status": failed.status})
        raises[signature] = raises.get(signature, 0) + 1
        if raises[signature] > LIMIT_RAISES:
            raise search.PruneAbort("limits did not settle", {"limits": derived, "raises": raises})
        derived[signature] *= 2
        pruning.note("limit raised", limit=signature, value=derived[signature])


def joint_runs(pruning: Pruning, policy: cfgfile.Policy) -> bool:
    """Whether verification_runs unobserved runs with every layer on all match the reference."""
    return all(pruning.matches(pruning.run(policy, JOINT, "verification")) for _ in range(pruning.budget.verification_runs))


def unminimised(pruning: Pruning, policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy with every grant and rule the minimisations removed put back."""
    restored = with_pairs(policy, sorted({(path, section) for path, sections in policy.fs.items() for section in sections}
                                         | pruning.removed_pairs))
    connect = tuple(dict.fromkeys(policy.connect + tuple(rule for kind, rule in sorted(pruning.removed_rules)
                                                         if kind == "connect")))
    bind = tuple(dict.fromkeys(policy.bind + tuple(rule for kind, rule in sorted(pruning.removed_rules) if kind == "bind")))
    return normalised(pruning, dataclasses.replace(restored, connect=connect, bind=bind))


def verify(pruning: Pruning, policy: cfgfile.Policy) -> cfgfile.Policy:
    """Stage 4: the joint verification, exactly as grading runs, with the routing of A.6.4.

    When it fails, the grants the minimisations removed are restored first ("minimisation unstable");
    otherwise one observed run is diagnosed. Only a confirmed denial that its stage turns into a grant
    or a rule the policy does not hold yet sends the policy back to that stage, seeded with it, at most
    ROUTING_ROUNDS times; a failure with no such denial aborts. For an exercise that declares hosts a
    filesystem routing grows with the declared hosts reachable and is not minimised again under the
    final rules, which errs permissive in the way filesystem_run states.
    """
    current = policy
    for routed in range(ROUTING_ROUNDS + 1):
        if joint_runs(pruning, current):
            return current
        widened = unminimised(pruning, current)
        if widened != current and joint_runs(pruning, widened):
            pruning.note("minimisation unstable", restored=True)
            return widened
        if routed == ROUTING_ROUNDS:
            break
        diagnosis = pruning.run(current, OBSERVED_JOINT, "verification diagnosis")
        found = denials_of(pruning, diagnosis)
        grants = filesystem_grants(pruning, found, snapshot_for(pruning, current), current.fs)
        survived = search.already_granted(current, grants)
        new_grants = {path: sections for path, sections in grants.items() if path not in survived}
        decision = network.network_rules([denial for denial in found if denial.layer == record.LAYER_NETWORK
                                          and control.landlock_caused(denial)],
                                         network.bound_ports(diagnosis.trace), pruning.exercise.declared_hosts)
        new_connect = tuple(rule for rule in decision.connect if rule not in current.connect)
        new_bind = tuple(rule for rule in decision.bind if rule not in current.bind)
        pruning.note("verification routing", grants=jsonable(new_grants), connect=list(new_connect),
                     bind=list(new_bind))
        if new_grants:
            seed = search.with_grants(current, new_grants)
            current = dataclasses.replace(prune_filesystem(pruning, seed), connect=current.connect,
                                          bind=current.bind, limits=current.limits)
        elif new_connect or new_bind:
            current = dataclasses.replace(prune_network(pruning, current, current.connect + new_connect,
                                                        current.bind + new_bind), limits=current.limits)
        else:
            raise search.PruneAbort("the joint verification failed without a denial a stage owns",
                                    {"layers": sorted({denial.layer for denial in found})})
    raise search.PruneAbort("the joint verification did not settle")


def verify_pinned_roots(pruning: Pruning, when: str = "before the first run") -> None:
    """Checks every pinned read root the exercise declares against its manifest; PruneAbort if one does not match.

    Done before the first run, since only a root that passed is ever granted as a directory
    (generalise.grants_and_notes), and again before the joint verification and at the end, because the
    runs execute as the uid that could change the tree: a prune whose runs changed it is not one to ship.
    The record says which were checked, how many files each manifest fixes and what else each tree holds.
    """
    checked = []
    for root in pruning.exercise.pinned_read_roots:
        try:
            counts = pinned.verify(root)
        except ValueError as failure:
            raise search.PruneAbort(f"a pinned read root does not match its manifest ({when}): {failure}",
                                    {"path": root.path, "manifest": root.manifest}) from failure
        pruning.pinned_roots[root.path] = pinned.GRANT_COMMENT.format(path=root.path, manifest=root.manifest)
        checked.append({"path": root.path, "manifest": root.manifest, **counts})
    if checked:
        pruning.note("pinned read roots", when=when, roots=checked)


def check_pinned_grants(pruning: Pruning, policy: cfgfile.Policy) -> None:
    """Refuses a policy that makes a pinned read root anything but read-only; PruneAbort naming the entry.

    The root itself may hold [read] and nothing else, and no write-class right may sit on it or on an
    ancestor of it, which would make the pinned tree writable. Writes beneath it stay file by file.
    """
    for root in pruning.pinned_roots:
        if set(policy.fs.get(root, ())) - {"read"}:
            raise search.PruneAbort(f"the pinned read root {root} is granted more than [read]",
                                    {"sections": sorted(policy.fs[root])})
        for path, sections in policy.fs.items():
            if sections & generalise.WRITE_CLASS and (path == root or generalise.is_beneath(root, path)):
                raise search.PruneAbort(f"the pinned read root {root} lies under a write-class grant on {path}",
                                        {"sections": sorted(sections)})


def require_prune_container() -> None:
    """Refuses to go on outside the prune container, which sets PRUNE_CONTAINER_VARIABLE=1.

    Every run restores the index taken before the first one, which deletes what the runs left, so
    anything that does so must not run on a host. Assumes the container sets the variable.
    """
    if os.environ.get(PRUNE_CONTAINER_VARIABLE) != "1":
        raise runner.PrunerDefect(-1, pathlib.Path(os.devnull), "the pruner removes what its runs leave behind, so it "
                                  f"runs only in the prune container, which sets {PRUNE_CONTAINER_VARIABLE}=1")


def verify_merged(exercise: runner.Exercise, configs: tuple[pathlib.Path, ...], environment: runner.Environment,
                  pristine: generalise.Snapshot) -> list[dict]:
    """Runs the exercise under the merged configuration files exactly as grading will apply them (A.9); the record.

    The orchestrator writes a language's base as the union of its exercises and each exercise's file
    as what that base lacks, so the pair, not the policy the exercise was pruned with, is what grading
    applies. A baseline as the prune's, then verification_runs runs with every layer on, each from
    the state the index records; any run that does not match the reference raises PruneAbort.
    The base is passed with --config, so its [read] and [execute] paths must exist as an exercise
    configuration's must, which a base beside phobos-policysystem.sh need not: this errs restrictive.
    """
    require_prune_container()
    if not sampler.become_subreaper():
        raise runner.PrunerDefect(-1, pathlib.Path(os.devnull), "the kernel refused to make the pruner a child subreaper")
    pruning = Pruning(exercise=exercise, budget=Budget(), environment=environment, pristine=pristine)
    try:
        pruning.reference = baseline(pruning)
        runner.gate_configs(configs, environment, runner.log_paths(environment, "verify-gate")[0])
        for _ in range(pruning.budget.verification_runs):
            restore_pristine(pruning)
            result = runner.run_configured(exercise, configs, JOINT, environment, runner.log_paths(environment, "verify"))
            pruning.note("merged verification", run=result.log_path.name, status=result.status,
                         verdict=dataclasses.asdict(result.verdict), configs=[str(config) for config in configs])
            if not pruning.matches(result):
                raise search.PruneAbort("a run under the merged base and its exercise file did not match the reference")
    except search.PruneAbort as abort:
        abort.evidence["record"] = pruning.log
        raise
    return pruning.log


def prune_exercise(exercise: runner.Exercise, budget: Budget, environment: runner.Environment,
                   stage: str = "all", pristine: generalise.Snapshot | None = None) -> tuple[cfgfile.Policy, list[dict]]:
    """The pipeline for one exercise up to `stage` (filesystem, network, limits or all); the policy and the record.

    Only "all" runs the joint verification and the containment checks; an earlier stage's policy is a
    step of the pipeline, for tests and diagnosis, not one to ship. PruneAbort carries the record in
    its evidence. `pristine` is the index of what existed before the container's first run
    (pristine_index), taken here when the caller passes none.
    """
    require_prune_container()
    containment.plant_canaries()
    if not sampler.become_subreaper():
        raise runner.PrunerDefect(-1, pathlib.Path(os.devnull), "the kernel refused to make the pruner a child subreaper")
    index = pristine if pristine is not None else pristine_index(environment)
    pruning = Pruning(exercise=exercise, budget=budget, environment=environment, pristine=index)
    try:
        verify_pinned_roots(pruning)
        pruning.reference = baseline(pruning)
        permissive_run(pruning)
        policy = prune_filesystem(pruning, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
        if stage != "filesystem":
            policy = prune_network(pruning, policy)
            if set(network.seed_rules(exercise.declared_hosts)) - set(policy.connect):
                policy = minimise_policy_fs(pruning, policy, "filesystem after network", final_network=True)
        if stage in ("limits", "all"):
            policy = prune_limits(pruning, policy)
        check_pinned_grants(pruning, policy)
        if stage == "all":
            verify_pinned_roots(pruning, "before the joint verification")
            policy = verify(pruning, policy)
            check_pinned_grants(pruning, policy)
            pruning.note("containment", checks=containment.run_checks(policy, environment))
        verify_pinned_roots(pruning, "after the last run")
    except search.PruneAbort as abort:
        abort.evidence["record"] = pruning.log
        raise
    return policy, pruning.log
