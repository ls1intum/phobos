"""The per-exercise pipeline of A.6.4: baseline, permissive run, filesystem, network, limits, verification.

Each stage has one layer that can deny, which keeps attribution unambiguous: the filesystem stage runs
with the network layer and the limits off, the network stage with the filesystem fixed, the limits
stage under both. The joint verification is the only run shape that matters for grading, and a denial
found there goes back to the stage that owns it. Everything a stage concludes is appended to the
record, so a reviewer of the generated policy sees why each grant is there and what was left out.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
from typing import Any

from layer_prune import (
    attribute,
    cfgfile,
    containment,
    control,
    generalise,
    limits,
    network,
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
    pristine: generalise.Snapshot = dataclasses.field(
        default_factory=lambda: generalise.Snapshot(existing=frozenset(), directories=frozenset(), scanned=()))

    def note(self, stage: str, **details: Any) -> None:
        """Appends one entry to the record."""
        self.log.append({"stage": stage, **details})

    def run(self, policy: cfgfile.Policy, shape: runner.RunShape, stage: str) -> runner.RunResult:
        """One layered run, recorded with its shape and outcome."""
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
    return reference


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
    found, notes = generalise.grants_and_notes(remaining, snapshot, generalise.DEFAULT_FINE_ROOTS, held)
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


def grow_filesystem(pruning: Pruning, seed: cfgfile.Policy) -> cfgfile.Policy:
    """Stage 1's grow loop from a seed policy (A.6.4)."""
    snapshots: list[tuple[generalise.Snapshot, cfgfile.Policy]] = []

    def observed(policy: cfgfile.Policy) -> runner.RunResult:
        """One observed filesystem run, with the snapshot taken before it."""
        snapshots.append((snapshot_for(pruning, policy), policy))
        return pruning.run(normalised(pruning, policy), OBSERVED_FILESYSTEM, "filesystem")

    def derive(result: runner.RunResult) -> dict[str, frozenset[str]]:
        """The grants of one run's denials, generalised against the snapshot taken before it."""
        return filesystem_grants(pruning, denials_of(pruning, result), snapshots[-1][0], snapshots[-1][1].fs)

    def unobserved(policy: cfgfile.Policy) -> runner.RunResult:
        """The same run without the observer."""
        return pruning.run(normalised(pruning, policy), UNOBSERVED_FILESYSTEM, "filesystem rerun")

    return search.grow(observed, seed, pruning.reference, pruning.budget.grow_rounds, derive, unobserved)


def minimise_policy_fs(pruning: Pruning, policy: cfgfile.Policy, shape: runner.RunShape, stage: str) -> cfgfile.Policy:
    """Removes every (path, section) grant two unobserved runs show is not needed (A.6.4, decision 10)."""
    pairs = sorted((path, section) for path, sections in policy.fs.items() for section in sections)

    def passes(kept: list[tuple[str, str]]) -> bool:
        """One unobserved run with only the kept grants."""
        return pruning.matches(pruning.run(normalised(pruning, with_pairs(policy, kept)), shape, stage))

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
    """Stage 1: grow from denials, compact, normalise, minimise, with the network layer and the limits off."""
    grown = grow_filesystem(pruning, seed)
    compacted = generalise.compact(grown.fs, generalise.DEFAULT_COMPACTION_THRESHOLD, generalise.DEFAULT_FINE_ROOTS)
    pruning.note("compaction", before=sorted(grown.fs), after=sorted(compacted))
    minimised = minimise_policy_fs(pruning, normalised(pruning, dataclasses.replace(grown, fs=compacted)),
                                   UNOBSERVED_FILESYSTEM, "filesystem")
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
    ROUTING_ROUNDS times; a failure with no such denial aborts.
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


def prune_exercise(exercise: runner.Exercise, budget: Budget, environment: runner.Environment,
                   stage: str = "all", pristine: generalise.Snapshot | None = None) -> tuple[cfgfile.Policy, list[dict]]:
    """The pipeline for one exercise up to `stage` (filesystem, network, limits or all); the policy and the record.

    Only "all" runs the joint verification and the containment checks; an earlier stage's policy is a
    step of the pipeline, for tests and diagnosis, not one to ship. PruneAbort carries the record in
    its evidence. `pristine` is the index of what existed before the container's first run
    (pristine_index), taken here when the caller passes none.
    """
    containment.plant_canaries()
    if not sampler.become_subreaper():
        raise runner.PrunerDefect(-1, pathlib.Path(os.devnull), "the kernel refused to make the pruner a child subreaper")
    index = pristine if pristine is not None else pristine_index(environment)
    pruning = Pruning(exercise=exercise, budget=budget, environment=environment, pristine=index)
    try:
        pruning.reference = baseline(pruning)
        permissive_run(pruning)
        policy = prune_filesystem(pruning, cfgfile.Policy(fs={}, connect=(), bind=(), limits={}))
        if stage != "filesystem":
            policy = prune_network(pruning, policy)
        if stage in ("limits", "all"):
            policy = prune_limits(pruning, policy)
        if stage == "all":
            policy = verify(pruning, policy)
            pruning.note("containment", checks=containment.run_checks(policy, environment))
    except search.PruneAbort as abort:
        abort.evidence["record"] = pruning.log
        raise
    return policy, pruning.log
