"""One run of the reference exercise: unsandboxed, or through the shipped phobos.sh with a candidate policy.

Every candidate passes the acceptance gate before it is run: cfgfile.render refuses what the parser
would refuse, and phobos-policysystem.sh must build a specification from it. A run Phobos itself
stopped before the command started is never a verdict but a defect of the pruner (A.6.4), because
reading it as "the policy is too narrow" would turn a malformed candidate into more grants. The
exercise is copied afresh into the working directory before every run, so no run sees another's output.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import pathlib
import shutil
import signal
import subprocess  # nosec B404
import tempfile
import time
import uuid

from layer_prune import cfgfile, limits, network, sampler, strace_parse, verdict

# Where the run-phase image keeps Phobos, the working directory grading uses, and where the
# candidate configurations are written: under /run, which no policy the pruner writes makes writable.
PHOBOS_HOME = "/var/tmp/opt/core"
TESTING_DIR = "/var/tmp/testing-dir"
CANDIDATE_DIR = "/run/layer-prune"
SPEC_PARENT = "/var/tmp"
# The status a run gets when the pruner's own hard limit ended it, read as a timeout by the verdict.
HARD_LIMIT_STATUS = verdict.TIMEOUT_STATUS
# The names an exercise's build script may have, in the order they are looked for.
BUILD_SCRIPT_NAMES = ("build_script.sh", "build_script")
# How long a run may take at most, in seconds, whatever its policy says (Budget.run_seconds).
DEFAULT_RUN_SECONDS = 1800


class PrunerDefect(Exception):
    """Phobos stopped a run before the command started, or refused the candidate: never a verdict."""

    def __init__(self, status: int, log_path: pathlib.Path, reason: str) -> None:
        """Keeps the status, the log and the reason."""
        super().__init__(f"{reason} (status {status}, log {log_path})")
        self.status = status
        self.log_path = log_path
        self.reason = reason


class ExerciseRefused(Exception):
    """The exercise does not meet the contract of A.6.8."""

    def __init__(self, reason: str) -> None:
        """Keeps the reason."""
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class Exercise:
    """One exercise as A.6.8 defines it: its pristine copy, its build script and what prune.json says."""

    name: str
    workdir: pathlib.Path
    build_script: str
    report_globs: tuple[str, ...]
    declared_hosts: tuple[str, ...]
    heap_pinned: bool = False


@dataclasses.dataclass(frozen=True)
class RunShape:
    """How a run is made: observed by strace, with the network layer, with limits, sampled."""

    observe: bool
    network: bool
    limits: bool
    sample: bool


@dataclasses.dataclass(frozen=True)
class RunResult:
    """What one run produced: its verdict and status, the trace and samples where taken, its duration and log."""

    verdict: verdict.Verdict
    status: int
    trace: strace_parse.Trace | None
    samples: list[dict] | None
    wall_seconds: float
    log_path: pathlib.Path


@dataclasses.dataclass(frozen=True)
class Environment:
    """Where the runner finds Phobos and strace, where it runs, and how long a run may take."""

    phobos_home: str = PHOBOS_HOME
    strace: str = "strace"
    testing_dir: str = TESTING_DIR
    candidate_dir: str = CANDIDATE_DIR
    spec_parent: str = SPEC_PARENT
    log_dir: str = "/var/tmp/layer-prune-logs"
    run_seconds: int = DEFAULT_RUN_SECONDS
    resolver: str | None = None


RUN_NUMBERS = itertools.count(1)


def read_exercise(directory: pathlib.Path) -> Exercise:
    """Reads an exercise directory and its optional prune.json, refusing one that breaks A.6.8.

    It needs an executable build script, and its committed copy must match none of its report globs,
    so a stale report can never stand in for a run. A declared host must be well formed (seed_rules).
    """
    script = next((name for name in BUILD_SCRIPT_NAMES if (directory / name).is_file()), None)
    if script is None or not os.access(directory / script, os.X_OK):
        raise ExerciseRefused(f"{directory} has no executable build_script or build_script.sh")
    settings = {}
    if (directory / "prune.json").is_file():
        settings = json.loads((directory / "prune.json").read_text())
    globs = tuple(settings.get("report_globs", verdict.DEFAULT_REPORT_GLOBS))
    declared = tuple(settings.get("declared_hosts", ()))
    network.seed_rules(declared)
    stale = [path for pattern in globs for path in directory.glob(pattern)]
    if stale:
        raise ExerciseRefused(f"{directory} already holds a report its globs match: {stale[0]}")
    return Exercise(name=directory.name, workdir=directory, build_script=script, report_globs=globs,
                    declared_hosts=declared, heap_pinned=bool(settings.get("heap_pinned", False)))


def restore(exercise: Exercise, environment: Environment) -> pathlib.Path:
    """Replaces the working directory with a fresh copy of the exercise and returns it."""
    target = pathlib.Path(environment.testing_dir)
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(exercise.workdir, target, symlinks=True)
    return target


def log_paths(environment: Environment, label: str) -> tuple[pathlib.Path, pathlib.Path]:
    """A fresh log file and trace file for one run, numbered in the order the runs were made."""
    directory = pathlib.Path(environment.log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    number = next(RUN_NUMBERS)
    return directory / f"run-{number:04d}-{label}.log", directory / f"run-{number:04d}-{label}.trace"


def started_command(build_script: str, sentinel: str) -> list[str]:
    """The command phobos.sh runs: it writes the sentinel to stderr, then becomes the build script.

    Whatever Phobos printed before the sentinel was printed before the command started.
    """
    return ["/bin/bash", "-c", f'printf "%s\\n" "$1" >&2; exec /bin/bash "./{build_script}"', "phobos-layer-prune",
            sentinel]


def execute(argv: list[str], cwd: pathlib.Path, log_path: pathlib.Path, environment: Environment,
            shape_sample: bool) -> tuple[int, float, list[dict] | None]:
    """Runs argv in its own process group with output to the log, within the hard limit; status, seconds, samples.

    A run that outlives environment.run_seconds is killed with its whole group and given HARD_LIMIT_STATUS.
    """
    started = time.monotonic()
    with open(log_path, "wb") as log:
        process = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,  # nosec B603
                                   stdin=subprocess.DEVNULL, start_new_session=True)
        watcher = sampler.Sampler(os.getpid(), include_root=False) if shape_sample else None
        if watcher is not None:
            watcher.start()
        try:
            status = process.wait(timeout=environment.run_seconds)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            status = HARD_LIMIT_STATUS
        samples = watcher.stop() if watcher is not None else None
    if status < 0:
        status = verdict.SIGNAL_STATUS_BASE - status
    return status, time.monotonic() - started, samples


def reports(exercise: Exercise, workdir: pathlib.Path) -> list[pathlib.Path]:
    """The report files the run wrote, by the exercise's globs."""
    return sorted({path for pattern in exercise.report_globs for path in workdir.glob(pattern)})


def gate(text: str, cfg: pathlib.Path, environment: Environment, log_path: pathlib.Path) -> None:
    """Writes the candidate and has phobos-policysystem.sh build a specification from it; raises PrunerDefect if it refuses."""
    cfg.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg.write_text(text)
    spec = tempfile.mkdtemp(prefix="layer-prune-gate.", dir=environment.spec_parent)
    try:
        argv = [os.path.join(environment.phobos_home, "phobos-policysystem.sh"), "--spec-dir", spec, "--config", str(cfg)]
        checked = subprocess.run(argv, capture_output=True, text=True, check=False)  # nosec B603
    finally:
        shutil.rmtree(spec, ignore_errors=True)
    if checked.returncode != 0:
        log_path.write_text(checked.stdout + checked.stderr)
        raise PrunerDefect(checked.returncode, log_path, "phobos-policysystem.sh refused the candidate")


def render_candidate(policy: cfgfile.Policy, shape: RunShape, log_path: pathlib.Path) -> str:
    """The candidate's text, with every limit off unless the run is one with limits; PrunerDefect if render refuses."""
    effective = policy if shape.limits else dataclasses.replace(policy, limits=dict(limits.LIMITS_OFF))
    try:
        return cfgfile.render(effective)
    except ValueError as refusal:
        log_path.write_text(str(refusal))
        raise PrunerDefect(-1, log_path, f"render refused the candidate: {refusal}") from refusal


def phobos_argv(cfg: pathlib.Path, shape: RunShape, exercise: Exercise, environment: Environment,
                sentinel: str, trace_path: pathlib.Path) -> list[str]:
    """The argument vector of one layered run, strace outermost when the run is observed."""
    argv = [os.path.join(environment.phobos_home, "phobos.sh"), "--config", str(cfg)]
    if not shape.network:
        argv.append("-nnr")
    if environment.resolver:
        argv += ["--resolver", environment.resolver]
    argv += ["--", *started_command(exercise.build_script, sentinel)]
    if shape.observe:
        argv = [environment.strace, *strace_parse.STRACE_ARGUMENTS, "-o", str(trace_path), *argv]
    return argv


def run_layers(exercise: Exercise, policy: cfgfile.Policy, shape: RunShape,
               environment: Environment = Environment()) -> RunResult:  # noqa: B008
    """One run through phobos.sh under the candidate policy, in the given shape (A.6.4).

    Raises PrunerDefect when render or the gate refuses the candidate, or when the run ends with a
    Phobos stop status and Phobos's marker came before the command started.
    """
    log_path, trace_path = log_paths(environment, "layers")
    text = render_candidate(policy, shape, log_path)
    cfg = pathlib.Path(environment.candidate_dir) / f"{log_path.stem}.cfg"
    gate(text, cfg, environment, log_path)
    workdir = restore(exercise, environment)
    sentinel = f"phobos-layer-prune: the command starts {uuid.uuid4().hex}"
    argv = phobos_argv(cfg, shape, exercise, environment, sentinel, trace_path)
    status, seconds, samples = execute(argv, workdir, log_path, environment, shape.sample)
    log_text = log_path.read_text(errors="replace")
    marker = verdict.phobos_stopped(status, log_text.split(sentinel, 1)[0])
    if marker is not None:
        raise PrunerDefect(status, log_path, f"Phobos stopped the run before the command started: {marker}")
    trace = None
    if shape.observe:
        with open(trace_path, encoding="utf-8", errors="surrogateescape") as lines:
            trace = strace_parse.parse_trace(lines)
    return RunResult(verdict=verdict.read_verdict(status, log_text, reports(exercise, workdir)), status=status,
                     trace=trace, samples=samples, wall_seconds=seconds, log_path=log_path)


def run_direct(exercise: Exercise, environment: Environment = Environment()) -> RunResult:  # noqa: B008
    """One run of the build script without Phobos, in the same working directory: the baseline."""
    log_path, _ = log_paths(environment, "direct")
    workdir = restore(exercise, environment)
    status, seconds, _ = execute(["/bin/bash", f"./{exercise.build_script}"], workdir, log_path, environment, False)
    log_text = log_path.read_text(errors="replace")
    return RunResult(verdict=verdict.read_verdict(status, log_text, reports(exercise, workdir)), status=status,
                     trace=None, samples=None, wall_seconds=seconds, log_path=log_path)


def run_reference(exercise: Exercise, environment: Environment = Environment()) -> RunResult:  # noqa: B008
    """The baseline run of A.6.4: unsandboxed, or for an exercise with declared hosts, layered and limited to them.

    An exercise that declares hosts is run under the permissive policy, whose only external rules are
    its declared hosts, with the limits off, so that not even its reference run reaches an undeclared
    host (decision 11).
    """
    if not exercise.declared_hosts:
        return run_direct(exercise, environment)
    policy = cfgfile.permissive_policy(pathlib.Path("/"), exercise.declared_hosts)
    return run_layers(exercise, policy, RunShape(observe=False, network=True, limits=False, sample=False), environment)
