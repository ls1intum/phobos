"""One run of the reference exercise: unsandboxed, or through the shipped phobos.sh with a candidate policy.

Every candidate passes the acceptance gate before it is run: cfgfile.render refuses what the parser
would refuse, and phobos-policysystem.sh must build a specification from it. A run Phobos itself
stopped before the command started is never a verdict but a defect of the pruner (A.6.4), because
reading it as "the policy is too narrow" would turn a malformed candidate into more grants. The
exercise is copied afresh into the working directory before every run, so no run sees another's output.
"""

from __future__ import annotations

import contextlib
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
# candidate configurations are written. A pruned policy may grant writing under /run, so every
# candidate is created under a fresh name, exclusively, and only after the previous run's processes
# are gone (reap_leftovers), so nothing a run left there can stand in for it.
PHOBOS_HOME = "/var/tmp/opt/core"
TESTING_DIR = "/var/tmp/testing-dir"
CANDIDATE_DIR = "/run/layer-prune"
SPEC_PARENT = "/var/tmp"
# The status a run gets when the pruner's own hard limit ended it, read as a timeout by the verdict.
HARD_LIMIT_STATUS = verdict.TIMEOUT_STATUS
# The status and the marker Phobos ends a run with when it could not read the command's exit status.
ESTATUS_STATUS = 16
ESTATUS_MARKER = "(PHB-ESTATUS)"
# The names an exercise's build script may have, in the order they are looked for.
BUILD_SCRIPT_NAMES = ("build_script.sh", "build_script")
# How long a run may take at most, in seconds, whatever its policy says (Budget.run_seconds).
DEFAULT_RUN_SECONDS = 1800
# How long reap_leftovers waits for the processes it killed to be reaped, and how often it looks.
REAP_SECONDS = 10
REAP_INTERVAL_SECONDS = 0.05
# The keys prune.json may hold, with the type each value must have (A.6.8).
SETTING_TYPES = {"report_globs": list, "declared_hosts": list, "heap_pinned": bool}


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
class Execution:
    """What executing one run's command gave: its status, how long it took, and its samples where taken."""

    status: int
    seconds: float
    samples: list[dict] | None


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


def read_settings(directory: pathlib.Path) -> dict:
    """The exercise's prune.json, or an empty one; ExerciseRefused when it is not a JSON object of the known
    keys, each of its type, with only strings in its lists and only relative report globs."""
    path = directory / "prune.json"
    if not path.is_file():
        return {}
    try:
        settings = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ExerciseRefused(f"{path} is not readable as JSON: {error}") from error
    if not isinstance(settings, dict):
        raise ExerciseRefused(f"{path} does not hold a JSON object")
    for key, value in settings.items():
        if key not in SETTING_TYPES or not isinstance(value, SETTING_TYPES[key]):
            raise ExerciseRefused(f"{path} holds {key!r} with a value prune.json does not take")
        if isinstance(value, list) and not all(isinstance(item, str) and item for item in value):
            raise ExerciseRefused(f"{path} holds {key!r} with an entry that is not a non-empty string")
    if any(pattern.startswith("/") for pattern in settings.get("report_globs", ())):
        raise ExerciseRefused(f"{path} holds an absolute report glob")
    return settings


def read_exercise(directory: pathlib.Path) -> Exercise:
    """Reads an exercise directory and its optional prune.json, refusing one that breaks A.6.8.

    It needs an executable build script, and its committed copy must match none of its report globs,
    so a stale report can never stand in for a run. A declared host must be well formed (seed_rules).
    """
    script = next((name for name in BUILD_SCRIPT_NAMES if (directory / name).is_file()), None)
    if script is None or not os.access(directory / script, os.X_OK):
        raise ExerciseRefused(f"{directory} has no executable build_script or build_script.sh")
    settings = read_settings(directory)
    globs = tuple(settings.get("report_globs", verdict.DEFAULT_REPORT_GLOBS))
    declared = tuple(settings.get("declared_hosts", ()))
    try:
        network.seed_rules(declared)
    except ValueError as error:
        raise ExerciseRefused(f"{directory}/prune.json declares a host no rule can carry: {error}") from error
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


def reap_leftovers(proc: str = "/proc") -> None:
    """Kills every process left below the pruner and reaps it, so that no run outlives its turn.

    The pruner is the child subreaper (sampler.become_subreaper), so whatever a run left behind, a
    daemon, a server, or a command that escaped its group with setsid, is its descendant. Left alive,
    it would be sampled in a later run, could serve a later run under a narrower policy, and would
    race the next restore; left a zombie, it would hold a pid and count as a task.
    """
    deadline = time.monotonic() + REAP_SECONDS
    while time.monotonic() < deadline:
        left = [pid for pid in sampler.descendants(pathlib.Path(proc), os.getpid()) if pid != os.getpid()]
        for pid in left:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
        with contextlib.suppress(ChildProcessError):
            while os.waitpid(-1, os.WNOHANG)[0] > 0:
                pass
        if not left:
            return
        time.sleep(REAP_INTERVAL_SECONDS)


def execute(argv: list[str], cwd: pathlib.Path, log_path: pathlib.Path, environment: Environment,
            shape_sample: bool) -> Execution:
    """Runs argv in its own process group with output to the log, within the hard limit.

    A run that outlives environment.run_seconds is killed with its whole group and given
    HARD_LIMIT_STATUS; either way every process it left behind is then killed and reaped.
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
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            status = HARD_LIMIT_STATUS
        samples = watcher.stop() if watcher is not None else None
        reap_leftovers()
    if status < 0:
        status = verdict.SIGNAL_STATUS_BASE - status
    return Execution(status=status, seconds=time.monotonic() - started, samples=samples)


def reports(exercise: Exercise, workdir: pathlib.Path) -> list[pathlib.Path]:
    """The report files the run wrote, by the exercise's globs."""
    return sorted({path for pattern in exercise.report_globs for path in workdir.glob(pattern)})


def write_candidate(text: str, cfg: pathlib.Path, log_path: pathlib.Path) -> None:
    """Creates the candidate under its fresh name, exclusively and without following a link; PrunerDefect if it cannot."""
    cfg.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if cfg.parent.is_symlink():
        raise PrunerDefect(-1, log_path, f"the candidate directory {cfg.parent} is a symbolic link")
    try:
        descriptor = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as error:
        raise PrunerDefect(-1, log_path, f"the candidate {cfg} cannot be created afresh: {error}") from error
    with os.fdopen(descriptor, "w") as candidate:
        candidate.write(text)


def gate(text: str, cfg: pathlib.Path, environment: Environment, log_path: pathlib.Path) -> None:
    """Writes the candidate and has phobos-policysystem.sh build a specification from it; raises PrunerDefect if it refuses."""
    write_candidate(text, cfg, log_path)
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

    Raises PrunerDefect when render or the gate refuses the candidate, when the run ends with a Phobos
    stop status and Phobos's marker came before the command started, or when it ends with the status
    reporter's PHB-ESTATUS, which Phobos prints after the command ended.
    """
    files = log_paths(environment, "layers")
    log_path = files[0]
    trace_path = files[1]
    text = render_candidate(policy, shape, log_path)
    cfg = pathlib.Path(environment.candidate_dir) / f"{log_path.stem}.cfg"
    try:
        gate(text, cfg, environment, log_path)
        workdir = restore(exercise, environment)
        sentinel = f"phobos-layer-prune: the command starts {uuid.uuid4().hex}"
        argv = phobos_argv(cfg, shape, exercise, environment, sentinel, trace_path)
        executed = execute(argv, workdir, log_path, environment, shape.sample)
    finally:
        cfg.unlink(missing_ok=True)
    status = executed.status
    log_text = log_path.read_text(errors="replace")
    marker = verdict.phobos_stopped(status, log_text.split(sentinel, 1)[0])
    if marker is not None:
        raise PrunerDefect(status, log_path, f"Phobos stopped the run before the command started: {marker}")
    if status == ESTATUS_STATUS and ESTATUS_MARKER in log_text:
        raise PrunerDefect(status, log_path, "Phobos could not read the command's exit status (PHB-ESTATUS)")
    trace = None
    if shape.observe:
        with open(trace_path, encoding="utf-8", errors="surrogateescape") as lines:
            trace = strace_parse.parse_trace(lines)
    return RunResult(verdict=verdict.read_verdict(status, log_text, reports(exercise, workdir)), status=status,
                     trace=trace, samples=executed.samples, wall_seconds=executed.seconds, log_path=log_path)


def run_direct(exercise: Exercise, environment: Environment = Environment()) -> RunResult:  # noqa: B008
    """One run of the build script without Phobos, in the same working directory: the baseline."""
    log_path = log_paths(environment, "direct")[0]
    workdir = restore(exercise, environment)
    executed = execute(["/bin/bash", f"./{exercise.build_script}"], workdir, log_path, environment, False)
    log_text = log_path.read_text(errors="replace")
    return RunResult(verdict=verdict.read_verdict(executed.status, log_text, reports(exercise, workdir)),
                     status=executed.status, trace=None, samples=None, wall_seconds=executed.seconds,
                     log_path=log_path)


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
