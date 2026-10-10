"""Runs one session of a program under strace with nothing between it and its terminal.

strace runs with -DDD (strace_parse.RECORD_ARGUMENTS): the tracer detaches as a grandchild in a
session of its own, and the process this module starts becomes the program itself. So the
program's exit status is its own, and Ctrl+C or Ctrl+Z reach the program's process group, never
the tracer. The recorder makes itself a child subreaper, so the detached tracer is reparented to
it, and the trace is complete only once every child it is left with has ended, the tracer
among them. A process the session left running (a build tool's daemon) would keep that wait open
for good, so after LINGER_SECONDS it is named and stopped: grading would not keep it either.

A recording directory holds `sessions/<n>/trace` and `sessions/<n>/session.json` for each session,
and `snapshots/<container>.txt` for every container a session ran in (see snapshot.py).
"""

from __future__ import annotations

import ctypes
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

from runtime_pruner.src.infrastructure import guard, pty_script, snapshot
from shared.src.domain import strace_parse
from shared.src.infrastructure import sampler

# prctl's option that makes a process the reaper of its orphaned descendants (linux/prctl.h).
PR_SET_CHILD_SUBREAPER = 36

# The system call number of landlock_create_ruleset, the same on x86-64 and arm64, and its flag
# that asks for the ABI version rather than a ruleset.
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1

# The status a shell reports for a command a signal ended: this plus the signal's number.
SIGNAL_STATUS_BASE = 128

# The status of a session whose command could not be started at all, as a shell reports it.
EXIT_NOT_STARTED = 127

# How long the recorder waits, once the command ended, for the processes the session left running,
# and how long a stopped one gets between SIGTERM and SIGKILL.
LINGER_SECONDS = 10.0
STOP_GRACE_SECONDS = 5.0

# How often the wait for leftovers looks again.
POLL_SECONDS = 0.2

# The name the tracer runs under, which the wait for leftovers must leave running: it ends by itself
# once nothing it traces is left.
TRACER_NAME = "strace"

# Where a session may write files besides its working directory, for the size of the largest one.
SCRATCH_ROOTS = (pathlib.Path("/tmp"), pathlib.Path("/var/tmp"))
BYTES_PER_MEGABYTE = 1024 * 1024

CHDIR_LINE = re.compile(r"^--chdir[ =](?P<directory>\S+)\s*$")
CONTAINER_LINE = re.compile(r"/docker/containers/(?P<id>[0-9a-f]{12,64})/")


@dataclasses.dataclass(frozen=True)
class SessionResult:
    """One recorded session: its number in the recording, the command's status, and whether it ran
    with a terminal (scripted sessions run in a pseudo-terminal, so they count as interactive) and,
    for a scripted one, whether every expectation of the script held. `signal` is the signal that
    ended a command run on the person's terminal, so the recorder can end the same way."""

    number: int
    status: int
    interactive: bool
    expectations_met: bool | None = None
    signal: int | None = None


@dataclasses.dataclass(frozen=True)
class TracedRun:
    """How one traced run ended: the status, the ending signal of a terminal run, whether a script's
    expectations held (None without a script), and the processes it left running that were stopped."""

    status: int
    signal: int | None
    expectations_met: bool | None
    stopped: list[str]


def tail_chdir(tail_flags: pathlib.Path) -> pathlib.Path:
    """The working directory the tail flags give a graded command (`--chdir <dir>`).

    Assumes the file is TailPhobos.cfg or one like it, one flag per line, comments starting with
    `#`. Raises ValueError when no --chdir line is there, since a recording made elsewhere would
    describe paths grading never uses (plan A.4, defect 2).
    """
    for line in tail_flags.read_text(encoding="utf-8").split("\n"):
        match = CHDIR_LINE.match(line.strip())
        if match is not None:
            return pathlib.Path(match.group("directory"))
    raise ValueError(f"{tail_flags} names no --chdir directory")


def container_id() -> str:
    """The id of the container this runs in, as Docker names it, or the host name.

    Assumes Docker, which bind-mounts the container's own hostname file from a path naming its id.
    Without it the host name stands in; containers given one fixed host name then look alike, which
    errs safe: the replay check refuses each as the recording's own container.
    """
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as handle:
            for line in handle:
                match = CONTAINER_LINE.search(line)
                if match is not None:
                    return match.group("id")
    except OSError:
        pass
    return os.uname().nodename


def landlock_abi() -> int:
    """The Landlock ABI version this kernel offers, or -1 where it offers none.

    Assumes Linux; asking costs nothing and restricts nothing.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    return int(libc.syscall(LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0),
                            ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION)))


def prepare_container(recording: pathlib.Path, workdir: pathlib.Path, exercise: pathlib.Path | None,
                      root: pathlib.Path = pathlib.Path("/")) -> pathlib.Path:
    """The snapshot of this container, taken first when no session ran here before.

    On the container's first session the exercise is copied into the working directory, file times
    kept, and only then is every path under root listed, so the listing is the state the session
    starts in. Assumes the recordings directory is skipped by the listing, as snapshot.DEFAULT_SKIP
    says; root is the container's root except in a test.
    """
    listing = recording / "snapshots" / f"{container_id()}.txt"
    if listing.exists():
        return listing
    copy_exercise(exercise, workdir)
    listing.parent.mkdir(parents=True, exist_ok=True)
    snapshot.take(listing, root=root)
    return listing


def copy_exercise(exercise: pathlib.Path | None, workdir: pathlib.Path) -> None:
    """Creates the working directory and copies the exercise into it, keeping the files' times.

    Assumes nothing else is in the working directory that should stay; files of the exercise
    replace any of the same name.
    """
    workdir.mkdir(parents=True, exist_ok=True)
    if exercise is not None and exercise.is_dir():
        shutil.copytree(exercise, workdir, symlinks=True, dirs_exist_ok=True)


def record_session(command: list[str], recording: pathlib.Path, workdir: pathlib.Path,
                   script: pathlib.Path | None, listing: pathlib.Path | None = None,
                   sample: bool = False) -> SessionResult:
    """Records one session of the command in workdir and answers its result.

    Assumes strace is installed and that this process may trace its own descendants. The terminal
    is passed through untouched; with a script, the session is typed from it through a
    pseudo-terminal instead (pty_script). `listing` is the snapshot the session belongs to, written
    into session.json relative to the recording. The script is parsed before anything is created,
    and session.json is written once the trace is complete, so a recording never holds a session
    without one unless the recorder itself was killed. With `sample`, the session's process tree is
    sampled beside it (the tracer left out) and samples.json is written next to the trace.
    """
    actions = pty_script.parse(script.read_text(encoding="utf-8")) if script is not None else None
    number = _next_session(recording)
    directory = recording / "sessions" / str(number)
    directory.mkdir(parents=True)
    argv = ["strace", *strace_parse.RECORD_ARGUMENTS, "-o", str(directory / "trace"), "--", *command]
    started = _now()
    interactive = script is not None or sys.stdin.isatty()
    watcher = sampler.Sampler(os.getpid(), include_root=False, exclude=frozenset({TRACER_NAME})) if sample else None
    began = time.monotonic()
    if watcher is not None:
        watcher.start()
    try:
        run = run_traced(argv, workdir, actions, directory / "transcript")
    finally:
        samples = watcher.stop() if watcher is not None else []
    if watcher is not None:
        wall = time.monotonic() - began
        held = {"wall_seconds": wall, "samples": samples,
                "largest_file_mb": largest_changed_file_mb((workdir, *SCRATCH_ROOTS), time.time() - wall)}
        (directory / "samples.json").write_text(json.dumps(held) + "\n", encoding="utf-8")
    meta = {
        "command": command,
        "started": started,
        "ended": _now(),
        "status": run.status,
        "interactive": interactive,
        "scripted": script is not None,
        "script_sha256": script_digest(script),
        "expectations_met": run.expectations_met,
        "stopped_leftovers": run.stopped,
        "container_id": container_id(),
        "snapshot": str(listing.relative_to(recording)) if listing is not None else None,
        "workdir": str(workdir),
        "kernel": os.uname().release,
        "landlock_abi": landlock_abi(),
        "strace": _strace_version(),
        "uid": os.getuid(),
    }
    (directory / "session.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return SessionResult(number=number, status=run.status, interactive=interactive,
                         expectations_met=run.expectations_met, signal=run.signal)


def largest_changed_file_mb(roots: tuple[pathlib.Path, ...], since: float) -> float:
    """The largest regular file under the roots modified at or after `since` (epoch seconds), in megabytes.

    What `ulimit -f` bounds is the size a process writes a file to; a file the session wrote is
    changed after it started. Symbolic links are not followed, and the recordings directory is left out.
    """
    largest = 0
    for root in roots:
        for current, subdirectories, files in os.walk(root):
            subdirectories[:] = [name for name in subdirectories if os.path.join(current, name) not in snapshot.DEFAULT_SKIP]
            for name in files:
                try:
                    status = os.lstat(os.path.join(current, name))
                except OSError:
                    continue
                if stat.S_ISREG(status.st_mode) and status.st_mtime >= since:
                    largest = max(largest, status.st_size)
    return largest / BYTES_PER_MEGABYTE


def run_traced(argv: list[str], workdir: pathlib.Path, actions: list[pty_script.Action] | None,
               transcript: pathlib.Path) -> TracedRun:
    """Runs argv, a strace -DDD command line, in workdir to its end and answers how it ended.

    Assumes Linux. Typed from the actions through a pseudo-terminal when there are any, on this
    process's terminal otherwise. Ctrl+C and Ctrl+\\ are caught by this process for the whole run,
    the wait for leftovers included, so neither can leave a session half written; its handlers do
    not survive into the command's exec. Every process the run leaves behind is waited for at most
    LINGER_SECONDS, then named on standard error and stopped, and the tracer is waited for last.
    """
    become_subreaper()
    previous = {number: signal.signal(number, _ignore) for number in (signal.SIGINT, signal.SIGQUIT)}
    try:
        if actions is not None:
            outcome = pty_script.drive(argv, actions, workdir, transcript)
            status = outcome.status
            ended_by = None
            expectations_met: bool | None = outcome.expectations_met
        else:
            code = run_passing_terminal(argv, workdir)
            status = SIGNAL_STATUS_BASE - code if code < 0 else code
            ended_by = -code if code < 0 else None
            expectations_met = None
        stopped = stop_leftovers(LINGER_SECONDS)
        reap_children()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return TracedRun(status=status, signal=ended_by, expectations_met=expectations_met, stopped=stopped)


def require_strace() -> None:
    """Refuses with the status for the wrong place when strace cannot be found, before anything is made."""
    if shutil.which("strace") is None:
        raise guard.Refused(guard.EXIT_ENVIRONMENT,
                            "phobos-record runs only in the prune image: this image has no strace to record with.")


def script_digest(script: pathlib.Path | None) -> str | None:
    """The SHA-256 of a script's bytes, which tells sessions typed from the same script; None without one."""
    if script is None:
        return None
    return hashlib.sha256(script.read_bytes()).hexdigest()


def become_subreaper() -> None:
    """Makes this process the reaper of its orphaned descendants; assumes Linux."""
    ctypes.CDLL(None, use_errno=True).prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)


def run_passing_terminal(argv: list[str], workdir: pathlib.Path) -> int:
    """Runs argv in workdir with this process's terminal and answers its wait code.

    The code is the exit status, or the negative number of the signal that ended it. Assumes this
    process is in the terminal's foreground process group with the command and catches Ctrl+C
    itself (run_traced does); Ctrl+Z stops both, and fg resumes both. A command that cannot start
    answers EXIT_NOT_STARTED.
    """
    try:
        child = subprocess.Popen(argv, cwd=workdir)
    except OSError:
        return EXIT_NOT_STARTED
    return child.wait()


def stop_leftovers(seconds: float) -> list[str]:
    """Waits at most seconds for this process's descendants but the tracer, then stops the rest.

    Assumes this process is a child subreaper, so every process a session left running is one of
    its descendants. Children that end are reaped while it waits. Answers "<pid> <name>" for every
    process it had to stop, after naming them on standard error with the reason.
    """
    deadline = time.monotonic() + seconds
    while True:
        _reap_ended()
        left = _descendants()
        if not left or time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    if not left:
        return []
    named = [f"{pid} {name}" for pid, name in sorted(left.items())]
    print(f"phobos-record: the session left {len(named)} processes running ({', '.join(named)}); stopping them so "
          "the trace can end. A daemon keeps a recording open: run the program without one (for Gradle, "
          "--no-daemon and the exercise's own settings).", file=sys.stderr)
    _signal_all(left, signal.SIGTERM)
    grace = time.monotonic() + STOP_GRACE_SECONDS
    while _descendants() and time.monotonic() < grace:
        _reap_ended()
        time.sleep(POLL_SECONDS)
    remaining = _descendants()
    while remaining:
        _signal_all(remaining, signal.SIGKILL)
        _reap_ended()
        time.sleep(POLL_SECONDS)
        remaining = _descendants()
    return named


def reap_children() -> None:
    """Waits for every child this process still has, the reparented tracer among them.

    Assumes this process is a child subreaper and that stop_leftovers ran first, so only the tracer
    and processes about to end are left.
    """
    while True:
        try:
            os.wait()
        except ChildProcessError:
            return
        except InterruptedError:
            continue


def _descendants() -> dict[int, str]:
    """Every live descendant of this process but the tracer, mapped to its name, from /proc.

    Assumes Linux; a process that ends while it is read is left out.
    """
    parents = {}
    names = {}
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = text[text.find("(") + 1:text.rfind(")")]
        fields = text[text.rfind(")") + 2:].split()
        if len(fields) < 2 or fields[0] == "Z":
            continue
        parents[int(entry.name)] = int(fields[1])
        names[int(entry.name)] = name
    own = {os.getpid()}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in own and pid not in own:
                own.add(pid)
                changed = True
    own.discard(os.getpid())
    return {pid: names[pid] for pid in own if names.get(pid) != TRACER_NAME}


def _reap_ended() -> None:
    """Reaps every child of this process that has already ended, without waiting for one."""
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def _signal_all(processes: dict[int, str], number: int) -> None:
    """Sends the signal to every process given; one that has ended already is not an error."""
    for pid in processes:
        try:
            os.kill(pid, number)
        except ProcessLookupError:
            continue


def _ignore(number: int, frame: object) -> None:
    """A signal handler that does nothing; assumes it is installed only while a session runs."""


def _next_session(recording: pathlib.Path) -> int:
    """The number the next session of the recording gets: one more than the highest so far."""
    sessions = recording / "sessions"
    numbers = [int(path.name) for path in sessions.glob("*") if path.name.isdigit()] if sessions.is_dir() else []
    return max(numbers, default=0) + 1


def _now() -> str:
    """The current time in UTC as an ISO 8601 text."""
    return datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")


def _strace_version() -> str:
    """The first line strace -V prints, or empty where strace cannot say."""
    try:
        result = subprocess.run(["strace", "-V"], capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return result.stdout.split("\n", 1)[0]
