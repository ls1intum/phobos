"""Types a session from a script into a command running in a pseudo-terminal.

A script is plain text, one action per line, so a session can be repeated exactly and the suites
can drive one:

    # a comment
    send import os          types the text and Enter
    expect ^OK-R1           waits for output matching the regular expression
    key ctrl-c              sends one control character
    idle                    waits until every process of the terminal's foreground group is asleep
    sleep 1                 waits, in seconds

An expectation is searched in the output after the previous match, and the terminal echoes what
is typed, so a script prints markers the echo of its own line cannot contain (`"OK-" + "R1"`).
Job control needs an interactive shell around the command, whose own typed lines the script drives.

`idle` is for what a script cannot see in the output: a signal some process of the command is
still about to pass on, which a busy machine delivers late, and which would land on whatever is typed
next. A process that has such a signal to handle is awake, so once every process of the foreground
group has been asleep, or stopped, on several samples in a row there is none left. It never replaces
an `expect` for something the command prints; it is for the quiet after a key such as Ctrl+C.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import pty
import re
import select
import signal
import sys
import time

# The status a session ends with when an expectation was not met within its time.
EXPECT_FAILED = 4

# The control characters a script may send, each as the terminal driver reads it.
KEYS = {"ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-z": "\x1a", "ctrl-backslash": "\x1c"}

KINDS = ("send", "expect", "key", "idle", "sleep")

# How many samples in a row must find every process of the foreground group asleep or stopped for
# `idle` to answer, and how far apart they are. A shell that polls its child wakes for a moment every
# tenth of a second, so one awake sample says nothing; the next sample is taken again.
IDLE_SAMPLES = 4
IDLE_INTERVAL_SECONDS = 0.05

# The states of /proc/<pid>/stat that count as idle: sleeping, stopped (by a signal or a tracer),
# a zombie nobody has waited for yet, and the idle kernel thread state.
IDLE_STATES = frozenset("SZTtI")

# The number of the process group among the fields of /proc/<pid>/stat after the command's name and
# the state, counting the state as 0 and the parent as 1.
GROUP_FIELD = 2

# How long one read of the terminal waits before the deadline is looked at again.
POLL_SECONDS = 0.2

# How much of the terminal's output one read takes.
READ_BYTES = 65536

# The status a shell reports for a command that a signal ended: this plus the signal's number.
SIGNAL_STATUS_BASE = 128


@dataclasses.dataclass(frozen=True)
class Action:
    """One line of a script: what to do, and the text, key, pattern or seconds it does it with."""

    kind: str
    value: str


def parse(text: str) -> list[Action]:
    """Reads a script into its actions, skipping blank lines and comments.

    Assumes the script's lines end with a line feed. Raises ValueError naming the line for an
    unknown action, an unknown key, a sleep that is not a non-negative number, and an expectation
    that is empty or not a regular expression.
    """
    actions = []
    for number, line in enumerate(text.split("\n"), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        kind, _, value = line.partition(" ")
        actions.append(_checked(Action(kind, value), number))
    return actions


@dataclasses.dataclass(frozen=True)
class Outcome:
    """How a scripted session ended: the command's status, and whether every expectation held.

    Kept apart because a command may itself end with the status EXPECT_FAILED stands for.
    """

    status: int
    expectations_met: bool


def run(command: list[str], actions: list[Action], cwd: pathlib.Path, transcript: pathlib.Path,
        step_seconds: float = 60.0) -> int:
    """Runs the command in a new pseudo-terminal in cwd and types the actions into it.

    Assumes the command is found through PATH and reads its terminal. Everything the terminal
    shows is written to transcript. Answers EXPECT_FAILED, after killing the command's process
    group, when an expectation is not met within step_seconds; otherwise the command's own status,
    a signal written as 128 plus its number. A command still running step_seconds after the last
    action is hung up on, as closing a terminal window would, and its process group is killed
    when it is still running step_seconds after that.
    """
    outcome = drive(command, actions, cwd, transcript, step_seconds)
    return outcome.status if outcome.expectations_met else EXPECT_FAILED


def drive(command: list[str], actions: list[Action], cwd: pathlib.Path, transcript: pathlib.Path,
          step_seconds: float = 60.0) -> Outcome:
    """What run does, answered as an Outcome, so a caller can tell an unmet expectation apart.

    Assumes what run assumes. After an unmet expectation the status is the one the killed command
    ended with.
    """
    pid, descriptor = pty.fork()
    if pid == 0:
        _start(command, cwd)
    terminal = _Terminal(descriptor, transcript)
    try:
        for action in actions:
            if not _perform(terminal, action, step_seconds):
                _kill_group(pid)
                return Outcome(status=_status(pid), expectations_met=False)
        terminal.drain(step_seconds)
    finally:
        os.close(descriptor)
    return Outcome(status=_reap(pid, step_seconds), expectations_met=True)


class _Terminal:
    """The controlling side of a pseudo-terminal, with the output read so far and a transcript."""

    def __init__(self, descriptor: int, transcript: pathlib.Path):
        """Starts an empty transcript; assumes descriptor is the pseudo-terminal's master side."""
        self.descriptor = descriptor
        self.transcript = transcript
        self.buffer = ""
        self.closed = False
        transcript.write_bytes(b"")

    def send(self, text: str) -> None:
        """Types text into the terminal; assumes the command may have ended, which is not an error."""
        try:
            os.write(self.descriptor, text.encode())
        except OSError:
            self.closed = True

    def expect(self, pattern: str, seconds: float) -> bool:
        """Waits until the output after the previous match holds the pattern, at most seconds.

        Assumes pattern is a valid regular expression; `^` and `$` match at every line.
        """
        compiled = re.compile(pattern, re.MULTILINE)
        deadline = time.monotonic() + seconds
        while True:
            match = compiled.search(self.buffer)
            if match:
                self.buffer = self.buffer[match.end():]
                return True
            if self.closed or time.monotonic() >= deadline:
                return False
            self.read(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))

    def wait(self, seconds: float) -> None:
        """Keeps reading for seconds, so the command never blocks on a full terminal meanwhile."""
        deadline = time.monotonic() + seconds
        while not self.closed and time.monotonic() < deadline:
            self.read(min(POLL_SECONDS, deadline - time.monotonic()))
        while self.closed and time.monotonic() < deadline:
            time.sleep(min(POLL_SECONDS, deadline - time.monotonic()))

    def idle(self, seconds: float) -> bool:
        """Waits until the terminal's foreground process group is quiet, at most seconds; False if it is not.

        Quiet is IDLE_SAMPLES samples in a row, IDLE_INTERVAL_SECONDS apart, each finding every process
        of the group asleep or stopped (IDLE_STATES). Output is read between the samples, so a command
        that writes is never blocked on a full terminal meanwhile. Assumes Linux, where /proc names the
        group's processes; elsewhere there is nothing to look at, so it answers True at once. A command
        that has closed the terminal has nothing left to wait for either.
        """
        if not sys.platform.startswith("linux"):
            return True
        deadline = time.monotonic() + seconds
        quiet = 0
        while time.monotonic() < deadline:
            quiet = quiet + 1 if all(state in IDLE_STATES for state in foreground_states(self.descriptor)) else 0
            if quiet >= IDLE_SAMPLES or self.closed:
                return True
            self.read(IDLE_INTERVAL_SECONDS)
        return False

    def drain(self, seconds: float) -> None:
        """Reads until the command has closed the terminal, at most seconds.

        Assumes the caller closes the master side afterwards, which hangs up on a command still
        running.
        """
        deadline = time.monotonic() + seconds
        while not self.closed and time.monotonic() < deadline:
            self.read(min(POLL_SECONDS, deadline - time.monotonic()))

    def read(self, seconds: float) -> None:
        """Reads what the terminal has within seconds into the buffer and the transcript.

        Assumes end of file and EIO both mean every process holding the terminal has closed it.
        """
        ready, _, _ = select.select([self.descriptor], [], [], seconds)
        if not ready:
            return
        try:
            chunk = os.read(self.descriptor, READ_BYTES)
        except OSError:
            chunk = b""
        if not chunk:
            self.closed = True
            return
        with open(self.transcript, "ab") as handle:
            handle.write(chunk)
        self.buffer += chunk.decode("utf-8", "replace")


def foreground_states(descriptor: int) -> list[str]:
    """The /proc state letter of every process in the terminal's foreground process group.

    Assumes Linux and that `descriptor` is the master side of the pseudo-terminal. A process that
    ends while /proc is read is left out; a terminal with no foreground group answers an empty list.
    """
    try:
        group = os.tcgetpgrp(descriptor)
    except OSError:
        return []
    states = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError:
            continue
        fields = text[text.rfind(")") + 2:].split()
        if len(fields) > GROUP_FIELD and int(fields[GROUP_FIELD]) == group:
            states.append(fields[0])
    return states


def _checked(action: Action, number: int) -> Action:
    """The action unchanged when it is well formed; raises ValueError naming its line otherwise.

    Assumes number is the action's line in the script, counted from 1.
    """
    if action.kind not in KINDS:
        raise ValueError(f"line {number}: unknown action {action.kind!r}; expected one of {', '.join(KINDS)}")
    if action.kind == "key" and action.value not in KEYS:
        raise ValueError(f"line {number}: unknown key {action.value!r}; expected one of {', '.join(KEYS)}")
    if action.kind == "idle" and action.value:
        raise ValueError(f"line {number}: idle takes nothing after it, not {action.value!r}")
    if action.kind == "sleep" and not _seconds(action.value):
        raise ValueError(f"line {number}: sleep needs a non-negative number of seconds, not {action.value!r}")
    if action.kind == "expect":
        if not action.value:
            raise ValueError(f"line {number}: expect needs a regular expression")
        try:
            re.compile(action.value)
        except re.error as error:
            raise ValueError(f"line {number}: expect needs a regular expression: {error}") from error
    return action


def _seconds(text: str) -> bool:
    """Whether text is a finite, non-negative number of seconds; assumes nothing else of it."""
    try:
        value = float(text)
    except ValueError:
        return False
    return 0.0 <= value < float("inf")


def _perform(terminal: _Terminal, action: Action, step_seconds: float) -> bool:
    """Carries out one action; answers False only for an expectation that was not met.

    Assumes the action passed _checked.
    """
    if action.kind == "send":
        terminal.send(action.value + "\r")
    elif action.kind == "key":
        terminal.send(KEYS[action.value])
    elif action.kind == "idle":
        return terminal.idle(step_seconds)
    elif action.kind == "sleep":
        terminal.wait(float(action.value))
    else:
        return terminal.expect(action.value, step_seconds)
    return True


def _start(command: list[str], cwd: pathlib.Path) -> None:
    """Replaces the forked child with the command in cwd; assumes it runs in the child only.

    A command that cannot start ends the child with 127, as a shell reports a missing command.
    """
    try:
        os.chdir(cwd)
        os.execvp(command[0], command)
    except OSError:
        os._exit(127)


def _kill_group(pid: int) -> None:
    """Kills the process group the forked child leads; assumes the child is a session leader.

    A group that has already gone is not an error.
    """
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _reap(pid: int, seconds: float) -> int:
    """Waits at most seconds for the child to end, then kills its process group, and answers
    its status.

    Assumes the terminal has just been closed, which hangs up on the child; one that ignores the
    hang-up is killed rather than waited for without end.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        ended, wait_status = os.waitpid(pid, os.WNOHANG)
        if ended:
            return _code(wait_status)
        time.sleep(POLL_SECONDS)
    _kill_group(pid)
    return _status(pid)


def _status(pid: int) -> int:
    """Waits for the child and answers its status, a signal as 128 plus its number.

    Assumes pid is a child of this process that nothing else waits for.
    """
    _, wait_status = os.waitpid(pid, 0)
    return _code(wait_status)


def _code(wait_status: int) -> int:
    """A wait status as a shell reports it: the exit code, or 128 plus the ending signal's number."""
    code = os.waitstatus_to_exitcode(wait_status)
    return SIGNAL_STATUS_BASE - code if code < 0 else code
