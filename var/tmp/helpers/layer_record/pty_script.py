"""Types a session from a script into a command running in a pseudo-terminal.

A script is plain text, one action per line, so a session can be repeated exactly and the suites
can drive one:

    # a comment
    send import os          types the text and Enter
    expect ^OK-R1           waits for output matching the regular expression
    key ctrl-c              sends one control character
    sleep 1                 waits, in seconds

An expectation is searched in the output after the previous match, and the terminal echoes what
is typed, so a script prints markers the echo of its own line cannot contain (`"OK-" + "R1"`).
Job control cannot be scripted this way, since it needs an interactive shell around the command.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import pty
import re
import select
import signal
import time

# The status a session ends with when an expectation was not met within its time.
EXPECT_FAILED = 4

# The control characters a script may send, each as the terminal driver reads it.
KEYS = {"ctrl-c": "\x03", "ctrl-d": "\x04", "ctrl-z": "\x1a", "ctrl-backslash": "\x1c"}

KINDS = ("send", "expect", "key", "sleep")

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
    pid, descriptor = pty.fork()
    if pid == 0:
        _start(command, cwd)
    terminal = _Terminal(descriptor, transcript)
    try:
        for action in actions:
            if not _perform(terminal, action, step_seconds):
                _kill_group(pid)
                _status(pid)
                return EXPECT_FAILED
        terminal.drain(step_seconds)
    finally:
        os.close(descriptor)
    return _reap(pid, step_seconds)


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


def _checked(action: Action, number: int) -> Action:
    """The action unchanged when it is well formed; raises ValueError naming its line otherwise.

    Assumes number is the action's line in the script, counted from 1.
    """
    if action.kind not in KINDS:
        raise ValueError(f"line {number}: unknown action {action.kind!r}; expected one of {', '.join(KINDS)}")
    if action.kind == "key" and action.value not in KEYS:
        raise ValueError(f"line {number}: unknown key {action.value!r}; expected one of {', '.join(KEYS)}")
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
