"""Turns a strace -f log into the system calls the pruner reasons about.

The log is the one strace writes with STRACE_ARGUMENTS: every line starts with the id of the calling
thread, a call interrupted by another thread's line is printed as an `<unfinished ...>` half and a
later `<... name resumed>` half, every descriptor is decorated with the path or object it names, and
strings are printed whole with C escapes. This module joins the halves, keeps the calls the pruner
needs, and works out which of them were made inside the command's Landlock domain.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Iterator

from shared.src.domain.record import Syscall

# The options every observed run passes to strace: follow every process, quiet attach and exit
# notices, decorate every descriptor with the path it names, keep whole strings, and trace only the
# calls a layer can refuse plus the ones that build the process tree.
#
# --seccomp-bpf is left out on purpose, although it needs no privilege in the prune image and more
# than halves the cost of a traced run. Its filter answers SECCOMP_RET_TRACE, and the connect guard's
# filter answers SECCOMP_RET_USER_NOTIF for the calls it supervises, which takes precedence, so every
# connect, sendto and socket call the guard decides would be missing from the trace (measured with
# strace 6.8: the guard's refusal of a connect to 10.0.0.1 did not appear at all).
STRACE_ARGUMENTS = (
    "-f",
    "-qq",
    "-y",
    "-s",
    "4096",
    "-e",
    "trace=%file,%network,%process,%desc,landlock_restrict_self,setsid,setpgid,ioctl",
)

# The options the recording pruner (runtime_pruner) passes to strace around a program it records with no
# sandbox at all. -DDD detaches the tracer as a grandchild in a session of its own, so the program
# stays the calling shell's child and keeps the terminal, its job control and its signals. -yy also
# decorates a socket with its protocol and ends and a device with its numbers, which is how a
# recorded endpoint and a device ioctl are told apart; -x keeps a buffer such as a TLS ClientHello
# readable byte for byte. --seccomp-bpf is safe here, unlike in STRACE_ARGUMENTS, because no connect
# guard runs around a recorded program, and it makes a call-heavy program record several times
# faster. The trace set is the recording pruner plan's A.3.4: write brings the ClientHello, ioctl a
# device control no section can grant, and setsid, setpgid and io_uring_setup are calls the grading
# layers refuse whatever a policy grants. dup, dup2, dup3 and fcntl follow a device the session opened
# onto another descriptor, and open_by_handle_at, which %file does not include (measured with strace
# 6.8), is traced so that its use is reported as unsupported rather than missed.
RECORD_ARGUMENTS = (
    "-DDD",
    "-f",
    "-qq",
    "-yy",
    "-x",
    "-s",
    "4096",
    "--seccomp-bpf",
    "-e",
    ("trace=%file,%network,%process,ioctl,fchdir,write,setsid,setpgid,io_uring_setup,dup,dup2,dup3,fcntl,"
     "open_by_handle_at"),
)

# The successful calls parse_trace keeps beside every failed one: the ones that build the process
# tree and the domain, the ones that say what a socket is and which port it holds, and the ones that
# move a process's working directory, which a relative path is resolved against when strace did not
# decorate AT_FDCWD.
KEPT_SUCCESSES = frozenset({
    "landlock_restrict_self",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "socket",
    "bind",
    "listen",
    "getsockname",
    "chdir",
    "fchdir",
})

LINE = re.compile(
    r"^(?P<pid>\d+) +(?P<name>[a-z0-9_]+)\((?P<arguments>.*)\) += "
    r"(?P<result>-?\d+|\?|0x[0-9a-f]+)(?P<decoration><.*>)?(?: (?P<errno>E[A-Z0-9]+) \(.*\))?"
)
UNFINISHED = re.compile(r"^(?P<pid>\d+) +(?P<head>.*) <unfinished \.\.\.>$")
RESUMED = re.compile(r"^(?P<pid>\d+) +<\.\.\. (?P<name>[a-z0-9_]+) resumed>(?P<tail>.*)$")
NON_CALL = re.compile(r"^(\d+ +)?(\+\+\+ |--- |strace: )")
FORKING_CALLS = frozenset({"clone", "clone3", "fork", "vfork"})
DECORATED_DESCRIPTOR = re.compile(r"^(?:-?\d+|AT_FDCWD)<(?P<path>.*)>$")
# The enforcer the network layer runs to close bind with a Landlock domain that handles no path. Its
# domain is entered before the filesystem layer's own helper shells run, so it is not the command's.
PORT_ONLY_ENFORCER_FLAG = "--no-filesystem"
ENFORCER_NAME = "phobos-landlock-filesystem-and-networksystem"
OPENING_BRACKETS = {"(": ")", "{": "}", "[": "]", "<": ">"}
SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "v": "\v", "f": "\f", "a": "\a", "b": "\b",
                  "\\": "\\", '"': '"', "'": "'", "?": "?"}


@dataclasses.dataclass(frozen=True)
class Trace:
    """The calls of one observed run that matter to the pruner, and which of them were in the domain.

    `syscalls` holds every failed call and the successes named in KEPT_SUCCESSES, in log order.
    `domain_pids` holds every thread that was ever inside the command's Landlock domain, and
    `thread_group` maps every thread id seen to its thread-group id. `domain_from` maps each thread
    in the domain to the position in `syscalls` from which its calls are in the domain; use
    `in_domain` rather than reading it.
    """

    syscalls: list[Syscall]
    domain_pids: frozenset[int]
    thread_group: dict[int, int]
    domain_from: dict[int, int]

    def in_domain(self, index: int) -> bool:
        """Whether the call at `index` of `syscalls` was made inside the command's Landlock domain."""
        call = self.syscalls[index]
        start = self.domain_from.get(call.pid)
        return start is not None and index >= start


def parse_line(line: str) -> Syscall | None:
    """Parses one complete call line, or a resumed one already joined; None for anything else.

    Assumes the line came from strace -f with STRACE_ARGUMENTS or RECORD_ARGUMENTS, so it starts
    with a thread id.
    """
    match = LINE.match(line.rstrip("\n"))
    if match is None:
        return None
    raw_result = match.group("result")
    result = None if raw_result == "?" else int(raw_result, 0)
    return Syscall(
        pid=int(match.group("pid")),
        name=match.group("name"),
        arguments=match.group("arguments"),
        result=result,
        errno=match.group("errno"),
        decoration=match.group("decoration") or "",
    )


def is_non_call(line: str) -> bool:
    """Whether a line is not a complete call on its own: a status line, a half, or an empty line.

    Status lines are signal deliveries, exit notices and strace's own messages; a half is one of
    the two parts of a call another thread's line interrupted, which parse_trace joins.
    """
    stripped = line.rstrip("\n")
    if not stripped.strip():
        return True
    return bool(NON_CALL.match(stripped) or UNFINISHED.match(stripped) or RESUMED.match(stripped))


def joined_lines(lines: Iterable[str]) -> Iterable[str]:
    """Yields every line with each `<unfinished ...>` half joined to its `<... resumed>` half.

    The joined line takes the position of the resumed half, which is when the call returned. A half
    whose other half never arrives (the thread was killed in the call) is dropped.
    """
    pending: dict[int, str] = {}
    for raw in lines:
        line = raw.rstrip("\n")
        unfinished = UNFINISHED.match(line)
        if unfinished:
            pending[int(unfinished.group("pid"))] = unfinished.group("head")
            continue
        resumed = RESUMED.match(line)
        if resumed:
            pid = int(resumed.group("pid"))
            head = pending.pop(pid, None)
            if head is not None:
                yield f"{pid} {head}{resumed.group('tail')}"
            continue
        yield line


def iter_calls(lines: Iterable[str]) -> Iterator[Syscall]:
    """Yields every completed call of a log in the order the calls returned, successful or not.

    Each `<unfinished ...>` half is joined with its `<... resumed>` half first; status lines, signal
    deliveries and a half whose other half never arrived yield nothing.
    """
    for line in joined_lines(lines):
        call = parse_line(line)
        if call is not None:
            yield call


def split_arguments(text: str) -> list[str]:
    """Splits a call's argument text on its top-level commas, outside strings and brackets.

    A `>` that follows `-` or `=` is text rather than a closing bracket, because strace prints both
    `a->b` inside a socket decoration and `[128 => 16]` for an in-out length.
    """
    parts: list[str] = []
    depth: list[str] = []
    current: list[str] = []
    in_string = False
    escaped = False
    previous = ""
    for character in text:
        current.append(character)
        if in_string:
            escaped, in_string = string_state(character, escaped)
        elif character == '"':
            in_string = True
        elif character in OPENING_BRACKETS:
            depth.append(OPENING_BRACKETS[character])
        elif depth and character == depth[-1] and not (character == ">" and previous in ("-", "=")):
            depth.pop()
        elif character == "," and not depth:
            current.pop()
            parts.append("".join(current).strip())
            current = []
        previous = character
    tail = "".join(current).strip()
    if tail or parts:
        parts.append(tail)
    return parts


def string_state(character: str, escaped: bool) -> tuple[bool, bool]:
    """The (escaped, in_string) state after one character inside a quoted string."""
    if escaped:
        return False, True
    if character == "\\":
        return True, True
    return False, character != '"'


def argument(call: Syscall, index: int) -> str | None:
    """The raw text of one argument of a call, or None where the call has fewer arguments."""
    parts = split_arguments(call.arguments)
    if index >= len(parts):
        return None
    return parts[index]


def unescape(text: str) -> str:
    """Undoes strace's C escapes in the body of a quoted string, decoding the bytes as UTF-8.

    Bytes that are not valid UTF-8 survive as surrogate escapes, so a path round-trips to the same
    bytes through os.fsencode.
    """
    output = bytearray()
    position = 0
    while position < len(text):
        character = text[position]
        if character != "\\" or position + 1 >= len(text):
            output.extend(character.encode("utf-8", "surrogateescape"))
            position += 1
            continue
        position = unescape_one(text, position + 1, output)
    return output.decode("utf-8", "surrogateescape")


def unescape_one(text: str, position: int, output: bytearray) -> int:
    """Appends the byte of the escape whose letter is at `position`, and returns where the next starts."""
    letter = text[position]
    if letter in SIMPLE_ESCAPES:
        output.extend(SIMPLE_ESCAPES[letter].encode())
        return position + 1
    if letter == "x":
        digits = re.match(r"[0-9a-fA-F]{1,2}", text[position + 1:])
        if digits:
            output.append(int(digits.group(0), 16))
            return position + 1 + len(digits.group(0))
    octal = re.match(r"[0-7]{1,3}", text[position:])
    if octal:
        output.append(int(octal.group(0), 8) & 0xFF)
        return position + len(octal.group(0))
    output.extend(("\\" + letter).encode("utf-8", "surrogateescape"))
    return position + 1


def path_argument(call: Syscall, index: int) -> str | None:
    """The unescaped string of one argument, or None where that argument is not a quoted string.

    A string strace cut short is followed by `...`; the part it printed is returned.
    """
    raw = argument(call, index)
    if raw is None:
        return None
    match = re.match(r'^"(?P<body>(?:[^"\\]|\\.)*)"(?:\.\.\.)?$', raw, re.DOTALL)
    if match is None:
        return None
    return unescape(match.group("body"))


def descriptor_path(call: Syscall, index: int) -> str | None:
    """The path a decorated descriptor argument names (`3</srv>`, `AT_FDCWD</w>`), or None.

    None where the argument is not decorated, as AT_FDCWD is when strace does not decorate it.
    """
    raw = argument(call, index)
    if raw is None:
        return None
    match = DECORATED_DESCRIPTOR.match(raw)
    if match is None:
        return None
    return unescape(match.group("path"))


def forked_child(call: Syscall) -> int | None:
    """The id of the thread or process a successful clone, clone3, fork or vfork created, or None."""
    if call.name not in FORKING_CALLS or call.errno is not None or call.result is None or call.result <= 0:
        return None
    return call.result


def is_thread(call: Syscall) -> bool:
    """Whether a clone or clone3 call created a thread of its caller's thread group (CLONE_THREAD)."""
    return call.name in ("clone", "clone3") and re.search(r"\bCLONE_THREAD\b", call.arguments) is not None


def started_port_only_enforcer(call: Syscall) -> bool:
    """Whether a successful execve started the network layer's enforcer with its port-only domain."""
    if call.name != "execve" or call.errno is not None:
        return False
    program = path_argument(call, 0) or ""
    return program.endswith("/" + ENFORCER_NAME) and f'"{PORT_ONLY_ENFORCER_FLAG}"' in call.arguments


class ReusedProcessId(ValueError):
    """The kernel handed one process id to two processes within one trace.

    Calls are told apart only by the id strace prints, so the calls of the two processes could not be
    separated, and a refusal of one could be attributed to the other. Two clones returning one id,
    or a clone returning the id of the trace's root process, can only come from reuse, never from
    strace printing a clone's result after the child's own lines. A trace like this is refused
    rather than guessed at; the pruner aborts the run. With pid_max at 4194304, as in the prune
    containers measured, it needs millions of processes in one run.
    """


@dataclasses.dataclass
class DomainWalk:
    """The running state of parse_trace's walk over the log, kept apart from the finished Trace."""

    kept: list[Syscall] = dataclasses.field(default_factory=list)
    seen: set[int] = dataclasses.field(default_factory=set)
    port_only: set[int] = dataclasses.field(default_factory=set)
    entries: list[tuple[int, int, bool]] = dataclasses.field(default_factory=list)
    births: list[tuple[int, int, int, bool]] = dataclasses.field(default_factory=list)
    born: set[int] = dataclasses.field(default_factory=set)
    root: int | None = None

    def noting_root(self, lines: Iterable[str]) -> Iterable[str]:
        """Yields the lines unchanged, noting the id on the first of them as the trace's root process."""
        for line in lines:
            if self.root is None:
                match = re.match(r"^(\d+) ", line)
                if match:
                    self.root = int(match.group(1))
            yield line

    def take(self, call: Syscall) -> None:
        """Records one completed call: the process tree, the domain entries, and what to keep."""
        self.seen.add(call.pid)
        if call.name == "execve" and call.errno is None:
            if started_port_only_enforcer(call):
                self.port_only.add(call.pid)
            else:
                self.port_only.discard(call.pid)
        child = forked_child(call)
        if child is not None:
            if child in self.born or child == self.root:
                raise ReusedProcessId(f"process id {child} was created twice in one trace")
            self.born.add(child)
            self.seen.add(child)
            self.births.append((len(self.kept), call.pid, child, is_thread(call)))
        if call.errno is None and call.name not in KEPT_SUCCESSES:
            return
        if call.name == "landlock_restrict_self" and call.result == 0:
            self.entries.append((len(self.kept), call.pid, call.pid in self.port_only))
        self.kept.append(call)

    def thread_groups(self) -> dict[int, int]:
        """Every thread id seen mapped to its thread-group id, once every clone is known.

        A thread joins its creator's group and any other child starts its own. The walk repeats
        until nothing changes, because strace may print a thread's own clone before the clone that
        created it returned and named it.
        """
        group = {pid: pid for pid in self.seen}
        changed = True
        while changed:
            changed = False
            for _, parent, child, thread in self.births:
                wanted = group[parent] if thread else child
                if group[child] != wanted:
                    group[child] = wanted
                    changed = True
        return group

    def domain_from(self, count_port_only: bool) -> dict[int, int]:
        """Where each thread's calls enter the domain, counting port-only entries or not.

        A child is in the domain from its first call when its parent was in the domain at the
        clone. The walk repeats until nothing changes, because strace may print a child's own
        clone before the parent's clone returned and named it.
        """
        start: dict[int, int] = {}
        for position, pid, port_only in self.entries:
            if count_port_only or not port_only:
                start.setdefault(pid, position)
        changed = True
        while changed:
            changed = False
            for position, parent, child, _ in self.births:
                if parent in start and start[parent] <= position and start.get(child) != 0:
                    start[child] = 0
                    changed = True
        return start


def parse_trace(lines: Iterable[str]) -> Trace:
    """Parses a whole strace -f log into a Trace.

    A thread enters the command's domain at its own successful landlock_restrict_self, and every
    thread or process it creates afterwards is in the domain from its first call. The network
    layer's enforcer applies a domain that handles no path (started with --no-filesystem) before the
    filesystem layer's helper shells run, so its entry is not counted, unless the trace holds no
    other entry at all, as when the filesystem layer is switched off. Raises ReusedProcessId when
    one id was given to two processes.
    """
    walk = DomainWalk()
    for call in iter_calls(walk.noting_root(lines)):
        walk.take(call)
    start = walk.domain_from(count_port_only=False)
    if not start:
        start = walk.domain_from(count_port_only=True)
    return Trace(
        syscalls=walk.kept,
        domain_pids=frozenset(start),
        thread_group=walk.thread_groups(),
        domain_from=start,
    )
