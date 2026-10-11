"""What every successful call of a recorded session needs from Landlock, by the plan's A.6.1 and A.6.3.

The recorder blocks nothing, so a session's trace holds what succeeded. Each successful call is
turned into the sections Landlock checks for it on the object it reached: the object itself for a
read, a write, a truncation or an execution, the parent directory of the name for a creation, a
removal or a rename. Calls the grading layers refuse whatever a policy grants (a connection to a
UNIX socket, setsid, a device ioctl, ...) are fixed refusals: reported, never granted. Two of them
glibc makes on its own and copes with when they are refused, so they are tolerated, listed and no
fixed refusal: the AF_UNSPEC connect that resets a datagram socket between ranked addresses, and the
netlink route socket of its address check. A successful call the mapping does not state is
unsupported and reported, never silently dropped; the mapping is an allow-list of names
(MAPPED_CALLS), so a call a later kernel adds is unsupported too.

The same mapping, applied to one call as if it had succeeded, gives that call's access pairs, which
the replay check compares a refused call against (pairs_of_call). Pairs spell a per-run name (a
process's /proc entry, a pseudo-terminal) as a placeholder, so a recording and a replay that saw
different numbers still compare. Network endpoints are read only as far as those pairs need;
turning them into rules is the job of the network part of the recorder.

A snapshot here is any object with `existed(path) -> bool`, answering whether a path existed in
the container before its first session.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import stat
from collections.abc import Iterable
from typing import Protocol

from shared.src.domain import attribute, strace_parse
from shared.src.domain.record import Need, Syscall

SECTION_READ = attribute.SECTION_READ
SECTION_EXECUTE = attribute.SECTION_EXECUTE
SECTION_WRITE = attribute.SECTION_WRITE
SECTION_CREATE = attribute.SECTION_CREATE
SECTION_CREATE_IPC = attribute.SECTION_CREATE_IPC
SECTION_CREATE_SYMLINK = attribute.SECTION_CREATE_SYMLINK
SECTION_DELETE = attribute.SECTION_DELETE
SECTION_RESTRUCTURE = attribute.SECTION_RESTRUCTURE

# The second element of a pair that is not a section: a connection or datagram to an endpoint, a
# port held, and an operation the layers refuse whatever a policy grants.
PAIR_CONNECT = "connect"
PAIR_BIND = "bind"
PAIR_CALL = "call"

# A datagram sent to an endpoint. Not an access of its own: it is what makes a datagram socket's
# connect to that endpoint count, and it never leaves this module.
PAIR_SENT = "sent"

OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
EXEC_CALLS = frozenset({"execve", "execveat"})
MKDIR_CALLS = frozenset({"mkdir", "mkdirat"})
MKNOD_CALLS = frozenset({"mknod", "mknodat"})
SYMLINK_CALLS = frozenset({"symlink", "symlinkat"})
REMOVE_CALLS = frozenset({"unlink", "unlinkat", "rmdir"})
RENAME_CALLS = frozenset({"rename", "renameat", "renameat2"})
LINK_CALLS = frozenset({"link", "linkat"})
NAME_CALLS = MKDIR_CALLS | MKNOD_CALLS | SYMLINK_CALLS | REMOVE_CALLS | frozenset({"truncate"})
CONNECT_CALLS = frozenset({"connect", "sendto", "sendmsg", "sendmmsg"})
SEND_ON_CONNECTED_CALLS = frozenset({"write", "send", "sendto", "sendmsg", "sendmmsg"})
GROUP_CALLS = frozenset({"setsid", "setpgid"})
DUPLICATING_CALLS = frozenset({"dup", "dup2", "dup3", "fcntl"})

# Calls Landlock checks no right for (kernel Landlock documentation): they need no section.
UNCHECKED_FILE_CALLS = frozenset({
    "chdir",
    "fchdir",
    "getcwd",
    "stat",
    "lstat",
    "fstat",
    "stat64",
    "lstat64",
    "fstat64",
    "newfstatat",
    "fstatat64",
    "statx",
    "statfs",
    "statfs64",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getxattr",
    "lgetxattr",
    "listxattr",
    "llistxattr",
    "getxattrat",
    "listxattrat",
    "setxattr",
    "lsetxattr",
    "setxattrat",
    "removexattr",
    "lremovexattr",
    "removexattrat",
    "chmod",
    "fchmodat",
    "fchmodat2",
    "chown",
    "lchown",
    "fchownat",
    "utime",
    "utimes",
    "utimensat",
    "futimesat",
    "inotify_add_watch",
})

# Every call the mapping states an effect for, the ones that need nothing included. A successful
# call that is neither here nor in NON_FILE_CALLS is unsupported.
MAPPED_CALLS = OPEN_CALLS | EXEC_CALLS | NAME_CALLS | RENAME_CALLS | LINK_CALLS | UNCHECKED_FILE_CALLS

# The traced calls that are not file calls: the network and process sets and the ones named
# beside them in RECORD_ARGUMENTS. They are read by the mapping where it states them and are
# otherwise no file access, so they are never unsupported.
NON_FILE_CALLS = frozenset({
    "socket",
    "socketpair",
    "bind",
    "listen",
    "accept",
    "accept4",
    "connect",
    "getsockname",
    "getpeername",
    "send",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recv",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "shutdown",
    "setsockopt",
    "getsockopt",
    "clone",
    "clone3",
    "fork",
    "vfork",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "waitpid",
    "kill",
    "tkill",
    "tgkill",
    "rt_sigqueueinfo",
    "rt_tgsigqueueinfo",
    "pidfd_open",
    "pidfd_send_signal",
    "pidfd_getfd",
    "unshare",
    "setns",
    "ioctl",
    "write",
    "setsid",
    "setpgid",
    "io_uring_setup",
    "dup",
    "dup2",
    "dup3",
    "fcntl",
})

# The ioctl commands Landlock allows on any file whatever the policy (kernel Landlock documentation,
# LANDLOCK_ACCESS_FS_IOCTL_DEV).
ALWAYS_ALLOWED_IOCTLS = frozenset({
    "FIOCLEX",
    "FIONCLEX",
    "FIONBIO",
    "FIOASYNC",
    "FIFREEZE",
    "FITHAW",
    "FIGETBSZ",
    "FS_IOC_FIEMAP",
    "FICLONE",
    "FICLONERANGE",
    "FIDEDUPERANGE",
    "FS_IOC_GETFSUUID",
    "FS_IOC_GETFSSYSFSPATH",
})

# The kernel follows at most this many interpreters below the binary (BINPRM_MAX_RECURSION).
MAX_INTERPRETERS = 4

# How much of a call's text a need keeps as its evidence.
EVIDENCE_LIMIT = 512

# The standard streams' names under /dev, which are links to the calling process's descriptors.
STANDARD_STREAMS = {"/dev/stdin": "0", "/dev/stdout": "1", "/dev/stderr": "2"}

DEVICE_SUFFIX = re.compile(r"^(?P<path>/.*?)<(?:char|block) \d+:\d+>$")
SOCKET_DECORATION = re.compile(r"^<(?P<protocol>[A-Za-z0-9-]+):\[(?P<ends>.*)\]>$")
DESCRIPTOR_ARGUMENT = re.compile(r"^(?P<number>-?\d+)(?P<decoration><.*>)?$")
PROCESS_ENTRY = re.compile(r"^/proc/\d+(?P<task>/task/\d+)?(?=/|$)")
PSEUDO_TERMINAL = re.compile(r"^/dev/pts/\d+$")


class Snapshot(Protocol):
    """What the mapping asks of a snapshot: whether a path existed before the first session."""

    def existed(self, path: str) -> bool:
        """Whether the path existed in the container before its first session."""


@dataclasses.dataclass
class SessionNeeds:
    """What one recorded session needed, before any generalisation.

    `needs` are the filesystem accesses, `fixed` the operations the grading layers refuse whatever a
    policy grants, `tolerated` the refused-but-tolerated glibc operations, `unsupported` the trace
    text of every successful call the mapping does not state, `moves` every (source parent,
    destination parent) of a rename or link across directories, `process_ids` every thread and
    process of the session, and `listed_directories` every directory the session opened to list.
    """

    needs: list[Need] = dataclasses.field(default_factory=list)
    fixed: list[str] = dataclasses.field(default_factory=list)
    tolerated: list[str] = dataclasses.field(default_factory=list)
    unsupported: list[str] = dataclasses.field(default_factory=list)
    moves: set[tuple[str, str]] = dataclasses.field(default_factory=set)
    process_ids: frozenset[int] = frozenset()
    listed_directories: set[str] = dataclasses.field(default_factory=set)


@dataclasses.dataclass(frozen=True)
class Effect:
    """What one call needs: filesystem grants, the pairs of operations no policy grants, endpoints.

    `grants` holds (objects, sections) pairs, `fixed` (pair, description) pairs, `tolerated`
    descriptions, `endpoints` the network pairs the call reached or held, and `unsupported` is set
    when the mapping states nothing for a call that would need something.
    """

    grants: tuple[tuple[tuple[str, ...], frozenset[str]], ...] = ()
    fixed: tuple[tuple[tuple[str, str], str], ...] = ()
    tolerated: tuple[str, ...] = ()
    endpoints: tuple[tuple[str, str], ...] = ()
    moves: tuple[tuple[str, str], ...] = ()
    listed: tuple[str, ...] = ()
    unsupported: bool = False


class _Walk:
    """The state of a walk over one session: working directories, thread groups, devices, names.

    Assumes the calls are fed in log order through `follow`, which a successful call passes through
    after its effect was read. Every name created or removed by the session is remembered, in order,
    so a later call knows whether a name exists although the snapshot says otherwise; removing or
    renaming a directory removes every name beneath it. `replay` is set for a single refused call of
    a replay, where every device descriptor counts as opened by the session: Landlock refuses an
    ioctl only on a file opened inside its domain, so a refused one was never inherited.
    """

    def __init__(self, snapshot: Snapshot, workdir: str, replay: bool = False):
        """Starts with no thread known, every thread in `workdir`, and the snapshot's names."""
        self.snapshot = snapshot
        self.replay = replay
        empty = strace_parse.Trace(syscalls=[], domain_pids=frozenset(), thread_group={}, domain_from={})
        self.state = attribute.RunState(empty, workdir)
        self.groups: dict[int, int] = {}
        self.devices: dict[tuple[int, str], str] = {}
        self.created: dict[str, int] = {}
        self.removed: dict[str, int] = {}
        self.sequence = 0
        self.process_ids: set[int] = set()

    def group(self, pid: int) -> int:
        """The thread group of a thread; a thread not seen created is its own group."""
        return self.groups.get(pid, pid)

    def exists(self, path: str) -> bool:
        """Whether a name exists at this point of the session, by the snapshot and what it changed.

        The latest change wins: a creation of the name after every removal of it or of a directory
        above it means it exists, a removal without a later creation means it does not.
        """
        removal = max((self.removed.get(ancestor, 0) for ancestor in _self_and_ancestors(path)), default=0)
        creation = self.created.get(path, 0)
        if creation > removal:
            return True
        if removal:
            return False
        return self.snapshot.existed(path)

    def follow(self, call: Syscall) -> None:
        """Updates the state from one successful call: the process tree, directories and devices."""
        self.process_ids.add(call.pid)
        child = strace_parse.forked_child(call)
        if child is not None:
            self.process_ids.add(child)
            self.groups[child] = self.group(call.pid) if strace_parse.is_thread(call) else child
            self.state.trace.thread_group[child] = self.groups[child]
            if not strace_parse.is_thread(call):
                parent = self.group(call.pid)
                for (owner, number), device in list(self.devices.items()):
                    if owner == parent:
                        self.devices[(child, number)] = device
        self.state.follow(call)
        if call.result is None or call.result < 0:
            return
        if call.name in OPEN_CALLS:
            device = _device_path(call.decoration)
            if device is not None:
                self.devices[(self.group(call.pid), str(call.result))] = device
        elif call.name in DUPLICATING_CALLS and (call.name != "fcntl" or "F_DUPFD" in call.arguments):
            self._duplicated(call)

    def _duplicated(self, call: Syscall) -> None:
        """Carries a device the session opened over to a duplicate of its descriptor, and only such one.

        A duplicate of an inherited descriptor shares the file opened before the sandbox, which
        Landlock never restricts, so it never counts as the session's.
        """
        group = self.group(call.pid)
        match = DESCRIPTOR_ARGUMENT.match(strace_parse.argument(call, 0) or "")
        source = self.devices.get((group, match.group("number"))) if match else None
        if source is not None:
            self.devices[(group, str(call.result))] = source
        else:
            self.devices.pop((group, str(call.result)), None)

    def note_created(self, path: str) -> None:
        """Remembers that the session created the name, now."""
        self.sequence += 1
        self.created[path] = self.sequence

    def note_removed(self, path: str) -> None:
        """Remembers that the session removed the name and everything beneath it, now."""
        self.sequence += 1
        self.removed[path] = self.sequence

    def opened_device(self, call: Syscall) -> str | None:
        """The device a call's first descriptor names, when the session itself opened it there.

        The descriptor's own decoration must name a device, and in a recording the same device must
        have been opened or duplicated onto that number in the call's thread group.
        """
        match = DESCRIPTOR_ARGUMENT.match(strace_parse.argument(call, 0) or "")
        device = _device_path(match.group("decoration") or "") if match else None
        if device is None:
            return None
        if self.replay:
            return device
        opened = self.devices.get((self.group(call.pid), match.group("number")))
        return device if opened == device else None


def read_session(calls: Iterable[Syscall], snapshot: Snapshot, workdir: str, run: int) -> SessionNeeds:
    """Every need, fixed refusal and unsupported call of one recorded session, before generalisation.

    Assumes the calls are a whole session's trace in log order (strace_parse.iter_calls) and that
    `workdir` is where the session's command started, which every thread inherits at a clone and
    leaves at a chdir or fchdir. Only successful calls are read.
    """
    walk = _Walk(snapshot, workdir)
    result = SessionNeeds()
    for call in calls:
        if call.errno is not None:
            continue
        effect = _effect(call, walk)
        if effect.unsupported:
            result.unsupported.append(_call_text(call))
        for objects, sections in effect.grants:
            result.needs.append(Need(objects=objects, sections=sections, run=run, tid=call.pid,
                                     tgid=walk.group(call.pid), evidence=_call_text(call)[:EVIDENCE_LIMIT]))
        result.fixed.extend(description for _, description in effect.fixed)
        result.tolerated.extend(effect.tolerated)
        result.moves.update(effect.moves)
        result.listed_directories.update(effect.listed)
        walk.follow(call)
    result.process_ids = frozenset(walk.process_ids)
    return result


def access_pairs(calls: Iterable[Syscall], snapshot: Snapshot, workdir: str) -> set[tuple[str, str]]:
    """Every (object, section) and operation pair a session's successful calls needed, ungeneralised.

    Assumes what read_session assumes. A datagram socket connected to a destination counts only when
    a datagram was then sent to it (plan A.8.4): glibc connects one to rank addresses and sends nothing.
    A non-blocking connect that answered EINPROGRESS counts too: the pairs only feed the replay
    check, which this makes stricter, never a grant.
    """
    walk = _Walk(snapshot, workdir)
    pairs: set[tuple[str, str]] = set()
    probed: set[tuple[str, str]] = set()
    for call in calls:
        pending = call.name == "connect" and call.errno == "EINPROGRESS"
        if call.errno is not None and not pending:
            continue
        effect = _effect(call, walk)
        pairs.update(_pairs(effect))
        if call.name == "connect":
            probed.update(pair for pair in effect.endpoints if pair[0].endswith(" udp"))
        if not pending:
            walk.follow(call)
    sent = {endpoint for endpoint, kind in pairs if kind == PAIR_SENT}
    unsent = {pair for pair in probed if pair[0] not in sent}
    return {pair for pair in pairs if pair[1] != PAIR_SENT and pair not in unsent}


def pairs_of_call(call: Syscall, snapshot: Snapshot, cwd: str) -> set[tuple[str, str]]:
    """The pairs one call would need had it succeeded, spelt as access_pairs spells them.

    Assumes `cwd` is the calling thread's working directory, which a relative path not decorated
    with a directory is resolved against, and that the call is a refused call of a replay.
    """
    walk = _Walk(snapshot, cwd, replay=True)
    return {pair for pair in _pairs(_effect(call, walk)) if pair[1] != PAIR_SENT}


def exec_chain(path: str) -> list[str]:
    """The binary and every interpreter the kernel opens to run it, each canonical, in that order.

    Assumes the files can be read where this runs, which is the recording's own image. An ELF
    file's PT_INTERP and a script's `#!` program are followed, at most MAX_INTERPRETERS of them.
    """
    chain = [os.path.realpath(path)]
    while len(chain) <= MAX_INTERPRETERS:
        interpreter = attribute.interpreter_of(chain[-1])
        if interpreter is None or not interpreter.startswith("/"):
            break
        resolved = os.path.realpath(interpreter)
        if resolved in chain:
            break
        chain.append(resolved)
    return chain


def comparable(path: str) -> str:
    """A path as pairs spell it: a process's /proc entry and a pseudo-terminal as a placeholder.

    Their numbers differ in every run, so a recording and a replay could never compare them
    otherwise; the comparison then errs towards finding a regression rather than missing one.
    """
    entry = PROCESS_ENTRY.match(path)
    if entry is not None:
        task = "/task/<tid>" if entry.group("task") else ""
        return "/proc/<pid>" + task + path[entry.end():]
    if PSEUDO_TERMINAL.match(path):
        return "/dev/pts/<n>"
    return path


def _pairs(effect: Effect) -> list[tuple[str, str]]:
    """The access pairs of an effect: each object with each section, then the other pairs."""
    pairs = [(comparable(path), section) for objects, sections in effect.grants for path in objects
             for section in sections]
    pairs.extend(pair for pair, _ in effect.fixed)
    pairs.extend(effect.endpoints)
    return pairs


def _effect(call: Syscall, walk: _Walk) -> Effect:
    """What one call needs, by the mapping; assumes the walk's state is the one before the call."""
    if call.name in OPEN_CALLS:
        return _open(call, walk)
    if call.name in EXEC_CALLS:
        return _execute(call, walk)
    if call.name in RENAME_CALLS or call.name in LINK_CALLS:
        return _move(call, walk)
    if call.name in NAME_CALLS:
        return _path_call(call, walk)
    if call.name in MAPPED_CALLS:
        return Effect()
    if call.name in NON_FILE_CALLS:
        return _other(call, walk)
    return Effect(unsupported=True)


def _open(call: Syscall, walk: _Walk) -> Effect:
    """An open: read, write or both on the file reached, and a creation on its parent for a new file.

    A result decoration that names no path (a pipe, a socket, an anonymous inode reached through
    /dev/stdin or /proc/self/fd) means no path Landlock checks, so it needs nothing.
    """
    flags = set(attribute.open_flags(call).split("|"))
    if "O_PATH" in flags:
        return Effect()
    if "O_TMPFILE" in flags:
        return Effect(unsupported=True)
    if not _names_a_path(call.decoration):
        return Effect()
    descriptor_index, path_index = attribute.PATH_ARGUMENTS[call.name]
    follows = "O_NOFOLLOW" not in flags and not {"O_CREAT", "O_EXCL"} <= flags
    path = _object_path(call.decoration) or _resolved(call, walk, descriptor_index, path_index, follows)
    if path is None:
        return Effect(unsupported=True)
    grants = []
    created = "O_CREAT" in flags and not walk.exists(path)
    if created:
        grants.append(((attribute.parent_of(path),), frozenset({SECTION_CREATE})))
        if call.errno is None:
            walk.note_created(path)
    sections = {SECTION_WRITE} if "O_WRONLY" in flags else {SECTION_READ, SECTION_WRITE} if "O_RDWR" in flags \
        else {SECTION_READ}
    if "O_TRUNC" in flags and not created:
        sections.add(SECTION_WRITE)
    grants.append(((path,), frozenset(sections)))
    directory = "O_DIRECTORY" in flags or (os.path.isdir(path) and not os.path.islink(path))
    listed = (path,) if directory and SECTION_READ in sections else ()
    return Effect(grants=tuple(grants), listed=listed)


def _execute(call: Syscall, walk: _Walk) -> Effect:
    """An execution: execute and read on the binary and every interpreter it names (A.4, defect 1)."""
    if call.name == "execveat" and "AT_EMPTY_PATH" in call.arguments and strace_parse.path_argument(call, 1) == "":
        path = strace_parse.descriptor_path(call, 0)
        if path is None or not path.startswith("/") or path.endswith(" (deleted)") or path.startswith("/memfd:"):
            return Effect(unsupported=True)
    else:
        descriptor_index, path_index = attribute.PATH_ARGUMENTS[call.name]
        path = _resolved(call, walk, descriptor_index, path_index, True)
        if path is None or path.startswith("/proc/"):
            return Effect(unsupported=True)
    return Effect(grants=((tuple(exec_chain(path)), frozenset({SECTION_EXECUTE, SECTION_READ})),))


def _path_call(call: Syscall, walk: _Walk) -> Effect:
    """A call on one name: a creation or removal on the parent, a truncation on the file it reaches."""
    descriptor_index, path_index = attribute.PATH_ARGUMENTS[call.name]
    path = _resolved(call, walk, descriptor_index, path_index, call.name == "truncate")
    if path is None:
        return Effect(unsupported=True)
    parent = attribute.parent_of(path)
    if call.name == "truncate":
        return Effect(grants=(((path,), frozenset({SECTION_WRITE})),))
    if call.name in REMOVE_CALLS:
        if call.errno is None:
            walk.note_removed(path)
        return Effect(grants=(((parent,), frozenset({SECTION_DELETE})),))
    if call.errno is None:
        walk.note_created(path)
    if call.name in SYMLINK_CALLS:
        return Effect(grants=(((parent,), frozenset({SECTION_CREATE_SYMLINK})),))
    if call.name in MKNOD_CALLS:
        mode = strace_parse.argument(call, 1 if call.name == "mknod" else 2) or ""
        if "S_IFCHR" in mode or "S_IFBLK" in mode:
            return Effect(fixed=((("mknod " + comparable(path), PAIR_CALL),
                                  (f"mknod of the device node {path!r}: refused by Landlock whenever it handles "
                                   "the filesystem; no section grants a device node")),))
        if "S_IFIFO" in mode or "S_IFSOCK" in mode:
            return Effect(grants=(((parent,), frozenset({SECTION_CREATE_IPC})),))
    return Effect(grants=(((parent,), frozenset({SECTION_CREATE})),))


def _move(call: Syscall, walk: _Walk) -> Effect:
    """A rename or link: creation and removal in one directory, and across two the refer right too.

    Across directories Landlock checks REFER on both parents, and a move from S to D is listed so
    that generation can give S every section D holds (plan A.6.2). Both names are names, so a
    symbolic link in their last component is never followed.
    """
    (source_descriptor, source_index), (target_descriptor, target_index) = attribute.TWO_PATH_ARGUMENTS[call.name]
    source = _resolved(call, walk, source_descriptor, source_index, False)
    target = _resolved(call, walk, target_descriptor, target_index, False)
    if source is None or target is None:
        return Effect(unsupported=True)
    source_parent = attribute.parent_of(source)
    target_parent = attribute.parent_of(target)
    exchange = call.name == "renameat2" and "RENAME_EXCHANGE" in (strace_parse.argument(call, 4) or "")
    link = call.name in LINK_CALLS
    target_existed = walk.exists(target)
    sources: dict[str, set[str]] = {}
    sources.setdefault(target_parent, set()).add(_creation_section(target, source))
    if not link:
        sources.setdefault(source_parent, set()).add(SECTION_DELETE)
    if target_existed and not link:
        sources[target_parent].add(SECTION_DELETE)
    if exchange:
        sources.setdefault(source_parent, set()).add(_creation_section(source, target))
        sources[target_parent].add(SECTION_DELETE)
    moves: list[tuple[str, str]] = []
    if source_parent != target_parent:
        sources.setdefault(source_parent, set()).add(SECTION_RESTRUCTURE)
        sources[target_parent].add(SECTION_RESTRUCTURE)
        moves.append((source_parent, target_parent))
        if exchange:
            moves.append((target_parent, source_parent))
    if call.errno is None and not exchange:
        if not link:
            walk.note_removed(source)
        walk.note_created(target)
    grants = tuple(((parent,), frozenset(sections)) for parent, sections in sources.items())
    return Effect(grants=grants, moves=tuple(moves))


def _creation_section(*candidates: str) -> str:
    """The section that creates an object of the kind the first existing candidate name holds.

    Assumes it runs in the recording's or replay's container: after a recorded move the object sits
    at its new name, before a refused one at its old name, so both are given in that order. A
    regular file or directory, or nothing found, needs [create].
    """
    for path in candidates:
        try:
            status = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(status.st_mode):
            return SECTION_CREATE_SYMLINK
        if stat.S_ISFIFO(status.st_mode) or stat.S_ISSOCK(status.st_mode):
            return SECTION_CREATE_IPC
        return SECTION_CREATE
    return SECTION_CREATE


def _other(call: Syscall, walk: _Walk) -> Effect:
    """A network, process or named call: endpoints, a pathname socket, or a fixed refusal."""
    if call.name in GROUP_CALLS or call.name == "io_uring_setup":
        return Effect(fixed=(((call.name, PAIR_CALL), _fixed_call_text(call.name)),))
    if call.name == "socket":
        return _socket(call)
    if call.name == "ioctl":
        return _ioctl(call, walk)
    if call.name == "bind":
        return _bind(call, walk)
    if call.name == "listen":
        socket_text = strace_parse.argument(call, 0) or ""
        local, _ = socket_ends(socket_text)
        transport = transport_of(socket_text)
        if local is None and transport is not None:
            return Effect(endpoints=((f"0 {transport}", PAIR_BIND),))
        return Effect()
    if call.name in CONNECT_CALLS or call.name in SEND_ON_CONNECTED_CALLS:
        return _connect(call)
    return Effect()


def _socket(call: Syscall) -> Effect:
    """A socket the connect guard refuses to create: a packet, raw or ICMP datagram socket.

    glibc's address check (AI_ADDRCONFIG) opens a raw netlink route socket and falls back when it is
    refused, so that one is tolerated rather than a fixed refusal.
    """
    arguments = strace_parse.split_arguments(call.arguments)
    family = arguments[0] if arguments else ""
    kind = arguments[1] if len(arguments) > 1 else ""
    protocol = arguments[2] if len(arguments) > 2 else ""
    if family == "AF_NETLINK" and protocol == "NETLINK_ROUTE":
        return Effect(tolerated=(("socket AF_NETLINK NETLINK_ROUTE: refused by the connect guard, which glibc's "
                                  "address check copes with; a program that needs netlink itself cannot run "
                                  "under the guard"),))
    refused = family == "AF_PACKET" or "SOCK_RAW" in kind or ("SOCK_DGRAM" in kind and "ICMP" in protocol)
    if not refused:
        return Effect()
    text = f"socket {family} {kind.split('|')[0]} {protocol}".strip()
    return Effect(fixed=(((text, PAIR_CALL), f"{text}: refused by the connect guard on every Landlock version"),))


def _ioctl(call: Syscall, walk: _Walk) -> Effect:
    """A device ioctl on a device the session opened itself, which no section grants (IOCTL_DEV)."""
    device = walk.opened_device(call)
    command = strace_parse.argument(call, 1) or ""
    if device is None or command in ALWAYS_ALLOWED_IOCTLS:
        return Effect()
    text = f"ioctl {command} {comparable(device)}"
    return Effect(fixed=(((text, PAIR_CALL),
                          (f"ioctl {command} on {device!r}, a device the session opened: refused by Landlock from "
                           "version 5 on, since no section grants IOCTL_DEV; free below it")),))


def _bind(call: Syscall, walk: _Walk) -> Effect:
    """A bind: create-ipc on the parent of a pathname socket, a held port for an IPv4 or IPv6 socket."""
    text = strace_parse.argument(call, 1) or ""
    family, _, port = attribute.parse_address(text)
    if family == "AF_UNIX":
        path = attribute.unix_path(text)
        if path is None:
            return Effect()
        if not path.startswith("/"):
            path = os.path.join(walk.state.directory(call.pid), path)
        path = _canonical(path, call.pid, walk.group(call.pid), False)
        if call.errno is None:
            walk.note_created(path)
        return Effect(grants=(((attribute.parent_of(path),), frozenset({SECTION_CREATE_IPC})),))
    transport = transport_of(strace_parse.argument(call, 0) or "")
    if family not in attribute.INET_FAMILIES or port is None or transport is None:
        return Effect()
    return Effect(endpoints=((f"{port} {transport}", PAIR_BIND),))


def _connect(call: Syscall) -> Effect:
    """A connection or datagram: its destination, or the remote end of a connected datagram socket.

    A connection to a UNIX socket, the session's own included, is a fixed refusal: the connect guard
    carries no UNIX family. AF_UNSPEC on a datagram socket is glibc resetting its ranking socket,
    tolerated. A netlink destination follows a netlink socket, which _socket already judged. A
    datagram sent without an address on a connected socket is recorded as `sent`, which is what
    makes that socket's connect count (plan A.8.4).
    """
    socket_text = strace_parse.argument(call, 0) or ""
    transport = transport_of(socket_text)
    destination = attribute.destination_text(call) if call.name in CONNECT_CALLS else ""
    family, address, port = attribute.parse_address(destination)
    if family == "AF_UNIX":
        path = attribute.unix_path(destination)
        name = path if path is not None else "@" + _abstract_name(destination)
        pair = (f"unix:{name}", PAIR_CONNECT)
        return Effect(fixed=((pair, (f"connection to the UNIX socket {name!r}: refused by the connect guard "
                                     "whenever the network layer is on, on every Landlock version")),))
    if family == "AF_UNSPEC" and transport == "udp":
        return Effect(tolerated=(("connect AF_UNSPEC on a datagram socket: glibc resetting the socket it ranks "
                                  "addresses with; refused by the connect guard, which glibc copes with"),))
    if family == "AF_NETLINK":
        return Effect()
    if family is not None and family not in attribute.INET_FAMILIES:
        pair = (f"family:{family}", PAIR_CONNECT)
        return Effect(fixed=((pair, (f"{call.name} with the address family {family}: refused by the connect "
                                     "guard, which carries only AF_INET and AF_INET6, on every Landlock version")),))
    if family in attribute.INET_FAMILIES and address is not None and port is not None:
        endpoint = endpoint_text(address, port, transport or ("tcp" if call.name == "connect" else "udp"))
        endpoints = [(endpoint, PAIR_CONNECT)]
        if call.name != "connect":
            endpoints.append((endpoint, PAIR_SENT))
        return Effect(endpoints=tuple(endpoints))
    if transport == "udp" and call.name in SEND_ON_CONNECTED_CALLS:
        _, remote = socket_ends(socket_text)
        if remote is not None:
            return Effect(endpoints=((endpoint_text(remote[0], remote[1], "udp"), PAIR_SENT),))
    return Effect()


def _abstract_name(text: str) -> str:
    """The name of an abstract UNIX address strace printed as sun_path=@"name", or empty."""
    match = re.search(r'sun_path=@"((?:[^"\\]|\\.)*)"', text)
    return strace_parse.unescape(match.group(1)) if match else ""


def endpoint_text(address: str, port: int, transport: str) -> str:
    """An endpoint spelt once: IPv4-mapped IPv6 as IPv4, IPv6 in brackets, then port and transport."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"{address}:{port} {transport}"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    text = f"[{parsed}]" if isinstance(parsed, ipaddress.IPv6Address) else str(parsed)
    return f"{text}:{port} {transport}"


def transport_of(socket_text: str) -> str | None:
    """tcp or udp from a socket argument's -yy decoration (`5<TCP:[...]>`), None otherwise."""
    match = DESCRIPTOR_ARGUMENT.match(socket_text)
    decoration = match.group("decoration") if match else None
    socket = SOCKET_DECORATION.match(decoration or "")
    if socket is None:
        return None
    protocol = socket.group("protocol").upper()
    if protocol in ("TCP", "TCPV6"):
        return "tcp"
    if protocol in ("UDP", "UDPV6", "UDPLITE", "UDPLITEV6"):
        return "udp"
    return None


def socket_ends(socket_text: str) -> tuple[tuple[str, int] | None, tuple[str, int] | None]:
    """The local and remote end a -yy socket decoration shows; None for an end it does not show.

    A socket that is neither bound nor connected is decorated with its inode only (`<TCP:[1234]>`).
    """
    match = DESCRIPTOR_ARGUMENT.match(socket_text)
    socket = SOCKET_DECORATION.match((match.group("decoration") if match else None) or "")
    if socket is None:
        return None, None
    local, _, remote = socket.group("ends").partition("->")
    return _end(local), _end(remote)


def _end(text: str) -> tuple[str, int] | None:
    """An address and port from `1.2.3.4:5` or `[::1]:5`; None for an inode or nothing."""
    match = re.match(r"^\[?(?P<address>[0-9A-Fa-f:.]+?)\]?:(?P<port>\d+)$", text)
    if match is None or ("." not in match.group("address") and ":" not in match.group("address")):
        return None
    return match.group("address"), int(match.group("port"))


def _fixed_call_text(name: str) -> str:
    """The description of a call the grading layers refuse outright."""
    if name == "io_uring_setup":
        return "io_uring_setup: refused by the connect guard, which refuses io_uring on every Landlock version"
    return (f"{name}: refused by the timeout's group lock whenever a timeout is set, and by the connect guard; "
            "an interactive shell's job control needs it")


def _object_path(decoration: str) -> str | None:
    """The path a result's decoration names, without a device's numbers; None for no path."""
    if not decoration.startswith("<") or not decoration.endswith(">"):
        return None
    inner = strace_parse.unescape(decoration[1:-1])
    device = DEVICE_SUFFIX.match(inner)
    if device is not None:
        return device.group("path")
    if not inner.startswith("/") or inner.endswith(" (deleted)"):
        return None
    return inner


def _names_a_path(decoration: str) -> bool:
    """Whether a result's decoration, if any, names a path; a pipe, socket or anonymous inode does not.

    A path the kernel shows as deleted still names one: another process removed it after the open.
    """
    if not decoration:
        return True
    return strace_parse.unescape(decoration[1:-1]).startswith("/")


def _device_path(decoration: str) -> str | None:
    """The device path a decoration names, when it is a character or block device."""
    if not decoration.startswith("<") or not decoration.endswith(">"):
        return None
    device = DEVICE_SUFFIX.match(strace_parse.unescape(decoration[1:-1]))
    return device.group("path") if device else None


def _resolved(call: Syscall, walk: _Walk, descriptor_index: int | None, path_index: int,
              follow: bool) -> str | None:
    """The canonical absolute path a call names, resolved as the layer pruner resolves it.

    `follow` says whether the call follows a symbolic link in the last component, as an open or an
    execution does, or acts on the name itself, as a creation, removal or rename does. Assumes it
    runs in the recording's or replay's image, whose links are the ones the session met.
    """
    path = walk.state.resolve(call, descriptor_index, path_index)
    if path is None:
        return None
    return _canonical(path, call.pid, walk.group(call.pid), follow)


def _canonical(path: str, tid: int, tgid: int, follow: bool) -> str:
    """A path as Landlock meets it: magic links named for the calling process, then resolved.

    /proc/self, /proc/thread-self, /dev/fd and the standard streams name the process that resolves
    them, so they are rewritten for the calling thread first and never resolved in the analyser's
    own process; nothing under /proc is resolved further. Elsewhere symbolic links are resolved,
    the last component only when `follow` is set.
    """
    rewritten = _for_process(path, tid, tgid)
    normalised = os.path.normpath(rewritten)
    if normalised == "/proc" or normalised.startswith("/proc/"):
        return normalised
    if follow:
        return os.path.realpath(rewritten)
    parent, name = os.path.split(rewritten.rstrip("/") or "/")
    if not name or name in (".", ".."):
        return os.path.realpath(rewritten)
    return os.path.join(os.path.realpath(parent or "/"), name)


def _for_process(path: str, tid: int, tgid: int) -> str:
    """The path with the links that name the calling process written out for that process.

    Assumes an absolute path; a doubled or trailing slash is folded first, nothing else.
    """
    path = re.sub(r"/+", "/", path)
    if len(path) > 1:
        path = path.rstrip("/")
    if path in STANDARD_STREAMS:
        return f"/proc/{tgid}/fd/{STANDARD_STREAMS[path]}"
    for prefix, replacement in (("/dev/fd", f"/proc/{tgid}/fd"), ("/proc/thread-self", f"/proc/{tgid}/task/{tid}"),
                                ("/proc/self", f"/proc/{tgid}")):
        if path == prefix or path.startswith(prefix + "/"):
            return replacement + path[len(prefix):]
    return path


def _self_and_ancestors(path: str) -> list[str]:
    """The path and every directory above it, up to and including the root."""
    found = [path]
    while path not in ("/", ""):
        path = os.path.dirname(path)
        found.append(path)
    return found


def _call_text(call: Syscall) -> str:
    """The call as strace printed it, for evidence and for the list of unsupported calls."""
    result = "?" if call.result is None else str(call.result)
    return f"{call.pid} {call.name}({call.arguments}) = {result}{call.decoration}"
