"""Attributes each refused call of an observed run to the layer that refused it and to what it needs.

The mapping is the table of A.6.2 in the prune-on-the-layers plan: Landlock checks a read, a write, a
truncation or an execution on the object itself, and a creation, a removal or a rename on the parent
directory, so a refused call is turned into the paths and the configuration sections that would grant
it. Only calls made inside the command's Landlock domain count, and only EACCES, EPERM and EXDEV (plus
an exhausted resource on the calls that meet a limit) are refusals; everything else is an ordinary
error of the program. Whether a filesystem refusal was really Landlock's is decided afterwards, by the
control replay in control.py.
"""

from __future__ import annotations

import dataclasses
import os
import re
import struct

from shared.src.domain import strace_parse
from shared.src.domain.record import (
    LAYER_FILESYSTEM,
    LAYER_FIXED,
    LAYER_LIMIT,
    LAYER_NETWORK,
    LAYER_OTHER,
    Denial,
    Syscall,
)

# The configuration sections a denial can ask for, spelt as phobos-policysystem.sh reads them.
SECTION_READ = "read"
SECTION_EXECUTE = "execute"
SECTION_WRITE = "write"
SECTION_CREATE = "create"
SECTION_CREATE_IPC = "create-ipc"
SECTION_CREATE_SYMLINK = "create-symlink"
SECTION_DELETE = "delete"
SECTION_RESTRUCTURE = "restructure"
SECTION_CONNECT = "connect"
SECTION_BIND = "bind"

# The errors a layer answers a refusal with. Landlock refuses a path with EACCES, and a rename or link
# across directories without the refer right with EXDEV; the connect guard and Landlock's port rules
# refuse with EACCES; the timeout's group lock refuses setsid and setpgid.
REFUSAL_ERRNOS = frozenset({"EACCES", "EPERM", "EXDEV"})
# The calls on which an exhausted resource is a limit Phobos set (A.6.5), and on no other: a
# non-blocking read answers EAGAIN all the time and says nothing about a limit.
LIMIT_CALLS = {
    "EMFILE": frozenset({"open", "openat", "openat2", "creat", "socket", "socketpair", "pipe", "pipe2",
                         "dup", "dup2", "dup3", "accept", "accept4", "fcntl", "epoll_create",
                         "epoll_create1", "eventfd", "eventfd2", "inotify_init", "inotify_init1",
                         "memfd_create", "timerfd_create", "signalfd", "signalfd4"}),
    "EAGAIN": frozenset({"clone", "clone3", "fork", "vfork"}),
    "ENOMEM": frozenset({"mmap", "brk", "clone", "clone3", "fork", "vfork"}),
}
OPEN_CALLS = frozenset({"open", "openat", "openat2", "creat"})
GROUP_CALLS = frozenset({"setsid", "setpgid"})
RENAME_CALLS = frozenset({"rename", "renameat", "renameat2"})
LINK_CALLS = frozenset({"link", "linkat"})
# Where each path call keeps its directory descriptor and its path, as argument indexes; None for a
# call that takes no descriptor and resolves a relative path against the working directory.
PATH_ARGUMENTS = {
    "open": (None, 0),
    "creat": (None, 0),
    "openat": (0, 1),
    "openat2": (0, 1),
    "mkdir": (None, 0),
    "mkdirat": (0, 1),
    "mknod": (None, 0),
    "mknodat": (0, 1),
    "symlink": (None, 1),
    "symlinkat": (1, 2),
    "unlink": (None, 0),
    "rmdir": (None, 0),
    "unlinkat": (0, 1),
    "truncate": (None, 0),
    "execve": (None, 0),
    "execveat": (0, 1),
}
# Where a two-path call keeps its source and destination, as (descriptor, path) argument indexes.
TWO_PATH_ARGUMENTS = {
    "rename": ((None, 0), (None, 1)),
    "link": ((None, 0), (None, 1)),
    "renameat": ((0, 1), (2, 3)),
    "renameat2": ((0, 1), (2, 3)),
    "linkat": ((0, 1), (2, 3)),
}
DESCRIPTOR_CALLS = frozenset({"ftruncate", "getdents", "getdents64"})
SEND_CALLS = frozenset({"sendto", "sendmsg", "sendmmsg"})
# The socket families the connect guard carries and a [connect] or [bind] rule can name.
INET_FAMILIES = frozenset({"AF_INET", "AF_INET6"})
# The program header type of an ELF interpreter, and how far into a file the pruner reads to find it.
PT_INTERP = 3
ELF_READ_LIMIT = 65536
SHEBANG_READ_LIMIT = 256


class RunState:
    """What the walk over a trace knows besides the call at hand: working directories and sockets.

    Assumes the calls are fed in log order. A child inherits its parent's working directory and open
    sockets at the clone; threads of one thread group share their sockets.
    """

    def __init__(self, trace: strace_parse.Trace, working_directory: str) -> None:
        """Starts every process in `working_directory`, with no socket known."""
        self.trace = trace
        self.initial = working_directory
        self.directories: dict[int, str] = {}
        self.sockets: dict[tuple[int, str], tuple[str, str]] = {}

    def group(self, pid: int) -> int:
        """The thread-group id of a thread, which is what descriptors belong to."""
        return self.trace.thread_group.get(pid, pid)

    def directory(self, pid: int) -> str:
        """The working directory of a thread as far as the trace shows it."""
        return self.directories.get(pid, self.initial)

    def follow(self, call: Syscall) -> None:
        """Updates the state from one successful call: a clone, a chdir, an fchdir or a socket."""
        child = strace_parse.forked_child(call)
        if child is not None:
            self.directories[child] = self.directory(call.pid)
            for (owner, descriptor), kind in list(self.sockets.items()):
                if owner == self.group(call.pid):
                    self.sockets[(self.group(child), descriptor)] = kind
        elif call.name == "chdir":
            target = strace_parse.path_argument(call, 0)
            if target is not None:
                self.directories[call.pid] = os.path.join(self.directory(call.pid), target)
        elif call.name == "fchdir":
            target = strace_parse.descriptor_path(call, 0)
            if target is not None:
                self.directories[call.pid] = target
        elif call.name == "socket" and call.result is not None and call.result >= 0:
            arguments = strace_parse.split_arguments(call.arguments)
            if len(arguments) >= 2:
                self.sockets[(self.group(call.pid), str(call.result))] = (arguments[0], arguments[1])

    def transport(self, call: Syscall) -> str | None:
        """tcp or udp for the socket a call's first argument names, or None where it is unknown."""
        raw = strace_parse.argument(call, 0) or ""
        descriptor = raw.split("<", 1)[0]
        kind = self.sockets.get((self.group(call.pid), descriptor))
        if kind is None:
            return None
        if "SOCK_STREAM" in kind[1]:
            return "tcp"
        if "SOCK_DGRAM" in kind[1]:
            return "udp"
        return None

    def resolve(self, call: Syscall, descriptor_index: int | None, path_index: int) -> str | None:
        """The absolute path a call names, joined with its directory descriptor or working directory.

        None where the path is not a string, or where it is relative to a descriptor strace did not
        decorate, which leaves nothing to resolve it against.
        """
        path = strace_parse.path_argument(call, path_index)
        if path is None:
            return None
        if path.startswith("/"):
            return path
        if descriptor_index is None:
            return os.path.join(self.directory(call.pid), path)
        base = strace_parse.descriptor_path(call, descriptor_index)
        if base is not None:
            return os.path.join(base, path)
        if strace_parse.argument(call, descriptor_index) == "AT_FDCWD":
            return os.path.join(self.directory(call.pid), path)
        return None


def parent_of(path: str) -> str:
    """The directory Landlock checks a creation, a removal or a rename in: the path's parent."""
    return os.path.dirname(path.rstrip("/")) or "/"


def make_denial(call: Syscall, layer: str, objects: tuple[str, ...] = (), sections: frozenset[str] = frozenset(),
                address: str | None = None, port: int | None = None, transport: str | None = None) -> Denial:
    """A Denial of one call, with the call's own id, name and errno."""
    return Denial(pid=call.pid, layer=layer, operation=call.name, objects=objects, sections=sections,
                  address=address, port=port, transport=transport, errno=call.errno or "")


def filesystem(call: Syscall, objects: tuple[str, ...], *sections: str) -> Denial:
    """A filesystem Denial asking for `sections` on `objects`."""
    return make_denial(call, LAYER_FILESYSTEM, objects, frozenset(sections))


def open_flags(call: Syscall) -> str:
    """The flags text of an open call: O_WRONLY|O_CREAT|... (creat is spelt as what it means)."""
    if call.name == "creat":
        return "O_WRONLY|O_CREAT|O_TRUNC"
    if call.name == "open":
        return strace_parse.argument(call, 1) or ""
    raw = strace_parse.argument(call, 2) or ""
    if call.name == "openat2":
        match = re.search(r"flags=([A-Z0-9_|]+)", raw)
        return match.group(1) if match else ""
    return raw


def attribute_open(call: Syscall, path: str) -> Denial:
    """A refused open: read, write or both on the file, or a creation on its parent (A.6.2).

    An O_PATH open is not checked by Landlock, and for an unnamed O_TMPFILE file the table does
    not state which right Landlock checks, so both are reported as `other` and never granted.
    """
    flags = set(open_flags(call).split("|"))
    if "O_PATH" in flags or "O_TMPFILE" in flags:
        return make_denial(call, LAYER_OTHER, (path,))
    if "O_CREAT" in flags and not os.path.lexists(path):
        return filesystem(call, (parent_of(path),), SECTION_CREATE)
    sections = set()
    if "O_WRONLY" in flags:
        sections.add(SECTION_WRITE)
    elif "O_RDWR" in flags:
        sections.update({SECTION_READ, SECTION_WRITE})
    else:
        sections.add(SECTION_READ)
    if "O_TRUNC" in flags:
        sections.add(SECTION_WRITE)
    return filesystem(call, (path,), *sorted(sections))


def attribute_mknod(call: Syscall, path: str) -> Denial:
    """A refused mknod: a FIFO or socket asks for create-ipc, a device node is never granted."""
    mode = strace_parse.argument(call, 1 if call.name == "mknod" else 2) or ""
    if "S_IFCHR" in mode or "S_IFBLK" in mode:
        return make_denial(call, LAYER_FIXED, (path,))
    if "S_IFIFO" in mode or "S_IFSOCK" in mode:
        return filesystem(call, (parent_of(path),), SECTION_CREATE_IPC)
    return filesystem(call, (parent_of(path),), SECTION_CREATE)


def interpreter_of(path: str) -> str | None:
    """The interpreter the kernel opens to run a file: its `#!` program or its ELF PT_INTERP, or None.

    Read from the file outside the sandbox. None where the file cannot be read or names neither.
    """
    try:
        with open(path, "rb") as handle:
            head = handle.read(ELF_READ_LIMIT)
    except OSError:
        return None
    if head.startswith(b"#!"):
        line = head[2:SHEBANG_READ_LIMIT].split(b"\n", 1)[0].strip()
        words = line.split()
        return os.fsdecode(words[0]) if words else None
    if head.startswith(b"\x7fELF"):
        return elf_interpreter(head)
    return None


def elf_interpreter(head: bytes) -> str | None:
    """The PT_INTERP path of an ELF image whose first bytes are `head`, or None where it has none."""
    try:
        return elf_interpreter_unchecked(head)
    except (struct.error, IndexError):
        return None


def elf_interpreter_unchecked(head: bytes) -> str | None:
    """elf_interpreter without the guard: raises struct.error or IndexError where `head` is cut short."""
    wide = head[4] == 2
    order = "<" if head[5] == 1 else ">"
    if wide:
        table, entry_size, count = struct.unpack_from(order + "Q14xHH", head, 32)
    else:
        table, entry_size, count = struct.unpack_from(order + "I10xHH", head, 28)
    for number in range(count):
        start = table + number * entry_size
        if start + entry_size > len(head):
            return None
        if struct.unpack_from(order + "I", head, start)[0] != PT_INTERP:
            continue
        if wide:
            offset, size = struct.unpack_from(order + "Q16xQ", head, start + 8)
        else:
            offset, size = struct.unpack_from(order + "I8xI", head, start + 4)
        name = head[offset:offset + size].split(b"\x00", 1)[0]
        return os.fsdecode(name) if name else None
    return None


def attribute_execve(call: Syscall, path: str) -> Denial:
    """A refused execve: execute and read on the binary, and on the interpreter it names (A.6.2)."""
    objects = [path]
    interpreter = interpreter_of(path)
    if interpreter is not None and interpreter.startswith("/") and interpreter != path:
        objects.append(interpreter)
    return filesystem(call, tuple(objects), SECTION_EXECUTE, SECTION_READ)


def attribute_path_call(call: Syscall, path: str) -> Denial | None:
    """A refused call on one path, by the table of A.6.2."""
    if call.name in OPEN_CALLS:
        return attribute_open(call, path)
    if call.name in ("mkdir", "mkdirat"):
        return filesystem(call, (parent_of(path),), SECTION_CREATE)
    if call.name in ("mknod", "mknodat"):
        return attribute_mknod(call, path)
    if call.name in ("symlink", "symlinkat"):
        return filesystem(call, (parent_of(path),), SECTION_CREATE_SYMLINK)
    if call.name in ("unlink", "unlinkat", "rmdir"):
        return filesystem(call, (parent_of(path),), SECTION_DELETE)
    if call.name == "truncate":
        return filesystem(call, (path,), SECTION_WRITE)
    if call.name in ("execve", "execveat"):
        return attribute_execve(call, path)
    return None


def attribute_two_paths(call: Syscall, state: RunState) -> Denial | None:
    """A refused rename or link: restructure on both parents for EXDEV, else make and remove."""
    (source_descriptor, source_index), (target_descriptor, target_index) = TWO_PATH_ARGUMENTS[call.name]
    source = state.resolve(call, source_descriptor, source_index)
    target = state.resolve(call, target_descriptor, target_index)
    if source is None or target is None:
        return make_denial(call, LAYER_OTHER)
    parents = tuple(dict.fromkeys((parent_of(source), parent_of(target))))
    if call.errno == "EXDEV":
        return filesystem(call, parents, SECTION_RESTRUCTURE)
    if call.name in LINK_CALLS:
        return filesystem(call, (parent_of(target),), SECTION_CREATE)
    return filesystem(call, parents, SECTION_CREATE, SECTION_DELETE)


def parse_address(text: str) -> tuple[str | None, str | None, int | None]:
    """The family, address and port of a socket address strace printed, each None where absent."""
    family = re.search(r"sa_family=(AF_[A-Z0-9_]+)", text)
    port = re.search(r"sin6?_port=htons\((\d+)\)", text)
    address = re.search(r'inet_addr\("([^"]*)"\)', text) or re.search(r'inet_pton\(AF_INET6, "([^"]*)"', text)
    return (family.group(1) if family else None,
            address.group(1) if address else None,
            int(port.group(1)) if port else None)


def unix_path(text: str) -> str | None:
    """The filesystem path an AF_UNIX address names, or None for an abstract or unnamed socket."""
    match = re.search(r'sun_path="((?:[^"\\]|\\.)*)"', text)
    if match is None:
        return None
    return strace_parse.unescape(match.group(1))


def destination_text(call: Syscall) -> str:
    """The socket address text a connect, sendto, sendmsg or sendmmsg sends to, or empty."""
    if call.name == "connect":
        return strace_parse.argument(call, 1) or ""
    if call.name == "sendto":
        return strace_parse.argument(call, 4) or ""
    match = re.search(r"msg_name=(\{[^}]*\})", call.arguments)
    return match.group(1) if match else ""


def attribute_send(call: Syscall, state: RunState) -> Denial:
    """A refused connect or datagram: the guard or Landlock's port rule for an IPv4 or IPv6 destination.

    The guard refuses every other family (AF_UNIX, and AF_UNSPEC, which disconnects a datagram
    socket), so that is a fixed rule. A call without a destination the trace names, such as a send
    on a connected socket, is reported as `other`: a [connect] rule needs an address and a port.
    """
    family, address, port = parse_address(destination_text(call))
    if family is not None and family not in INET_FAMILIES:
        return make_denial(call, LAYER_FIXED)
    if family is None or address is None or port is None:
        return make_denial(call, LAYER_OTHER)
    transport = state.transport(call)
    if call.name in SEND_CALLS and transport is None:
        transport = "udp"
    return make_denial(call, LAYER_NETWORK, (), frozenset({SECTION_CONNECT}), address, port, transport)


def attribute_bind(call: Syscall, state: RunState) -> Denial:
    """A refused bind: a pathname socket asks for create-ipc on its parent, an IPv4 or IPv6 port for [bind].

    An abstract socket, another family or an address without a port is reported as `other`.
    """
    text = strace_parse.argument(call, 1) or ""
    family, address, port = parse_address(text)
    if family == "AF_UNIX":
        path = unix_path(text)
        if path is None:
            return make_denial(call, LAYER_OTHER)
        if not path.startswith("/"):
            path = os.path.join(state.directory(call.pid), path)
        return filesystem(call, (parent_of(path),), SECTION_CREATE_IPC)
    if family not in INET_FAMILIES or port is None:
        return make_denial(call, LAYER_OTHER)
    return make_denial(call, LAYER_NETWORK, (), frozenset({SECTION_BIND}), address, port, state.transport(call))


def attribute_network(call: Syscall, state: RunState) -> Denial | None:
    """A refused socket call, by the network rows of A.6.2; None for a call that is not one."""
    if call.name == "connect" or call.name in SEND_CALLS:
        return attribute_send(call, state)
    if call.name == "bind":
        return attribute_bind(call, state)
    if call.name == "listen":
        return make_denial(call, LAYER_NETWORK, (), frozenset({SECTION_BIND}), None, 0, state.transport(call) or "tcp")
    if call.name in ("socket", "socketpair"):
        return make_denial(call, LAYER_FIXED)
    return None


def attribute_eacces(call: Syscall, state: RunState) -> Denial:
    """A call refused with EACCES or EXDEV, by the table of A.6.2; `other` for a call it does not name."""
    if call.name in TWO_PATH_ARGUMENTS:
        return attribute_two_paths(call, state)
    if call.errno == "EXDEV":
        return make_denial(call, LAYER_OTHER)
    network = attribute_network(call, state)
    if network is not None:
        return network
    if call.name == "ioctl":
        return make_denial(call, LAYER_FIXED, tuple(filter(None, [strace_parse.descriptor_path(call, 0)])))
    if call.name in DESCRIPTOR_CALLS:
        path = strace_parse.descriptor_path(call, 0)
        if path is None:
            return make_denial(call, LAYER_OTHER)
        section = SECTION_WRITE if call.name == "ftruncate" else SECTION_READ
        return filesystem(call, (path,), section)
    if call.name in PATH_ARGUMENTS:
        descriptor_index, path_index = PATH_ARGUMENTS[call.name]
        path = state.resolve(call, descriptor_index, path_index)
        if path is None:
            return make_denial(call, LAYER_OTHER)
        denial = attribute_path_call(call, path)
        if denial is not None:
            return denial
    return make_denial(call, LAYER_OTHER)


def attribute_call(call: Syscall, state: RunState) -> Denial | None:
    """The Denial a failed call inside the domain amounts to, or None for an ordinary error."""
    errno = call.errno or ""
    if call.name in LIMIT_CALLS.get(errno, frozenset()):
        return make_denial(call, LAYER_LIMIT)
    if errno not in REFUSAL_ERRNOS:
        return None
    if call.name in GROUP_CALLS:
        return make_denial(call, LAYER_FIXED)
    if errno == "EPERM":
        return make_denial(call, LAYER_OTHER)
    return attribute_eacces(call, state)


def denials(trace: strace_parse.Trace, working_directory: str) -> list[Denial]:
    """Every refusal inside the command's domain, attributed, in log order.

    Each denial carries the refusing thread as `tid` and its thread group, the process, as `pid`.

    `working_directory` is where the command started, which a relative path is resolved against
    when strace did not decorate AT_FDCWD; every clone inherits it and every chdir moves it.
    """
    return [denial for _, denial, _ in refusals(trace, working_directory)]


def refusals(trace: strace_parse.Trace, working_directory: str) -> list[tuple[Syscall, Denial, str]]:
    """What denials answers, each Denial with the refused call and its thread's working directory.

    The recording pruner's replay check reads the refused call itself and not only its Denial, so
    that it can compare exactly the accesses of that call with the ones a recorded session needed.
    Assumes the same as denials.
    """
    state = RunState(trace, working_directory)
    found: list[tuple[Syscall, Denial, str]] = []
    for index, call in enumerate(trace.syscalls):
        if call.errno is None:
            state.follow(call)
            continue
        if not trace.in_domain(index):
            continue
        denial = attribute_call(call, state)
        if denial is not None:
            attributed = dataclasses.replace(denial, pid=state.group(call.pid), tid=call.pid)
            found.append((call, attributed, state.directory(call.pid)))
    return found
