"""The control replay: whether a refused access also fails outside every Landlock domain.

The command runs as the same uid as the pruner and under the same AppArmor profile, so a refusal
Landlock did not cause (a mode, an owner, a mount, a privileged port) also happens to the pruner
itself. Each candidate denial is therefore replayed here, outside the sandbox (A.6.3). A replay that
fails means granting would not help, and the denial must never become a grant.

A replay changes nothing it leaves behind: a read or write opens without truncating and closes again,
a device node, FIFO or socket is never opened (its permission is asked with access(2) instead, so no
driver sees an open), a creation makes one temporary file and removes it again, and a bind takes a
loopback port and closes it. Only a pruner killed between creating and removing that temporary file
leaves it behind. Nothing follows a symbolic link: a link is resolved to its target first, which is
what Landlock checks, and the target is then opened with O_NOFOLLOW.
"""

from __future__ import annotations

import errno
import os
import socket
import stat
import tempfile

from layer_prune.attribute import (
    SECTION_BIND,
    SECTION_CREATE,
    SECTION_EXECUTE,
    SECTION_READ,
    SECTION_RESTRUCTURE,
    SECTION_WRITE,
)
from layer_prune.record import LAYER_FILESYSTEM, LAYER_NETWORK, Denial

# The flags every replayed open carries: never block on a FIFO, never follow a final symbolic link,
# never leak the descriptor.
REPLAY_OPEN_FLAGS = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


def is_special(mode: int) -> bool:
    """Whether a file mode is a device node, a FIFO or a socket, which a replay never opens."""
    return stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def opens(path: str, flags: int) -> bool:
    """Whether `path` opens with `flags` plus REPLAY_OPEN_FLAGS; the descriptor is closed at once."""
    try:
        descriptor = os.open(path, flags | REPLAY_OPEN_FLAGS)
    except OSError:
        return False
    os.close(descriptor)
    return True


def status_of(path: str) -> tuple[str, os.stat_result] | None:
    """The resolved target of a path and its status, or None where nothing exists there now."""
    target = os.path.realpath(path)
    try:
        return target, os.stat(target)
    except OSError:
        return None


def replay_read(path: str) -> bool:
    """Whether the pruner can read the object: open a file or a directory, ask for anything else."""
    found = status_of(path)
    if found is None:
        return False
    target, status = found
    if is_special(status.st_mode):
        return os.access(target, os.R_OK)
    if stat.S_ISDIR(status.st_mode):
        return opens(target, os.O_RDONLY | os.O_DIRECTORY)
    return opens(target, os.O_RDONLY)


def replay_write(path: str) -> bool:
    """Whether the pruner can write the object: open a regular file without truncating it, ask otherwise."""
    found = status_of(path)
    if found is None:
        return False
    target, status = found
    if not stat.S_ISREG(status.st_mode):
        return os.access(target, os.W_OK)
    return opens(target, os.O_WRONLY)


def replay_execute(path: str) -> bool:
    """Whether the pruner may execute the object: a regular file with an execute bit it may use."""
    found = status_of(path)
    if found is None:
        return False
    target, status = found
    return stat.S_ISREG(status.st_mode) and bool(status.st_mode & 0o111) and os.access(target, os.X_OK)


def nearest_existing_directory(path: str) -> str | None:
    """The path itself or its nearest ancestor that is a directory now, resolved; None if there is none.

    A directory the run created and removed again, or that a fresh copy of the exercise no longer
    holds, is replayed in the ancestor it was created in, whose permissions it would have inherited
    the right to be created under.
    """
    candidate = path
    while not os.path.isdir(candidate):
        parent = os.path.dirname(candidate)
        if parent == candidate:
            return None
        candidate = parent
    return os.path.realpath(candidate)


def replay_create(path: str) -> bool:
    """Whether the pruner can create a file in the directory: make a temporary file, remove it at once."""
    directory = nearest_existing_directory(path)
    if directory is None:
        return False
    try:
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=".phobos-prune-control.")
    except OSError:
        return False
    try:
        os.close(descriptor)
    finally:
        os.unlink(name)
    return True


def replay_bind(denial: Denial) -> bool:
    """Whether the pruner can bind the refused port itself, on loopback of the address's family.

    Only a refusal with EACCES counts against the grant: a port below the kernel's unprivileged
    start, for a uid without the capability to bind it, is refused there too, and a [bind] rule could
    not help. A port already in use answers EADDRINUSE, which says nothing about permission. Port 0
    (an ephemeral port, or a listen on an unbound socket) is never privileged.
    """
    if not denial.port:
        return True
    family = socket.AF_INET6 if denial.address and ":" in denial.address else socket.AF_INET
    kind = socket.SOCK_DGRAM if denial.transport == "udp" else socket.SOCK_STREAM
    loopback = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    try:
        with socket.socket(family, kind) as probe:
            probe.bind((loopback, denial.port))
    except OSError as refusal:
        return refusal.errno != errno.EACCES
    return True


def replay_directory_change(path: str) -> bool:
    """Whether the pruner may change entries of the directory: write and search permission on it."""
    directory = nearest_existing_directory(path)
    return directory is not None and os.access(directory, os.W_OK | os.X_OK)


def same_filesystem(paths: tuple[str, ...]) -> bool:
    """Whether every path's nearest existing directory lies on one filesystem, so EXDEV was Landlock's."""
    devices = set()
    for path in paths:
        directory = nearest_existing_directory(path)
        if directory is None:
            return False
        devices.add(os.stat(directory).st_dev)
    return len(devices) == 1


def replay(path: str, section: str) -> bool:
    """Whether one section's access to one object succeeds outside the sandbox."""
    if section == SECTION_READ:
        return replay_read(path)
    if section == SECTION_WRITE:
        return replay_write(path)
    if section == SECTION_EXECUTE:
        return replay_execute(path)
    if section == SECTION_CREATE:
        return replay_create(path)
    return replay_directory_change(path)


def landlock_caused(denial: Denial) -> bool:
    """Whether granting the denial could help, because the access it was refused succeeds unsandboxed.

    A refused connect or datagram needs no replay: in the prune container only the connect guard and
    Landlock's port rules answer EACCES there. A refused bind is replayed, because the kernel also
    refuses a privileged port with EACCES. A fixed rule, a limit or another mechanism's refusal is
    never one a grant could undo. A rename or link refused with EXDEV is Landlock's only when both
    parents share a filesystem; otherwise it is the filesystem's own answer.
    """
    if denial.layer == LAYER_NETWORK:
        return SECTION_BIND not in denial.sections or replay_bind(denial)
    if denial.layer != LAYER_FILESYSTEM or not denial.objects:
        return False
    if denial.errno == "EXDEV" and SECTION_RESTRUCTURE in denial.sections and not same_filesystem(denial.objects):
        return False
    return all(replay(path, section) for path in denial.objects for section in sorted(denial.sections))
