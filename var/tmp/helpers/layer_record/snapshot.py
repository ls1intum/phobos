"""The listing of every path that existed in a container before its first recorded session.

Each line is `<fingerprint>\\t<path>`. The fingerprint is `f <mode> <size> <mtime_ns>` for a
regular file, `l <target>` for a symbolic link, `d <mode>` for a directory and `o <mode>` for
anything else, so the listing answers both questions asked of it later: whether a path existed
before the sessions (only then may it become a [read] or [execute] row), and whether a replay
container starts in the state the recording did. A directory's modification time is left out on
purpose, because copying the exercise in changes it. A change that keeps a file's size and
modification time is not seen; the listing guards against leftovers, not against an adversary.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import stat

# Never walked: the kernel trees generate their entries per process, and the recordings
# directory is where the recorder itself writes while it records.
DEFAULT_SKIP = ("/proc", "/sys", "/var/tmp/recordings")

# Docker writes these into every container itself, so two fresh containers from one image differ
# in them; the starting-state comparison leaves them out, the listing keeps them. Measured over
# 24 516 paths of the recording image: nothing else differed between fresh containers started
# with and without a terminal. /.dockerenv is created anew, with a new time, in every container,
# and /dev/console exists only in one started with -t.
DOCKER_MANAGED = ("/etc/hostname", "/etc/hosts", "/etc/resolv.conf", "/.dockerenv", "/dev/console")

# Names whose value changes with every run whatever the image: a pseudo-terminal's number.
PER_RUN_NAME = re.compile(r"^/dev/pts/[0-9]+$")

# How a path or link target is written so that no name can end its line or split its fields.
ESCAPES = {"\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r"}
UNESCAPES = {"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}


def take(path: pathlib.Path, root: pathlib.Path = pathlib.Path("/"),
         skip: tuple[str, ...] = DEFAULT_SKIP) -> int:
    """Writes the listing of root to path and a copy of root's /etc/hosts beside it.

    Assumes skip names absolute paths as seen from root and that path lies under one of them or
    outside root, so the listing does not list itself. The copy gets the suffix `.hosts` and is
    written only when root has an /etc/hosts. Answers the number of paths written.
    """
    listing = _walk(root, skip)
    with open(path, "w", encoding="utf-8", errors="surrogateescape", newline="") as handle:
        handle.writelines(f"{_escape(listing[name])}\t{_escape(name)}\n" for name in sorted(listing))
    hosts = root / "etc" / "hosts"
    if hosts.is_file():
        shutil.copyfile(hosts, path.with_suffix(".hosts"))
    return len(listing)


def fingerprint(root: pathlib.Path = pathlib.Path("/")) -> dict[str, str]:
    """The listing take would write for root, held in memory and without DOCKER_MANAGED.

    Assumes the same skip list as take's default, so that two fresh containers from one image,
    with the exercise copied in the same way, give equal fingerprints.
    """
    listing = _walk(root, DEFAULT_SKIP)
    for name in DOCKER_MANAGED:
        listing.pop(name, None)
    return listing


def read_listing(path: pathlib.Path) -> dict[str, str]:
    """Reads a listing written by take back into a mapping of path to fingerprint.

    Assumes the file was written by take; a line without a tab is not one and is skipped.
    """
    listing = {}
    with open(path, encoding="utf-8", errors="surrogateescape", newline="") as handle:
        for line in handle.read().split("\n"):
            value, separator, name = line.partition("\t")
            if separator:
                listing[_unescape(name)] = _unescape(value)
    return listing


def _walk(root: pathlib.Path, skip: tuple[str, ...]) -> dict[str, str]:
    """Every path under root, written as absolute from root, mapped to its fingerprint.

    Assumes nothing is followed through a symbolic link, and that a path which vanishes or
    cannot be read while the walk runs is simply not listed.
    """
    base = os.fspath(root)
    listing = {}
    top = _entry(base, "/")
    if top is not None:
        listing["/"] = top
    for directory, subdirectories, files in os.walk(base, followlinks=False):
        relative = _absolute(base, directory)
        subdirectories[:] = [name for name in subdirectories if not _skipped(_join(relative, name), skip)]
        for name in subdirectories + files:
            shown = _join(relative, name)
            if _skipped(shown, skip) or PER_RUN_NAME.match(shown):
                continue
            value = _entry(os.path.join(directory, name), shown)
            if value is not None:
                listing[shown] = value
    return listing


def _entry(real: str, shown: str) -> str | None:
    """The fingerprint of one path, or None when it vanished or cannot be read.

    Assumes real is the path on this system and shown its name in the listing; only real is
    looked at.
    """
    try:
        status = os.lstat(real)
        if stat.S_ISLNK(status.st_mode):
            return f"l {os.readlink(real)}"
    except OSError:
        return None
    mode = format(stat.S_IMODE(status.st_mode), "04o")
    if stat.S_ISREG(status.st_mode):
        return f"f {mode} {status.st_size} {status.st_mtime_ns}"
    if stat.S_ISDIR(status.st_mode):
        return f"d {mode}"
    return f"o {mode}"


def _absolute(base: str, directory: str) -> str:
    """The directory as an absolute path seen from base; assumes directory lies under base."""
    relative = os.path.relpath(directory, base)
    return "/" if relative == "." else "/" + relative


def _join(directory: str, name: str) -> str:
    """The absolute name of an entry of directory; assumes directory is absolute."""
    return directory.rstrip("/") + "/" + name


def _skipped(name: str, skip: tuple[str, ...]) -> bool:
    """Whether name is one of the skipped paths or lies beneath one; assumes both absolute."""
    return any(name == root or name.startswith(root.rstrip("/") + "/") for root in skip)


def _escape(text: str) -> str:
    """Text with a backslash, tab, newline and carriage return written as escapes; nothing else."""
    return "".join(ESCAPES.get(character, character) for character in text)


def _unescape(text: str) -> str:
    """The inverse of _escape; assumes text came from it, and keeps an unknown escape as it is."""
    result = []
    index = 0
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if character == "\\" and following in UNESCAPES:
            result.append(UNESCAPES[following])
            index += 2
        else:
            result.append(character)
            index += 1
    return "".join(result)
