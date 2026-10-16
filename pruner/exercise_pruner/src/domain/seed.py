"""The per-language seed of a prune: rows a language's build is known to need that no refusal can show (decision 7).

The pruner derives every grant from a refusal, and never generalises a write-class right on a name that
differs in every run. A build that writes scratch files with random names in a shared directory cannot be
granted by refusals alone. Markus decided that such rows come from a seed: a configuration file named by
the exercise's prune.json, `"seed": "<language>.cfg"`, that lives in pruner/config/seeds/ and is
copied into the prune image. Language-specific content, and the reason
for it, is only ever in that file, never in the pruner's code or in core.

The seed is a starting point, not a grant: its rows go into the first policy, so the minimisation drops
every row the build does not need, and each row that stays carries a comment saying it comes from the seed.
A seed names only filesystem rows with the sections below, on existing real directories, never `/` and
never a directory the pruner owns (the specification, working, candidate, log and Phobos directories) or an
ancestor of one, and never a write-class section on or beneath /proc, /sys or /dev, whose entries are the
kernel's and its devices', not a build's scratch files.

A kept seed, named by `"kept_seed": "<name>.cfg"` in prune.json and kept beside the seeds, holds rows a build
needs on some machines although the prune machine does not show it, such as a device a runtime reads only when
it has few CPUs. No minimisation removes them, so they err wider by design: a kept row is granted whether or
not a run here needs it, and the file says why each row is there. Its rows take the sections a seed takes, on
an existing real directory, regular file or character device; a file or device takes only `read` and `write`,
since `create` and `delete` act on a directory's entries. No write-class section may sit on or beneath /proc
or /sys, and beneath /dev only a character device may be written.
"""

from __future__ import annotations

import os
import pathlib
import re
import stat
from collections.abc import Iterable

from shared.src.domain import cfgfile

# Where the prune image keeps the seeds, and what a seed file is called: a plain name ending in .cfg.
SEED_DIRECTORY = "/usr/local/share/phobos-prune/seeds"
SEED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.cfg")
# The sections a seed may name: reading what a build wrote, and creating, writing and deleting its own files.
SEED_SECTIONS = frozenset({"read", "write", "create", "delete"})
# The comment above a seed row that survived the minimisation.
SEED_COMMENT = "seed: {sections} on {path} come from the {name} seed of the prune image, not from a refusal"
# The sections a kept row may carry on a regular file or a character device.
KEPT_FILE_SECTIONS = frozenset({"read", "write"})
# The pseudo file systems no seed row or kept row may carry a write-class section on or beneath.
UNWRITABLE_ROOTS = ("/proc", "/sys")
# The device directory: a seed row may not write on or beneath it, and a kept row may write only a character device.
DEVICE_ROOT = "/dev"
# The comment above a kept row, and above a path that holds a kept directory's rights through the hierarchy rule.
KEPT_COMMENT = ("kept: {sections} on {path} come from the {name} kept seed of the prune image, which no "
                "minimisation removes; that file says why")
KEPT_INHERITED_COMMENT = ("kept: {sections} on {path} are the {name} kept seed's rights on {ancestor}, copied down "
                          "by the hierarchy rule")


def parse_name(value: object, source: str) -> str:
    """The seed name a prune.json holds; ValueError, naming `source`, unless it is a plain *.cfg file name."""
    if not isinstance(value, str) or SEED_NAME.fullmatch(value) is None:
        raise ValueError(f"{source}: seed is a plain file name ending in .cfg, not {value!r}")
    return value


def overlaps(entry: str, protected: Iterable[str]) -> bool:
    """Whether an entry is, lies beneath, or is an ancestor of one of the protected directories."""
    return any(entry == other or cfgfile.is_beneath(entry, other) or cfgfile.is_beneath(other, entry)
               for other in protected)


def read_rows(kind: str, name: str, directory: str, protected: Iterable[str]) -> cfgfile.Policy:
    """The rows of a seed file of `kind` ("seed" or "kept seed"), checked as every seed file is; ValueError if not.

    The file is a plain *.cfg name, a real file in `directory`, readable, and names filesystem rows and nothing else,
    each with sections a seed may name, never on `/` and never on, beneath or above a directory in `protected`.
    """
    parse_name(name, kind)
    path = pathlib.Path(directory) / name
    if os.path.realpath(path) != str(path) or not path.is_file():
        raise ValueError(f"the {kind} {name} is not a real file in {directory}")
    try:
        policy = cfgfile.read_policy(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError) as failure:
        raise ValueError(f"the {kind} {name} cannot be read: {failure}") from failure
    if policy.connect or policy.bind or policy.limits:
        raise ValueError(f"the {kind} {name} names more than filesystem rows")
    if not policy.fs:
        raise ValueError(f"the {kind} {name} names no row")
    for entry, sections in policy.fs.items():
        if not sections <= SEED_SECTIONS:
            raise ValueError(f"the {kind} {name} names {sorted(sections - SEED_SECTIONS)} on {entry}, "
                             "which a seed may not")
        if entry == "/" or overlaps(entry, protected):
            raise ValueError(f"the {kind} {name} names {entry}, which is the root or a directory the pruner owns, "
                             "or lies beneath or above one")
    return policy


def load(name: str, directory: str, protected: Iterable[str]) -> cfgfile.Policy:
    """The seed's rows as a policy; ValueError naming what is wrong with the seed or its absence.

    `protected` are the directories the pruner owns, which no row may be, lie beneath or sit above.
    """
    policy = read_rows("seed", name, directory, protected)
    for entry, sections in policy.fs.items():
        if os.path.realpath(entry) != entry or not pathlib.Path(entry).is_dir():
            raise ValueError(f"the seed {name} names {entry}, which is not an existing real directory")
        writes = sections & set(cfgfile.WRITE_SECTIONS)
        if writes and at_or_beneath(entry, (*UNWRITABLE_ROOTS, DEVICE_ROOT)):
            raise ValueError(f"the seed {name} names {sorted(writes)} on {entry}, on or beneath "
                             f"{', '.join((*UNWRITABLE_ROOTS, DEVICE_ROOT))}, which a seed may not write")
    return policy


def at_or_beneath(path: str, roots: Iterable[str]) -> bool:
    """Whether `path` is one of `roots` or lies beneath one, by path components."""
    return any(path == root or cfgfile.is_beneath(path, root) for root in roots)


def kept_entry_problem(entry: str, sections: frozenset[str]) -> str | None:
    """Why a kept row may not grant `sections` on `entry`, or None: the kinds of path and the pseudo file systems."""
    try:
        mode = os.lstat(entry).st_mode
    except OSError:
        return "which does not exist"
    if os.path.realpath(entry) != entry:
        return "which is not a real path"
    if stat.S_ISDIR(mode):
        kind = "directory"
    elif stat.S_ISREG(mode) or stat.S_ISCHR(mode):
        kind = "file"
    else:
        return "which is no directory, regular file or character device"
    if kind == "file" and not sections <= KEPT_FILE_SECTIONS:
        return (f"a file or device, which takes {sorted(KEPT_FILE_SECTIONS)} and not "
                f"{sorted(sections - KEPT_FILE_SECTIONS)}")
    writes = sections & set(cfgfile.WRITE_SECTIONS)
    if writes and at_or_beneath(entry, UNWRITABLE_ROOTS):
        return f"on or beneath {' or '.join(UNWRITABLE_ROOTS)}, which takes no {sorted(writes)}"
    if writes and at_or_beneath(entry, (DEVICE_ROOT,)) and not stat.S_ISCHR(mode):
        return f"on or beneath {DEVICE_ROOT} but no character device, which takes no {sorted(writes)}"
    return None


def load_kept(name: str, directory: str, protected: Iterable[str]) -> cfgfile.Policy:
    """The kept seed's rows as a policy; ValueError naming what is wrong with the file or one of its rows.

    `protected` are the directories the pruner owns, as for load. Each row is checked by kept_entry_problem.
    """
    policy = read_rows("kept seed", name, directory, protected)
    for entry, sections in policy.fs.items():
        problem = kept_entry_problem(entry, sections)
        if problem is not None:
            raise ValueError(f"the kept seed {name} names {sorted(sections)} on {entry}, {problem}")
    return policy


# The comment above a path that holds rights of a seeded ancestor only because the hierarchy rule copies them down.
INHERITED_COMMENT = "seed: {sections} on {path} are the {name} seed's rights on {ancestor}, copied down by the hierarchy rule"


def comment_inherited(name: str, ancestor: str, path: str, sections: Iterable[str]) -> str:
    """The comment above a path beneath a seeded one: which seeded rights it holds, and that they are copied down."""
    return INHERITED_COMMENT.format(sections=", ".join(f"[{section}]" for section in sorted(sections)), path=path,
                                    name=name, ancestor=ancestor)


def comment_for(name: str, path: str, sections: Iterable[str]) -> str:
    """The comment above a seed path: the sections of the seed that survived, and that they came from it."""
    return SEED_COMMENT.format(sections=", ".join(f"[{section}]" for section in sorted(sections)), path=path, name=name)


def comment_kept(name: str, path: str, sections: Iterable[str]) -> str:
    """The comment above a kept row: its sections, and that it comes from the kept seed, which nothing minimises."""
    return KEPT_COMMENT.format(sections=", ".join(f"[{section}]" for section in sorted(sections)), path=path, name=name)


def comment_kept_inherited(name: str, ancestor: str, path: str, sections: Iterable[str]) -> str:
    """The comment above a path beneath a kept directory: which of its rights it holds, copied down to it."""
    return KEPT_INHERITED_COMMENT.format(sections=", ".join(f"[{section}]" for section in sorted(sections)), path=path,
                                         name=name, ancestor=ancestor)
