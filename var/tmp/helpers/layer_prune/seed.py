"""The per-language seed of a prune: rows a language's build is known to need that no refusal can show (decision 7).

The pruner derives every grant from a refusal, and never generalises a write-class right on a name that
differs in every run. A build that writes scratch files with random names in a shared directory cannot be
granted by refusals alone. Markus decided that such rows come from a seed: a configuration file named by
the exercise's prune.json, `"seed": "<language>.cfg"`, that lives beside the prune image's Dockerfile
(docker/prune_phase/layers/seeds/) and is copied into the image. Language-specific content, and the reason
for it, is only ever in that file, never in the pruner's code or in core.

The seed is a starting point, not a grant: its rows go into the first policy, so the minimisation drops
every row the build does not need, and each row that stays carries a comment saying it comes from the seed.
A seed names only filesystem rows with the sections below, on existing real directories, never `/` and
never a directory the pruner owns (the specification, working, candidate, log and Phobos directories) or an
ancestor of one.
"""

from __future__ import annotations

import os
import pathlib
import re
from collections.abc import Iterable

from layer_prune import cfgfile

# Where the prune image keeps the seeds, and what a seed file is called: a plain name ending in .cfg.
SEED_DIRECTORY = "/usr/local/share/phobos-prune/seeds"
SEED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.cfg")
# The sections a seed may name: reading what a build wrote, and creating, writing and deleting its own files.
SEED_SECTIONS = frozenset({"read", "write", "create", "delete"})
# The comment above a seed row that survived the minimisation.
SEED_COMMENT = "seed: {sections} on {path} come from the {name} seed of the prune image, not from a refusal"


def parse_name(value: object, source: str) -> str:
    """The seed name a prune.json holds; ValueError, naming `source`, unless it is a plain *.cfg file name."""
    if not isinstance(value, str) or SEED_NAME.fullmatch(value) is None:
        raise ValueError(f"{source}: seed is a plain file name ending in .cfg, not {value!r}")
    return value


def overlaps(entry: str, protected: Iterable[str]) -> bool:
    """Whether an entry is, lies beneath, or is an ancestor of one of the protected directories."""
    return any(entry == other or cfgfile.is_beneath(entry, other) or cfgfile.is_beneath(other, entry)
               for other in protected)


def load(name: str, directory: str, protected: Iterable[str]) -> cfgfile.Policy:
    """The seed's rows as a policy; ValueError naming what is wrong with the seed or its absence.

    `protected` are the directories the pruner owns, which no row may be, lie beneath or sit above.
    """
    parse_name(name, "seed")
    path = pathlib.Path(directory) / name
    if os.path.realpath(path) != str(path) or not path.is_file():
        raise ValueError(f"the seed {name} is not a real file in {directory}")
    try:
        policy = cfgfile.read_policy(path.read_text())
    except (OSError, UnicodeDecodeError, ValueError) as failure:
        raise ValueError(f"the seed {name} cannot be read: {failure}") from failure
    if policy.connect or policy.bind or policy.limits:
        raise ValueError(f"the seed {name} names more than filesystem rows")
    if not policy.fs:
        raise ValueError(f"the seed {name} names no row")
    for entry, sections in policy.fs.items():
        if not sections <= SEED_SECTIONS:
            raise ValueError(f"the seed {name} names {sorted(sections - SEED_SECTIONS)} on {entry}, which a seed may not")
        if entry == "/" or overlaps(entry, protected):
            raise ValueError(f"the seed {name} names {entry}, which is the root or a directory the pruner owns, "
                             "or lies beneath or above one")
        if os.path.realpath(entry) != entry or not pathlib.Path(entry).is_dir():
            raise ValueError(f"the seed {name} names {entry}, which is not an existing real directory")
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
