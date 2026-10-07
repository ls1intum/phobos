"""The per-language seed of a prune: rows a language's build is known to need that no refusal can show (decision 7).

The pruner derives every grant from a refusal, and never generalises a write-class right on a name that
differs in every run. A build that writes scratch files with random names in /tmp (Ares writes
/tmp/EssentialPackages_<random>.yaml, Surefire /tmp/surefire-root/...) therefore cannot be granted by
refusals alone, and the shipped Java base grants /tmp anyway. Markus decided that such rows come from a
seed: a configuration file named by the exercise's prune.json, `"seed": "java.cfg"`, that lives beside
the prune image's Dockerfile and is copied into the image. Language-specific content is only ever in
that file, never in the pruner's code or in core.

The seed is a starting point, not a grant: its rows go into the first policy, so the minimisation drops
every row the build does not need, and each row that stays carries a comment saying it comes from the
seed and that the shipped base grants it already. A seed names only filesystem rows on existing
directories, never `/` and never the specification directory or an ancestor of it.
"""

from __future__ import annotations

import pathlib
import posixpath
import re

from layer_prune import cfgfile

# Where the prune image keeps the seeds, and what a seed file is called: a plain name ending in .cfg.
SEED_DIRECTORY = "/usr/local/share/phobos-prune/seeds"
SEED_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.cfg")
# The sections a seed may name: reading what a build wrote, and the write-class rights on its scratch directory.
SEED_SECTIONS = frozenset({"read", "write", "create", "delete", "create-ipc", "restructure"})
# The comment above a seed row that survived the minimisation.
SEED_COMMENT = ("seed: {sections} on {path} come from the {name} seed of the prune image, for a build that writes "
                "scratch files with random names there; the shipped base grants them already")


def parse_name(value: object, source: str) -> str:
    """The seed name a prune.json holds; ValueError, naming `source`, unless it is a plain *.cfg file name."""
    if not isinstance(value, str) or SEED_NAME.fullmatch(value) is None:
        raise ValueError(f"{source}: seed is a plain file name ending in .cfg, not {value!r}")
    return value


def load(name: str, directory: str = SEED_DIRECTORY, spec_parent: str = "/var/tmp") -> cfgfile.Policy:
    """The seed's rows as a policy; ValueError naming what is wrong with the seed or its absence."""
    parse_name(name, "seed")
    path = pathlib.Path(directory) / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"the seed {name} is not a file in {directory}")
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
        if entry == "/" or entry == spec_parent or spec_parent.startswith(entry.rstrip("/") + "/"):
            raise ValueError(f"the seed {name} names {entry}, which is the root, the specification directory or an "
                             "ancestor of it")
        if posixpath.normpath(entry) != entry or not pathlib.Path(entry).is_dir() or pathlib.Path(entry).is_symlink():
            raise ValueError(f"the seed {name} names {entry}, which is not an existing real directory")
    return policy


def comments_for(name: str, policy: cfgfile.Policy) -> dict[str, str]:
    """The comment above each seed path: which sections the seed gave it, and that the shipped base grants them."""
    return {entry: SEED_COMMENT.format(sections=", ".join(f"[{section}]" for section in sorted(sections)), path=entry,
                                       name=name)
            for entry, sections in policy.fs.items()}
