"""Read-only trees whose contents are fixed by checksum, which a prune may grant as one directory (decision 7).

Inside a fine-grained root such as /root a grant is otherwise always file by file, so that it names only
what the reference opened. A dependency repository pre-loaded into the run-phase image is different: the
image build holds it to a committed manifest of SHA-256 sums (docker/run_phase/java/pin-repository.sh), so
a file in it is not something a graded run can have changed, and a build that stops at the first file it
cannot read shows the pruner one file per round. An exercise therefore declares such a tree in its
prune.json, `"pinned_read_roots": [{"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/<name>"}]`,
and the pruner grants `[read]`, and nothing else, on exactly that directory once it has checked the tree
against the manifest by the very rule pin-repository.sh applies.

The declaration is strict: the path is absolute and normalised, lies strictly beneath a fine-grained root
and is never one, the manifest lies in the directory the prune container mounts manifests read-only, and
there is no field through which a right could be named. A tree that does not match its manifest refuses
the exercise.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import pathlib
import posixpath
import re

from layer_prune import generalise

# Where the prune container mounts the manifests, read-only.
MANIFEST_DIRECTORY = "/srv/phobos-manifest"
# The keys of one declaration, and no others.
DECLARATION_KEYS = frozenset({"path", "manifest"})
# A line of a manifest: the SHA-256 and the path relative to the tree, two spaces apart.
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  (.+)")
# The file Maven writes beside every artefact with a comment holding the time it was written: the sum of
# such a file is that of its content without the comment lines, as pin-repository.sh reckons it.
TIMESTAMPED_FILE = "_remote.repositories"
# The comment above the grant, saying why this directory is not granted file by file.
GRANT_COMMENT = ("pinned: [read] on the directory {path} as one entry, not file by file; its contents are fixed by "
                 "the checksums of {manifest}, which the image build held it to and this prune checked again")


@dataclasses.dataclass(frozen=True)
class PinnedRoot:
    """One declared tree and the manifest that fixes its contents."""

    path: str
    manifest: str


def refusal(message: str) -> ValueError:
    """The error for a declaration that is not strictly one; a ValueError whatever the wrong type, as the callers expect."""
    return ValueError(message)


def parse(entries: object, source: str) -> tuple[PinnedRoot, ...]:
    """The declarations of a prune.json value; ValueError, naming `source`, for anything that is not strictly one."""
    if not isinstance(entries, list):
        raise refusal(f"{source}: pinned_read_roots is a list of objects")
    roots = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != DECLARATION_KEYS:
            raise ValueError(f"{source}: a pinned read root is an object with exactly path and manifest, "
                             "and no right can be named in it")
        path = entry["path"]
        manifest = entry["manifest"]
        if not isinstance(path, str) or not isinstance(manifest, str):
            raise refusal(f"{source}: the path and the manifest of a pinned read root are strings")
        if not path.startswith("/") or posixpath.normpath(path) != path:
            raise ValueError(f"{source}: the pinned read root {path!r} is not an absolute, normalised path")
        if path in generalise.DEFAULT_FINE_ROOTS or not generalise.within(path, generalise.DEFAULT_FINE_ROOTS):
            raise ValueError(f"{source}: the pinned read root {path!r} does not lie strictly beneath a fine-grained "
                             f"root ({', '.join(generalise.DEFAULT_FINE_ROOTS)})")
        if (posixpath.normpath(manifest) != manifest or posixpath.dirname(manifest) != MANIFEST_DIRECTORY
                or posixpath.basename(manifest) in ("", ".", "..")):
            raise ValueError(f"{source}: the manifest {manifest!r} is not a file directly in {MANIFEST_DIRECTORY}")
        if any(path == other.path or generalise.is_beneath(path, other.path) or generalise.is_beneath(other.path, path)
               for other in roots):
            raise ValueError(f"{source}: the pinned read root {path!r} repeats or overlaps another")
        roots.append(PinnedRoot(path=path, manifest=manifest))
    return tuple(roots)


def digest(file: pathlib.Path) -> str:
    """The SHA-256 of a file by the rule of pin-repository.sh: without the comment lines for _remote.repositories."""
    content = file.read_bytes()
    if file.name == TIMESTAMPED_FILE:
        lines = content.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        content = b"".join(line + b"\n" for line in lines if not line.startswith(b"#"))
    return hashlib.sha256(content).hexdigest()


def listed(manifest: pathlib.Path) -> list[tuple[str, str]]:
    """The (sum, relative path) of every line of a manifest; ValueError when it is missing, empty or malformed."""
    try:
        text = manifest.read_text()
    except (OSError, UnicodeDecodeError) as failure:
        raise ValueError(f"the manifest {manifest} cannot be read: {failure}") from failure
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        matched = MANIFEST_LINE.fullmatch(line)
        if matched is None:
            raise ValueError(f"line {number} of {manifest} is not '<sha256>  <path>'")
        relative = matched.group(2)
        if posixpath.isabs(relative) or posixpath.normpath(relative) != relative or relative.startswith(".."):
            raise ValueError(f"line {number} of {manifest} names {relative!r}, which is not a path beneath the tree")
        entries.append((matched.group(1), relative))
    if not entries:
        raise ValueError(f"the manifest {manifest} lists no file, so it fixes nothing")
    return entries


def verify(root: PinnedRoot) -> int:
    """Checks the tree against its manifest; the number of files checked, ValueError naming what does not match.

    The tree must be a real directory, not a link, and every listed file a regular file that really lies
    beneath it with the sum the manifest gives. Nothing is read outside the listed files.
    """
    tree = pathlib.Path(root.path)
    if tree.is_symlink() or not tree.is_dir() or os.path.realpath(root.path) != root.path:
        raise ValueError(f"the pinned read root {root.path} is not a real directory")
    problems = []
    entries = listed(pathlib.Path(root.manifest))
    for wanted, relative in entries:
        file = tree / relative
        if file.is_symlink() or not file.is_file() or os.path.realpath(file) != str(file):
            problems.append(f"{relative}: missing, or not a regular file beneath the tree")
        elif digest(file) != wanted:
            problems.append(f"{relative}: its SHA-256 differs from the manifest's")
    if problems:
        raise ValueError(f"{root.path} does not match {root.manifest}: {'; '.join(problems[:5])}"
                         f"{' and more' if len(problems) > 5 else ''}")
    return len(entries)
