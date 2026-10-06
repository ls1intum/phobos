"""From attributed filesystem denials to grants on paths (A.6.5, "Filesystem"; decision 7).

The rules, each erring in the direction A.7 names:

- Write-class rights are never widened: [write] goes on the file, the create, delete and restructure
  sections on the directory Landlock checks them on; an object the run itself created moves to its
  nearest ancestor that existed before the run, because only existing paths can be named.
- [read] and [execute] on an object that existed go on the object inside the fine-grained roots, file
  by file, and on its containing directory elsewhere (a directory object on itself). A containing
  directory nearer the root than MINIMUM_WIDENING_DEPTH is never used: the file is granted instead.
- A per-run name (a kernel-assigned id in PER_RUN_PATTERNS, seen changing or equal to the refusing
  process's or thread's own id) is granted on its smallest stable directory, with a comment.
- Compaction joins at least `threshold` read-class children into their directory, never inside a
  fine-grained root, never at a depth below MINIMUM_WIDENING_DEPTH.

Paths are compared as written: the caller passes them through os.path.realpath first.
"""

from __future__ import annotations

import dataclasses
import os
import re
from collections.abc import Iterable

from layer_prune import cfgfile
from layer_prune.record import LAYER_FILESYSTEM, Denial

# The directories inside which grants stay file by file and are never compacted (decision 7).
DEFAULT_FINE_ROOTS = ("/etc", "/dev", "/proc", "/sys", "/root", "/home", "/run")
# How many children with equal read-class rights compaction joins into their directory (A.6.5).
DEFAULT_COMPACTION_THRESHOLD = 3
# The shallowest directory a grant may be widened to: never `/`, never a top-level directory.
MINIMUM_WIDENING_DEPTH = 2
# The sections that may be widened to a containing directory or compacted; every other one is write-class.
READ_CLASS = frozenset({"read", "execute"})
# A kernel-assigned id: 0 or a number without a leading zero.
NUMBER = r"(?:0|[1-9][0-9]*)"
# The table of A.6.5: each pattern names a path whose numbered components the kernel assigns, with
# the placeholder each such component is written as. Matched against the whole path, first match wins.
PER_RUN_PATTERNS = (
    (re.compile(rf"^/proc/(?P<pid>{NUMBER})/task/(?P<tid>{NUMBER})(?:/.*)?$"), ("<pid>", "<tid>")),
    (re.compile(rf"^/proc/(?P<pid>{NUMBER})/(?:fd|fdinfo)/(?P<fd>{NUMBER})$"), ("<pid>", "<fd>")),
    (re.compile(rf"^/proc/(?P<pid>{NUMBER})(?:/.*)?$"), ("<pid>",)),
    (re.compile(rf"^/dev/pts/(?P<pty>{NUMBER})$"), ("<n>",)),
)


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """What existed before a run: every path and every directory under the scanned roots.

    `existed` and `is_directory` answer from the snapshot for a path under a scanned root, the
    exercise and the write grants, which a run may change, and from the filesystem now for any
    other path, which no run could write to.
    """

    existing: frozenset[str]
    directories: frozenset[str]
    scanned: tuple[str, ...]

    @classmethod
    def take(cls, roots: Iterable[str]) -> Snapshot:
        """Walks each root without following symbolic links and records every path beneath it."""
        existing: set[str] = set()
        directories: set[str] = set()
        scanned = tuple(roots)
        for root in scanned:
            if not os.path.lexists(root):
                continue
            existing.add(root)
            if os.path.isdir(root) and not os.path.islink(root):
                directories.add(root)
            for current, subdirectories, files in os.walk(root):
                for name in subdirectories:
                    existing.add(os.path.join(current, name))
                    directories.add(os.path.join(current, name))
                for name in files:
                    existing.add(os.path.join(current, name))
        return cls(existing=frozenset(existing), directories=frozenset(directories), scanned=scanned)

    def scanned_path(self, path: str) -> bool:
        """Whether a path lies under a root the snapshot walked."""
        return any(path == root or is_beneath(path, root) for root in self.scanned)

    def existed(self, path: str) -> bool:
        """Whether the path existed before the run."""
        return path in self.existing if self.scanned_path(path) else os.path.lexists(path)

    def is_directory(self, path: str) -> bool:
        """Whether the path was a directory before the run."""
        return path in self.directories if self.scanned_path(path) else os.path.isdir(path)


def is_beneath(path: str, ancestor: str) -> bool:
    """Whether `path` lies strictly beneath `ancestor`, by components."""
    return cfgfile.is_beneath(path, ancestor)


def depth(path: str) -> int:
    """How many components a path has below `/`: 0 for `/`, 1 for `/usr`."""
    return len([part for part in path.split("/") if part])


def within(path: str, roots: tuple[str, ...]) -> bool:
    """Whether a path is one of the roots or lies beneath one."""
    return any(path == root or is_beneath(path, root) for root in roots)


def nearest_existing(path: str, snapshot: Snapshot) -> str:
    """The path itself if it existed before the run, otherwise its nearest ancestor that did."""
    candidate = path
    while candidate != "/" and not snapshot.existed(candidate):
        candidate = os.path.dirname(candidate)
    return candidate


def writable_name(path: str) -> str:
    """The path, or its nearest ancestor a policy line can carry (no wildcard, `#` or control character)."""
    candidate = path
    while candidate != "/" and cfgfile.FORBIDDEN_PATH_CHARACTERS.search(candidate):
        candidate = os.path.dirname(candidate)
    return candidate


def rewrite_self(path: str, tgid: int, tid: int) -> str:
    """Rewrites /proc/self with the refusing thread's thread group and /proc/thread-self with both ids.

    The pruner never resolves these links itself, which would name its own process; the caller takes
    `tid` from the trace line and `tgid` from Trace.thread_group.
    """
    for link, replacement in (("/proc/thread-self", f"/proc/{tgid}/task/{tid}"), ("/proc/self", f"/proc/{tgid}")):
        if path == link or path.startswith(link + "/"):
            return replacement + path[len(link):]
    return path


@dataclasses.dataclass(frozen=True)
class PerRunMatch:
    """One object matching the per-run table: its pattern's placeholders and the values in it."""

    shape: str
    values: tuple[tuple[str, int, int], ...]


def per_run_match(path: str) -> PerRunMatch | None:
    """The per-run match of a path: the path with each kernel-assigned id replaced by its placeholder,
    and each id's (placeholder, value, offset of the component that ends before it); None if no entry matches."""
    for pattern, placeholders in PER_RUN_PATTERNS:
        match = pattern.match(path)
        if match is None:
            continue
        shape = path
        values: list[tuple[str, int, int]] = []
        for group, placeholder in reversed(list(zip(match.groupdict(), placeholders, strict=True))):
            start, end = match.span(group)
            shape = shape[:start] + placeholder + shape[end:]
            values.append((placeholder, int(match.group(group)), start))
        return PerRunMatch(shape=shape, values=tuple(reversed(values)))
    return None


def per_run_key(denial: Denial, match: PerRunMatch) -> tuple[str, frozenset[str], str]:
    """What makes two observations "the same refused call": the call, the sections and the shape."""
    return denial.operation, denial.sections, match.shape


def stable_directory(path: str, denial: Denial, match: PerRunMatch, changing: set[int]) -> str | None:
    """The parent of the leftmost per-run component of a path, or None where no component is per-run.

    A component is per-run when its value is seen changing (its position is in `changing`) or, for a
    process or thread id, equals the refusing process's or thread's own id.
    """
    own = {denial.pid, denial.tid}
    for position, (placeholder, value, start) in enumerate(match.values):
        if position in changing or (placeholder in ("<pid>", "<tid>") and value in own):
            return path[:start].rstrip("/") or "/"
    return None


def classify_per_run(denials: list[Denial]) -> dict[tuple[int, str], tuple[str, str]]:
    """Every (denial index, object) that is a per-run name, mapped to (stable directory, shape)."""
    observed: dict[tuple[str, frozenset[str], str], list[tuple[int, str, PerRunMatch]]] = {}
    for index, denial in enumerate(denials):
        if denial.layer != LAYER_FILESYSTEM:
            continue
        for path in denial.objects:
            match = per_run_match(path)
            if match is not None:
                observed.setdefault(per_run_key(denial, match), []).append((index, path, match))
    taken: dict[tuple[int, str], tuple[str, str]] = {}
    for observations in observed.values():
        changing = changing_positions(denials, observations)
        for index, path, match in observations:
            directory = stable_directory(path, denials[index], match, changing)
            if directory is not None:
                taken[(index, path)] = (directory, match.shape)
    return taken


def changing_positions(denials: list[Denial], observations: list[tuple[int, str, PerRunMatch]]) -> set[int]:
    """The positions of the per-run components whose value differs between two observed runs."""
    changing: set[int] = set()
    for position in range(len(observations[0][2].values)):
        by_run: dict[int, set[int]] = {}
        for index, _, match in observations:
            by_run.setdefault(denials[index].run, set()).add(match.values[position][1])
        values = {value for run_values in by_run.values() for value in run_values}
        if len(by_run) >= 2 and len(values) >= 2:
            changing.add(position)
    return changing


def per_run_grants(denials: list[Denial]) -> tuple[dict[str, frozenset[str]], dict[str, str]]:
    """The grants on smallest stable directories for per-run names, and the comment above each.

    A matching name seen with one value only, in another process than the refusing one, is not taken
    here and stays file by file in grants_for; a changing name outside the table is never taken.
    """
    grants: dict[str, set[str]] = {}
    seen: dict[str, dict[str, set[str]]] = {}
    for (index, path), (directory, shape) in classify_per_run(denials).items():
        grants.setdefault(directory, set()).update(denials[index].sections)
        seen.setdefault(directory, {}).setdefault(shape, set()).add(path)
    comments = {}
    for directory, shapes in seen.items():
        parts = [f"{shape}, observed as {' and '.join(sorted(paths))}" for shape, paths in sorted(shapes.items())]
        comments[directory] = f"per-run name: {'; '.join(parts)}; granted on {directory}"
    return {directory: frozenset(sections) for directory, sections in grants.items()}, comments


def read_class_target(path: str, snapshot: Snapshot, fine_roots: tuple[str, ...]) -> str:
    """Where a read or execute right on an object goes: itself, its directory, or its nearest existing ancestor."""
    if not snapshot.existed(path):
        return nearest_existing(path, snapshot)
    if snapshot.is_directory(path) or within(path, fine_roots):
        return path
    parent = os.path.dirname(path)
    return parent if depth(parent) >= MINIMUM_WIDENING_DEPTH else path


def grants_for(denials: list[Denial], snapshot: Snapshot, fine_roots: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """The grants the filesystem denials ask for, generalised as the module docstring states.

    Denials of other layers are ignored, and objects per_run_grants takes are left to it.
    """
    taken = classify_per_run(denials)
    grants: dict[str, set[str]] = {}
    for index, denial in enumerate(denials):
        if denial.layer != LAYER_FILESYSTEM:
            continue
        for path in denial.objects:
            if (index, path) in taken:
                continue
            for section in denial.sections:
                if section in READ_CLASS:
                    target = read_class_target(path, snapshot, fine_roots)
                else:
                    target = nearest_existing(path, snapshot)
                grants.setdefault(writable_name(target), set()).add(section)
    return {path: frozenset(sections) for path, sections in grants.items()}


def compact(grants: dict[str, frozenset[str]], threshold: int, fine_roots: tuple[str, ...]) -> dict[str, frozenset[str]]:
    """Joins at least `threshold` children with equal read-class rights into their directory, repeatedly.

    Never inside a fine-grained root (the directory is neither one nor beneath one), never into a
    directory at a depth below MINIMUM_WIDENING_DEPTH. The directory keeps any rights it already had.
    """
    result = dict(grants)
    changed = True
    while changed:
        changed = False
        families: dict[tuple[str, frozenset[str]], list[str]] = {}
        for path, sections in result.items():
            parent = os.path.dirname(path)
            if path != "/" and sections <= READ_CLASS:
                families.setdefault((parent, sections), []).append(path)
        for (parent, sections), children in sorted(families.items()):
            if len(children) < threshold or depth(parent) < MINIMUM_WIDENING_DEPTH or within(parent, fine_roots):
                continue
            for child in children:
                del result[child]
            result[parent] = result.get(parent, frozenset()) | sections
            changed = True
            break
    return result


def normalise_hierarchy(grants: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """Raises every entry whose rights are a strict subset of an ancestor's to that ancestor's sections.

    Landlock already grants those rights there, so enforcement does not change, and an exercise
    configuration naming that exact path keeps folding onto it (AGENTS.md).
    """
    result = dict(grants)
    changed = True
    while changed:
        changed = False
        for path, sections in sorted(result.items()):
            for ancestor, ancestor_sections in result.items():
                if is_beneath(path, ancestor) and cfgfile.rights_of(sections) < cfgfile.rights_of(ancestor_sections):
                    result[path] = sections | ancestor_sections
                    changed = True
                    break
    return result
