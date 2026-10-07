"""From attributed filesystem denials to grants on paths (A.6.5, "Filesystem"; decision 7).

The rules, each erring in the direction A.7 names, and every case no rule covers reported, not granted:

- Write-class rights are never widened: [write] goes on the file, the create, delete and restructure
  sections on the directory Landlock checks them on; an object the run itself created moves to its
  nearest ancestor that existed before the run, because only existing paths can be named. That climb
  stays inside the roots the snapshot scanned: a missing path elsewhere (a /proc entry of a process
  that has ended) is reported.
- [read] and [execute] on an object that existed go on the object inside the fine-grained roots, file
  by file, and on its containing directory elsewhere. A directory object goes on itself, with a
  comment when it lies inside a fine-grained root, since Phobos has no list-only right.
- No directory nearer the root than MINIMUM_WIDENING_DEPTH is granted, except a write-class right on
  the directory Landlock checks it on (a creation in /tmp); a [read] of such a directory, or a
  widening or a climb that would reach one, is reported instead.
- The one exception to "file by file" inside a fine-grained root, Markus's explicit decision: a tree the
  exercise declares as a pinned read root (pinned.py), whose contents the image build fixed by checksum,
  gets `[read]`, and only `[read]`, as one entry on exactly that directory, for every read of anything
  beneath it, with a comment saying why. It is never widened to an ancestor, never write-class, and
  [execute] and every other section on a path beneath it keep every rule above.
- A per-run name (a kernel-assigned id in PER_RUN_PATTERNS whose value differs between observed runs,
  or equals the refusing process's or thread's own id) is granted on its smallest stable directory,
  with a comment, and only for [read] and [execute]; a write-class right on a per-run name is reported.
- Compaction joins at least `threshold` read-class children into their directory, never inside a
  fine-grained root, never at a depth below MINIMUM_WIDENING_DEPTH.
- [execute] is never left on, nor compacted into, a directory that overlaps a write-class right of the
  grants, or of the policy they are layered on (`held`): one on the directory itself, on an ancestor,
  or on an entry beneath it, since a file written there could then be executed. Execute stays on the
  exact files the reference executed there, each with a comment saying why, and saying so when the
  file itself stays writable. An executed object that did not exist before the run was written by it,
  so it is reported and never granted, wherever it lies. Per-run directories (/proc, /dev/pts) are
  left to per_run_grants: a run cannot create a regular file in them.

The caller rewrites /proc/self and /proc/thread-self with rewrite_self first and then resolves every
path outside /proc and /dev with os.path.realpath; never the other way round, which would resolve the
pruner's own process. grants_and_notes rewrites them again, so a path the caller left is still safe.
"""

from __future__ import annotations

import dataclasses
import os
import posixpath
import re
from collections.abc import Iterable

from layer_prune import cfgfile
from layer_prune.record import LAYER_FILESYSTEM, Denial

# The directories inside which grants stay file by file and are never compacted (decision 7).
DEFAULT_FINE_ROOTS = ("/etc", "/dev", "/proc", "/sys", "/root", "/home", "/run")
# How many children with equal read-class rights compaction joins into their directory (A.6.5).
DEFAULT_COMPACTION_THRESHOLD = 3
# The fewest children compaction may ever be asked to join.
MINIMUM_COMPACTION_THRESHOLD = 2
# The shallowest directory a grant may be widened to: never `/`, never a top-level directory.
MINIMUM_WIDENING_DEPTH = 2
# How many observed paths a per-run comment names before it only counts the rest.
COMMENT_EXAMPLES = 3
# The sections that may be widened to a containing directory or compacted; every other one is write-class.
READ_CLASS = frozenset({"read", "execute"})
# The sections that change what a directory holds or what a file contains.
WRITE_CLASS = frozenset(cfgfile.WRITE_SECTIONS)
# The comment above a file whose [execute] was kept on the file rather than on its directory, and what
# it adds when the file itself can be written in place.
EXECUTE_KEPT_COMMENT = ("execute: kept on the files the reference executed, because {directory} overlaps a "
                        "write-class right; a file written there is not executable")
EXECUTE_KEPT_WRITABLE = ", but this file itself can be overwritten in place"
# The comment above any other executable file a write-class right lets the run overwrite in place.
EXECUTE_WRITABLE_COMMENT = "execute: this file can also be overwritten in place, and then executed"
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
# The magic links procfs resolves to the process doing the lookup.
SELF_LINKS = ("/proc/self", "/proc/thread-self")


@dataclasses.dataclass(frozen=True)
class Snapshot:
    """What existed before a run: every path and every directory under the scanned and the indexed roots.

    `existed` and `is_directory` answer from the snapshot for a path under a scanned root (the
    exercise and the write grants, which a run may change) or under an indexed root (what the caller
    walked before any run, so that an earlier run's leftovers do not read as part of the system), and
    from the filesystem now for any other path. Only a scanned root is climbed from: a path missing
    from an indexed root, or missing now elsewhere, is reported by the callers.
    """

    existing: frozenset[str]
    directories: frozenset[str]
    scanned: tuple[str, ...]
    indexed: tuple[str, ...] = ()

    @classmethod
    def take(cls, roots: Iterable[str], excluded: tuple[str, ...] = ()) -> Snapshot:
        """Walks each root, resolved first, without following symbolic links beneath it, and without
        descending into an excluded path; an unreadable directory raises."""
        existing: set[str] = set()
        directories: set[str] = set()
        scanned = tuple(os.path.realpath(root) for root in roots)
        for root in scanned:
            if not os.path.lexists(root) or within(root, excluded):
                continue
            existing.add(root)
            if os.path.isdir(root):
                directories.add(root)
            for current, subdirectories, files in os.walk(root, onerror=raise_walk_error):
                subdirectories[:] = [name for name in subdirectories
                                     if not within(os.path.join(current, name), excluded)]
                for name in subdirectories:
                    full = os.path.join(current, name)
                    existing.add(full)
                    if not os.path.islink(full):
                        directories.add(full)
                existing.update(os.path.join(current, name) for name in files)
        return cls(existing=frozenset(existing), directories=frozenset(directories), scanned=scanned)

    def scanned_path(self, path: str) -> bool:
        """Whether a path lies under a root the snapshot walked to climb from."""
        return any(path == root or is_beneath(path, root) for root in self.scanned)

    def answered(self, path: str) -> bool:
        """Whether the snapshot, rather than the filesystem now, says whether the path existed."""
        return self.scanned_path(path) or within(path, self.indexed)

    def existed(self, path: str) -> bool:
        """Whether the path existed before the run."""
        return path in self.existing if self.answered(path) else os.path.lexists(path)

    def is_directory(self, path: str) -> bool:
        """Whether the path was a directory before the run."""
        return path in self.directories if self.answered(path) else os.path.isdir(path)


def raise_walk_error(error: OSError) -> None:
    """Raises the error os.walk met, so an unreadable directory never reads as one the run created."""
    raise error


def is_beneath(path: str, ancestor: str) -> bool:
    """Whether `path` lies strictly beneath `ancestor`, by components."""
    return cfgfile.is_beneath(path, ancestor)


def depth(path: str) -> int:
    """How many components a path has below `/`: 0 for `/`, 1 for `/usr`."""
    return len([part for part in path.split("/") if part])


def within(path: str, roots: tuple[str, ...]) -> bool:
    """Whether a path is one of the roots or lies beneath one."""
    return any(path == root or is_beneath(path, root) for root in roots)


def nearest_existing(path: str, snapshot: Snapshot) -> str | None:
    """The path if it existed before the run, otherwise its nearest ancestor that did, climbing only
    inside the scanned roots and never above MINIMUM_WIDENING_DEPTH; None where no such ancestor is."""
    if snapshot.existed(path):
        return path
    if not snapshot.scanned_path(path):
        return None
    candidate = os.path.dirname(path)
    while snapshot.scanned_path(candidate) and depth(candidate) >= MINIMUM_WIDENING_DEPTH:
        if snapshot.existed(candidate):
            return candidate
        candidate = os.path.dirname(candidate)
    return None


def writable(path: str) -> bool:
    """Whether a policy line can carry the path as it is (cfgfile.check_path would accept it)."""
    try:
        cfgfile.check_path(path)
    except ValueError:
        return False
    return True


def rewrite_self(path: str, tgid: int, tid: int) -> str:
    """Rewrites /proc/self with the refusing thread's thread group and /proc/thread-self with both ids.

    The pruner never resolves these links itself, which would name its own process; the caller takes
    `tid` from the trace line and `tgid` from Trace.thread_group.
    """
    for link, replacement in (("/proc/thread-self", f"/proc/{tgid}/task/{tid}"), ("/proc/self", f"/proc/{tgid}")):
        if path == link or path.startswith(link + "/"):
            return replacement + path[len(link):]
    return path


def object_paths(denial: Denial) -> list[str]:
    """The denial's objects with /proc/self rewritten; a self link of a denial without ids is left as it is."""
    if not denial.pid or not denial.tid:
        return list(denial.objects)
    return [rewrite_self(path, denial.pid, denial.tid) for path in denial.objects]


def is_self_link(path: str) -> bool:
    """Whether a path still goes through /proc/self or /proc/thread-self."""
    return any(path == link or path.startswith(link + "/") for link in SELF_LINKS)


@dataclasses.dataclass(frozen=True)
class PerRunMatch:
    """One object matching the per-run table: its shape and each id's (placeholder, value, offset)."""

    shape: str
    values: tuple[tuple[str, int, int], ...]


def per_run_match(path: str) -> PerRunMatch | None:
    """The per-run match of a path, with each kernel-assigned id replaced by its placeholder in the shape."""
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


def changing_values(denials: list[Denial], observations: list[tuple[int, str, PerRunMatch]]) -> set[tuple[int, int]]:
    """The (position, value) pairs seen changing: a position changes when at least two observed runs of the
    same call each hold a value no other run of it holds in every run, and then those values are per-run.

    A value present in every run that made the call is stable, however many values there are, and a
    value that only one run added beside stable ones does not make its position change.
    """
    changing: set[tuple[int, int]] = set()
    for position in range(len(observations[0][2].values)):
        by_run: dict[int, set[int]] = {}
        for index, _, match in observations:
            by_run.setdefault(denials[index].run, set()).add(match.values[position][1])
        if len(by_run) < 2:
            continue
        stable = set.intersection(*by_run.values())
        if sum(1 for values in by_run.values() if values - stable) < 2:
            continue
        changing.update((position, value) for values in by_run.values() for value in values - stable)
    return changing


def stable_directory(path: str, denial: Denial, match: PerRunMatch, changing: set[tuple[int, int]]) -> str | None:
    """The parent of the leftmost per-run component of a path, or None where no component is per-run."""
    own = {denial.pid, denial.tid}
    for position, (placeholder, value, start) in enumerate(match.values):
        if (position, value) in changing or (placeholder in ("<pid>", "<tid>") and value in own):
            return path[:start].rstrip("/") or "/"
    return None


def classify_per_run(denials: list[Denial]) -> dict[tuple[int, str], tuple[str, str]]:
    """Every (denial index, object as rewritten) that is a per-run name, mapped to (stable directory, shape)."""
    observed: dict[tuple[str, frozenset[str], str], list[tuple[int, str, PerRunMatch]]] = {}
    for index, denial in enumerate(denials):
        if denial.layer != LAYER_FILESYSTEM:
            continue
        for path in object_paths(denial):
            match = per_run_match(path)
            if match is not None:
                observed.setdefault(per_run_key(denial, match), []).append((index, path, match))
    taken: dict[tuple[int, str], tuple[str, str]] = {}
    for observations in observed.values():
        changing = changing_values(denials, observations)
        for index, path, match in observations:
            directory = stable_directory(path, denials[index], match, changing)
            if directory is not None:
                taken[(index, path)] = (directory, match.shape)
    return taken


def per_run_comment(directory: str, shapes: dict[str, set[str]]) -> str:
    """The comment above a per-run grant: each shape with a few of the paths observed, and the directory."""
    parts = []
    for shape, paths in sorted(shapes.items()):
        examples = sorted(paths)[:COMMENT_EXAMPLES]
        more = f" and {len(paths) - len(examples)} more" if len(paths) > len(examples) else ""
        parts.append(f"{shape}, observed as {' and '.join(examples)}{more}")
    return f"per-run name: {'; '.join(parts)}; granted on {directory}"


def per_run_grants(denials: list[Denial]) -> tuple[dict[str, frozenset[str]], dict[str, str]]:
    """The [read] and [execute] grants on smallest stable directories for per-run names, and the comment above each.

    A matching name seen with one value only, in another process than the refusing one, is not taken
    here and stays file by file in grants_for; a changing name outside the table is never taken; a
    write-class right on a per-run name is never granted (grants_and_notes reports it).
    """
    grants: dict[str, set[str]] = {}
    seen: dict[str, dict[str, set[str]]] = {}
    for (index, path), (directory, shape) in classify_per_run(denials).items():
        sections = denials[index].sections & READ_CLASS
        if not sections:
            continue
        grants.setdefault(directory, set()).update(sections)
        seen.setdefault(directory, {}).setdefault(shape, set()).add(path)
    comments = {directory: per_run_comment(directory, shapes) for directory, shapes in seen.items()}
    return {directory: frozenset(sections) for directory, sections in grants.items()}, comments


@dataclasses.dataclass
class Notes:
    """What grants_and_notes found beside its grants: the comment above a grant, and what it left ungranted."""

    comments: dict[str, str] = dataclasses.field(default_factory=dict)
    reported: list[dict[str, str]] = dataclasses.field(default_factory=list)

    def report(self, path: str, section: str, reason: str) -> None:
        """Records a requested grant left out, with the reason."""
        self.reported.append({"path": path, "section": section, "reason": reason})


def read_class_target(path: str, snapshot: Snapshot, fine_roots: tuple[str, ...]) -> str | None:
    """Where a read or execute right on an object goes: itself, its directory, its nearest existing ancestor, or nowhere."""
    if not snapshot.existed(path):
        return nearest_existing(path, snapshot)
    if snapshot.is_directory(path):
        return path if depth(path) >= MINIMUM_WIDENING_DEPTH else None
    if within(path, fine_roots):
        return path
    parent = os.path.dirname(path)
    return parent if depth(parent) >= MINIMUM_WIDENING_DEPTH else path


def placed(path: str, section: str, snapshot: Snapshot, fine_roots: tuple[str, ...], notes: Notes) -> str | None:
    """Where one section asked for on one object is granted, or None when it is reported instead."""
    if is_self_link(path):
        notes.report(path, section, "a /proc/self link of a denial without process ids")
        return None
    if section == "execute" and not snapshot.existed(path):
        notes.report(path, section, "the run executed what it wrote; a written file is never made executable")
        return None
    if section in READ_CLASS:
        target = read_class_target(path, snapshot, fine_roots)
    else:
        target = nearest_existing(path, snapshot)
    if target is None:
        notes.report(path, section, "no path that existed before the run, inside the scanned roots and deep enough")
        return None
    if writable(target):
        if section in READ_CLASS and within(target, fine_roots) and snapshot.is_directory(target):
            notes.comments.setdefault(target, f"listed: [read] on the directory {target} makes every entry beneath "
                                              "it readable; Phobos has no list-only right")
        return target
    if section not in READ_CLASS or within(target, fine_roots):
        notes.report(path, section, "a name a policy line cannot carry, and the right may not be widened here")
        return None
    parent = posixpath.dirname(target)
    while parent != "/" and not writable(parent):
        parent = posixpath.dirname(parent)
    if depth(parent) < MINIMUM_WIDENING_DEPTH:
        notes.report(path, section, "a name a policy line cannot carry, with no carriable ancestor deep enough")
        return None
    notes.report(path, section, f"a name a policy line cannot carry; widened to {parent}")
    return parent


def overlaps_write(path: str, grants: dict[str, frozenset[str]],
                   held: dict[str, frozenset[str]] | None = None) -> bool:
    """Whether the grants or the held entries hold a write-class right on the path, an ancestor, or an entry beneath it."""
    return any(sections & WRITE_CLASS and (other == path or is_beneath(path, other) or is_beneath(other, path))
               for entries in (grants, held or {}) for other, sections in entries.items())


def holds(path: str, section: str, entries: dict[str, frozenset[str]] | dict[str, set[str]]) -> bool:
    """Whether an entry on the path or on an ancestor of it grants the section."""
    return any(section in sections and (other == path or is_beneath(path, other)) for other, sections in entries.items())


def narrow_execute(grants: dict[str, frozenset[str]], executed: Iterable[str], snapshot: Snapshot,
                   notes: Notes, held: dict[str, frozenset[str]] | None = None) -> dict[str, frozenset[str]]:
    """The grants with [execute] taken off every directory that overlaps a write-class right, and put on the files.

    `executed` names the objects the reference was refused executing, and `held` the entries of the
    policy the grants are layered on, whose write-class rights count as well. First every such
    directory loses [execute]; then each executed object beneath one of them that no remaining entry
    still lets execute gets [execute] on itself, when it was a file before the run and a name a
    policy line can carry, with the comment saying why; any other is reported. Every other file left
    with [execute] that a [write] on it or an ancestor lets the run overwrite gets a comment saying so.
    """
    narrowed = [path for path in sorted(grants) if "execute" in grants[path] and snapshot.is_directory(path)
                and overlaps_write(path, grants, held)]
    result = {path: set(sections) for path, sections in grants.items()}
    for path in narrowed:
        result[path].discard("execute")
    for item in sorted(set(executed)):
        directory = max((path for path in narrowed if item == path or is_beneath(item, path)), key=depth, default=None)
        if directory is None or holds(item, "execute", result):
            continue
        if not writable(item):
            notes.report(item, "execute", f"its widening to {directory} is withdrawn: that overlaps a write-class right")
        elif snapshot.existed(item) and not snapshot.is_directory(item):
            result.setdefault(item, set()).add("execute")
            comment = EXECUTE_KEPT_COMMENT.format(directory=directory)
            if holds(item, "write", result) or holds(item, "write", held or {}):
                comment += EXECUTE_KEPT_WRITABLE
            notes.comments.setdefault(item, comment)
        else:
            notes.report(item, "execute", f"executed beneath {directory}, which overlaps a write-class right, "
                                          "and not a file that existed before the run")
    for path, sections in sorted(result.items()):
        if "execute" in sections and not snapshot.is_directory(path) and (
                holds(path, "write", result) or holds(path, "write", held or {})):
            notes.comments.setdefault(path, EXECUTE_WRITABLE_COMMENT)
    return {path: frozenset(sections) for path, sections in result.items() if sections}


def pinned_root_of(path: str, pinned_roots: dict[str, str]) -> str | None:
    """The declared pinned read root a path is, or lies beneath; None when it is in none."""
    return next((root for root in pinned_roots if path == root or is_beneath(path, root)), None)


def grants_and_notes(denials: list[Denial], snapshot: Snapshot, fine_roots: tuple[str, ...],
                     held: dict[str, frozenset[str]] | None = None,
                     pinned_roots: dict[str, str] | None = None) -> tuple[dict[str, frozenset[str]], Notes]:
    """The grants the filesystem denials ask for outside per-run names, with the comments and reports beside them.

    `pinned_roots` maps each verified pinned read root to the comment its grant gets (pinned.py). A
    [read] of anything in one goes on that directory; no other section ever does, and no write-class right
    is ever granted on one or on an ancestor of one: that is reported instead.

    [execute] is narrowed to the executed files wherever it would sit on a directory that overlaps a
    write-class right of these grants or of `held`, the policy they are layered on (narrow_execute).
    """
    taken = classify_per_run(denials)
    notes = Notes()
    grants: dict[str, set[str]] = {}
    executed: set[str] = set()
    for index, denial in enumerate(denials):
        if denial.layer != LAYER_FILESYSTEM:
            continue
        for path in object_paths(denial):
            for section in sorted(denial.sections):
                if (index, path) in taken:
                    if section not in READ_CLASS:
                        notes.report(path, section, "a write-class right on a per-run name is never widened")
                    continue
                if section == "execute" and snapshot.existed(path):
                    executed.add(path)
                pinned = pinned_root_of(path, pinned_roots or {}) if section == "read" else None
                if pinned is not None:
                    grants.setdefault(pinned, set()).add(section)
                    notes.comments.setdefault(pinned, (pinned_roots or {})[pinned])
                    continue
                target = placed(path, section, snapshot, fine_roots, notes)
                if target is not None and section not in READ_CLASS and any(
                        target == root or is_beneath(root, target) for root in pinned_roots or {}):
                    notes.report(path, section, "a write-class right on a pinned read root or on an ancestor of one "
                                                "would make the pinned tree writable")
                    continue
                if target is not None:
                    grants.setdefault(target, set()).add(section)
    found = {path: frozenset(sections) for path, sections in grants.items()}
    return narrow_execute(found, executed, snapshot, notes, held), notes


def grants_for(denials: list[Denial], snapshot: Snapshot, fine_roots: tuple[str, ...],
               held: dict[str, frozenset[str]] | None = None,
               pinned_roots: dict[str, str] | None = None) -> dict[str, frozenset[str]]:
    """The grants the filesystem denials ask for, generalised as the module docstring states.

    Denials of other layers are ignored, objects per_run_grants takes are left to it, and whatever no
    rule covers is left out; grants_and_notes says why. `held` is the policy the grants are layered on.
    """
    return grants_and_notes(denials, snapshot, fine_roots, held, pinned_roots)[0]


def compact(grants: dict[str, frozenset[str]], threshold: int, fine_roots: tuple[str, ...],
            held: dict[str, frozenset[str]] | None = None) -> dict[str, frozenset[str]]:
    """Joins at least `threshold` children with equal read-class rights into their directory, repeatedly.

    Never inside a fine-grained root (the directory is neither one nor beneath one), never into a
    directory at a depth below MINIMUM_WIDENING_DEPTH, and never [execute] into a directory that
    overlaps a write-class right of the grants or of `held`, the policy they are layered on. The
    directory keeps any rights it already had.
    """
    if threshold < MINIMUM_COMPACTION_THRESHOLD:
        raise ValueError(f"a compaction threshold below {MINIMUM_COMPACTION_THRESHOLD} would widen a single grant")
    result = dict(grants)
    changed = True
    while changed:
        changed = False
        families: dict[tuple[str, frozenset[str]], list[str]] = {}
        for path, sections in result.items():
            if path != "/" and sections <= READ_CLASS:
                families.setdefault((os.path.dirname(path), sections), []).append(path)
        for (parent, sections), children in sorted(families.items()):
            if len(children) < threshold or depth(parent) < MINIMUM_WIDENING_DEPTH or within(parent, fine_roots):
                continue
            if "execute" in sections and overlaps_write(parent, result, held):
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
