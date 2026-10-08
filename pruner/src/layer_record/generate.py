"""From recorded sessions to a Phobos policy, with the layer pruner's own generalisation rules.

`load` reads every session of a recording directory, `filesystem_grants` turns what the sessions
needed into grants (the code is the layer pruner's: generalise.per_run_grants, grants_and_notes,
compact and normalise_hierarchy, so the two pruners agree by construction), and `write` puts the
policy and its record next to the sessions and runs it through the acceptance gate. Nothing observed
is written unchecked: cfgfile.render refuses a path it cannot carry and escapes every comment.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import subprocess  # nosec B404
import tempfile
from collections.abc import Callable

from layer_prune import cfgfile, generalise, limits, strace_parse
from layer_prune.record import Need

from layer_record import endpoints, names, needs, snapshot

# generate's exit statuses: the gate refused the policy, calls were not mapped, a [read] or [execute]
# row names a path that did not exist before the sessions.
EXIT_INVARIANT = 4
EXIT_GATE = 5
EXIT_INCOMPLETE = 6

# Where the gate builds its specification. Never /tmp: a specification directory beneath a write
# path is refused, and /tmp is one.
SPEC_PARENT = "/var/tmp"
# How many calls a grant lists as evidence in record.json, and how many observed paths a widening names.
EVIDENCE_EXAMPLES = 5
# The `INCOMPLETE` header line, with the number of calls it counts.
INCOMPLETE_LINE = "INCOMPLETE: {count} recorded calls are not mapped; see record.json"
UNGRANTED_LINE = "INCOMPLETE: {count} accesses cannot be granted by a policy; see record.json"
HEADER = (
    "Recorded by phobos-record, not pruned. Sessions merged: {count} ({dates}).",
    "It grants what those sessions exercised and nothing else: a code path no session took,",
    "a file no session opened in a fine-grained root, a host no session reached, is denied",
    "at grading time. Review record.json, which lists every widening.",
    "Recorded from the reference program; never record an untrusted submission.",
)
RESOLVER_LINE = "This policy needs --resolver (a [connect] rule names a host)."
NOT_GRANTED_LINE = "Not granted: [{section}] {path}: {reason}"
REFUSAL_LINE = "Grading refuses this whatever a policy grants: {description}"
WITHHELD_LINE = ("Not granted: a move from {source} to {destination} needs [{section}] on the source, which would "
                 "overlap a write-class right; grading refuses that move")
INTERACTIVE_LIMIT_LINE = ("Limits: no timeout derived (an interactive session's wall clock measures the person), "
                          "so the default applies.")
NO_LIMITS_LINE = "Limits: none derived (generate --limits derives them from a sampled session)."
MEMORY_LINE = "Limits: no mem_mb derived (ulimit -v is address space; pass --memory-pinned when the program pins it)."


class ImageMismatch(Exception):
    """Sessions recorded in containers of different images, whose paths describe different filesystems."""

    def __init__(self, images: set[str]):
        """Holds the digests of the images found."""
        super().__init__("the sessions of this recording ran in different images: " + ", ".join(sorted(images)))
        self.images = images


@dataclasses.dataclass
class Session:
    """One recorded session as generation reads it: its metadata, its needs, its network use and its listing."""

    number: int
    meta: dict
    needs: needs.SessionNeeds
    network: endpoints.NetworkNeeds
    listing: dict[str, str]
    hosts: dict[str, str]
    measurement: limits.Measurement | None = None


@dataclasses.dataclass
class Recording:
    """Every session of a recording directory, in the order they were recorded."""

    directory: pathlib.Path
    sessions: list[Session]


@dataclasses.dataclass
class Grants:
    """What filesystem_grants found: the grants, the comment above each wider one, the widenings, and
    `ungranted`, every access a session made that no grant covers, each as `{"path", "section", "reason"}`."""

    grants: dict[str, frozenset[str]]
    comments: dict[str, str]
    widenings: list[dict]
    ungranted: list[dict]


class Recorded:
    """What existed before the sessions, across the snapshots of every container they ran in.

    It answers as generalise.Snapshot does. A path counts as pre-existing only when it was in every
    snapshot, since a replay starts in a fresh container; a directory is one in any snapshot that lists
    it. Everything outside the kernel trees was scanned, so a climb from a created path may go as far
    up as the shallowest allowed depth.
    """

    def __init__(self, listings: list[dict[str, str]]):
        """Holds the listings; assumes each was read by snapshot.read_listing."""
        self.existing = [snapshot.Existing(listing) for listing in listings]
        self.listings = listings

    def existed(self, path: str) -> bool:
        """Whether the path existed before every session's first one in its container."""
        return all(existing.existed(path) for existing in self.existing)

    def is_directory(self, path: str) -> bool:
        """Whether a snapshot lists the path as a directory; the kernel trees, never listed, are directories."""
        return path in snapshot.DEFAULT_SKIP or any(listing.get(path, "").startswith("d") for listing in self.listings)

    def scanned_path(self, path: str) -> bool:
        """Whether the path lies outside the trees the snapshot never lists."""
        return not any(path == skipped or path.startswith(skipped + "/") for skipped in snapshot.DEFAULT_SKIP)

    def answered(self, path: str) -> bool:
        """Whether the snapshots, rather than the filesystem now, answer for the path."""
        return self.scanned_path(path)


def load(directory: pathlib.Path) -> Recording:
    """Reads every session of the recording: its trace, its snapshot, its metadata and its samples.

    Assumes the layout phobos-record record wrote. Raises ImageMismatch when the snapshots do not
    describe one image, and ValueError for a session without its metadata.
    """
    sessions = []
    cache: dict[str, dict[str, str]] = {}
    numbered = sorted((path for path in (directory / "sessions").glob("*") if path.name.isdigit()),
                      key=lambda path: int(path.name))
    for path in numbered:
        meta = json.loads((path / "session.json").read_text(encoding="utf-8"))
        relative = meta["snapshot"]
        if relative not in cache:
            cache[relative] = snapshot.read_listing(directory / relative)
        listing = cache[relative]
        lines = (path / "trace").read_text(encoding="utf-8", errors="surrogateescape").split("\n")
        calls = list(strace_parse.iter_calls(lines))
        number = int(path.name)
        hosts_path = (directory / relative).with_suffix(".hosts")
        hosts = names.hosts_file(hosts_path.read_text(encoding="utf-8", errors="replace")) if hosts_path.is_file() else {}
        sessions.append(Session(number=number, meta=meta,
                                needs=needs.read_session(calls, snapshot.Existing(listing), meta.get("workdir", "/"), number),
                                network=endpoints.observe(calls), listing=listing, hosts=hosts,
                                measurement=_measurement(path, meta)))
    images = {image_digest(listing) for listing in cache.values()}
    if len(images) > 1:
        raise ImageMismatch(images)
    return Recording(directory=directory, sessions=sessions)


def image_digest(listing: dict[str, str]) -> str:
    """A digest of what an image holds in a listing: /usr, /opt and the release file, with their fingerprints.

    Two containers of one image agree on it, whatever each session did in the working directory, /tmp
    and /root; containers of different images differ in it. Assumes the listing was taken before a
    session ran.
    """
    digest = hashlib.sha256()
    for path in sorted(listing):
        if path.startswith(("/usr/", "/opt/")) or path == "/etc/os-release":
            digest.update(f"{path}\0{listing[path]}\n".encode("utf-8", "surrogateescape"))
    return digest.hexdigest()[:16]


def _measurement(session: pathlib.Path, meta: dict) -> limits.Measurement | None:
    """The peaks of a sampled session, or None where it was not sampled."""
    path = session / "samples.json"
    if not path.is_file():
        return None
    held = json.loads(path.read_text(encoding="utf-8"))
    samples = held["samples"]
    last: dict[int, dict] = {}
    for sample in samples:
        last[sample["pid"]] = sample
    return limits.Measurement(
        wall_seconds=held["wall_seconds"],
        cpu_seconds=max((sample["cpu_seconds"] for sample in last.values()), default=0.0),
        vm_peak_mb=max((sample["vm_peak_mb"] for sample in samples), default=0.0),
        tasks=max((sample["tasks"] for sample in samples), default=0),
        highest_descriptor=max((sample["highest_descriptor"] for sample in samples), default=0),
        largest_file_mb=held.get("largest_file_mb", 0.0),
    )


def filesystem_grants(recording: Recording) -> Grants:
    """The grants every session's needs ask for, the comment above each wider one, the widenings and the gaps.

    Per-run names are judged against the ids of every process of every session; the grants are
    compacted and normalised exactly as the layer pruner does, a move across directories gives its
    source what its destination holds (source_covers_destination), and the result is normalised again.
    Each widening is `{"path", "sections", "observed", "observed_count", "files_beneath", "reason"}`.
    An access no policy can grant (a file created directly beneath a top-level directory, say, whose
    right Phobos never places there) is returned in `ungranted` with the reason, never dropped.
    """
    everything = [need for session in recording.sessions for need in session.needs.needs]
    own_ids = frozenset().union(*(session.needs.process_ids for session in recording.sessions))
    recorded = Recorded([session.listing for session in recording.sessions])
    per_run, comments = generalise.per_run_grants(everything, own_ids)
    found, notes = generalise.grants_and_notes(everything, recorded, generalise.DEFAULT_FINE_ROOTS, None, None, own_ids)
    merged: dict[str, set[str]] = {}
    for grants in (per_run, found):
        for path, sections in grants.items():
            merged.setdefault(path, set()).update(sections)
    compacted = generalise.compact({path: frozenset(sections) for path, sections in merged.items()},
                                   generalise.DEFAULT_COMPACTION_THRESHOLD, generalise.DEFAULT_FINE_ROOTS)
    ungranted = list(notes.reported)
    moves = placed_moves({move for session in recording.sessions for move in session.needs.moves}, recorded, ungranted)
    covered, _ = source_covers_destination(generalise.normalise_hierarchy(compacted), moves)
    grants = generalise.normalise_hierarchy(covered)
    comments = {**notes.comments, **comments}
    kept = {path: text for path, text in comments.items() if path in grants}
    return Grants(grants=grants, comments=kept, widenings=widenings(grants, everything, recorded, kept),
                  ungranted=ungranted)


def placed_moves(moves: set[tuple[str, str]], recorded: Recorded, ungranted: list[dict]) -> set[tuple[str, str]]:
    """The moves with both ends on a directory that existed before the sessions and a policy can name.

    A directory a session made (a temporary one it moved a file out of) is replaced by its nearest
    ancestor that existed, since that is where the rights it inherits are granted. A move with an end
    that cannot be placed (the root, a directory above the specification directory, a name a policy line
    cannot carry) is dropped and appended to `ungranted`.
    """
    result: set[tuple[str, str]] = set()
    for source, destination in sorted(moves):
        ends = (existing_ancestor(source, recorded), existing_ancestor(destination, recorded))
        if None in ends:
            ungranted.append({"path": f"{source} -> {destination}", "section": "restructure",
                              "reason": "a move across directories with an end no policy can name"})
            continue
        result.add((ends[0], ends[1]))  # type: ignore[arg-type]
    return result


def existing_ancestor(path: str, recorded: Recorded) -> str | None:
    """The path or its nearest ancestor that existed before the sessions, if a policy may name it; else None.

    Never the root or a directory the specification directory lies beneath, whose write-class rights
    phobos-policysystem.sh refuses, and never a name a policy line cannot carry.
    """
    candidate = path
    while not recorded.existed(candidate) and candidate != "/":
        candidate = os.path.dirname(candidate)
    if candidate in generalise.SPECIFICATION_ANCESTORS or not generalise.writable(candidate):
        return None
    return candidate


def source_covers_destination(grants: dict[str, frozenset[str]],
                              moves: set[tuple[str, str]]) -> tuple[dict[str, frozenset[str]], list[tuple[str, str, str]]]:
    """Gives the source of every move the sections its destination holds, until nothing changes (plan A.6.2).

    Landlock refuses a rename or link across directories when the file would gain access rights in the
    destination that it lacked in the source. What a directory holds counts with what its ancestors
    grant. [execute] is never given to a source: the source holds write-class rights, and [execute]
    never sits beside one; such a move is returned as withheld, (source, destination, section).
    """
    result = {path: frozenset(sections) for path, sections in grants.items()}
    withheld: set[tuple[str, str, str]] = set()
    changed = True
    while changed:
        changed = False
        for source, destination in sorted(moves):
            held = _held_at(destination, result)
            missing = {section for section in held
                       if not cfgfile.SECTION_RIGHTS[section] <= cfgfile.rights_of(_held_at(source, result))}
            for section in sorted(missing):
                if section == "execute":
                    withheld.add((source, destination, section))
                    continue
                result[source] = result.get(source, frozenset()) | {section}
                changed = True
    return result, sorted(withheld)


def _held_at(path: str, grants: dict[str, frozenset[str]]) -> frozenset[str]:
    """The sections granted on a path or on any of its ancestors."""
    held: frozenset[str] = frozenset()
    for other, sections in grants.items():
        if other == path or cfgfile.is_beneath(path, other):
            held |= sections
    return held


def missing_read_or_execute(grants: dict[str, frozenset[str]], recorded: Recorded) -> list[str]:
    """The [read] and [execute] rows whose path did not exist before the sessions; empty when the invariant holds.

    phobos-policysystem.sh refuses such a row, and a row for a path a session created would grant
    nothing a fresh container has.
    """
    return sorted(path for path, sections in grants.items()
                  if sections & generalise.READ_CLASS and not recorded.existed(path))


def widenings(grants: dict[str, frozenset[str]], everything: list[Need], recorded: Recorded,
              reasons: dict[str, str]) -> list[dict]:
    """Every directory grant with the objects the sessions touched beneath it, how many entries it covers and why."""
    observed = sorted({path for need in everything for path in need.objects})
    found = []
    for path, sections in sorted(grants.items()):
        if not recorded.is_directory(path):
            continue
        behind = [item for item in observed if item == path or cfgfile.is_beneath(item, path)]
        beneath = sum(1 for other in recorded.listings[0] if cfgfile.is_beneath(other, path)) if recorded.listings else 0
        found.append({"path": path, "sections": sorted(sections), "observed": behind[:EVIDENCE_EXAMPLES],
                      "observed_count": len(behind), "files_beneath": beneath, "reason": reasons.get(path, "")})
    return found


def derived_limits(metas: list[dict], measurements: list[limits.Measurement],
                   memory_pinned: bool) -> tuple[dict[str, int], list[str]]:
    """The limits the sampled sessions give, and the header lines saying which were not derived and why.

    A timeout comes only from sessions that all ran with standard input not a terminal: the wall
    clock of an interactive session measures the person at the keyboard. `mem_mb` comes only when the
    caller asserts the program pins its address space (ulimit -v bounds address space, not use).
    """
    if not measurements:
        return {}, [NO_LIMITS_LINE]
    values = limits.margins(measurements, limits.Margins(), memory_pinned)
    header = []
    if any(meta.get("interactive") for meta in metas):
        values.pop("timeout", None)
        header.append(INTERACTIVE_LIMIT_LINE)
    if not memory_pinned:
        header.append(MEMORY_LINE)
    return values, header


def policysystem_gate(phobos_home: pathlib.Path) -> Callable[[pathlib.Path], tuple[int, str]]:
    """A gate that has phobos-policysystem.sh build a specification from the policy, as an exercise configuration.

    The specification is built under /var/tmp, never /tmp, and removed again. The gate answers the
    status and what the script printed.
    """

    def gate(policy: pathlib.Path) -> tuple[int, str]:
        """Runs the real parser over the policy; 0 means it accepts it."""
        spec = tempfile.mkdtemp(prefix="record-gate.", dir=SPEC_PARENT)
        try:
            argv = [str(phobos_home / "phobos-policysystem.sh"), "--spec-dir", spec, "--config", str(policy)]
            checked = subprocess.run(argv, capture_output=True, text=True, check=False)  # nosec B603
        finally:
            subprocess.run(["rm", "-rf", spec], check=False)  # nosec B603 B607
        return checked.returncode, (checked.stdout + checked.stderr).strip()

    return gate


def write(directory: pathlib.Path, with_limits: bool, memory_pinned: bool,
          gate: Callable[[pathlib.Path], tuple[int, str]]) -> int:
    """Writes policy.cfg and record.json for the recording and runs the policy through the gate.

    Answers 0, EXIT_INVARIANT when a [read] or [execute] row names a path that did not exist before
    the sessions (nothing is written then), EXIT_GATE when phobos-policysystem.sh refuses the policy
    (the files stay, for inspection), or EXIT_INCOMPLETE after writing both files when a recorded call
    was not mapped. A recording without a session raises ValueError.
    """
    recording = load(directory)
    if not recording.sessions:
        raise ValueError(f"{directory} holds no recorded session")
    found = filesystem_grants(recording)
    grants = found.grants
    recorded = Recorded([session.listing for session in recording.sessions])
    absent = missing_read_or_execute(grants, recorded)
    if absent:
        print("phobos-record: these [read] or [execute] rows name paths that did not exist before the sessions:\n  "
              + "\n  ".join(repr(path) for path in absent), flush=True)
        return EXIT_INVARIANT
    hosts = recording.sessions[0].hosts
    network = endpoints.rules([session.network for session in recording.sessions], hosts)
    values: dict[str, int] = {}
    limit_header = [NO_LIMITS_LINE]
    if with_limits:
        measured = [session.measurement for session in recording.sessions if session.measurement is not None]
        values, limit_header = derived_limits([session.meta for session in recording.sessions], measured, memory_pinned)
        if measured:
            limit_header.append(f"Limits were derived from {len(measured)} of {len(recording.sessions)} sampled sessions.")
    unsupported = [line for session in recording.sessions for line in session.needs.unsupported]
    fixed = list(dict.fromkeys(line for session in recording.sessions for line in session.needs.fixed))
    ignored: list[dict] = []
    moves = placed_moves({move for session in recording.sessions for move in session.needs.moves}, recorded, ignored)
    _, withheld = source_covers_destination(grants, moves)
    policy = cfgfile.Policy(
        fs=grants, connect=network.connect, bind=network.bind, limits=values, comments=found.comments,
        header=_header(recording, network.needs_resolver, limit_header, len(unsupported), len(found.ungranted)),
        notes=(*(REFUSAL_LINE.format(description=line) for line in fixed),
               *(NOT_GRANTED_LINE.format(path=item["path"], section=item["section"], reason=item["reason"])
                 for item in found.ungranted),
               *(WITHHELD_LINE.format(source=s, destination=d, section=section) for s, d, section in withheld),
               *(f"Not granted: {note}" for note in network.notes)))
    text = cfgfile.render(policy)
    (directory / "policy.cfg").write_text(text, encoding="utf-8")
    (directory / "record.json").write_text(json.dumps(_record(recording, found, network, values, fixed, unsupported,
                                                              withheld), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    status, message = gate(directory / "policy.cfg")
    if status != 0:
        print(f"phobos-record: phobos-policysystem.sh refused the generated policy (status {status}):\n{message}", flush=True)
        return EXIT_GATE
    if unsupported or found.ungranted:
        print(f"phobos-record: {len(unsupported)} recorded calls are not mapped and {len(found.ungranted)} accesses "
              "cannot be granted; see record.json", flush=True)
        return EXIT_INCOMPLETE
    return 0


def _header(recording: Recording, needs_resolver: bool, limit_header: list[str], unsupported: int,
            ungranted: int) -> tuple[str, ...]:
    """The header lines: what the file is, from how many sessions, what it does not cover, what it needs."""
    dates = sorted({str(session.meta.get("started", ""))[:10] for session in recording.sessions} - {""})
    lines = [INCOMPLETE_LINE.format(count=unsupported)] if unsupported else []
    if ungranted:
        lines.append(UNGRANTED_LINE.format(count=ungranted))
    first, *rest = HEADER
    lines.append(first.format(count=len(recording.sessions), dates=", ".join(dates) or "undated"))
    lines.extend(rest)
    if needs_resolver:
        lines.append(RESOLVER_LINE)
    lines.extend(limit_header)
    return tuple(lines)


def _record(recording: Recording, found: Grants, network: endpoints.NetworkRules,
            values: dict[str, int], fixed: list[str], unsupported: list[str],
            withheld: list[tuple[str, str, str]]) -> dict:
    """record.json: every grant with the calls behind it, the widenings, and everything left ungranted."""
    all_needs = [need for session in recording.sessions for need in session.needs.needs]
    return {
        "sessions": [{"number": session.number, "command": session.meta.get("command"),
                      "started": session.meta.get("started"), "status": session.meta.get("status"),
                      "interactive": session.meta.get("interactive"), "landlock_abi": session.meta.get("landlock_abi"),
                      "strace": session.meta.get("strace")} for session in recording.sessions],
        "grants": [{"path": path, "sections": sorted(sections), **_evidence(path, all_needs)}
                   for path, sections in sorted(found.grants.items())],
        "widenings": found.widenings,
        "ungranted": found.ungranted,
        "fixed_refusals": fixed,
        "tolerated": sorted({line for session in recording.sessions for line in session.needs.tolerated}),
        "unsupported": unsupported,
        "moves_withheld": [list(item) for item in withheld],
        "network": {"connect": [{"rule": rule.text, "comment": rule.comment} for rule in network.connect],
                    "bind": [{"rule": rule.text, "comment": rule.comment} for rule in network.bind],
                    "notes": list(network.notes), "needs_resolver": network.needs_resolver,
                    "rejected_names": list(network.rejected_names),
                    "reached": [dataclasses.asdict(endpoint) for endpoint in network.reached]},
        "limits": values,
    }


def _evidence(path: str, all_needs: list[Need]) -> dict:
    """The calls behind a grant: how many needs lie at or beneath the path and the first few of them."""
    behind = [need for need in all_needs
              if any(item == path or cfgfile.is_beneath(item, path) for item in need.objects)]
    return {"needs": len(behind), "evidence": [need.evidence for need in behind[:EVIDENCE_EXAMPLES]]}
