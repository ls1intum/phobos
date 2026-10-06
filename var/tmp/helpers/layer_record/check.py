"""The replay check: does a recorded session still run under the real layers with its policy?

This module so far holds the part that decides where the check may run. A replay in the
recording's own container, or in one whose starting state differs from the recording's, can pass
on files the recording or an earlier run left behind, so the check compares the container's
starting state with the recording's rather than taking freshness on trust, and refuses a
container that is not fresh unless the caller opts in with --same-container (Markus's decision 12
in the recording pruner's plan).

A recording directory holds `sessions/<n>/session.json` for every session, naming the
`container_id` it was recorded in and the `snapshot` of that container, a path relative to the
recording directory.
"""

from __future__ import annotations

import json
import pathlib

from layer_record import (
    guard,
    snapshot,
)

NOT_FRESH_WARNING = ("Warning: this check does not run in a fresh container. Files the recording or an "
                     "earlier run left behind can make it pass where a fresh container would fail.")

# How many differing paths a refusal names before it only counts the rest.
MAX_LISTED_DIFFERENCES = 20


def mode(recording: pathlib.Path, container_id: str, fingerprint: dict[str, str], same_container: bool) -> str:
    """Which kind of container the replay runs in, or a refusal when it may not run there.

    Assumes fingerprint is this container's starting state from snapshot.fingerprint, taken after
    the exercise was copied in afresh and before the replay. Answers "fresh-container" when no
    session of the recording ran in container_id and the fingerprint equals the one of the
    recording's first session. Otherwise answers "same-container" (a container a session ran in)
    or "changed-container" (another container whose starting state differs) when same_container
    is set, and raises guard.Refused with EXIT_ENVIRONMENT, naming the container or the
    differences, when it is not.
    """
    sessions = _sessions(recording)
    if any(meta["container_id"] == container_id for meta in sessions):
        if same_container:
            return "same-container"
        raise guard.Refused(guard.EXIT_ENVIRONMENT,
                            f"This container ({container_id}) recorded a session of {recording}, so a replay "
                            "here is not fresh. Run the check in a new container, or pass --same-container "
                            "to accept a check that may pass on what the recording left behind.")
    differences = _differences(_starting_state(recording, sessions[0]), fingerprint)
    if not differences:
        return "fresh-container"
    if same_container:
        return "changed-container"
    raise guard.Refused(guard.EXIT_ENVIRONMENT,
                        "This container does not start in the state the recording started in, so a replay "
                        "here is not fresh. Run the check in a new container, or pass --same-container to "
                        "accept that. What differs:\n" + _listed(differences))


def _sessions(recording: pathlib.Path) -> list[dict]:
    """The metadata of every session of the recording, in the order the sessions were recorded.

    Assumes sessions are the numbered directories under `sessions/`. Raises guard.Refused with
    EXIT_USAGE when there is none, or when a session.json lacks the keys the check reads.
    """
    numbered = [path for path in (recording / "sessions").glob("*") if path.name.isdigit()]
    sessions = []
    for directory in sorted(numbered, key=lambda path: int(path.name)):
        meta = json.loads((directory / "session.json").read_text(encoding="utf-8"))
        if not isinstance(meta, dict) or "container_id" not in meta or "snapshot" not in meta:
            raise guard.Refused(guard.EXIT_USAGE,
                                f"{directory / 'session.json'} does not name its container_id and snapshot.")
        sessions.append(meta)
    if not sessions:
        raise guard.Refused(guard.EXIT_USAGE,
                            f"{recording} holds no recorded session. Record one with phobos-record record first.")
    return sessions


def _starting_state(recording: pathlib.Path, first: dict) -> dict[str, str]:
    """The first session's snapshot as a fingerprint, the files Docker writes itself left out.

    Assumes the snapshot was written by snapshot.take, which keeps those files.
    """
    listing = snapshot.read_listing(recording / first["snapshot"])
    return {path: value for path, value in listing.items() if path not in snapshot.DOCKER_MANAGED}


def _differences(recorded: dict[str, str], current: dict[str, str]) -> list[str]:
    """Every path whose fingerprint differs between the two states, with what differs, sorted.

    Assumes both mappings were made with the same rules, so a difference is a change and not a
    difference in how they were taken. Paths and fingerprints are quoted as Python literals, so a
    name holding a line break cannot make the message say something else.
    """
    differences = []
    for path in sorted(recorded.keys() | current.keys()):
        was = recorded.get(path)
        now = current.get(path)
        if was == now:
            continue
        if was is None:
            differences.append(f"{path!r}: added ({now!r})")
        elif now is None:
            differences.append(f"{path!r}: removed (was {was!r})")
        else:
            differences.append(f"{path!r}: was {was!r}, now {now!r}")
    return differences


def _listed(differences: list[str]) -> str:
    """At most MAX_LISTED_DIFFERENCES differences, one per line, and the number left out."""
    lines = [f"  {difference}" for difference in differences[:MAX_LISTED_DIFFERENCES]]
    rest = len(differences) - MAX_LISTED_DIFFERENCES
    if rest > 0:
        lines.append(f"  and {rest} more")
    return "\n".join(lines)
