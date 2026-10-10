"""Which exercises of a testing root belong to a key.

The root holds <family>/<exercise>/. An exercise belongs to the key its prune.json names with "key", and
to the key that is its family's folder name when it names none. The folder a reference exercise lives in
is therefore free to group related exercises (exercises/java holds the Gradle and the Maven reference),
while the key, which names the artefacts and the base the exercise is merged into, is stated by the
exercise itself.

Only "key" is read here. Every other setting is judged later, per exercise, by runner.read_settings, so
one exercise's bad setting still aborts that exercise alone. What cannot be judged later is a prune.json
from which no key can be read, because then it is unknown which key's policy the exercise would have
changed: that ends the whole invocation, before anything is written, rather than let a language policy
be merged without one of its exercises.
"""

from __future__ import annotations

import json
import os
import pathlib
import re

# What a key may be: it ends up in file names, on kernel command lines and in the base's name.
KEY_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class DiscoveryRefused(Exception):
    """The tree cannot be sorted into keys without guessing; the invocation ends before it writes anything."""


def visible_directories(parent: pathlib.Path) -> list[pathlib.Path]:
    """The subdirectories of parent that do not start with a dot, in name order."""
    return sorted(path for path in parent.iterdir() if path.is_dir() and not path.name.startswith("."))


def key_of(family: str, directory: pathlib.Path) -> str:
    """The key of one exercise: the "key" of its prune.json, else its family's folder name.

    Raises DiscoveryRefused for a prune.json that cannot be read, that is not a JSON object, or whose "key"
    is not a string of lower-case words joined by hyphens.
    """
    path = directory / "prune.json"
    if not os.path.lexists(path):
        return family
    if not path.is_file():
        raise DiscoveryRefused(f"{path} is not a file, so the key of its exercise is unknown")
    try:
        settings = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiscoveryRefused(f"{path} cannot be read, so the key of its exercise is unknown: {error}") from error
    if not isinstance(settings, dict):
        raise DiscoveryRefused(f"{path} does not hold a JSON object, so the key of its exercise is unknown")
    if "key" not in settings:
        return family
    declared = settings["key"]
    if not isinstance(declared, str) or not KEY_PATTERN.fullmatch(declared):
        raise DiscoveryRefused(f"{path} holds a key that is not lower-case words joined by hyphens: {declared!r}")
    return declared


def exercises_of(testing_root: pathlib.Path, key: str) -> list[pathlib.Path]:
    """The exercise directories under testing_root whose key is key, in family and name order.

    Raises DiscoveryRefused when any exercise's key cannot be read, or when two exercises of the key share a
    folder name, because the artefacts are named <key>_<folder name> and one would overwrite the other.
    """
    found = [directory
             for family in visible_directories(testing_root)
             for directory in visible_directories(family)
             if key_of(family.name, directory) == key]
    seen: dict[str, pathlib.Path] = {}
    for directory in found:
        if directory.name in seen:
            raise DiscoveryRefused(f"{seen[directory.name]} and {directory} are both the exercise {directory.name} "
                                   f"of the key {key}, and would write the same artefacts")
        seen[directory.name] = directory
    return found
