"""The layer pruner's command line: prune every exercise of one language key and write its artefacts (A.9).

    python3 main.py [--stage filesystem|network|limits|all] [--testing-root DIR] [--output-dir DIR] <key>

For each exercise under <testing-root>/<key> it writes <key>_<exercise>.cfg, the policy, and
<key>_<exercise>.json, the record (schema version 2), each to a temporary file renamed into place, and
only once the exercise has passed every stage asked for. An exercise that aborts gets
<key>_<exercise>.aborted.json with the reason and no .cfg, and the command then ends with status 1
naming each. Earlier artefacts of the key are removed first, so no stale file survives a prune.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess  # nosec B404
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from layer_prune import cfgfile, runner, search, stages

# The record's schema version (A.9).
SCHEMA_VERSION = 2
# Where the prune container mounts the exercises read-only, and where the artefacts go (A.6.1).
DEFAULT_TESTING_ROOT = "/srv/phobos-prune-exercises"
DEFAULT_OUTPUT_DIR = "/var/tmp/path_sets"
# The stages main can stop after, in pipeline order.
STAGES = ("filesystem", "network", "limits", "all")
# landlock_create_ruleset's number, the same on every architecture, and its flag that asks for the version.
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_CREATE_RULESET_VERSION = 1
# The status main ends with when an exercise aborted.
EXIT_ABORTED = 1


def landlock_version() -> int:
    """The Landlock ABI version this kernel offers, or -1 where it offers none."""
    libc = ctypes.CDLL(None, use_errno=True)
    return int(libc.syscall(LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION))


def strace_version(environment: runner.Environment) -> str:
    """The first line strace -V prints, or "absent"."""
    if shutil.which(environment.strace) is None:
        return "absent"
    finished = subprocess.run([environment.strace, "-V"], capture_output=True, text=True, check=False)  # nosec B603
    return finished.stdout.splitlines()[0] if finished.stdout else "unknown"


def provenance(environment: runner.Environment) -> dict[str, str | int]:
    """What the record and the .cfg header say about where the policy was pruned."""
    return {"pruner": "phobos layer pruner", "kernel": platform.release(), "architecture": platform.machine(),
            "landlock_abi": landlock_version(), "uid": os.getuid(), "strace": strace_version(environment),
            "date": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")}


def header(origin: dict[str, str | int], key: str, exercise: str) -> str:
    """The comment lines a written .cfg starts with: what pruned it, where, and as whom."""
    lines = [f"Pruned by the {origin['pruner']} for {key}/{exercise} on {origin['date']}.",
             (f"Kernel {origin['kernel']} ({origin['architecture']}), Landlock ABI {origin['landlock_abi']}, "
              f"uid {origin['uid']}, {origin['strace']}."),
             "Every grant rests on a refusal the grading layers recorded; see the .json beside this file."]
    for line in lines:
        cfgfile.check_rule(line)
    return "".join(f"# {line}\n" for line in lines)


def write_atomically(path: pathlib.Path, text: str) -> None:
    """Writes the file to a temporary name beside it and renames it into place."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text)
    os.replace(temporary, path)


def remove_stale(output: pathlib.Path, key: str) -> None:
    """Removes every earlier artefact of this key, so none survives into the orchestrator's merge."""
    for pattern in (f"{key}_*.cfg", f"{key}_*.json"):
        for path in output.glob(pattern):
            path.unlink()


def prune_one(directory: pathlib.Path, key: str, stage: str, environment: runner.Environment,
              output: pathlib.Path, origin: dict[str, str | int]) -> str | None:
    """Prunes one exercise and writes its artefacts; the abort reason, or None when it succeeded."""
    base = f"{key}_{directory.name}"
    try:
        exercise = runner.read_exercise(directory)
        policy, log = stages.prune_exercise(exercise, stages.Budget(), environment, stage)
    except (search.PruneAbort, runner.ExerciseRefused, runner.PrunerDefect) as failure:
        evidence = getattr(failure, "evidence", {})
        reason = getattr(failure, "reason", str(failure))
        write_atomically(output / f"{base}.aborted.json",
                         json.dumps({"schema_version": SCHEMA_VERSION, "key": key, "exercise": directory.name,
                                     "stage": stage, "aborted": reason, "evidence": stages.jsonable(evidence),
                                     "provenance": origin}, indent=2, sort_keys=True) + "\n")
        return reason
    text = header(origin, key, directory.name) + cfgfile.render(policy)
    digest = hashlib.sha256(text.encode()).hexdigest()
    record = {"schema_version": SCHEMA_VERSION, "key": key, "exercise": directory.name, "stage": stage,
              "provenance": origin, "cfg_sha256": digest, "policy": stages.jsonable(dataclasses.asdict(policy)),
              "log": stages.jsonable(log)}
    write_atomically(output / f"{base}.cfg", text)
    write_atomically(output / f"{base}.json", json.dumps(record, indent=2, sort_keys=True) + "\n")
    return None


def arguments(argv: list[str]) -> argparse.Namespace:
    """The command line."""
    parser = argparse.ArgumentParser(description="Prune every exercise of one key on the grading layers.")
    parser.add_argument("--stage", choices=STAGES, default="all")
    parser.add_argument("--testing-root", default=os.environ.get("TESTING_DIR", DEFAULT_TESTING_ROOT))
    parser.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR", DEFAULT_OUTPUT_DIR))
    parser.add_argument("key")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Prunes every exercise of the key; 0 when all succeeded, EXIT_ABORTED naming each that aborted."""
    options = arguments(argv)
    environment = runner.Environment()
    output = pathlib.Path(options.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    remove_stale(output, options.key)
    exercises = sorted(path for path in (pathlib.Path(options.testing_root) / options.key).iterdir() if path.is_dir())
    origin = provenance(environment)
    aborted = {}
    for directory in exercises:
        reason = prune_one(directory, options.key, options.stage, environment, output, origin)
        print(f"{options.key}/{directory.name}: {'pruned' if reason is None else 'aborted: ' + reason}", flush=True)
        if reason is not None:
            aborted[directory.name] = reason
    if not exercises:
        print(f"no exercise under {options.testing_root}/{options.key}", file=sys.stderr)
        return EXIT_ABORTED
    return EXIT_ABORTED if aborted else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
