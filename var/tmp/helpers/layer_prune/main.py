"""The layer pruner's command line: prune every exercise of one language key and write its artefacts (A.9).

    python3 main.py [--stage filesystem|network|limits|all] [--testing-root DIR] [--output-dir DIR]
                    [--resolver ADDRESS] [--verify MERGED_DIR] [--kernel-observer audit] <key>

For each exercise under <testing-root>/<key> it writes <key>_<exercise>.cfg, the policy, and
<key>_<exercise>.json, the record (schema version 2), each to a temporary file renamed into place, and
only once the exercise has passed every stage, the joint verification and the containment checks. A
run stopped after an earlier stage (--stage) writes its artefacts under partial/ instead, where the
orchestrator never looks, with the stage named in the header. An exercise that aborts, for any
reason including a defect of the pruner, gets <key>_<exercise>.aborted.json with the reason and no
.cfg, and the command then ends with status 1 naming each. Earlier artefacts of the key are removed
first, so no stale file survives a prune.

With --verify it prunes nothing: it runs every exercise of the key under the orchestrator's merged
BaseLanguage-<key>.cfg and exercises/<key>_<exercise>.cfg in MERGED_DIR, as grading will apply them,
writes verify/<key>_<exercise>.json beneath the output directory, and ends with status 1 naming each
exercise that did not match its reference. It touches no artefact of the prune.

With --kernel-observer audit, which runs only in a KVM guest (A.6.9), it prunes nothing either: for each
exercise it reads <key>_<exercise>.cfg and its record from the output directory, checks strace's
attribution against the kernel's own Landlock audit records and verifies the policy on this kernel's
Landlock ABI, and writes <key>_<exercise>.abi10.json, and <key>_<exercise>.abi10.cfg only where it adds a
UDP bind row (kvm.py). It ends with status 3 where the guest cannot observe the records at all.
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
import tempfile

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from layer_prune import cfgfile, generalise, kvm, runner, search, stages

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
# Where the artefacts of a run stopped after an earlier stage go, beneath the output directory.
PARTIAL_DIRECTORY = "partial"
# Where the verification of the merged base writes its records, beneath the output directory.
VERIFY_DIRECTORY = "verify"


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


def header(origin: dict[str, str | int], key: str, exercise: str, stage: str) -> str:
    """The comment lines a written .cfg starts with: what pruned it, where, as whom, and up to which stage."""
    lines = [f"Pruned by the {origin['pruner']} for {key}/{exercise} on {origin['date']}, stage {stage}.",
             (f"Kernel {origin['kernel']} ({origin['architecture']}), Landlock ABI {origin['landlock_abi']}, "
              f"uid {origin['uid']}, {origin['strace']}."),
             ("Every grant rests on a refusal the grading layers recorded, except the [connect] rules of the "
              "declared hosts; see the .json beside this file.")]
    if stage != "all":
        lines.append("Not verified jointly and not checked for containment: not a policy to ship.")
    for line in lines:
        cfgfile.check_rule(line)
    return "".join(f"# {line}\n" for line in lines)


def write_atomically(path: pathlib.Path, text: str) -> None:
    """Writes the file to a temporary name beside it and renames it into place."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text)
    os.replace(temporary, path)


def remove_stale(output: pathlib.Path, key: str) -> None:
    """Removes every earlier artefact of this key, partial ones, verifications and the `.paths` of the retired
    Bubblewrap pruner included, so none survives a prune.

    Meant for the keys the layer pruner owns: a key still produced as path sets would lose them.
    """
    for directory in (output, output / PARTIAL_DIRECTORY, output / VERIFY_DIRECTORY):
        for pattern in (f"{key}_*.cfg", f"{key}_*.json", f"{key}_*.paths"):
            for path in directory.glob(pattern):
                path.unlink()


def abort_record(failure: BaseException) -> dict:
    """The reason and the evidence of an aborted exercise: a PruneAbort's own, a refusal's or a defect's."""
    if isinstance(failure, search.PruneAbort):
        return {"aborted": failure.reason, "evidence": stages.jsonable(failure.evidence)}
    if isinstance(failure, runner.ExerciseRefused):
        return {"aborted": f"the exercise was refused: {failure.reason}", "evidence": {}}
    if isinstance(failure, runner.PrunerDefect):
        return {"aborted": f"a defect of the pruner: {failure.reason}",
                "evidence": {"status": failure.status, "log": str(failure.log_path)}}
    return {"aborted": f"a defect of the pruner: {type(failure).__name__}: {failure}", "evidence": {}}


def prune_one(directory: pathlib.Path, key: str, stage: str, environment: runner.Environment,
              output: pathlib.Path, origin: dict[str, str | int], pristine: generalise.Snapshot) -> str | None:
    """Prunes one exercise and writes its artefacts; the abort reason, or None when it succeeded.

    Whatever ends the exercise early, a defect of the pruner included, is written as its aborted
    record, and the next exercise is pruned all the same. The except is broad for that reason.
    """
    base = f"{key}_{directory.name}"
    try:
        exercise = runner.read_exercise(directory)
        pruned = stages.prune_exercise(exercise, stages.Budget(), environment, stage, pristine)
        policy = pruned[0]
        text = header(origin, key, directory.name, stage) + cfgfile.render(policy)
    except Exception as failure:  # noqa: BLE001
        aborted = abort_record(failure)
        write_atomically(output / f"{base}.aborted.json",
                         json.dumps({"schema_version": SCHEMA_VERSION, "key": key, "exercise": directory.name,
                                     "stage": stage, **aborted, "provenance": origin}, indent=2, sort_keys=True)
                         + "\n")
        return aborted["aborted"]
    log = pruned[1]
    if stage != "all":
        output = output / PARTIAL_DIRECTORY
        output.mkdir(exist_ok=True)
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
    parser.add_argument("--testing-root", default=DEFAULT_TESTING_ROOT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--resolver", default=None, help="the resolver phobos.sh is given for declared hosts")
    parser.add_argument("--verify", default=None, metavar="MERGED_DIR",
                        help="verify the orchestrator's merged configuration in MERGED_DIR instead of pruning")
    parser.add_argument("--kernel-observer", choices=("audit",), default=None,
                        help="in a KVM guest, check strace's attribution against Landlock's audit records and add ABI 10 rows")
    parser.add_argument("key")
    return parser.parse_args(argv)


def overlaps(path: pathlib.Path, other: pathlib.Path) -> bool:
    """Whether two directories are one, or one lies beneath the other, once resolved."""
    first = path.resolve()
    second = other.resolve()
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


def verify_one(directory: pathlib.Path, key: str, environment: runner.Environment, merged: pathlib.Path,
               output: pathlib.Path, pristine: generalise.Snapshot, origin: dict[str, str | int]) -> str | None:
    """Verifies one exercise under the merged configuration and writes its record; the reason it failed, or None.

    Both files must be there: the orchestrator writes one per exercise it merged, so an exercise
    without one was not merged, and grading would never apply the base to it alone. The broad except
    writes any failure, a defect of the pruner included, as the exercise's result.
    """
    configs = (merged / f"BaseLanguage-{key}.cfg", merged / "exercises" / f"{key}_{directory.name}.cfg")
    entry: dict = {"schema_version": SCHEMA_VERSION, "key": key, "exercise": directory.name,
                   "configs": [str(config) for config in configs], "provenance": origin}
    if all(config.is_file() for config in configs):
        entry["configs_sha256"] = [hashlib.sha256(config.read_bytes()).hexdigest() for config in configs]
    reason = None
    try:
        missing = [str(config) for config in configs if not config.is_file()]
        if missing:
            raise search.PruneAbort(f"the merged configuration lacks {', '.join(missing)}: was it merged before "
                                    "this exercise was pruned?")
        entry["log"] = stages.jsonable(stages.verify_merged(runner.read_exercise(directory), configs, environment,
                                                            pristine))
    except Exception as failure:  # noqa: BLE001
        aborted = abort_record(failure)
        entry |= aborted
        reason = aborted["aborted"]
    entry["verified"] = reason is None
    (output / VERIFY_DIRECTORY).mkdir(parents=True, exist_ok=True)
    write_atomically(output / VERIFY_DIRECTORY / f"{key}_{directory.name}.json", json.dumps(entry, indent=2, sort_keys=True) + "\n")
    return reason


def kernel_observe(options: argparse.Namespace, environment: runner.Environment, exercises: list[pathlib.Path],
                   output: pathlib.Path, origin: dict[str, str | int], pristine: generalise.Snapshot) -> int:
    """Runs the audit observer over every exercise of the key; 0 when all held, EXIT_ABORTED or EXIT_INDETERMINATE."""
    failed = False
    with tempfile.TemporaryDirectory(prefix="layer-prune-kvm.") as scratch:
        capture = None
        try:
            capture = kvm.Capture(sentinel=kvm.sentinel_for(environment, pathlib.Path(scratch)))
            proof = kvm.selftest(environment, capture, int(origin["landlock_abi"]), pathlib.Path(scratch))
            print(f"the guest observes Landlock: {proof['selftest_record']}", flush=True)
            for directory in exercises:
                entry, sidecar, reason = kvm.verify_exercise(directory, options.key, environment, output, pristine,
                                                             origin, capture, abort_record)
                base = f"{options.key}_{directory.name}"
                for stale in (output / f"{base}.abi10.cfg", output / f"{base}.abi10.json"):
                    stale.unlink(missing_ok=True)
                if sidecar is not None:
                    write_atomically(output / f"{base}.abi10.cfg", sidecar)
                write_atomically(output / f"{base}.abi10.json", json.dumps(entry, indent=2, sort_keys=True) + "\n")
                print(f"{options.key}/{directory.name}: "
                      f"{'verified on this kernel' if reason is None else 'failed: ' + reason}", flush=True)
                failed = failed or reason is not None
        except (kvm.Indeterminate, OSError) as failure:
            print(f"the guest cannot observe Landlock's audit records: {failure}", file=sys.stderr)
            return kvm.EXIT_INDETERMINATE
        finally:
            if capture is not None:
                capture.close()
    return EXIT_ABORTED if failed else 0


def main(argv: list[str]) -> int:
    """Prunes, or with --verify verifies, every exercise of the key; 0 when all succeeded, EXIT_ABORTED otherwise."""
    options = arguments(argv)
    if options.verify is not None and options.stage != "all":
        print("--verify checks the merged configuration of a whole prune; it takes no --stage", file=sys.stderr)
        return EXIT_ABORTED
    if options.kernel_observer is not None and (options.verify is not None or options.stage != "all"):
        print("--kernel-observer checks a finished prune on this kernel; it takes neither --verify nor --stage",
              file=sys.stderr)
        return EXIT_ABORTED
    if os.environ.get(stages.PRUNE_CONTAINER_VARIABLE) != "1":
        print(f"the pruner removes what its runs leave behind, so it runs only in the prune container, which sets "
              f"{stages.PRUNE_CONTAINER_VARIABLE}=1", file=sys.stderr)
        return EXIT_ABORTED
    environment = runner.Environment(resolver=options.resolver, kept=(options.output_dir,))
    root = pathlib.Path(options.testing_root) / options.key
    for name, given in (("testing root", options.testing_root), ("output directory", options.output_dir)):
        if overlaps(pathlib.Path(given), pathlib.Path(environment.testing_dir)):
            print(f"the {name} {given} overlaps {environment.testing_dir}, which every run replaces; refusing it",
                  file=sys.stderr)
            return EXIT_ABORTED
    if not root.is_dir():
        print(f"no exercise under {root}", file=sys.stderr)
        return EXIT_ABORTED
    output = pathlib.Path(options.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    if options.kernel_observer is not None:
        pass
    elif options.verify is None:
        remove_stale(output, options.key)
    else:
        for stale in (output / VERIFY_DIRECTORY).glob(f"{options.key}_*.json"):
            stale.unlink()
    exercises = sorted(path for path in root.iterdir() if path.is_dir() and not path.name.startswith("."))
    origin = provenance(environment)
    pristine = stages.pristine_index(environment)
    if options.kernel_observer is not None:
        if not exercises:
            print(f"no exercise under {options.testing_root}/{options.key}", file=sys.stderr)
            return EXIT_ABORTED
        return kernel_observe(options, environment, exercises, output, origin, pristine)
    aborted = {}
    for directory in exercises:
        if options.verify is None:
            reason = prune_one(directory, options.key, options.stage, environment, output, origin, pristine)
            done = "pruned"
        else:
            reason = verify_one(directory, options.key, environment, pathlib.Path(options.verify), output, pristine,
                                origin)
            done = "verified"
        print(f"{options.key}/{directory.name}: {done if reason is None else 'aborted: ' + reason}", flush=True)
        if reason is not None:
            aborted[directory.name] = reason
    if not exercises:
        print(f"no exercise under {options.testing_root}/{options.key}", file=sys.stderr)
        return EXIT_ABORTED
    return EXIT_ABORTED if aborted else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
