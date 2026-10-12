"""The steps of `phobos-cli.sh submissions` that run in a container but run no submission code.

    python3 submissions.py check-template TEMPLATE KEY
    python3 submissions.py seal RUN KEY HELPERS RUN_PHASE_IMAGE PRUNE_IMAGE
    python3 submissions.py validate RUN KEY HELPERS RUN_PHASE_IMAGE PRUNE_IMAGE
    python3 submissions.py union RUN KEY HELPERS
    python3 submissions.py batch RUN BATCH HELPERS
    python3 submissions.py verify-report RUN BATCH KEY HELPERS

A policy from past student submissions is the layer pruner's policy of each submission, staged over
the exercise's template, merged. The pruner runs a submission's baseline without Phobos, so a
submission can shape its own result: this whole use rests on the instructor's assumption that the
submissions are vetted and harmless. What these steps do guarantee is that the result is exactly the
union of what the pruner wrote for each submission, measured against the grading bases of the image,
and that nothing changed between the steps: every input is sealed by its digest and checked again
before it is used.

check-template refuses a template whose trusted files could be reached by student material. seal
classifies each submission's prune and writes the manifest, and validate checks it again, with the images
a verification is to use. union writes the candidate policy, a
report, and the rows the menu offers. batch fixes the policy one verification checks, and
verify-report classifies that verification. Each ends with 0 when it succeeded, with EXIT_REFUSED when
what it found does not hold, and verify-report with EXIT_MISMATCH when the policy did not match the
reference of a submission.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import pathlib
import stat
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3]))

from exercise_pruner.src.application import discovery
from exercise_pruner.src.domain import verdict
from exercise_pruner.src.infrastructure import runner
from exercise_pruner.src.interface import orchestrate
from shared.src.domain import cfgfile, generalise

# The digest format of a tree, named in every manifest so that a later change of format is never
# compared with an earlier one.
TREE_FORMAT = "phobos-tree-v2"
# The manifest's and the batch's schema versions.
MANIFEST_SCHEMA = 1
BATCH_SCHEMA = 1
# The layer pruner's record schema version, as main.py writes it.
RECORD_SCHEMA = 2
# The directory the student material is staged in, the only one a submission replaces.
ASSIGNMENT = "assignment"
# The reason verify_merged gives when a run under the policy did not match the submission's reference.
MISMATCH = "a run under the merged base and its exercise file did not match the reference"
# How an abort record names a defect of the pruner rather than an outcome of the submission.
DEFECT_PREFIX = "a defect of the pruner"
# The key whose template may declare pinned read roots: the Maven repository the image pre-loads.
PINNED_KEY = "java-maven"
# The file name of the prune image's own base, which must grant nothing.
PRUNE_BASE = "BasePrune.cfg"
# The exit statuses: refused, and a verification that did not match. Python ends with 1 on an exception
# nothing caught, so neither is 1 and such a failure is never read as a mismatch.
EXIT_REFUSED = 4
EXIT_MISMATCH = 3


class Refused(Exception):
    """What was found does not hold; the message says why."""


def tree_records(root: pathlib.Path) -> list[bytes]:
    """The records of every entry beneath root, sorted by path: for a directory its type, its mode and its
    path, for a regular file also the SHA-256 of its content, each field ended by NUL. A path cannot hold
    NUL, so no two trees share their records. Refused for any other kind of entry, links included."""
    records = []
    for directory, names, files in os.walk(root, followlinks=False):
        for name in sorted(names + files):
            path = pathlib.Path(directory) / name
            relative = os.fsencode(path.relative_to(root))
            status = path.lstat()
            mode = oct(stat.S_IMODE(status.st_mode)).encode()
            if stat.S_ISDIR(status.st_mode):
                records.append(b"d\0" + mode + b"\0" + relative + b"\0")
            elif stat.S_ISREG(status.st_mode):
                content = hashlib.sha256(path.read_bytes()).hexdigest().encode()
                records.append(b"f\0" + mode + b"\0" + content + b"\0" + relative + b"\0")
            else:
                raise Refused(f"{path} is neither a directory nor a regular file")
    return sorted(records, key=lambda record: record.split(b"\0")[-2])


def tree_digest(root: pathlib.Path) -> str:
    """The digest of the tree beneath root in TREE_FORMAT."""
    if not root.is_dir() or root.is_symlink():
        raise Refused(f"{root} is not a directory")
    return hashlib.sha256(b"".join(tree_records(root))).hexdigest()


def file_digest(path: pathlib.Path) -> str:
    """The SHA-256 of a regular file that is not a link."""
    if path.is_symlink() or not path.is_file():
        raise Refused(f"{path} is not a regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def glob_problem(pattern: str) -> str | None:
    """Why a report glob could reach the student material, or None when it cannot.

    The glob is split at "/", and empty and "." components are dropped. What remains must not be empty,
    absolute or hold "..", and its first component must neither be "**" nor match "assignment".
    """
    if pattern.startswith("/"):
        return f"the report glob {pattern!r} is absolute"
    components = [part for part in pattern.split("/") if part not in ("", ".")]
    if not components:
        return f"the report glob {pattern!r} names nothing"
    if ".." in components:
        return f"the report glob {pattern!r} leaves the exercise"
    if components[0] == "**" or fnmatch.fnmatchcase(ASSIGNMENT, components[0]):
        return f"the report glob {pattern!r} could match a report the student material wrote"
    return None


def template_problems(template: pathlib.Path, key: str) -> list[str]:
    """Every reason the template cannot hold submissions under the key: student material must reach none of
    the files the runs trust, and only what the image itself provides may be declared."""
    try:
        settings = runner.read_settings(template)
        declared = discovery.key_of(key, template)
    except (runner.ExerciseRefused, discovery.DiscoveryRefused) as refusal:
        return [str(refusal)]
    problems = []
    if settings.get("key") != key or declared != key:
        problems.append(f"the template's prune.json does not name the key {key}")
    if settings.get("declared_hosts"):
        problems.append("the template declares hosts, and a policy from submissions is pruned offline")
    if settings.get("pinned_read_roots") and key != PINNED_KEY:
        problems.append(f"only a {PINNED_KEY} template may declare pinned read roots")
    if settings.get("compiled_programs_directory", ASSIGNMENT) != ASSIGNMENT:
        problems.append(f"the template's compiled programs directory is not {ASSIGNMENT}")
    assignment = template / ASSIGNMENT
    if assignment.is_symlink() or not assignment.is_dir():
        problems.append(f"the template has no {ASSIGNMENT} directory")
    for pattern in settings.get("report_globs", verdict.DEFAULT_REPORT_GLOBS):
        problem = glob_problem(pattern)
        if problem is not None:
            problems.append(problem)
    try:
        runner.read_exercise(template)
    except runner.ExerciseRefused as refusal:
        problems.append(refusal.reason)
    return problems


def write_json(path: pathlib.Path, value: object) -> None:
    """Writes the value as JSON to a temporary name beside path and renames it into place."""
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def read_json(path: pathlib.Path) -> dict:
    """A JSON object from a regular file; Refused when it is anything else."""
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise Refused(f"{path} is not readable as JSON: {error}") from error
    if not isinstance(value, dict):
        raise Refused(f"{path} does not hold a JSON object")
    return value


def submission_names(run: pathlib.Path) -> list[str]:
    """The normalised names of the staged submissions, each a key-shaped name as discovery requires."""
    names = sorted(entry.name for entry in (run / "staging").iterdir())
    for name in names:
        if not discovery.KEY_PATTERN.fullmatch(name):
            raise Refused(f"the staged submission {name!r} has a name the pruner cannot carry")
    return names


def classify(run: pathlib.Path, key: str, name: str) -> dict:
    """The result of one submission's prune: ok, or aborted with the reason it recorded. Refused when the
    container's status and what it wrote do not agree, or when the pruner recorded a defect of its own."""
    status_text = (run / "results" / name).read_text().strip()
    output = run / "output" / name
    present = sorted(entry.name for entry in output.iterdir())
    stem = f"{key}_{name}"
    if status_text == "0":
        if present != [f"{stem}.cfg", f"{stem}.json"]:
            raise Refused(f"{name}: a prune that ended with 0 left {present}")
        problem = orchestrate.cfg_record_disagreement(key, stem, output / f"{stem}.cfg", output / f"{stem}.json")
        if problem is not None:
            raise Refused(f"{name}: {problem}")
        return {"result": "ok"}
    if status_text == "1":
        if present != [f"{stem}{orchestrate.ABORTED_SUFFIX}"]:
            raise Refused(f"{name}: a prune that ended with 1 left {present}")
        record = read_json(output / f"{stem}{orchestrate.ABORTED_SUFFIX}")
        reason = record.get("aborted")
        if (record.get("schema_version") != RECORD_SCHEMA or record.get("key") != key or record.get("exercise") != name
                or record.get("stage") != "all" or not isinstance(reason, str)):
            raise Refused(f"{name}: its abort record is not one of this prune")
        if reason.startswith(DEFECT_PREFIX):
            raise Refused(f"{name}: the pruner recorded a defect of its own: {reason}")
        return {"result": "aborted", "reason": reason}
    raise Refused(f"{name}: the prune ended with status {status_text!r}")


def grants_nothing(path: pathlib.Path) -> bool:
    """Whether the policy file grants no path, no rule and no limit."""
    try:
        policy = cfgfile.read_policy(path.read_text())
    except ValueError:
        return False
    return not policy.fs and not policy.connect and not policy.bind and not policy.limits


def seal(run: pathlib.Path, key: str, helpers: pathlib.Path, run_phase_image: str, prune_image: str) -> dict:
    """The manifest of a finished prune: every input and result with its digest. Refused when a result does
    not hold, when the prune image's own base grants anything, or when no submission was pruned."""
    bases = {path.name: file_digest(path) for path in sorted((run / "bases").iterdir())}
    if not bases or not all(name.startswith("Base") and name.endswith(".cfg") for name in bases):
        raise Refused("the grading bases are missing or hold an unexpected file")
    prune_base = run / "prune-base" / PRUNE_BASE
    if not grants_nothing(prune_base):
        raise Refused(f"the prune image's {PRUNE_BASE} grants something")
    submissions = []
    for name in submission_names(run):
        entry = {"name": name, "source": (run / "sources" / name).read_text(), **classify(run, key, name),
                 "staging": tree_digest(run / "staging" / name), "artefacts": tree_digest(run / "output" / name)}
        submissions.append(entry)
    excluded = sorted(entry.name for entry in (run / "excluded").iterdir())
    for name in excluded:
        submissions.append({"name": name, "source": (run / "sources" / name).read_text(), "result": "excluded",
                            "reason": (run / "excluded" / name).read_text().strip()})
    if not any(entry["result"] == "ok" for entry in submissions):
        raise Refused("no submission was pruned, so there is no policy to derive")
    return {"schema_version": MANIFEST_SCHEMA, "format": TREE_FORMAT, "key": key, "run_phase_image": run_phase_image,
            "prune_image": prune_image, "helpers": tree_digest(helpers), "bases": bases, "bases_tree": tree_digest(run / "bases"),
            "prune_base": file_digest(prune_base), "submissions": submissions}


def validated_manifest(run: pathlib.Path, key: str, helpers: pathlib.Path) -> dict:
    """The sealed manifest, once every digest it names has been computed again from what is on disk now
    and the inventory is exactly the one sealed. Refused at the first difference."""
    manifest = read_json(run / "seal" / "manifest.json")
    if manifest.get("schema_version") != MANIFEST_SCHEMA or manifest.get("format") != TREE_FORMAT or manifest.get("key") != key:
        raise Refused("the manifest is not one of this kind of run")
    if tree_digest(helpers) != manifest.get("helpers"):
        raise Refused("the helpers of the pruner changed since the run was sealed")
    bases = {path.name: file_digest(path) for path in sorted((run / "bases").iterdir())}
    if (bases != manifest.get("bases") or tree_digest(run / "bases") != manifest.get("bases_tree")
            or file_digest(run / "prune-base" / PRUNE_BASE) != manifest.get("prune_base")):
        raise Refused("the grading bases changed since the run was sealed")
    staged = submission_names(run)
    sealed = [entry for entry in manifest.get("submissions", []) if entry.get("result") != "excluded"]
    if sorted(entry.get("name") for entry in sealed) != staged:
        raise Refused("the staged submissions are not the ones sealed")
    for entry in sealed:
        name = entry["name"]
        if tree_digest(run / "staging" / name) != entry.get("staging") or tree_digest(run / "output" / name) != entry.get("artefacts"):
            raise Refused(f"{name}: its staged input or its artefacts changed since the run was sealed")
        if classify(run, key, name) != {field: entry[field] for field in ("result", "reason") if field in entry}:
            raise Refused(f"{name}: its prune status is not the one sealed")
    return manifest


def validate(run: pathlib.Path, key: str, helpers: pathlib.Path, run_phase_image: str, prune_image: str) -> None:
    """Checks the sealed run again, and that the images a verification is to use are the ones it was sealed with."""
    manifest = validated_manifest(run, key, helpers)
    if manifest.get("run_phase_image") != run_phase_image or manifest.get("prune_image") != prune_image:
        raise Refused("the images recorded for this run are not the ones it was sealed with")


def union_fs(*parts: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """Every path of the parts with every section any of them grants it."""
    result: dict[str, frozenset[str]] = {}
    for part in parts:
        for path, sections in part.items():
            result[path] = result.get(path, frozenset()) | sections
    return result


def merged_limits(policies: list[cfgfile.Policy]) -> dict[str, int]:
    """Every limit any policy names, merged as the policy system merges them: 0 wins, otherwise the largest."""
    limits: dict[str, int] = {}
    for policy in policies:
        for key, value in policy.limits.items():
            limits[key] = cfgfile.merged_limit(limits.get(key), value)
    return limits


def candidate(parts: list[cfgfile.Policy], base: cfgfile.Policy) -> tuple[cfgfile.Policy, frozenset[str]]:
    """The exercise policy the parts need beyond the base, and the paths only added to make it acceptable.

    The union of the parts loses what the base grants along each path's ancestors (cfgfile.remainder).
    Beside the base, a row could then hold fewer rights than an ancestor, which the policy system refuses:
    every path whose rights normalisation over base and remainder raises is written with the raised
    sections, base-only paths included. Landlock grants those rights there already, so nothing widens.
    Refused when execute would sit beside a write-class right no part had beside it, or when the result
    beside the base still breaks the hierarchy.
    """
    union = cfgfile.Policy(fs=union_fs(*(part.fs for part in parts)),
                           connect=tuple(sorted({rule for part in parts for rule in part.connect})),
                           bind=tuple(sorted({rule for part in parts for rule in part.bind})), limits={})
    with_base = orchestrate.union_policy([*parts, base])
    conflicts = orchestrate.execute_conflicts([*parts, base], with_base)
    if conflicts:
        raise Refused(f"execute would sit beside a write-class right no submission had beside it: {', '.join(conflicts)}")
    remainder = cfgfile.remainder(union, base)
    combined = union_fs(base.fs, remainder.fs)
    normalised = generalise.normalise_hierarchy(combined)
    raised = frozenset(path for path in normalised if normalised[path] != combined[path])
    fs = {path: normalised[path] for path in set(remainder.fs) | raised}
    try:
        cfgfile.check_hierarchy(union_fs(base.fs, fs))
    except ValueError as error:
        raise Refused(f"the policy cannot stand beside the grading base: {error}") from error
    policy = cfgfile.Policy(fs=fs, connect=remainder.connect, bind=remainder.bind, limits=merged_limits(parts))
    cfgfile.check_policy(policy)
    return policy, raised - frozenset(remainder.fs)


def rows(policy: cfgfile.Policy, parts: dict[str, cfgfile.Policy]) -> list[tuple[int, str, str]]:
    """The rows of the policy with how many parts hold each: a filesystem row per path and section, a
    rule per [connect] and [bind] rule, a limit per key, the rarest first and in the order of a policy file."""
    order = {section: index for index, section in enumerate((*cfgfile.FILESYSTEM_SECTIONS, "connect", "bind", "limits"))}
    found = []
    for path, sections in policy.fs.items():
        for section in sections:
            count = sum(1 for part in parts.values() if section in part.fs.get(path, frozenset()))
            found.append((count, section, path))
    for section, rules in (("connect", policy.connect), ("bind", policy.bind)):
        for rule in rules:
            found.append((sum(1 for part in parts.values() if rule in getattr(part, section)), section, rule))
    for key, value in policy.limits.items():
        found.append((sum(1 for part in parts.values() if key in part.limits), "limits", f"{key}={value}"))
    return sorted(found, key=lambda row: (row[0], order[row[1]], row[2]))


def union(run: pathlib.Path, key: str, helpers: pathlib.Path) -> None:
    """Writes the candidate policy, the report and the rows of the sealed run into run/union."""
    manifest = validated_manifest(run, key, helpers)
    ok = [entry["name"] for entry in manifest["submissions"] if entry["result"] == "ok"]
    parts = {}
    for name in ok:
        try:
            parts[name] = cfgfile.read_policy((run / "output" / name / f"{key}_{name}.cfg").read_text())
        except ValueError as error:
            raise Refused(f"{name}: its policy cannot be read: {error}") from error
    try:
        bases = [cfgfile.read_policy((run / "bases" / name).read_text()) for name in sorted(manifest["bases"])]
    except ValueError as error:
        raise Refused(f"a grading base cannot be read: {error}") from error
    base = cfgfile.Policy(fs=union_fs(*(policy.fs for policy in bases)),
                          connect=tuple(sorted({rule for policy in bases for rule in policy.connect})),
                          bind=tuple(sorted({rule for policy in bases for rule in policy.bind})), limits={})
    policy, added = candidate(list(parts.values()), base)
    found = rows(policy, parts)
    target = run / "union"
    (target / "candidate.cfg").write_text(cfgfile.render(policy))
    with (target / "rows.tsv").open("w") as table:
        for count, section, entry in found:
            table.write(f"{count}\t{len(parts)}\t{section}\t{entry}\n")
    write_json(target / "report.json", {
        "schema_version": MANIFEST_SCHEMA, "key": key, "submissions": manifest["submissions"],
        "rows": [{"count": count, "of": len(parts), "section": section, "entry": entry,
                  "added_to_stand_beside_the_base": section in cfgfile.FILESYSTEM_SECTIONS and entry in added}
                 for count, section, entry in found],
        "limits": {name: part.limits for name, part in parts.items()},
        "disabled_limits": sorted(key for key, value in policy.limits.items() if value == 0),
        "candidate_sha256": file_digest(target / "candidate.cfg"),
        "run_phase_image": manifest["run_phase_image"], "prune_image": manifest["prune_image"],
        "bases": manifest["bases"]})


def batch(run: pathlib.Path, folder: pathlib.Path, helpers: pathlib.Path) -> None:
    """Fixes what one verification checks: the digest of its private policy copy, the bases every
    verification container must find beside phobos.sh, and the helpers that run it."""
    manifest = read_json(run / "seal" / "manifest.json")
    if tree_digest(helpers) != manifest.get("helpers"):
        raise Refused("the helpers of the pruner changed since the run was sealed")
    write_json(folder / "batch.json", {"schema_version": BATCH_SCHEMA, "policy_sha256": file_digest(folder / "policy.cfg"),
                                       "bases": {**manifest["bases"], PRUNE_BASE: manifest["prune_base"]},
                                       "helpers": manifest["helpers"]})


def verdict_of(folder: pathlib.Path, key: str, name: str, expected: dict) -> str:
    """match, mismatch or failure for one submission's verification, from its container status and record."""
    path = folder / "records" / name / "verify" / f"{key}_{name}.json"
    try:
        status = (folder / "status" / name).read_text().strip()
        record = read_json(path)
    except (OSError, Refused):
        return "failure"
    agrees = (record.get("schema_version") == RECORD_SCHEMA and record.get("key") == key and record.get("exercise") == name
              and record.get("configs_sha256") == [expected["policy_sha256"]] and record.get("bases") == expected["bases"])
    if not agrees:
        return "failure"
    if status == "0" and record.get("verified") is True and "aborted" not in record:
        return "match"
    if status == "1" and record.get("verified") is False and record.get("aborted") == MISMATCH:
        return "mismatch"
    return "failure"


def verify_report(run: pathlib.Path, folder: pathlib.Path, key: str, helpers: pathlib.Path) -> int:
    """Classifies a verification of every pruned submission and writes run/<batch>/result.json; 0 when all
    matched, EXIT_MISMATCH when some did not and none failed otherwise, EXIT_REFUSED otherwise."""
    manifest = validated_manifest(run, key, helpers)
    expected = read_json(folder / "batch.json")
    if expected.get("schema_version") != BATCH_SCHEMA or file_digest(folder / "policy.cfg") != expected.get("policy_sha256"):
        raise Refused("the policy of this verification changed while it was checked")
    results = {entry["name"]: verdict_of(folder, key, entry["name"], expected)
               for entry in manifest["submissions"] if entry["result"] == "ok"}
    write_json(folder / "result.json", {"schema_version": BATCH_SCHEMA, "results": results})
    for name, result in sorted(results.items()):
        print(f"{name}: {result}")
    if any(result == "failure" for result in results.values()):
        return EXIT_REFUSED
    return EXIT_MISMATCH if any(result == "mismatch" for result in results.values()) else 0


def arguments(argv: list[str]) -> argparse.Namespace:
    """The command line: one subcommand and its operands."""
    parser = argparse.ArgumentParser(description="The container steps of phobos-cli.sh submissions.")
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check-template")
    checking.add_argument("template", type=pathlib.Path)
    checking.add_argument("key")
    sealing = commands.add_parser("seal")
    for operand in ("run", "key", "helpers", "run_phase_image", "prune_image"):
        sealing.add_argument(operand)
    validating = commands.add_parser("validate")
    for operand in ("run", "key", "helpers", "run_phase_image", "prune_image"):
        validating.add_argument(operand)
    merging = commands.add_parser("union")
    for operand in ("run", "key", "helpers"):
        merging.add_argument(operand)
    fixing = commands.add_parser("batch")
    for operand in ("run", "batch", "helpers"):
        fixing.add_argument(operand)
    reporting = commands.add_parser("verify-report")
    for operand in ("run", "batch", "key", "helpers"):
        reporting.add_argument(operand)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    """Runs one subcommand; its status, EXIT_REFUSED when what it found does not hold or cannot be read."""
    options = arguments(argv)
    try:
        if options.command == "check-template":
            problems = template_problems(options.template, options.key)
            for problem in problems:
                print(f"phobos-cli.sh submissions: {problem}", file=sys.stderr)
            return EXIT_REFUSED if problems else 0
        if options.command == "seal":
            run = pathlib.Path(options.run)
            manifest = seal(run, options.key, pathlib.Path(options.helpers), options.run_phase_image, options.prune_image)
            write_json(run / "seal" / "manifest.json", manifest)
            return 0
        if options.command == "validate":
            validate(pathlib.Path(options.run), options.key, pathlib.Path(options.helpers), options.run_phase_image,
                     options.prune_image)
            return 0
        if options.command == "union":
            union(pathlib.Path(options.run), options.key, pathlib.Path(options.helpers))
            return 0
        if options.command == "batch":
            batch(pathlib.Path(options.run), pathlib.Path(options.batch), pathlib.Path(options.helpers))
            return 0
        return verify_report(pathlib.Path(options.run), pathlib.Path(options.batch), options.key, pathlib.Path(options.helpers))
    except (OSError, Refused) as refusal:
        print(f"phobos-cli.sh submissions: {refusal}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
