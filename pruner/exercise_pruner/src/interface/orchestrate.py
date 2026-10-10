#!/usr/bin/env python3
"""
orchestrate.py - merge & build the Base*.cfg policy files that
`protecter/src/phobos-policysystem.sh` applies at run time.

It reads what the layer pruner (`pruner/exercise_pruner/src/interface/main.py`) wrote for every exercise of
each requested language: a complete `<lang>_<exercise>.cfg` and its record `<lang>_<exercise>.json`,
the record carrying the SHA-256 of the .cfg it describes. Each .cfg is held to its record before
anything is merged. The configuration files are read and written with `shared/src/domain/cfgfile.py`,
found through --helpers-dir, pinned by tests to the format the shell parser reads. It prunes
nothing itself: each language is pruned in its own container first.

Beside an exercise's .cfg it may find the KVM run's `<lang>_<exercise>.abi10.json` and, where that run
added UDP bind rows, `<lang>_<exercise>.abi10.cfg` (A.6.9). Each is held to the record, which names
the SHA-256 of the .cfg it verified and of the sidecar, and a sidecar that holds anything but
`[bind] allow <port> udp` is refused. The rows are written to `Abi10-<lang>.cfg` and
`exercises/<lang>_<exercise>.abi10.cfg`, never into the base: the enforcer refuses a UDP bind rule that
names a port on a kernel below Landlock version 10, so a base that held one would stop every run of
the language there. Without sidecars nothing changes.

The merge errs wide on purpose: an exercise is graded with what every
other exercise of its language needed, and so with their [connect] and [bind] rules too, which is
why the layer pruner's opt-in `java-egress` output, where declared hosts are kept, is never merged
by it. Where it cannot tell, it errs narrow: an [execute] it cannot prove safe beside a write
refuses the merge.

### Outputs (all in /var/tmp/opt/core/config)
* **BasePhobos.cfg**            - **UNION** of every language's base →
  used when the runtime cannot tell which language is running. It is left out, with a
  warning, when the union would let execute where one language writes and another executes
  (see execute_conflicts), since it is an alternative no language needs.
* **BaseLanguage-<lang>.cfg**   - the union of every exercise of that language: its
  filesystem sections, raised wherever a nested entry would hold fewer rights than an
  ancestor (Landlock grants those rights there anyway), and its [connect] and [bind] rules.
  Never a [limits] section: a limit belongs to one exercise. The merge is refused when the
  union would let [execute] sit beside a write-class right no exercise had beside it.
* **exercises/<lang>_<exercise>.cfg** - its [limits], and any entry its language's base does not
  already grant along its ancestors. The base is the union of every exercise of the language, so
  it already holds all of the exercise's own entries and, in practice, this file carries only the
  [limits]. It is passed with --config on top of the base.
* **Abi10-<lang>.cfg** and **exercises/<lang>_<exercise>.abi10.cfg** - only where a KVM run added
  UDP bind rows: for a host with Landlock version 10, passed with --config on top of the base.
* **TailPhobos.cfg**            - the runtime chdir, the only tail option the
  phobos-landlock-filesystem-and-networksystem runtime accepts, given by --runtime-chdir.

### For reading, in the debug/ subdirectory
These are never applied. They are the comparisons that say something
BaseLanguage-<lang>.cfg does not, so that a policy can be judged rather than only
inspected.
* **BasePhobosIntersect.cfg**   - what every language needed.
* **Base<Lang>Only.cfg**        - what no other language needed, which is where a
  policy grows when one language's prune goes wrong.
* **Base<Lang>Common.cfg**      - what every exercise of that language needed: the sections
  every exercise granted a path, raised as the base is.

Ship exactly one Base*.cfg beside phobos-policysystem.sh: it applies every Base*.cfg it
finds there, so a BasePhobos.cfg left next to a BaseLanguage-java-gradle.cfg gives a Java
run the paths of every other language as well.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import textwrap
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from shared.src.domain.cfgfile import Policy

# The terminal escape sequences the progress output is coloured with.
RED = '\033[31m'
YELLOW = '\033[33m'
BOLD = '\033[1m'
RESET = '\033[0m'
# The schema version of the layer pruner's record, the one that carries the SHA-256 of its .cfg.
LAYER_RECORD_SCHEMA = 2
# The name ending of the record the layer pruner writes for an exercise it aborted.
ABORTED_SUFFIX = '.aborted.json'
# The name endings of what the KVM run writes beside an exercise's .cfg and .json (main.py
# --kernel-observer audit): its record, and the UDP bind rows it added, if it added any.
ABI10_RECORD_SUFFIX = '.abi10.json'
ABI10_CFG_SUFFIX = '.abi10.cfg'
# The schema version of the KVM run's record, the Landlock version its kernel must have offered, and the
# one kind of rule a sidecar may hold: a UDP bind on a port from 1 to 65535, in ASCII digits.
ABI10_RECORD_SCHEMA = 1
ABI10_LANDLOCK_VERSION = 10
UDP_BIND_ROW = re.compile(r'allow (0|[1-9][0-9]{0,4}) udp', re.ASCII)
PORT_MAXIMUM = 65535
# The artefact the retired Bubblewrap pruner wrote, which nothing reads any more.
RETIRED_SUFFIX = '.paths'

# ────────────────────────────────────────── CLI


class Layout(NamedTuple):
    """Where one run reads its artefacts and writes its policies.

    The directories every step needs, resolved once from the command line and then handed
    to each step, so that importing this file parses nothing and creates nothing.
    """

    path_dir: Path
    core_dir: Path
    debug_dir: Path


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Read the command line. Takes *argv* so that a caller can supply one."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent(__doc__))
    parser.add_argument('--langs', required=True,
                        help='comma-separated keys: java-gradle,java-maven,python,c-fact')
    parser.add_argument('--path-dir', default='/var/tmp/path_sets',
                        help='Where the <lang>_<exercise>.cfg artefacts and their records live (input).')
    parser.add_argument('--helpers-dir', default='/var/tmp/helpers',
                        help='Where the pruner packages (exercise_pruner, runtime_pruner, shared) reside.')
    parser.add_argument('--runtime-chdir', default='/var/tmp/testing-dir',
                        help='Directory the runtime sandbox should chdir into.')
    parser.add_argument('--core-dir', default='/var/tmp/opt/core/config',
                        help='Where the generated policy files are written.')
    return parser.parse_args(argv)


def make_layout(arguments: argparse.Namespace) -> Layout:
    """Resolves the directories of one run and creates the three it writes into."""
    path_dir = Path(arguments.path_dir)
    core_dir = Path(arguments.core_dir)
    debug_dir = core_dir / 'debug'
    for directory in (path_dir, core_dir, debug_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return Layout(path_dir=path_dir, core_dir=core_dir, debug_dir=debug_dir)


def requested_languages(langs_argument: str) -> list[str]:
    """The languages named on the command line, in the order they were given."""
    return [name.strip() for name in langs_argument.split(',') if name.strip()]


# ────────────────────────────────────────── artefacts

def use_policy_helpers(helpers_dir: Path) -> None:
    """Puts the helpers directory on the import path, so that the shared cfgfile module can be imported.

    The configuration files are read and written by the module the layer pruner writes them with,
    so the two cannot come to disagree about the format. It is imported where it is used, after
    main has run this, because the directory is an option of this program.
    """
    if str(helpers_dir) not in sys.path:
        sys.path.insert(0, str(helpers_dir))


def exercise_stems(lang: str, path_dir: Path, suffix: str) -> set[str]:
    """The names, without *suffix*, of this language's per-exercise artefacts ending in it.

    The record of an exercise the layer pruner aborted, and what the KVM run wrote beside an
    exercise, share the name shape and are not exercises.
    """
    return {path.name.removesuffix(suffix) for path in path_dir.glob(f'{lang}_*{suffix}')
            if not path.name.endswith((ABORTED_SUFFIX, ABI10_RECORD_SUFFIX, ABI10_CFG_SUFFIX))}


def abi10_stems(lang: str, path_dir: Path) -> set[str]:
    """The names of the exercises of this language that have a KVM record or sidecar beside them."""
    return ({path.name.removesuffix(ABI10_RECORD_SUFFIX) for path in path_dir.glob(f'{lang}_*{ABI10_RECORD_SUFFIX}')}
            | {path.name.removesuffix(ABI10_CFG_SUFFIX) for path in path_dir.glob(f'{lang}_*{ABI10_CFG_SUFFIX}')})


def abi10_record_problem(lang: str, exercise: str, path_dir: Path) -> str | None:
    """Why the KVM run's record does not vouch for the .cfg and the sidecar beside it, or None when it does.

    The record names the SHA-256 of the .cfg it verified and of the sidecar it wrote, or null where it
    wrote none. A record of another exercise or schema, one with a mismatch of the audit cross-check,
    one that did not verify, a .cfg changed since, and a sidecar that is not the one the record names
    each refuse the merge, since the rows would come from a run that is not about this policy.
    """
    record_file = path_dir / f'{exercise}{ABI10_RECORD_SUFFIX}'
    sidecar = path_dir / f'{exercise}{ABI10_CFG_SUFFIX}'
    cfg_file = path_dir / f'{exercise}.cfg'
    if not cfg_file.exists():
        return f'{record_file.name} has no {cfg_file.name} beside it'
    if not record_file.exists():
        return f'{sidecar.name} has no {record_file.name} beside it'
    try:
        record = json.loads(record_file.read_text())
    except ValueError as exc:
        return f'{record_file.name} is not readable as JSON: {exc}'
    if not isinstance(record, dict) or record.get('schema_version') != ABI10_RECORD_SCHEMA:
        return f'{record_file.name} is not a KVM record of schema version {ABI10_RECORD_SCHEMA}'
    if record.get('key') != lang or f'{lang}_{record.get("exercise")}' != exercise:
        return f'{record_file.name} records {record.get("key")}/{record.get("exercise")}, not {exercise}'
    if not record.get('verified') or record.get('mismatches'):
        return f'{record_file.name} records a KVM run that did not verify the policy'
    if record.get('verified_cfg_sha256') != hashlib.sha256(cfg_file.read_bytes()).hexdigest():
        return f'{record_file.name} verified another {cfg_file.name} than the one beside it: its SHA-256 differs'
    if not isinstance(record.get('landlock_abi'), int) or record['landlock_abi'] < ABI10_LANDLOCK_VERSION:
        return f'{record_file.name} records a kernel below Landlock version {ABI10_LANDLOCK_VERSION}'
    wanted = record.get('abi10_cfg_sha256')
    if wanted is None:
        return f'{sidecar.name} is beside a record that wrote no sidecar' if sidecar.exists() else None
    if not sidecar.exists():
        return f'{record_file.name} wrote {sidecar.name}, which is missing'
    if wanted != hashlib.sha256(sidecar.read_bytes()).hexdigest():
        return f'{sidecar.name} is not the file {record_file.name} records: its SHA-256 differs'
    return None


def abi10_rows(exercise: str, path_dir: Path) -> tuple[str, ...]:
    """The UDP bind rows of an exercise's sidecar, or none; ValueError when it holds anything else.

    Only `[bind] allow <port> udp` is ever taken from a KVM run, so a sidecar that holds another
    section or another kind of rule, a port of 0 or above 65535 or one not written in plain ASCII
    digits, is refused whatever its hash says. The sidecar is read once and the bytes parsed are the
    bytes the record's hash is checked against.
    """
    from shared.src.domain import cfgfile
    sidecar = path_dir / f'{exercise}{ABI10_CFG_SUFFIX}'
    if not sidecar.exists():
        return ()
    content = sidecar.read_bytes()
    record = json.loads((path_dir / f'{exercise}{ABI10_RECORD_SUFFIX}').read_text())
    if record.get('abi10_cfg_sha256') != hashlib.sha256(content).hexdigest():
        raise ValueError(f'{sidecar.name} is not the file {sidecar.stem}.json records: its SHA-256 differs')
    policy = cfgfile.read_policy(content.decode())
    ports = [UDP_BIND_ROW.fullmatch(rule) for rule in policy.bind]
    if policy.fs or policy.connect or policy.limits or any(
            matched is None or int(matched.group(1)) > PORT_MAXIMUM for matched in ports):
        raise ValueError(f'{sidecar.name} holds more than UDP bind rows')
    return policy.bind


def cfg_record_disagreement(lang: str, exercise: str, cfg_file: Path, record_file: Path) -> str | None:
    """Why the layer pruner's record does not describe the .cfg beside it, or None when it does.

    main.py writes the record with the SHA-256 of the .cfg it has just written. A .cfg edited,
    truncated or left from another run afterwards is a different policy from the one the record
    vouches for, and nothing else would tell the two apart.
    """
    if not record_file.exists():
        return f'{cfg_file.name} has no {record_file.name} beside it'
    try:
        record = json.loads(record_file.read_text())
    except ValueError as exc:
        return f'{record_file.name} is not readable as JSON: {exc}'
    if not isinstance(record, dict) or record.get('schema_version') != LAYER_RECORD_SCHEMA:
        return f'{record_file.name} is not a layer pruner record of schema version {LAYER_RECORD_SCHEMA}'
    if record.get('stage') != 'all':
        return f'{record_file.name} records a prune stopped after its {record.get("stage")} stage, not one to ship'
    if record.get('key') != lang or f'{lang}_{record.get("exercise")}' != exercise:
        return f'{record_file.name} records {record.get("key")}/{record.get("exercise")}, not {exercise}'
    if record.get('cfg_sha256') != hashlib.sha256(cfg_file.read_bytes()).hexdigest():
        return f'{cfg_file.name} is not the file {record_file.name} records: its SHA-256 differs'
    return None


def cfg_artefact_disagreements(lang: str, path_dir: Path) -> list[str]:
    """Name every artefact of this language that its record does not vouch for."""
    configurations = exercise_stems(lang, path_dir, '.cfg')
    records = exercise_stems(lang, path_dir, '.json')
    problems = [f'{orphan}.json has no {orphan}.cfg beside it' for orphan in sorted(records - configurations)]
    for exercise in sorted(configurations):
        problem = cfg_record_disagreement(lang, exercise, path_dir / f'{exercise}.cfg',
                                          path_dir / f'{exercise}.json')
        if problem is not None:
            problems.append(problem)
    for exercise in sorted(abi10_stems(lang, path_dir)):
        problem = abi10_record_problem(lang, exercise, path_dir)
        if problem is not None:
            problems.append(problem)
        else:
            try:
                abi10_rows(exercise, path_dir)
            except ValueError as exc:
                problems.append(str(exc))
    return problems


def aborted_exercises(lang: str, path_dir: Path) -> list[str]:
    """Name every exercise of this language the layer pruner aborted, with the reason it recorded."""
    problems: list[str] = []
    for record_file in sorted(path_dir.glob(f'{lang}_*{ABORTED_SUFFIX}')):
        try:
            reason = json.loads(record_file.read_text()).get('aborted', 'no reason recorded')
        except (ValueError, AttributeError):
            reason = 'its record is not readable'
        problems.append(f'{record_file.name.removesuffix(ABORTED_SUFFIX)} was aborted: {reason}')
    return problems


def language_artefact_problems(lang: str, path_dir: Path) -> list[str]:
    """Every reason this language's artefacts cannot be merged as they stand.

    An aborted exercise is missing from the language, so its base would be narrower than its
    exercises need. A .paths path set is what the retired Bubblewrap pruner wrote: it is left from
    an earlier run, and merging beside it would hide that the language was not pruned again.
    """
    problems = aborted_exercises(lang, path_dir)
    problems += [f'{name}{RETIRED_SUFFIX} is a path set of the retired Bubblewrap pruner; remove it'
                 for name in sorted(exercise_stems(lang, path_dir, RETIRED_SUFFIX))]
    return problems + cfg_artefact_disagreements(lang, path_dir)


# ────────────────────────────────────────── policies


class LanguagePolicy(NamedTuple):
    """What one language's artefacts amount to: its base, its exercises by name, and what all of them needed."""

    base: Policy
    exercises: dict[str, Policy]
    common: Policy


def raised(fs: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """The entries, each nested one raised to its ancestor's sections where it would hold fewer rights.

    phobos-filesystem.sh refuses a nested entry whose rights are a strict subset of an ancestor's,
    and Landlock grants the ancestor's rights beneath it anyway, so raising it changes nothing that
    is enforced and keeps a merged file from being refused.
    """
    from shared.src.domain import generalise
    return generalise.normalise_hierarchy(fs)


def union_policy(policies: Sequence[Policy]) -> Policy:
    """The union of several policies, without limits: what a base built from them must grant.

    Every path holds every section any of them granted it, raised as `raised` says; the network
    rules are every rule any of them names, sorted. The comments of the exercises' .cfg files, the
    reasons a grant is wider than observed, are not carried over: they stay in those files and
    their records.
    """
    from shared.src.domain import cfgfile
    fs: dict[str, frozenset[str]] = {}
    for policy in policies:
        for path, sections in policy.fs.items():
            fs[path] = fs.get(path, frozenset()) | sections
    return cfgfile.Policy(fs=raised(fs),
                          connect=tuple(sorted({rule for policy in policies for rule in policy.connect})),
                          bind=tuple(sorted({rule for policy in policies for rule in policy.bind})),
                          limits={})


def execute_conflicts(parts: Sequence[Policy], union: Policy) -> list[str]:
    """The paths the union lets execute beside a write-class right that no part granting execute there had.

    Markus's decision on #185: [execute] never sits on a directory that overlaps a write-class right
    (on itself, an ancestor or an entry beneath it). Each part already holds to it, but a union can
    bring one part's write beside another's execute, and the orchestrator cannot tell a file from a
    directory, so it names every such path rather than guess.
    """
    from shared.src.domain import generalise
    return [path for path, sections in sorted(union.fs.items())
            if 'execute' in sections and generalise.overlaps_write(path, union.fs)
            and not any('execute' in part.fs.get(path, frozenset()) and generalise.overlaps_write(path, part.fs)
                        for part in parts)]


def common_policy(policies: Sequence[Policy]) -> Policy:
    """What every one of several policies grants: each path all of them name, with the sections all grant it."""
    from shared.src.domain import cfgfile
    shared = set.intersection(*(set(policy.fs) for policy in policies))
    fs = {path: frozenset.intersection(*(policy.fs[path] for policy in policies)) for path in shared}
    return cfgfile.Policy(fs=raised({path: sections for path, sections in fs.items() if sections}),
                          connect=tuple(sorted(set.intersection(*(set(policy.connect) for policy in policies)))),
                          bind=tuple(sorted(set.intersection(*(set(policy.bind) for policy in policies)))),
                          limits={})


def read_language(lang: str, path_dir: Path) -> LanguagePolicy | None:
    """The policy of a language from its per-exercise .cfg files, or None when it has none.

    Raises ValueError when a .cfg is not one cfgfile reads exactly as the run-time parser does.
    """
    from shared.src.domain import cfgfile
    exercises = {
        stem.removeprefix(f'{lang}_'): cfgfile.read_policy((path_dir / f'{stem}.cfg').read_text())
        for stem in sorted(exercise_stems(lang, path_dir, '.cfg'))
    }
    if not exercises:
        print(f'{YELLOW}[warn]{RESET} no {lang}_*.cfg in {path_dir}')
        return None
    return LanguagePolicy(base=union_policy(list(exercises.values())), exercises=exercises,
                          common=common_policy(list(exercises.values())))


def collect_language_data(langs: Iterable[str], path_dir: Path) -> dict[str, LanguagePolicy]:
    """Read the policy of every requested language that has a usable one.

    A policy naming no path is not a language that needs nothing: every real exercise needs at least
    the files its build runs, so an empty policy is a failure wearing a success's file, and it is
    left out like a missing one.
    """
    data: dict[str, LanguagePolicy] = {}
    for lang in langs:
        language = read_language(lang, path_dir)
        if language is None:
            continue
        if not language.base.fs:
            print(f'{YELLOW}[warn]{RESET} the policy pruned for {lang} names no path at all')
            continue
        data[lang] = language
    return data


def build_runtime_tail(runtime_chdir: str, core_dir: Path) -> None:
    """Write TailPhobos.cfg in *core_dir*, holding only the runtime chdir.

    phobos.sh appends every tail token to phobos-landlock-filesystem-and-networksystem, which exits on
    an option it does not know, so the tail holds the one it takes and nothing else.
    """
    dst_tail = core_dir / 'TailPhobos.cfg'
    dst_tail.write_text(f'--chdir {runtime_chdir}\n')
    print('  • wrote TailPhobos.cfg (runtime chdir set to', runtime_chdir + ')')


# ────────────────────────────────────────── the files


def cross_language_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """BasePhobos.cfg, the union across every language, and its intersection, by the file each goes to.

    The union is for an image that cannot tell which language is running, so it is an
    alternative to the per-language files rather than a part of them, and packaging picks
    one. The intersection is never applied; it is there to be read: every path every language
    names, with the sections the union grants it.
    """
    from shared.src.domain import cfgfile
    bases = [language.base for language in lang_data.values()]
    union = union_policy(bases)
    shared = set.intersection(*(set(base.fs) for base in bases))
    intersect = cfgfile.Policy(fs={path: union.fs[path] for path in shared},
                               connect=tuple(sorted(set.intersection(*(set(base.connect) for base in bases)))),
                               bind=tuple(sorted(set.intersection(*(set(base.bind) for base in bases)))),
                               limits={})
    policies = {layout.debug_dir / 'BasePhobosIntersect.cfg': intersect}
    conflicts = execute_conflicts(bases, union)
    if conflicts:
        print(f'{YELLOW}[warn]{RESET} BasePhobos.cfg is not written: across the languages it would let execute '
              f'beside a write on {", ".join(conflicts)}. Ship a BaseLanguage-<lang>.cfg instead.')
    else:
        policies[layout.core_dir / 'BasePhobos.cfg'] = union
    return policies


def language_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """Each language's policy, plus the two comparisons that say what it does not, by file.

    Base<Lang>Only names what no other language needed, which is where a policy grows when
    one language's prune goes wrong; Base<Lang>Common names what every exercise of that
    language needed. Neither is ever applied.
    """
    from shared.src.domain import cfgfile
    policies: dict[Path, Policy] = {}
    for lang, language in lang_data.items():
        policies[layout.core_dir / f'BaseLanguage-{lang}.cfg'] = language.base
        capitalised = lang.capitalize()
        other_paths: set[str] = set()
        other_rules: set[str] = set()
        for other_lang, other in lang_data.items():
            if other_lang != lang:
                other_paths |= set(other.base.fs)
                other_rules |= set(other.base.connect) | set(other.base.bind)
        policies[layout.debug_dir / f'Base{capitalised}Only.cfg'] = cfgfile.Policy(
            fs={path: sections for path, sections in language.base.fs.items() if path not in other_paths},
            connect=tuple(rule for rule in language.base.connect if rule not in other_rules),
            bind=tuple(rule for rule in language.base.bind if rule not in other_rules),
            limits={})
        policies[layout.debug_dir / f'Base{capitalised}Common.cfg'] = language.common
    return policies


def exercise_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """exercises/<lang>_<exercise>.cfg for every exercise: what its base lacks, and its limits."""
    from shared.src.domain import cfgfile
    return {layout.core_dir / 'exercises' / f'{lang}_{name}.cfg': cfgfile.remainder(policy, language.base)
            for lang, language in lang_data.items() for name, policy in language.exercises.items()}


def abi10_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """The UDP bind rows the KVM run added, by file: Abi10-<lang>.cfg and exercises/<lang>_<exercise>.abi10.cfg.

    They are written beside the base and never into it. A UDP bind rule that names a port is refused by
    the enforcer on a kernel below Landlock version 10, so a base that held one would stop every run of
    that language on such a kernel; these files are for a host known to have version 10, passed with
    --config on top of the base. Neither name starts with Base, so phobos-policysystem.sh never applies
    them on its own.
    """
    from shared.src.domain import cfgfile
    policies: dict[Path, Policy] = {}
    for lang, language in lang_data.items():
        rows = {name: abi10_rows(f'{lang}_{name}', layout.path_dir) for name in language.exercises}
        union = tuple(dict.fromkeys(row for exercise_rows in rows.values() for row in exercise_rows))
        if not union:
            continue
        policies[layout.core_dir / f'Abi10-{lang}.cfg'] = cfgfile.Policy(fs={}, connect=(), bind=union, limits={})
        for name, exercise_rows in rows.items():
            if exercise_rows:
                policies[layout.core_dir / 'exercises' / f'{lang}_{name}.abi10.cfg'] = cfgfile.Policy(
                    fs={}, connect=(), bind=exercise_rows, limits={})
    return policies


def write_policies(policies: dict[Path, Policy], langs: Iterable[str], layout: Layout) -> None:
    """Renders every policy, and only once all of them render, writes them.

    An earlier run's exercises/ files of these languages are removed first, so an exercise that
    is gone leaves no configuration behind that would still be applied to it. Raises ValueError,
    having written nothing, when any policy cannot be written as a file the parser reads as it.
    """
    from shared.src.domain import cfgfile
    texts = {destination: cfgfile.render(policy) for destination, policy in policies.items()}
    (layout.core_dir / 'BasePhobos.cfg').unlink(missing_ok=True)
    exercises_dir = layout.core_dir / 'exercises'
    exercises_dir.mkdir(exist_ok=True)
    for lang in langs:
        (layout.core_dir / f'Abi10-{lang}.cfg').unlink(missing_ok=True)
        for stale in exercises_dir.glob(f'{lang}_*.cfg'):
            stale.unlink()
    for destination, text in texts.items():
        destination.write_text(text)


def main(argv: Sequence[str] | None = None) -> int:
    """Checks and merges, and answers the status the program ends with.

    Every refusal below answers non-zero and leaves whatever is already on disk untouched.
    The files this writes are a security policy, where everything not named is denied, so a
    policy built from only the languages that happened to work would be narrower than anyone
    asked for and nothing downstream could tell that from a correct one.
    """
    arguments = parse_arguments(argv)
    layout = make_layout(arguments)
    use_policy_helpers(Path(arguments.helpers_dir))
    langs = requested_languages(arguments.langs)
    print(f'\n{BOLD}Orchestrating for:{RESET}', ', '.join(langs), '\n')

    artefact_problems: list[str] = []
    for lang in langs:
        artefact_problems += language_artefact_problems(lang, layout.path_dir)
    if artefact_problems:
        print(f'{RED}[error]{RESET} the per-exercise artefacts do not agree with their records:')
        for problem in artefact_problems:
            print(f'        {problem}')
        print('        Refusing to merge a policy from a measurement that is not whole.')
        return 1

    try:
        lang_data = collect_language_data(langs, layout.path_dir)
    except ValueError as refusal:
        print(f'{RED}[error]{RESET} a pruned configuration cannot be read: {refusal}')
        print('        Refusing to merge a policy the run-time parser would read differently.')
        return 1

    missing_languages = sorted(set(langs) - set(lang_data))
    if missing_languages:
        print(f'{RED}[error]{RESET} no usable pruning result for:', ', '.join(missing_languages))
        print('        Refusing to merge a policy that is missing a language that was asked for.')
        return 1

    conflicts = {lang: execute_conflicts(list(language.exercises.values()), language.base)
                 for lang, language in lang_data.items()}
    if any(conflicts.values()):
        print(f'{RED}[error]{RESET} the union of the exercises would let execute beside a write no exercise had:')
        for lang, paths in conflicts.items():
            for path in paths:
                print(f'        {lang}: {path}')
        print('        Refusing to merge a base that would make a writable tree executable.')
        return 1

    try:
        policies = {**cross_language_policies(lang_data, layout), **language_policies(lang_data, layout),
                    **exercise_policies(lang_data, layout), **abi10_policies(lang_data, layout)}
        write_policies(policies, langs, layout)
    except ValueError as refusal:
        print(f'{RED}[error]{RESET} a merged policy cannot be written: {refusal}')
        print('        Refusing to write any of them.')
        return 1
    build_runtime_tail(arguments.runtime_chdir, layout.core_dir)

    print(f'\n{BOLD}Done.{RESET}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
