#!/usr/bin/env python3
"""
orchestrate.py - prune, merge & build the Base*.cfg policy files that
`core/phobos-policysystem.sh` applies at run time.

A language reaches it from one of two producers, and the orchestrator merges both:
* the layer pruner (`var/tmp/helpers/layer_prune/main.py`, Java), which writes a complete
  `<lang>_<exercise>.cfg` and its record `<lang>_<exercise>.json` per exercise, the record
  carrying the SHA-256 of the .cfg it describes;
* the Bubblewrap pruner (`run_minimal_fs_all.sh` and `emit_artifacts.py`, Python until it
  moves to the layer pruner), which writes `<lang>_<exercise>.paths` and its .json.
Each artefact is held to the record written beside it in the same run before anything is
merged, and a language holding artefacts of both producers is refused. The merge errs wide on
purpose, as the Bubblewrap union did: an exercise is graded with what every other exercise of its
language needed, and so with their [connect] and [bind] rules too, which is why the layer pruner's
opt-in `java-egress` output, where declared hosts are kept, is never merged by it. Where it cannot
tell, it errs narrow: an [execute] it cannot prove safe beside a write refuses the merge. The configuration
files are read and written with `layer_prune/cfgfile.py`, found through --helpers-dir.

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
* **TailPhobos.cfg**            - the runtime chdir, the only tail option the
  phobos-landlock-filesystem-and-networksystem runtime accepts. (The pruning run's Bubblewrap mount and
  namespace flags and its per-exercise `--chdir` are dropped; the runtime chdir
  is injected via the `--runtime-chdir` CLI argument.)

### For reading, in the debug/ subdirectory
These are never applied. They are the comparisons that say something
BaseLanguage-<lang>.cfg does not, so that a policy can be judged rather than only
inspected.
* **BasePhobosIntersect.cfg**   - what every language needed.
* **Base<Lang>Only.cfg**        - what no other language needed, which is where a
  policy grows when one language's prune goes wrong.
* **Base<Lang>Common.cfg**      - what every exercise of that language needed: for the
  layer pruner, the sections every exercise granted a path, raised as the base is; for the
  Bubblewrap pruner, the intersection make_lang_sets.py writes over whole "mode path" lines.

Ship exactly one Base*.cfg beside phobos-policysystem.sh: it applies every Base*.cfg it
finds there, so a BasePhobos.cfg left next to a BaseLanguage-java.cfg gives a Java
run the paths of every other language as well.

Compose runs this with --skip-prune: the layer pruner prunes Java in its own container. Without
--skip-prune every requested language, Java included, is pruned here with Bubblewrap.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from layer_prune.cfgfile import Policy

# The terminal escape sequences the progress output is coloured with.
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
BOLD = '\033[1m'
RESET = '\033[0m'
# A line of a *_union.paths file: its mode and its path.
UNION_LINE_FIELDS = 2
# The schema version of the layer pruner's record, the one that carries the SHA-256 of its .cfg.
LAYER_RECORD_SCHEMA = 2
# The name ending of the record the layer pruner writes for an exercise it aborted.
ABORTED_SUFFIX = '.aborted.json'
# The sections a Bubblewrap path set's read-only and writable lines grant.
READ_ONLY_SECTIONS = frozenset({'read', 'execute'})
WRITABLE_SECTIONS = frozenset({'read', 'write', 'create', 'delete'})
# The loopback every policy built from a Bubblewrap path set names, as it always has.
BUBBLEWRAP_CONNECT = ('allow 127.0.0.1:*', 'allow [::1]', 'allow localhost')
# How many languages are pruned at once when the machine cannot say how many CPUs it has.
DEFAULT_JOBS = 4

# ────────────────────────────────────────── CLI


class Layout(NamedTuple):
    """Where one run reads its artefacts and writes its policies.

    The directories every step needs, resolved once from the command line and then handed
    to each step. They used to be module-level names assigned at import, which meant
    importing this file parsed a command line and created three directories, so nothing
    here could be exercised except by starting the program.
    """

    path_dir: Path
    core_dir: Path
    debug_dir: Path
    prune_script: Path
    make_lang_sets: Path


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Read the command line. Takes *argv* so that a caller can supply one."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent(__doc__))
    parser.add_argument('--langs', required=True,
                        help='comma-separated: java,python')
    parser.add_argument('--tests-dir', default='/var/tmp/testing-dir',
                        help='Root that contains <lang>/ sub-dirs with exercises (passed to prune script).')
    parser.add_argument('--path-dir', default='/var/tmp/path_sets',
                        help='Where <lang>_*.paths and *.json live (input).')
    parser.add_argument('--helpers-dir', default='/var/tmp/helpers',
                        help='Where helper scripts (make_lang_sets.py) reside.')
    parser.add_argument('--jobs', type=int, default=os.cpu_count() or DEFAULT_JOBS)
    parser.add_argument('--skip-prune', action='store_true',
                        help='Skip running prune scripts; use existing artefacts in --path-dir.')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--runtime-chdir', default='/var/tmp/testing-dir',
                        help='Directory the *runtime* sandbox should chdir into (overrides any per-exercise chdir seen during pruning).')
    parser.add_argument('--prune-script', default='/var/tmp/pruning/run_minimal_fs_all.sh',
                        help='Pruning entry point to run per language (the path the compose file mounts it at).')
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
    return Layout(
        path_dir=path_dir,
        core_dir=core_dir,
        debug_dir=debug_dir,
        prune_script=Path(arguments.prune_script),
        make_lang_sets=Path(arguments.helpers_dir) / 'make_lang_sets.py')


def requested_languages(langs_argument: str) -> list[str]:
    """The languages named on the command line, in the order they were given."""
    return [name.strip() for name in langs_argument.split(',') if name.strip()]


# ────────────────────────────────────────── helpers

def run(cmd: Sequence[str], tag: str = '',
        extra_environment: dict[str, str] | None = None) -> None:
    """Run *cmd* streaming output; raise if exit-status != 0.

    Always executed without a shell: every caller passes an argument list, so a
    string form was dead code and only widened the injection surface.

    *extra_environment* is added to this process's environment for the call. It is how an
    option of this program reaches a script that takes its setting from the environment.
    """
    pretty = ' '.join(shlex.quote(str(c)) for c in cmd)
    print(f'{BLUE}[{tag or "cmd"}]{RESET}', pretty)
    t0 = time.time()
    rc = subprocess.call(cmd, env={**os.environ, **(extra_environment or {})})
    dt = time.time() - t0
    if rc:
        raise RuntimeError(f'{tag} failed (rc={rc}, {dt:.1f}s)')
    print(f'{GREEN}✓ {tag} ({dt:.1f}s){RESET}')


# ────────────────────────────────────────── step 1 - prune

def prune_language(lang: str, layout: Layout, arguments: argparse.Namespace) -> None:
    """Prune every exercise of one language, unless --skip-prune says the artefacts exist.

    The prune script writes the per-exercise artefacts into the path directory through
    emit_artifacts.py; see run_minimal_fs_all.sh. It takes the root the exercises live under
    from TESTING_DIR, which is what --tests-dir names, and writes them where OUTPUT_DIR
    says, which is what --path-dir names. Both were parsed and then dropped, so a caller who
    pointed either elsewhere still pruned, and wrote, where the script's own defaults named.
    """
    if arguments.skip_prune:
        print(f'[skip] prune:{lang}')
        return
    if not layout.prune_script.exists():
        raise FileNotFoundError(f'pruning script not found: {layout.prune_script}')
    cmd: list[str] = [str(layout.prune_script)]
    if arguments.verbose:
        cmd.append('--verbose')
    cmd.append(lang)
    run(cmd, f'prune:{lang}',
        {'TESTING_DIR': arguments.tests_dir, 'OUTPUT_DIR': str(layout.path_dir)})


# ────────────────────────────────────────── language union generation

def gen_lang_sets(lang: str, layout: Layout) -> None:
    """Invoke make_lang_sets.py to produce <lang>_union.paths & _intersection.paths.

    A language with no per-exercise .paths, every exercise of it skipped, is skipped here too.
    """
    if not layout.make_lang_sets.exists():
        raise FileNotFoundError(f'make_lang_sets.py not found: {layout.make_lang_sets}')
    if not any(layout.path_dir.glob(f"{lang}_*.paths")):
        print(f'{YELLOW}[warn]{RESET} no {lang}_*.paths in {layout.path_dir}; skipping langsets.')
        return
    cmd = ['python3', str(layout.make_lang_sets), lang, str(layout.path_dir)]
    run(cmd, f'langsets:{lang}')


# ────────────────────────────────────────── utilities

def use_policy_helpers(helpers_dir: Path) -> None:
    """Puts the helpers directory on the import path, so that layer_prune's cfgfile can be imported.

    The configuration files are read and written by the module the layer pruner writes them with,
    so the two cannot come to disagree about the format. It is imported where it is used, after
    main has run this, because the directory is an option of this program.
    """
    if str(helpers_dir) not in sys.path:
        sys.path.insert(0, str(helpers_dir))


def _read_union(path: Path) -> dict[str, set[str]]:
    """Return {'r': readonly_set, 'w': write_set} from a *_union.paths file.

    Lines are expected in the form `r /abs/path` or `w /abs/path` as written by
    make_lang_sets.py.  Blank/comment lines, and lines without a path, are ignored.
    """
    readonly: set[str] = set()
    write: set[str] = set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != UNION_LINE_FIELDS:
            continue
        mode = fields[0]
        p = fields[1]
        if mode == 'w':
            write.add(p)
            readonly.discard(p)
        elif p not in write:
            readonly.add(p)
    return {'r': readonly, 'w': write}


def exercise_stems(lang: str, path_dir: Path, suffix: str) -> set[str]:
    """The names, without *suffix*, of this language's per-exercise artefacts ending in it.

    The union and intersection make_lang_sets.py writes, and the record of an exercise the layer
    pruner aborted, share the name shape and are not exercise artefacts.
    """
    return {
        path.name.removesuffix(suffix) for path in path_dir.glob(f'{lang}_*{suffix}')
        if not path.name.endswith(('_union.paths', '_intersection.paths', ABORTED_SUFFIX))
    }


def artefact_disagreements(lang: str, path_dir: Path) -> list[str]:
    """Name every per-exercise artefact pair of this language that does not agree.

    emit_artifacts.py writes two files per exercise from one parsed log: the .paths the
    policy is built from, and the .json that records what that run saw. Nothing read the
    .json, so a truncated or half-written .paths, which is a smaller policy and still looks
    like a correct one, had nothing to disagree with. They are compared here instead: the
    paths_all entries of the record are exactly the lines of the .paths file, in order.

    An exercise whose name ends in union or intersection is left out of the path sets by the
    same rule make_lang_sets.py applies, so its record reads as an orphan and stops the
    merge. That is the safe direction, and the name is the thing to change.
    """
    problems: list[str] = []
    records = exercise_stems(lang, path_dir, '.json')
    path_sets = exercise_stems(lang, path_dir, '.paths')
    problems += [f'{orphan}.json has no {orphan}.paths beside it'
                 for orphan in sorted(records - path_sets)]
    for exercise in sorted(path_sets):
        paths_file = path_dir / f'{exercise}.paths'
        record_file = path_dir / f'{exercise}.json'
        if not record_file.exists():
            problems.append(f'{paths_file.name} has no {record_file.name} beside it')
            continue
        try:
            record = json.loads(record_file.read_text())
        except ValueError as exc:
            problems.append(f'{record_file.name} is not readable as JSON: {exc}')
            continue
        recorded = [f'{entry["mode"]} {entry["path"]}' for entry in record.get('paths_all', [])]
        written = [line for line in paths_file.read_text().splitlines() if line]
        if recorded != written:
            problems.append(
                f'{paths_file.name} names {len(written)} path(s) while '
                f'{record_file.name} records {len(recorded)}')
    return problems


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
    """Name every layer-pruner artefact of this language that its record does not vouch for."""
    configurations = exercise_stems(lang, path_dir, '.cfg')
    records = exercise_stems(lang, path_dir, '.json')
    problems = [f'{orphan}.json has no {orphan}.cfg beside it' for orphan in sorted(records - configurations)]
    for exercise in sorted(configurations):
        problem = cfg_record_disagreement(lang, exercise, path_dir / f'{exercise}.cfg',
                                          path_dir / f'{exercise}.json')
        if problem is not None:
            problems.append(problem)
    return problems


def aborted_exercises(lang: str, path_dir: Path) -> list[str]:
    """Name every exercise of this language the layer pruner aborted, with the reason it recorded."""
    problems: list[str] = []
    for record_file in sorted(path_dir.glob(f'{lang}_*{ABORTED_SUFFIX}')):
        try:
            reason = json.loads(record_file.read_text()).get('aborted', 'no reason recorded')
        except (json.JSONDecodeError, AttributeError):
            reason = 'its record is not readable'
        problems.append(f'{record_file.name.removesuffix(ABORTED_SUFFIX)} was aborted: {reason}')
    return problems


def produced_by_layer_pruner(lang: str, path_dir: Path) -> bool:
    """Whether this language's artefacts are the layer pruner's .cfg files rather than path sets."""
    return bool(exercise_stems(lang, path_dir, '.cfg'))


def language_artefact_problems(lang: str, path_dir: Path) -> list[str]:
    """Every reason this language's artefacts cannot be merged as they stand.

    An aborted exercise is missing from the language, so its base would be narrower than its
    exercises need. Artefacts of both producers at once mean one of them is left from an earlier
    run, and nothing here can tell which.
    """
    problems = aborted_exercises(lang, path_dir)
    if produced_by_layer_pruner(lang, path_dir) and exercise_stems(lang, path_dir, '.paths'):
        return [*problems, f'{lang} has both .cfg and .paths artefacts; remove the producer not in use']
    if produced_by_layer_pruner(lang, path_dir):
        return problems + cfg_artefact_disagreements(lang, path_dir)
    return problems + artefact_disagreements(lang, path_dir)


# ────────────────────────────────────────── policies


class LanguagePolicy(NamedTuple):
    """What one language's artefacts amount to.

    *base* is the policy BaseLanguage-<lang>.cfg is written from, *exercises* the layer-pruned
    exercises by name (empty for a Bubblewrap language, which has no per-exercise policy), and
    *common* what every exercise needed, or None where nothing says.
    """

    base: Policy
    exercises: dict[str, Policy]
    common: Policy | None


def path_set_policy(union: dict[str, set[str]]) -> Policy:
    """The policy a Bubblewrap path set grants, as the orchestrator has always written it.

    A path pruning found read-only (an ro-bind) grants read and execute; a writable one grants
    read, write, create and delete, since write implies read. An empty [connect] denies every
    outbound connection, so the policy names the loopback the grading tools need (the Gradle
    daemon and the JVM talk over it) explicitly; external egress stays a deliberate per-exercise
    [connect] plus a no-network container.
    """
    from layer_prune import cfgfile
    fs = dict.fromkeys(union['r'], READ_ONLY_SECTIONS)
    fs |= dict.fromkeys(union['w'], WRITABLE_SECTIONS)
    return cfgfile.Policy(fs=fs, connect=BUBBLEWRAP_CONNECT, bind=(), limits={})


def raised(fs: dict[str, frozenset[str]]) -> dict[str, frozenset[str]]:
    """The entries, each nested one raised to its ancestor's sections where it would hold fewer rights.

    phobos-filesystem.sh refuses a nested entry whose rights are a strict subset of an ancestor's,
    and Landlock grants the ancestor's rights beneath it anyway, so raising it changes nothing that
    is enforced and keeps a merged file from being refused.
    """
    from layer_prune import generalise
    return generalise.normalise_hierarchy(fs)


def union_policy(policies: Sequence[Policy]) -> Policy:
    """The union of several policies, without limits: what a base built from them must grant.

    Every path holds every section any of them granted it, raised as `raised` says; the network
    rules are every rule any of them names, sorted. The comments of the exercises' .cfg files, the
    reasons a grant is wider than observed, are not carried over: they stay in those files and
    their records.
    """
    from layer_prune import cfgfile
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
    from layer_prune import generalise
    return [path for path, sections in sorted(union.fs.items())
            if 'execute' in sections and generalise.overlaps_write(path, union.fs)
            and not any('execute' in part.fs.get(path, frozenset()) and generalise.overlaps_write(path, part.fs)
                        for part in parts)]


def common_policy(policies: Sequence[Policy]) -> Policy:
    """What every one of several policies grants: each path all of them name, with the sections all grant it."""
    from layer_prune import cfgfile
    shared = set.intersection(*(set(policy.fs) for policy in policies))
    fs = {path: frozenset.intersection(*(policy.fs[path] for policy in policies)) for path in shared}
    return cfgfile.Policy(fs=raised({path: sections for path, sections in fs.items() if sections}),
                          connect=tuple(sorted(set.intersection(*(set(policy.connect) for policy in policies)))),
                          bind=tuple(sorted(set.intersection(*(set(policy.bind) for policy in policies)))),
                          limits={})


def read_layer_pruned_language(lang: str, path_dir: Path) -> LanguagePolicy:
    """The policy of a language the layer pruner produced, from its per-exercise .cfg files.

    Raises ValueError when a .cfg is not one cfgfile reads exactly as the run-time parser does.
    """
    from layer_prune import cfgfile
    exercises = {
        stem.removeprefix(f'{lang}_'): cfgfile.read_policy((path_dir / f'{stem}.cfg').read_text())
        for stem in sorted(exercise_stems(lang, path_dir, '.cfg'))
    }
    return LanguagePolicy(base=union_policy(list(exercises.values())), exercises=exercises,
                          common=common_policy(list(exercises.values())))


def read_path_set_language(lang: str, path_dir: Path) -> LanguagePolicy | None:
    """The policy of a language the Bubblewrap pruner produced, or None when its union is missing."""
    union_file = path_dir / f'{lang}_union.paths'
    if not union_file.exists():
        print(f'{YELLOW}[warn]{RESET} missing {union_file.name}')
        return None
    common_file = path_dir / f'{lang}_intersection.paths'
    common = path_set_policy(_read_union(common_file)) if common_file.exists() else None
    return LanguagePolicy(base=path_set_policy(_read_union(union_file)), exercises={}, common=common)


def collect_language_data(langs: Iterable[str], path_dir: Path) -> dict[str, LanguagePolicy]:
    """Read the policy of every requested language that has a usable one.

    A policy naming no path is not a language that needs nothing, it is a language whose pruning
    produced a file and no content: an unreadable log, or an emitter that wrote an empty
    artefact. Every real exercise needs at least the files its build runs, so an empty policy is
    a failure wearing a success's file, and it is left out like a missing one.
    """
    data: dict[str, LanguagePolicy] = {}
    for lang in langs:
        if produced_by_layer_pruner(lang, path_dir):
            language = read_layer_pruned_language(lang, path_dir)
        else:
            language = read_path_set_language(lang, path_dir)
        if language is None:
            continue
        if not language.base.fs:
            print(f'{YELLOW}[warn]{RESET} the policy pruned for {lang} names no path at all')
            continue
        data[lang] = language
    return data


# ────────────────────────────────────────── tail handling


def build_runtime_tail(runtime_chdir: str, core_dir: Path) -> None:
    """
    Write TailPhobos.cfg in *core_dir*, holding only the runtime chdir.

    A pruning run measures under Bubblewrap mount and namespace flags (--proc, --dev,
    --share-net, --unshare-*, --new-session) and a per-exercise --chdir. The runtime is
    phobos-landlock-filesystem-and-networksystem, and it accepts none of those Bubblewrap flags: they are not Landlock
    concepts, and it exits on an option it does not know. phobos.sh appends every tail
    token to phobos-landlock-filesystem-and-networksystem, so a tail carrying a Bubblewrap flag would fail every run.

    Network intent reaches the runtime through the [connect] section rather than the tail,
    and a namespace is the container's boundary rather than Landlock's. So the runtime
    tail is the stable runtime chdir and nothing else; the pruning run's per-exercise
    chdir is ephemeral and is discarded.
    """
    dst_tail = core_dir / 'TailPhobos.cfg'
    dst_tail.write_text(f'--chdir {runtime_chdir}\n')
    print('  • wrote TailPhobos.cfg (runtime chdir set to', runtime_chdir + ')')



# ────────────────────────────────────────── the pipeline


def prune_every_language(langs: list[str], layout: Layout,
                         arguments: argparse.Namespace) -> list[str]:
    """Prunes every language, in parallel, and names the ones whose prune failed.

    One failing language must not abort the runs for the others, so every failure is
    collected rather than raised, and one run then names all of them. The except below is
    deliberately broad for that reason: result() re-raises whatever the worker hit, and this
    collects it rather than letting it end the run.
    """
    failed_languages: list[str] = []
    with ThreadPoolExecutor(max_workers=arguments.jobs) as pool:
        language_of = {pool.submit(prune_language, name, layout, arguments): name
                       for name in langs}
        for finished in as_completed(language_of):
            lang = language_of[finished]
            try:
                finished.result()
            except Exception as exc:  # noqa: BLE001
                print(f'{RED}{lang} prune failed:{RESET}', exc)
                failed_languages.append(lang)
    return failed_languages


def forget_earlier_artefacts(langs: Iterable[str], path_dir: Path) -> None:
    """Removes what an earlier run left for these languages.

    Artefacts of an earlier run would otherwise be indistinguishable from this run's, and
    the completeness check further down asks whether a language produced a result: a
    leftover union file from last week would answer yes for a language that produced
    nothing today.
    """
    for lang in langs:
        for stale in path_dir.glob(f'{lang}_*'):
            stale.unlink()


def cross_language_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """BasePhobos.cfg, the union across every language, and its intersection, by the file each goes to.

    The union is for an image that cannot tell which language is running, so it is an
    alternative to the per-language files rather than a part of them, and packaging picks
    one. The intersection is never applied; it is there to be read: every path every language
    names, with the sections the union grants it.
    """
    from layer_prune import cfgfile
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
    from layer_prune import cfgfile
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
        if language.common is not None:
            policies[layout.debug_dir / f'Base{capitalised}Common.cfg'] = language.common
    return policies


def exercise_policies(lang_data: dict[str, LanguagePolicy], layout: Layout) -> dict[Path, Policy]:
    """exercises/<lang>_<exercise>.cfg for every layer-pruned exercise: what its base lacks, and its limits."""
    from layer_prune import cfgfile
    return {layout.core_dir / 'exercises' / f'{lang}_{name}.cfg': cfgfile.remainder(policy, language.base)
            for lang, language in lang_data.items() for name, policy in language.exercises.items()}


def write_policies(policies: dict[Path, Policy], langs: Iterable[str], layout: Layout) -> None:
    """Renders every policy, and only once all of them render, writes them.

    An earlier run's exercises/ files of these languages are removed first, so an exercise that
    is gone leaves no configuration behind that would still be applied to it. Raises ValueError,
    having written nothing, when any policy cannot be written as a file the parser reads as it.
    """
    from layer_prune import cfgfile
    texts = {destination: cfgfile.render(policy) for destination, policy in policies.items()}
    (layout.core_dir / 'BasePhobos.cfg').unlink(missing_ok=True)
    exercises_dir = layout.core_dir / 'exercises'
    exercises_dir.mkdir(exist_ok=True)
    for lang in langs:
        for stale in exercises_dir.glob(f'{lang}_*.cfg'):
            stale.unlink()
    for destination, text in texts.items():
        destination.write_text(text)


def main(argv: Sequence[str] | None = None) -> int:
    """Prunes, checks and merges, and answers the status the program ends with.

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

    if not arguments.skip_prune:
        forget_earlier_artefacts(langs, layout.path_dir)
    failed_languages = prune_every_language(langs, layout, arguments)
    if failed_languages:
        print(f'{RED}[error]{RESET} pruning failed for:', ', '.join(sorted(failed_languages)))
        print('        Refusing to merge a policy from only the languages that succeeded.')
        return 1

    artefact_problems: list[str] = []
    for lang in langs:
        artefact_problems += language_artefact_problems(lang, layout.path_dir)
    if artefact_problems:
        print(f'{RED}[error]{RESET} the per-exercise artefacts do not agree with their records:')
        for problem in artefact_problems:
            print(f'        {problem}')
        print('        Refusing to merge a policy from a measurement that is not whole.')
        return 1

    for lang in langs:
        if not produced_by_layer_pruner(lang, layout.path_dir):
            gen_lang_sets(lang, layout)
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
                 for lang, language in lang_data.items() if language.exercises}
    if any(conflicts.values()):
        print(f'{RED}[error]{RESET} the union of the exercises would let execute beside a write no exercise had:')
        for lang, paths in conflicts.items():
            for path in paths:
                print(f'        {lang}: {path}')
        print('        Refusing to merge a base that would make a writable tree executable.')
        return 1

    policies = {**cross_language_policies(lang_data, layout), **language_policies(lang_data, layout),
                **exercise_policies(lang_data, layout)}
    try:
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
