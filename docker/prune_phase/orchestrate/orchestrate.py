#!/usr/bin/env python3
"""
orchestrate.py - prune, merge & build the Base*.cfg policy files that
`core/phobos-policy.sh` applies at run time. Only the discovery (pruning) phase
uses Bubblewrap; the run phase is enforced by Landlock, not Bubblewrap.

It consumes the per-exercise artefacts (.paths and .json) that
`run_minimal_fs_all.sh` and `emit_artifacts.py` write, and holds each .paths to the
.json written beside it in the same run before it merges anything.

### Outputs (all in /var/tmp/opt/core/config)
* **BasePhobos.cfg**            - **UNION** of bindings from *all* languages →
  used when the runtime cannot tell which language is running.
* **BaseLanguage-<lang>.cfg**   - full binding set for that language (duplicates ok).
* **TailPhobos.cfg**            - the runtime chdir, the only tail option the
  phobos-landlock-filesystem-and-networksystem runtime accepts. (The pruning run's Bubblewrap mount and
  namespace flags and its per-exercise `--chdir` are dropped; the runtime chdir
  is injected via the `--runtime-chdir` CLI argument.)

### For reading, in the debug/ subdirectory
These are never applied. They are the two comparisons that say something
BaseLanguage-<lang>.cfg does not, so that a policy can be judged rather than only
inspected.
* **BasePhobosIntersect.cfg**   - what every language needed.
* **Base<Lang>Only.cfg**        - what no other language needed, which is where a
  policy grows when one language's prune goes wrong.
* **Base<Lang>Common.cfg**      - what every exercise of that language needed with the
  same right, from the intersection make_lang_sets.py writes. A path two exercises
  needed with different rights is absent from it: the intersection is taken over whole
  "mode path" lines.

Ship exactly one Base*.cfg beside phobos-policy.sh: it applies every Base*.cfg it
finds there, so a BasePhobos.cfg left next to a BaseLanguage-java.cfg gives a Java
run the paths of every other language as well.
"""

from __future__ import annotations

import argparse
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
from typing import NamedTuple

# The terminal escape sequences the progress output is coloured with.
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
BOLD = '\033[1m'
RESET = '\033[0m'
# A line of a *_union.paths file: its mode and its path.
UNION_LINE_FIELDS = 2
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
    records = {path.stem for path in path_dir.glob(f'{lang}_*.json')}
    path_sets = {
        path.stem for path in path_dir.glob(f'{lang}_*.paths')
        if not path.name.endswith(('_union.paths', '_intersection.paths'))
    }
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
        except json.JSONDecodeError as exc:
            problems.append(f'{record_file.name} is not readable as JSON: {exc}')
            continue
        recorded = [f'{entry["mode"]} {entry["path"]}' for entry in record.get('paths_all', [])]
        written = [line for line in paths_file.read_text().splitlines() if line]
        if recorded != written:
            problems.append(
                f'{paths_file.name} names {len(written)} path(s) while '
                f'{record_file.name} records {len(recorded)}')
    return problems


def collect_language_data(langs: Iterable[str], path_dir: Path) -> dict[str, dict[str, set[str]]]:
    """Read the union of every requested language that has a usable one.

    A union naming nothing is not a language that needs nothing, it is a language whose pruning
    produced a file and no content: an unreadable log, or an emitter that wrote an empty
    artefact. Every real exercise contributes the base bindings, so an empty union is a failure
    wearing a success's file, and it is left out like a missing one.
    """
    data: dict[str, dict[str, set[str]]] = {}
    for lang in langs:
        union_file = path_dir / f'{lang}_union.paths'
        if not union_file.exists():
            print(f'{YELLOW}[warn]{RESET} missing {union_file.name}')
            continue
        union = _read_union(union_file)
        if not union['r'] and not union['w']:
            print(f'{YELLOW}[warn]{RESET} {union_file.name} names no path at all')
            continue
        data[lang] = union
    return data


# ────────────────────────────────────────── writing one policy


def _write_cfg(read_set: set[str], write_set: set[str], dest: Path) -> None:
    """Write one policy cfg with a section per right.

    A path pruning found read-only (an ro-bind) grants read and execute; a writable one grants
    read, write, create and delete, since write implies read. An empty [connect] denies every
    outbound connection, so a generated base names the loopback the grading tools need (the
    Gradle daemon and the JVM talk over it) explicitly; external egress stays a deliberate
    per-exercise [connect] plus a no-network container.
    """
    lines: list[str] = []
    read_all = sorted(read_set | write_set)
    if read_all:
        lines += ['[read]', *read_all, '']
    if read_set:
        lines += ['[execute]', *sorted(read_set), '']
    if write_set:
        writable = sorted(write_set)
        for section in ('write', 'create', 'delete'):
            lines += [f'[{section}]', *writable, '']
    lines += ['[connect]', 'allow 127.0.0.1:*', 'allow [::1]', 'allow localhost', '']
    dest.write_text('\n'.join(lines))


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


def write_cross_language_policy(lang_data: dict[str, dict[str, set[str]]],
                                layout: Layout) -> None:
    """Writes BasePhobos.cfg, the union across every language, and its intersection.

    The union is for an image that cannot tell which language is running, so it is an
    alternative to the per-language files rather than a part of them, and packaging picks
    one. The intersection is never applied; it is there to be read.
    """
    read_union: set[str] = set()
    write_union: set[str] = set()
    for info in lang_data.values():
        write_union |= info['w']
    for info in lang_data.values():
        read_union |= (info['r'] - write_union)
    _write_cfg(read_union, write_union, layout.core_dir / 'BasePhobos.cfg')

    every_path = [(info['r'] | info['w']) for info in lang_data.values()]
    shared = set.intersection(*every_path)
    read_shared: set[str] = set()
    write_shared: set[str] = set()
    for path in shared:
        if any(path in info['w'] for info in lang_data.values()):
            write_shared.add(path)
        else:
            read_shared.add(path)
    _write_cfg(read_shared, write_shared, layout.debug_dir / 'BasePhobosIntersect.cfg')


def write_language_policies(lang_data: dict[str, dict[str, set[str]]],
                            layout: Layout) -> None:
    """Writes each language's policy, plus the two comparisons that say what it does not.

    Base<Lang>Only names what no other language needed, which is where a policy grows when
    one language's prune goes wrong; Base<Lang>Common names what every exercise of that
    language needed, read from the intersection make_lang_sets already writes. Neither is
    ever applied.
    """
    for lang, info in lang_data.items():
        _write_cfg(info['r'], info['w'], layout.core_dir / f'BaseLanguage-{lang}.cfg')
        capitalised = lang.capitalize()
        other_paths: set[str] = set()
        for other_lang, other_info in lang_data.items():
            if other_lang != lang:
                other_paths |= other_info['r'] | other_info['w']
        _write_cfg(info['r'] - other_paths, info['w'] - other_paths,
                   layout.debug_dir / f'Base{capitalised}Only.cfg')
        common_file = layout.path_dir / f'{lang}_intersection.paths'
        if common_file.exists():
            common = _read_union(common_file)
            _write_cfg(common['r'], common['w'],
                       layout.debug_dir / f'Base{capitalised}Common.cfg')


def main(argv: Sequence[str] | None = None) -> int:
    """Prunes, checks and merges, and answers the status the program ends with.

    Every refusal below answers non-zero and leaves whatever is already on disk untouched.
    The files this writes are a security policy, where everything not named is denied, so a
    policy built from only the languages that happened to work would be narrower than anyone
    asked for and nothing downstream could tell that from a correct one.
    """
    arguments = parse_arguments(argv)
    layout = make_layout(arguments)
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
        artefact_problems += artefact_disagreements(lang, layout.path_dir)
    if artefact_problems:
        print(f'{RED}[error]{RESET} the per-exercise artefacts do not agree with their records:')
        for problem in artefact_problems:
            print(f'        {problem}')
        print('        Refusing to merge a policy from a measurement that is not whole.')
        return 1

    for lang in langs:
        gen_lang_sets(lang, layout)
    lang_data = collect_language_data(langs, layout.path_dir)

    missing_languages = sorted(set(langs) - set(lang_data))
    if missing_languages:
        print(f'{RED}[error]{RESET} no usable pruning result for:', ', '.join(missing_languages))
        print('        Refusing to merge a policy that is missing a language that was asked for.')
        return 1

    write_cross_language_policy(lang_data, layout)
    write_language_policies(lang_data, layout)
    build_runtime_tail(arguments.runtime_chdir, layout.core_dir)

    print(f'\n{BOLD}Done.{RESET}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
