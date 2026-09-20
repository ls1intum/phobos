#!/usr/bin/env python3
"""
orchestrate.py – prune, merge & build the Base*.cfg policy files that
`core/phobos-policy.sh` applies at run time. Only the discovery (pruning) phase
uses Bubblewrap; the run phase is enforced by Landlock, not Bubblewrap.

It consumes the per-exercise artefacts (.paths and .json) that
`run_minimal_fs_all.sh` and `emit_artifacts.py` write, and holds each .paths to the
.json written beside it in the same run before it merges anything.

### Outputs (all in /var/tmp/opt/core/config)
* **BasePhobos.cfg**            – **UNION** of bindings from *all* languages →
  used when the runtime cannot tell which language is running.
* **BaseLanguage-<lang>.cfg**   – full binding set for that language (duplicates ok).
* **TailPhobos.cfg**            – the runtime chdir, the only tail option the
  phobos-landlock runtime accepts. (The pruning run's Bubblewrap mount and
  namespace flags and its per-exercise `--chdir` are dropped; the runtime chdir
  is injected via the `--runtime-chdir` CLI argument.)

### For reading, in the debug/ subdirectory
These are never applied. They are the two comparisons that say something
BaseLanguage-<lang>.cfg does not, so that a policy can be judged rather than only
inspected.
* **BasePhobosIntersect.cfg**   – what every language needed.
* **Base<Lang>Only.cfg**        – what no other language needed, which is where a
  policy grows when one language's prune goes wrong.
* **Base<Lang>Common.cfg**      – what every exercise of that language needed with the
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
ap = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description=textwrap.dedent(__doc__))

ap.add_argument('--langs', required=True,
                help='comma‑separated: java,python')
ap.add_argument('--tests-dir', default='/var/tmp/testing-dir',
                help='Root that contains <lang>/ sub‑dirs with exercises (passed to prune script).')
ap.add_argument('--path-dir', default='/var/tmp/path_sets',
                help='Where <lang>_*.paths and *.json live (input).')
ap.add_argument('--helpers-dir', default='/var/tmp/helpers',
                help='Where helper scripts (make_lang_sets.py) reside.')
ap.add_argument('--jobs', type=int, default=os.cpu_count() or DEFAULT_JOBS)
ap.add_argument('--skip-prune', action='store_true',
                help='Skip running prune scripts; use existing artifacts in --path-dir.')
ap.add_argument('--verbose', action='store_true')
ap.add_argument('--runtime-chdir', default='/var/tmp/testing-dir',
                help='Directory the *runtime* sandbox should chdir into (overrides any per‑exercise chdir seen during pruning).')
ap.add_argument('--prune-script', default='/var/tmp/pruning/run_minimal_fs_all.sh',
                help='Pruning entry point to run per language (the path the compose file mounts it at).')
ap.add_argument('--core-dir', default='/var/tmp/opt/core/config',
                help='Where the generated policy files are written.')
args = ap.parse_args()

langs: list[str] = [l.strip() for l in args.langs.split(',') if l.strip()]
PATH_DIR = Path(args.path_dir);            PATH_DIR.mkdir(parents=True, exist_ok=True)
CORE_DIR = Path(args.core_dir);            CORE_DIR.mkdir(parents=True, exist_ok=True)
INTERSECT_DIR = CORE_DIR / 'debug'
INTERSECT_DIR.mkdir(parents=True, exist_ok=True)

HELPERS_DIR = Path(args.helpers_dir)
PRUNE_SCRIPT = Path(args.prune_script)
MAKE_LANG_SETS = HELPERS_DIR / 'make_lang_sets.py'

# ────────────────────────────────────────── helpers

def run(cmd: Sequence[str], tag: str = '',
        extra_environment: dict[str, str] | None = None) -> None:
    """Run *cmd* streaming output; raise if exit‑status != 0.

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


# ────────────────────────────────────────── step 1 – prune

def prune_language(lang: str) -> None:
    """Prune every exercise of one language, unless --skip-prune says the artefacts exist.

    PRUNE_SCRIPT writes the per-exercise artefacts into PATH_DIR through emit_artifacts.py;
    see run_minimal_fs_all.sh. It takes the root the exercises live under from TESTING_DIR,
    which is what --tests-dir names, and writes them where OUTPUT_DIR says, which is what
    --path-dir names. Both were parsed and then dropped, so a caller who pointed either
    elsewhere still pruned, and wrote, where the script's own defaults named.
    """
    if args.skip_prune:
        print(f'[skip] prune:{lang}')
        return
    if not PRUNE_SCRIPT.exists():
        raise FileNotFoundError(f'pruning script not found: {PRUNE_SCRIPT}')
    cmd: list[str] = [str(PRUNE_SCRIPT)]
    if args.verbose:
        cmd.append('--verbose')
    cmd.append(lang)
    run(cmd, f'prune:{lang}',
        {'TESTING_DIR': args.tests_dir, 'OUTPUT_DIR': str(PATH_DIR)})


# ────────────────────────────────────────── language union generation

def gen_lang_sets(lang: str) -> None:
    """Invoke make_lang_sets.py to produce <lang>_union.paths & _intersection.paths.

    A language with no per-exercise .paths, every exercise of it skipped, is skipped here too.
    """
    if not MAKE_LANG_SETS.exists():
        raise FileNotFoundError(f'make_lang_sets.py not found: {MAKE_LANG_SETS}')
    if not any(PATH_DIR.glob(f"{lang}_*.paths")):
        print(f'{YELLOW}[warn]{RESET} no {lang}_*.paths in {PATH_DIR}; skipping langsets.')
        return
    cmd = ['python3', str(MAKE_LANG_SETS), lang, str(PATH_DIR)]
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


def artefact_disagreements(lang: str) -> list[str]:
    """Name every per-exercise artefact pair of this language that does not agree.

    emit_artifacts.py writes two files per exercise from one parsed log: the .paths the
    policy is built from, and the .json that records what that run saw. Nothing read the
    .json, so a truncated or half-written .paths, which is a smaller policy and still looks
    like a correct one, had nothing to disagree with. They are compared here instead: the
    paths_all entries of the record are exactly the lines of the .paths file, in order.
    """
    problems: list[str] = []
    records = {path.stem for path in PATH_DIR.glob(f'{lang}_*.json')}
    # An exercise whose name ends in union or intersection is left out of the path sets by
    # the same rule make_lang_sets.py applies, so its record reads as an orphan and stops
    # the merge. That is the safe direction, and the name is the thing to change.
    path_sets = {
        path.stem for path in PATH_DIR.glob(f'{lang}_*.paths')
        if not path.name.endswith(('_union.paths', '_intersection.paths'))
    }
    problems += [f'{orphan}.json has no {orphan}.paths beside it'
                 for orphan in sorted(records - path_sets)]
    for exercise in sorted(path_sets):
        paths_file = PATH_DIR / f'{exercise}.paths'
        record_file = PATH_DIR / f'{exercise}.json'
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


def collect_language_data(langs: Iterable[str]) -> dict[str, dict[str, set[str]]]:
    """Read the union of every requested language that has a usable one.

    A union naming nothing is not a language that needs nothing, it is a language whose pruning
    produced a file and no content: an unreadable log, or an emitter that wrote an empty
    artefact. Every real exercise contributes the base bindings, so an empty union is a failure
    wearing a success's file, and it is left out like a missing one.
    """
    data: dict[str, dict[str, set[str]]] = {}
    for lang in langs:
        union_file = PATH_DIR / f'{lang}_union.paths'
        if not union_file.exists():
            print(f'{YELLOW}[warn]{RESET} missing {union_file.name}')
            continue
        union = _read_union(union_file)
        if not union['r'] and not union['w']:
            print(f'{YELLOW}[warn]{RESET} {union_file.name} names no path at all')
            continue
        data[lang] = union
    return data


# ────────────────────────────────────────── tail handling


def build_runtime_tail(runtime_chdir: str) -> None:
    """
    Write CORE_DIR/TailPhobos.cfg holding only the runtime chdir.

    A pruning run measures under Bubblewrap mount and namespace flags (--proc, --dev,
    --share-net, --unshare-*, --new-session) and a per-exercise --chdir. The runtime is
    phobos-landlock, and it accepts none of those Bubblewrap flags: they are not Landlock
    concepts, and it exits on an option it does not know. phobos.sh appends every tail
    token to phobos-landlock, so a tail carrying a Bubblewrap flag would fail every run.

    Network intent reaches the runtime through the [connect] section rather than the tail,
    and a namespace is the container's boundary rather than Landlock's. So the runtime
    tail is the stable runtime chdir and nothing else; the pruning run's per-exercise
    chdir is ephemeral and is discarded.
    """
    dst_tail = CORE_DIR / 'TailPhobos.cfg'
    dst_tail.write_text(f'--chdir {runtime_chdir}\n')
    print('  • wrote TailPhobos.cfg (runtime chdir set to', runtime_chdir + ')')



# ────────────────────────────────────────── main pipeline
print(f'\n{BOLD}Orchestrating for:{RESET}', ', '.join(langs), '\n')

# 1) prune in parallel (creates per‑exercise artifacts in PATH_DIR)
# Artefacts of an earlier run would otherwise be indistinguishable from this run's.
# That matters because the completeness check further down asks whether a language
# produced a result: a leftover union file from last week would answer yes for a
# language that produced nothing today. Skipped on --skip-prune, whose whole purpose
# is to consume artefacts that an earlier run left behind on purpose.
if not args.skip_prune:
    for lang in langs:
        for stale in PATH_DIR.glob(f'{lang}_*'):
            stale.unlink()

failed_languages: list[str] = []
with ThreadPoolExecutor(max_workers=args.jobs) as pool:
    fut2lang = {pool.submit(prune_language, l): l for l in langs}
    for fut in as_completed(fut2lang):
        lang = fut2lang[fut]
        try:
            fut.result()
        # Deliberately broad: fut.result() re-raises whatever the worker hit, and
        # one failing language must not abort the runs for the others. Every
        # failure is collected instead, so one run names all of them.
        except Exception as exc:  # noqa: BLE001
            print(f'{RED}{lang} prune failed:{RESET}', exc)
            failed_languages.append(lang)

# The files below are a security policy: everything not in them is denied. Built
# from the languages that happened to succeed, they would be a narrower policy
# than anyone asked for, and nothing downstream could tell that from a correct
# one. Refuse instead, and leave whatever is already on disk untouched.
if failed_languages:
    print(f'{RED}[error]{RESET} pruning failed for:', ', '.join(sorted(failed_languages)))
    print('        Refusing to merge a policy from only the languages that succeeded.')
    sys.exit(1)

# 2) hold each language's artefacts to their own record, then generate the union and
# intersection files. A .paths that disagrees with the .json written beside it in the same
# run is a policy built from part of a measurement, which looks exactly like a correct one.
artefact_problems: list[str] = []
for L in langs:
    artefact_problems += artefact_disagreements(L)
if artefact_problems:
    print(f'{RED}[error]{RESET} the per-exercise artefacts do not agree with their records:')
    for problem in artefact_problems:
        print(f'        {problem}')
    print('        Refusing to merge a policy from a measurement that is not whole.')
    sys.exit(1)

for L in langs:
    gen_lang_sets(L)

# 3) gather *_union.paths
lang_data = collect_language_data(langs)

# Every requested language, not merely one of them. A language whose pruning exited
# zero without producing anything, because every exercise was skipped or because
# emit_artifacts.py failed and was only warned about, drops out silently here. The
# merge below would then write a policy for the languages that happened to work, and
# nothing downstream could tell that from a policy for all of them.
missing_languages = sorted(set(langs) - set(lang_data))
if missing_languages:
    print(f'{RED}[error]{RESET} no usable pruning result for:', ', '.join(missing_languages))
    print('        Refusing to merge a policy that is missing a language that was asked for.')
    sys.exit(1)

# 4) BasePhobos (UNION across langs)
read_union: set[str] = set()
write_union: set[str] = set()
for info in lang_data.values():
    write_union |= info['w']
for info in lang_data.values():
    read_union |= (info['r'] - write_union)
write_cfg_path = CORE_DIR / 'BasePhobos.cfg'

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

_write_cfg(read_union, write_union, write_cfg_path)

# 5) BasePhobosIntersect (intersection across languages)
all_sets = [(info['r'] | info['w']) for info in lang_data.values()]
inter_all = set.intersection(*all_sets)
read_inter_all: set[str] = set()
write_inter_all: set[str] = set()
for p in inter_all:
    if any(p in info['w'] for info in lang_data.values()):
        write_inter_all.add(p)
    else:
        read_inter_all.add(p)
_write_cfg(read_inter_all, write_inter_all, INTERSECT_DIR / 'BasePhobosIntersect.cfg')

# 6) per-language files, plus the two comparisons that say something the language file
# does not. Base<Lang>Only names what no other language needed, which is where a policy
# grows when one language's prune goes wrong; Base<Lang>Common names what every exercise
# of that language needed, read from the intersection make_lang_sets already writes.
for L, info in lang_data.items():
    _write_cfg(info['r'], info['w'], CORE_DIR / f'BaseLanguage-{L}.cfg')
    Lcap = L.capitalize()
    other_paths: set[str] = set()
    for other_lang, other_info in lang_data.items():
        if other_lang != L:
            other_paths |= other_info['r'] | other_info['w']
    _write_cfg(info['r'] - other_paths, info['w'] - other_paths,
               INTERSECT_DIR / f'Base{Lcap}Only.cfg')
    common_file = PATH_DIR / f'{L}_intersection.paths'
    if common_file.exists():
        common = _read_union(common_file)
        _write_cfg(common['r'], common['w'], INTERSECT_DIR / f'Base{Lcap}Common.cfg')
# 7) TailPhobos (sanitize & inject runtime chdir)
build_runtime_tail(args.runtime_chdir)

print(f'\n{BOLD}Done.{RESET}')
