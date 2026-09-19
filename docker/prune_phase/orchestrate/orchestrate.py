#!/usr/bin/env python3
"""
orchestrate.py – prune, merge & build the Base*.cfg policy files that
`core/phobos-policy.sh` applies at run time. Only the discovery (pruning) phase
uses Bubblewrap; the run phase is enforced by Landlock, not Bubblewrap.

Refactored to consume *pre‑generated* per‑exercise artifacts (.paths/.json) emitted
upstream by `run_minimal_fs_all.sh` + `emit_artifacts.py`.

### Outputs (all in /var/tmp/opt/core/config)
* **BasePhobos.cfg**            – **UNION** of bindings from *all* languages →
  used when the runtime cannot tell which language is running.
* **BaseLanguage-<lang>.cfg**   – full binding set for that language (duplicates ok).
* **BasePhobosIntersect.cfg**   – **INTERSECTION** (common bindings across all
  languages).
* **Base<lang>Intersect.cfg**   – intersection of that language with BasePhobos
  (redundant but useful for auditing).
* **TailPhobos.cfg**            – the runtime chdir, the only tail option the
  phobos-landlock runtime accepts. (The pruning run's Bubblewrap mount and
  namespace flags and its per‑exercise `--chdir` are dropped; the runtime chdir
  is injected via the `--runtime-chdir` CLI argument.)

Overlaps are fine; intersection files are for human inspection.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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
ap.add_argument('--jobs', type=int, default=os.cpu_count() or 4)
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

def run(cmd: Sequence[str], tag: str = '') -> None:
    """Run *cmd* streaming output; raise if exit‑status != 0.

    Always executed without a shell: every caller passes an argument list, so a
    string form was dead code and only widened the injection surface.
    """
    pretty = ' '.join(shlex.quote(str(c)) for c in cmd)
    print(f'\033[34m[{tag or "cmd"}]\033[0m', pretty)
    t0 = time.time()
    rc = subprocess.call(cmd)
    dt = time.time() - t0
    if rc:
        raise RuntimeError(f'{tag} failed (rc={rc}, {dt:.1f}s)')
    print(f'\033[32m✓ {tag} ({dt:.1f}s)\033[0m')


# ────────────────────────────────────────── step 1 – prune

def prune_language(lang: str) -> None:
    if args.skip_prune:
        print(f'[skip] prune:{lang}')
        return
    if not PRUNE_SCRIPT.exists():
        raise FileNotFoundError(f'pruning script not found: {PRUNE_SCRIPT}')
    cmd: list[str] = [str(PRUNE_SCRIPT)]
    if args.verbose:
        cmd.append('--verbose')
    # NOTE: PRUNE_SCRIPT infers EX_ROOT from /var/tmp/testing-dir/<lang>.  It
    # writes per‑exercise artifacts into PATH_DIR via emit_artifacts.py.  See
    # run_minimal_fs_all.sh.
    cmd.append(lang)
    run(cmd, f'prune:{lang}')


# ────────────────────────────────────────── language union generation

def gen_lang_sets(lang: str) -> None:
    """Invoke make_lang_sets.py to produce <lang>_union.paths & _intersection.paths."""
    if not MAKE_LANG_SETS.exists():
        raise FileNotFoundError(f'make_lang_sets.py not found: {MAKE_LANG_SETS}')
    # Skip languages that have no per‑exercise .paths (all exercises skipped).
    if not any(PATH_DIR.glob(f"{lang}_*.paths")):
        print(f'\033[33m[warn]\033[0m no {lang}_*.paths in {PATH_DIR}; skipping langsets.')
        return
    cmd = ['python3', str(MAKE_LANG_SETS), lang, str(PATH_DIR)]
    run(cmd, f'langsets:{lang}')


# ────────────────────────────────────────── utilities

def _read_union(path: Path) -> tuple[set[str], set[str]]:
    """Return (readonly_set, write_set) from a *_union.paths file.

    Lines are expected in the form `r /abs/path` or `w /abs/path` as written by
    make_lang_sets.py.  Blank/comment lines are ignored.
    """
    readonly, write = set(), set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            mode, p = line.split(maxsplit=1)
        except ValueError:
            continue
        if mode == 'w':
            write.add(p); readonly.discard(p)
        elif p not in write:
            readonly.add(p)
    return readonly, write


def collect_language_data(langs: Iterable[str]) -> dict[str, dict[str, set[str]]]:
    data: dict[str, dict[str, set[str]]] = {}
    for lang in langs:
        union_file = PATH_DIR / f'{lang}_union.paths'
        if not union_file.exists():
            print(f'\033[33m[warn]\033[0m missing {union_file.name}')
            continue
        r_set, w_set = _read_union(union_file)
        # A union naming nothing is not a language that needs nothing, it is a
        # language whose pruning produced a file and no content: an unreadable log,
        # or an emitter that wrote an empty artefact. Every real exercise contributes
        # the base bindings, so an empty union is a failure wearing a success's file.
        if not r_set and not w_set:
            print(f'\033[33m[warn]\033[0m {union_file.name} names no path at all')
            continue
        data[lang] = {'r': r_set, 'w': w_set}
    return data


# ────────────────────────────────────────── tail handling

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
print('\n\033[1mOrchestrating for:\033[0m', ', '.join(langs), '\n')

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
            print(f'\033[31m{lang} prune failed:\033[0m', exc)
            failed_languages.append(lang)

# The files below are a security policy: everything not in them is denied. Built
# from the languages that happened to succeed, they would be a narrower policy
# than anyone asked for, and nothing downstream could tell that from a correct
# one. Refuse instead, and leave whatever is already on disk untouched.
if failed_languages:
    print('\033[31m[error]\033[0m pruning failed for:', ', '.join(sorted(failed_languages)))
    print('        Refusing to merge a policy from only the languages that succeeded.')
    sys.exit(1)

# 2) generate per‑language union/intersection files
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
    print('\033[31m[error]\033[0m no usable pruning result for:', ', '.join(missing_languages))
    print('        Refusing to merge a policy that is missing a language that was asked for.')
    sys.exit(1)

# 4) BasePhobos (UNION across langs)
read_union, write_union = set(), set()
for info in lang_data.values():
    write_union |= info['w']
for info in lang_data.values():
    read_union |= (info['r'] - write_union)
write_cfg_path = CORE_DIR / 'BasePhobos.cfg'

def _write_cfg(read_set: set[str], write_set: set[str], dest: Path) -> None:
    lines: list[str] = []
    # Per-right sections. A former read-only (ro-bind) path grants read+execute; a former
    # writable path grants read+write+create+delete. Write implies read, so writable paths
    # also appear in [read].
    read_all = sorted(read_set | write_set)
    if read_all:
        lines += ['[read]', *read_all, '']
    if read_set:
        lines += ['[execute]', *sorted(read_set), '']
    if write_set:
        writable = sorted(write_set)
        for section in ('write', 'create', 'delete'):
            lines += [f'[{section}]', *writable, '']
    # An empty [connect] now denies every outbound connection, so a generated base names the
    # loopback the grading tools need (the Gradle daemon and the JVM talk over it) explicitly.
    # External egress stays a deliberate per-exercise [connect] plus a no-network container.
    lines += ['[connect]', 'allow 127.0.0.1:*', 'allow [::1]', 'allow localhost', '']
    dest.write_text('\n'.join(lines))

_write_cfg(read_union, write_union, write_cfg_path)

# 5) BasePhobosIntersect (intersection across languages)
all_sets = [(info['r'] | info['w']) for info in lang_data.values()]
inter_all = set.intersection(*all_sets)
read_inter_all, write_inter_all = set(), set()
for p in inter_all:
    if any(p in info['w'] for info in lang_data.values()):
        write_inter_all.add(p)
    else:
        read_inter_all.add(p)
_write_cfg(read_inter_all, write_inter_all, INTERSECT_DIR / 'BasePhobosIntersect.cfg')

# 6) per‑language files (full & intersection)
for L, info in lang_data.items():
    _write_cfg(info['r'], info['w'], CORE_DIR / f'BaseLanguage-{L}.cfg')
    Lcap = L.capitalize()
    lang_inter_read  = info['r'] & (read_union | write_union)
    lang_inter_write = info['w'] & (read_union | write_union)
    _write_cfg(lang_inter_read, lang_inter_write, INTERSECT_DIR / f'Base{Lcap}Intersect.cfg')
# 7) TailPhobos (sanitize & inject runtime chdir)
build_runtime_tail(args.runtime_chdir)

print('\n\033[1mDone.\033[0m')
