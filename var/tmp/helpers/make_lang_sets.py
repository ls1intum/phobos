#!/usr/bin/env python3
"""Folds one language's per-exercise path sets into a union and an intersection.

The union is every path any exercise of that language needed, which is what the policy
for that language is built from. The intersection is every path all of them needed, which
says what the language environment itself costs, before any exercise adds to it.

    make_lang_sets.py <language> <directory of the per-exercise .paths files>
"""

from __future__ import annotations

import functools
import pathlib
import sys

# Where the language and the directory of run results stand on the command line.
LANGUAGE_ARGUMENT = 1
DIRECTORY_ARGUMENT = 2

language = sys.argv[LANGUAGE_ARGUMENT]
path_directory = pathlib.Path(sys.argv[DIRECTORY_ARGUMENT])

# The per-exercise results only. The union and intersection of an earlier run live in the
# same directory under names of the same shape, and folding them in again would make a
# result depend on whether one had been written before.
run_results = [
    path for path in path_directory.glob(f"{language}_*.paths")
    if not (path.name.endswith("_union.paths") or path.name.endswith("_intersection.paths"))
]

if not run_results:
    sys.exit("no run-result .paths files found")

path_sets = [set(path.read_text().splitlines()) for path in run_results]

union = sorted(functools.reduce(set.union, path_sets))
intersection = sorted(functools.reduce(set.intersection, path_sets))

(path_directory / f"{language}_union.paths").write_text("\n".join(union))
(path_directory / f"{language}_intersection.paths").write_text("\n".join(intersection))
