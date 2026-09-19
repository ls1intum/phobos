#!/usr/bin/env python3
import functools
import pathlib
import sys

# Where the language and the directory of run results stand on the command line.
LANGUAGE_ARGUMENT = 1
DIRECTORY_ARGUMENT = 2

lang = sys.argv[LANGUAGE_ARGUMENT]
P = pathlib.Path(sys.argv[DIRECTORY_ARGUMENT])

# 1) collect only the “real” run-result files; skip union/intersection outputs
input_paths = [
    p for p in P.glob(f"{lang}_*.paths")
    if not (p.name.endswith("_union.paths") or p.name.endswith("_intersection.paths"))
]

if not input_paths:
    sys.exit("no run-result .paths files found")

# 2) read them into Python sets
sets = [set(p.read_text().splitlines()) for p in input_paths]

# 3) union & intersection
u = sorted(functools.reduce(set.union,     sets))
i = sorted(functools.reduce(set.intersection, sets))

# 4) write out
(P / f"{lang}_union.paths").write_text("\n".join(u))
(P / f"{lang}_intersection.paths").write_text("\n".join(i))

