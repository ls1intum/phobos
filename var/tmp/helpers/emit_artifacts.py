#!/usr/bin/env python3
"""
emit_artifacts.py
-----------------

Parse a `final_bindings.txt` log produced by `detect_minimal_fs.sh` and emit:

  • <out_dir>/<lang>_<exercise>.paths
      - 'r /path' / 'w /path' lines
      - 'n' (hidden) entries are not written.

  • <out_dir>/<lang>_<exercise>.json
      Structured record with:
         paths_dynamic : list[ {mode,path} ]       # may include 'n'
         paths_base    : list[ {mode,path} ]       # static Base binds
         paths_all     : list[ {mode,path} ]       # merged r/w (w overrides r)
         tail_flags    : list[str]                 # from 'Tail options:' line
         provenance    : log SHA256, timestamp, schema_version
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import time

# -----------------------------------------------------------------------------
# Regex and helpers
# -----------------------------------------------------------------------------
RX_DETAIL = re.compile(r"^(?P<path>\/[^ ]+)\s+->\s+(?P<mode>[rwn])$")  # /path -> r|w|n
# The words of the label in front of the options on a "Base options:" or "Tail options:" line.
OPTIONS_LABEL_WORDS = 2
# How far the JSON record is indented, for a reader rather than for a parser.
JSON_INDENT = 2
# The status the helper ends with when the log it was pointed at does not exist.
EXIT_NO_LOG = 2


def canon(p: str) -> str:
    """Canonicalise a path as it is written, without resolving symbolic links, keeping one that
    does not exist.

    Any failure of the external realpath falls back to the pure-Python resolution rather than
    abort the artefact run, which is why the exception caught is deliberately broad. That
    fallback does resolve symbolic links, so a run without GNU realpath can record a link's
    target where it would otherwise record the link.
    """
    try:
        out = subprocess.check_output(
            ["realpath", "--canonicalize-missing", "--no-symlinks", p],
            text=True,
        ).strip()
        return out or p
    except Exception:  # noqa: BLE001
        return str(pathlib.Path(p).resolve(strict=False))


# -----------------------------------------------------------------------------
# Parse detect_minimal_fs log
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ParsedLog:
    """What a final_bindings.txt log holds.

    dyn_pairs  – [('r'|'w'|'n', /path), ...] from the per-path lines
    base_modes – {path: 'r'|'w'} from the 'Base options:' line
    tail_flags – ['--flag', 'value', ...] from the 'Tail options:' line
    """

    dyn_pairs: list[tuple[str, str]]
    base_modes: dict[str, str]
    tail_flags: list[str]


def detail_pair(match: re.Match, workdir, runtime_root) -> tuple[str, str]:
    """The (mode, path) of one per-path line, its path canonical and moved from the pruning
    run's temporary workdir to the runtime root the policy is written for."""
    cp = canon(match["path"])
    if cp.startswith(workdir):
        cp = cp.replace(workdir, runtime_root, 1)
    return (match["mode"], cp)


def base_modes_from(line: str) -> dict[str, str]:
    """The static bind mounts of a 'Base options:' line, each path with 'r' for a read-only bind
    and 'w' for a writable one. The operands of the other mount options are skipped."""
    base_modes: dict[str, str] = {}
    it = iter(line.split()[OPTIONS_LABEL_WORDS:])
    for flag in it:
        try:
            if flag == "--ro-bind":
                p = canon(next(it))
                next(it)
                base_modes[p] = "r"
            elif flag == "--bind":
                p = canon(next(it))
                next(it)
                base_modes[p] = "w"
            elif flag in ("--proc", "--dev", "--tmpfs"):
                _ = next(it)
        except StopIteration:
            break
    return base_modes


def parse_log(path: pathlib.Path, workdir, runtime_root) -> ParsedLog:
    """Reads a final_bindings.txt log: its per-path lines, its 'Base options:' line and its
    'Tail options:' line, with the pruner's "[LOG] " prefix stripped where it has one."""
    parsed = ParsedLog(dyn_pairs=[], base_modes={}, tail_flags=[])
    with path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            line = line.removeprefix("[LOG] ")
            m = RX_DETAIL.match(line)
            if m:
                parsed.dyn_pairs.append(detail_pair(m, workdir, runtime_root))
            elif line.startswith("Base options:"):
                parsed.base_modes.update(base_modes_from(line))
            elif line.startswith("Tail options:"):
                parsed.tail_flags.extend(line.split()[OPTIONS_LABEL_WORDS:])
    return parsed


# -----------------------------------------------------------------------------
# Merge dynamic + base (w overrides r)
# -----------------------------------------------------------------------------
def merge_pairs(dyn: list[tuple[str, str]],
                base: dict[str, str]) -> list[tuple[str, str]]:
    """The static base binds merged with the pruned paths, a writable mode winning over a
    read-only one and hidden paths left out, sorted by path so the result is deterministic."""
    merged: dict[str, str] = dict(base)
    for mode, path in dyn:
        if mode == "n":
            continue
        prev = merged.get(path)
        if prev is None or (prev == "r" and mode == "w"):
            merged[path] = mode
    return sorted(((m, p) for p, m in merged.items()), key=lambda t: t[1])


# -----------------------------------------------------------------------------
# Writers
# -----------------------------------------------------------------------------
def write_paths(lang: str, ex: str,
                pairs: list[tuple[str, str]],
                out_dir: pathlib.Path) -> pathlib.Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"{lang}_{ex}.paths"
    dest.write_text("\n".join(f"{m} {p}" for m, p in pairs) + "\n")
    return dest


def write_json(lang: str, ex: str,
               dyn_pairs: list[tuple[str, str]],
               base_modes: dict[str, str],
               merged_pairs: list[tuple[str, str]],
               tail: list[str],
               log_path: pathlib.Path,
               out_dir: pathlib.Path) -> pathlib.Path:
    data = {
        "schema_version": 1,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "lang": lang,
        "exercise": ex,
        "paths_dynamic": [{"mode": m, "path": p} for m, p in dyn_pairs],
        "paths_base": [{"mode": m, "path": p} for p, m in sorted(base_modes.items())],
        "paths_all": [{"mode": m, "path": p} for m, p in merged_pairs],
        "tail_flags": tail,
        "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
        "log_filename": str(log_path),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"{lang}_{ex}.json"
    dest.write_text(json.dumps(data, indent=JSON_INDENT, sort_keys=True) + "\n")
    return dest


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", required=True)
    ap.add_argument("--exercise", required=True)
    ap.add_argument("--config-file", required=True,
                    help="final_bindings.txt from detect_minimal_fs.sh")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--workdir", required=True,
                    help="Temp workdir used during pruning; will be replaced.")
    ap.add_argument("--runtime-root", default="/var/tmp/testing-dir")
    args = ap.parse_args()

    log_path = pathlib.Path(args.config_file)
    out_dir = pathlib.Path(args.out_dir)

    if not log_path.is_file():
        print(f"emit_artifacts: no log file {log_path}", file=sys.stderr)
        return EXIT_NO_LOG

    parsed = parse_log(log_path, args.workdir, args.runtime_root)
    merged_pairs = merge_pairs(parsed.dyn_pairs, parsed.base_modes)

    p_file = write_paths(args.lang, args.exercise, merged_pairs, out_dir)
    j_file = write_json(args.lang, args.exercise,
                        parsed.dyn_pairs, parsed.base_modes, merged_pairs,
                        parsed.tail_flags, log_path, out_dir)
    print(f"emit_artifacts: wrote {p_file.name}, {j_file.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
