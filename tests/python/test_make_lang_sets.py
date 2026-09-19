"""Checks how make_lang_sets.py folds a language's run results into two policies.

Each run of the pruning phase leaves one ``{lang}_*.paths`` file, and this helper
turns the set of them into ``{lang}_union.paths`` (every path any run needed) and
``{lang}_intersection.paths`` (only the paths every run needed). Both become a
Landlock allow-list downstream, where everything not named is denied, so the two
must stay honest: the union may never drop a path a run asked for, the intersection
may never keep one a run did not, and neither may fold a previous run's own output
back in as though it were a fresh result.

The helper is a script rather than a module, so it is driven through a subprocess
with a language and a directory, the same way the pruning phase drives it.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

# How long the helper may run before the test gives up on it.
HELPER_TIMEOUT_SECONDS = 60

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "var" / "tmp" / "helpers" / "make_lang_sets.py"


def run_make_lang_sets(directory: pathlib.Path, lang: str = "java") -> subprocess.CompletedProcess:
    """Runs the helper over one language's run-result files in ``directory``."""
    return subprocess.run(
        [
            sys.executable,
            str(HELPER),
            lang,
            str(directory),
        ],
        capture_output=True,
        text=True,
        timeout=HELPER_TIMEOUT_SECONDS,
        check=False,
    )


def write_run(directory: pathlib.Path, name: str, lines: list[str]) -> None:
    """Writes one run-result file, matching how the pruning stub leaves them."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text("\n".join(lines) + "\n")


def read_set(path: pathlib.Path) -> list[str]:
    """The paths a written policy file ended up holding, in file order."""
    return path.read_text().splitlines()


def test_the_union_keeps_every_path_any_run_needed(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /b", "r /c"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_union.paths") == ["r /a", "r /b", "r /c"]


def test_the_intersection_keeps_only_paths_every_run_needed(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /b", "r /c"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_intersection.paths") == ["r /b"]


def test_a_path_no_run_shares_leaves_the_intersection_empty(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a"])
    write_run(tmp_path, "java_run2.paths", ["r /b"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_intersection.paths") == []


def test_both_policies_are_sorted(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /c", "r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /c", "r /a", "r /b"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_union.paths") == ["r /a", "r /b", "r /c"]
    assert read_set(tmp_path / "java_intersection.paths") == ["r /a", "r /b", "r /c"]


def test_a_path_repeated_within_and_across_runs_appears_once(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a", "r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /a"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_union.paths") == ["r /a", "r /b"]


def test_another_languages_files_never_leak_in(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /java"])
    write_run(tmp_path, "python_run1.paths", ["r /python"])
    result = run_make_lang_sets(tmp_path, lang="java")
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_union.paths") == ["r /java"]
    assert read_set(tmp_path / "java_intersection.paths") == ["r /java"]


def test_a_stale_union_output_is_not_folded_back_in(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /b", "r /c"])
    write_run(tmp_path, "java_union.paths", ["r /x", "r /y", "r /z"])
    write_run(tmp_path, "java_intersection.paths", ["r /x"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode == 0, result.stderr
    assert read_set(tmp_path / "java_union.paths") == ["r /a", "r /b", "r /c"]
    assert read_set(tmp_path / "java_intersection.paths") == ["r /b"]


def test_running_twice_leaves_the_policies_unchanged(tmp_path):
    write_run(tmp_path, "java_run1.paths", ["r /a", "r /b"])
    write_run(tmp_path, "java_run2.paths", ["r /b", "r /c"])
    first = run_make_lang_sets(tmp_path)
    assert first.returncode == 0, first.stderr
    union_after_first = read_set(tmp_path / "java_union.paths")
    intersection_after_first = read_set(tmp_path / "java_intersection.paths")
    second = run_make_lang_sets(tmp_path)
    assert second.returncode == 0, second.stderr
    assert read_set(tmp_path / "java_union.paths") == union_after_first
    assert read_set(tmp_path / "java_intersection.paths") == intersection_after_first


def test_only_prior_outputs_present_is_not_enough_to_run(tmp_path):
    write_run(tmp_path, "java_union.paths", ["r /x"])
    write_run(tmp_path, "java_intersection.paths", ["r /x"])
    result = run_make_lang_sets(tmp_path)
    assert result.returncode != 0
    assert "no run-result .paths files found" in result.stderr


def test_no_input_files_stops_rather_than_writing_an_empty_policy(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    result = run_make_lang_sets(tmp_path)
    assert result.returncode != 0
    assert "no run-result .paths files found" in result.stderr
    assert not (tmp_path / "java_union.paths").exists()
    assert not (tmp_path / "java_intersection.paths").exists()
