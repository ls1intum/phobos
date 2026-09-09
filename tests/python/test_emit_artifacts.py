"""Checks how emit_artifacts.py merges the tail flags of a pruning run.

The file it writes, TailPhobos.cfg, is read back on the next run and merged
again, so a merge that keeps duplicates grows without limit across runs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "var" / "tmp" / "helpers" / "emit_artifacts.py"


def load_helper():
    """Imports the helper by path, since var/tmp/helpers is not a package."""
    spec = importlib.util.spec_from_file_location("emit_artifacts", HELPER)
    module = importlib.util.module_from_spec(spec)
    sys.modules["emit_artifacts"] = module
    spec.loader.exec_module(module)
    return module


emit_artifacts = load_helper()


def tail_tokens(directory: pathlib.Path) -> list[str]:
    """The flags TailPhobos.cfg ended up holding, in order."""
    return (directory / "TailPhobos.cfg").read_text().split()


def test_a_repeated_flag_is_written_once(tmp_path):
    emit_artifacts.merge_tail(["--share-net", "--share-net", "--unshare-ipc"], tmp_path)
    assert tail_tokens(tmp_path) == ["--share-net", "--unshare-ipc"]


def test_a_flag_already_recorded_is_not_added_again(tmp_path):
    emit_artifacts.merge_tail(["--share-net"], tmp_path)
    emit_artifacts.merge_tail(["--share-net", "--unshare-uts"], tmp_path)
    assert tail_tokens(tmp_path) == ["--share-net", "--unshare-uts"]


def test_flags_already_recorded_keep_their_order(tmp_path):
    emit_artifacts.merge_tail(["--unshare-ipc", "--share-net"], tmp_path)
    emit_artifacts.merge_tail(["--unshare-uts"], tmp_path)
    assert tail_tokens(tmp_path) == ["--unshare-ipc", "--share-net", "--unshare-uts"]


def test_the_per_exercise_chdir_never_reaches_the_file(tmp_path):
    emit_artifacts.merge_tail(["--chdir", "/tmp/exercise-1234", "--share-net"], tmp_path)
    assert tail_tokens(tmp_path) == ["--share-net"]


def test_a_flag_outside_the_allow_list_is_dropped(tmp_path):
    """--unshare-utc is the misspelling the pruner used to pass; bubblewrap has
    no such option, and the allow-list here has always named the real one."""
    emit_artifacts.merge_tail(["--unshare-utc", "--share-net"], tmp_path)
    assert tail_tokens(tmp_path) == ["--share-net"]
