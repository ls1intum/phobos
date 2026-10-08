"""Checks the orchestrator's helpers directly, which needed it to be importable at all.

test_orchestrate.py starts the program as a whole, and keeps doing it: those tests are the proof
that the entry point behaves as it says. These are the other half, over the pieces a subprocess
test can only reach through the whole merge.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ORCHESTRATOR_DIRECTORY = REPO_ROOT / "docker" / "prune_phase" / "orchestrate"
sys.path.insert(0, str(ORCHESTRATOR_DIRECTORY))
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

import orchestrate
from layer_prune import cfgfile


def test_importing_the_module_creates_nothing_and_parses_nothing():
    """Import must be free of work, or nothing here could be tested without starting it."""
    assert callable(orchestrate.main)
    assert not hasattr(orchestrate, "args")
    assert not hasattr(orchestrate, "PATH_DIR")


def test_the_languages_are_read_in_the_order_they_were_given():
    assert orchestrate.requested_languages("java, python ,c") == ["java", "python", "c"]


def test_an_empty_language_name_is_dropped():
    assert orchestrate.requested_languages("java,,  ,python") == ["java", "python"]


def arguments_for(tmp_path: pathlib.Path, **overrides) -> object:
    """One parsed command line pointing at a temporary tree, with overrides applied."""
    argv = [
        "--langs", overrides.pop("langs", "java"),
        "--path-dir", str(tmp_path / "path_sets"),
        "--core-dir", str(tmp_path / "core"),
        "--helpers-dir", str(tmp_path / "helpers"),
    ]
    for name, value in overrides.items():
        argv += [f"--{name.replace('_', '-')}", str(value)]
    return orchestrate.parse_arguments(argv)


def test_the_layout_creates_the_three_directories_it_writes_into(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    assert layout.path_dir.is_dir()
    assert layout.core_dir.is_dir()
    assert layout.debug_dir.is_dir()
    assert layout.debug_dir == layout.core_dir / "debug"


def policy(fs: dict[str, set[str]]) -> cfgfile.Policy:
    """A policy of filesystem grants only."""
    return cfgfile.Policy(fs={path: frozenset(sections) for path, sections in fs.items()}, connect=(), bind=(),
                          limits={})


def language(fs: dict[str, set[str]]) -> orchestrate.LanguagePolicy:
    """A language of one exercise with the given grants."""
    single = policy(fs)
    return orchestrate.LanguagePolicy(base=single, exercises={"one": single}, common=single)


def test_the_cross_language_policy_is_the_union_and_its_intersection(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    lang_data = {
        "java": language({"/shared": {"read"}, "/java-only": {"read"}, "/work": {"write"}}),
        "python": language({"/shared": {"read"}, "/python-only": {"read"}}),
    }
    orchestrate.write_policies(orchestrate.cross_language_policies(lang_data, layout), ["java", "python"], layout)
    union = (layout.core_dir / "BasePhobos.cfg").read_text()
    assert "/java-only" in union
    assert "/python-only" in union
    intersect = (layout.debug_dir / "BasePhobosIntersect.cfg").read_text()
    assert "/shared" in intersect
    assert "/java-only" not in intersect


def test_a_language_policy_is_applied_and_its_comparisons_are_not(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    lang_data = {
        "java": language({"/shared": {"read"}, "/java-only": {"read"}}),
        "python": language({"/shared": {"read"}}),
    }
    orchestrate.write_policies(orchestrate.language_policies(lang_data, layout), ["java", "python"], layout)
    assert (layout.core_dir / "BaseLanguage-java.cfg").exists()
    only = (layout.debug_dir / "BaseJavaOnly.cfg").read_text()
    assert "/java-only" in only
    assert "/shared" not in only


def test_what_every_exercise_needed_is_the_sections_all_of_them_granted():
    common = orchestrate.common_policy([policy({"/a": {"read", "execute"}, "/b": {"read"}}),
                                        policy({"/a": {"read"}})])
    assert common.fs == {"/a": frozenset({"read"})}


def test_execute_beside_a_write_another_part_brought_is_a_conflict_and_one_s_own_is_not():
    parts = [policy({"/t": {"read", "execute"}}), policy({"/t/cache": {"write"}})]
    assert orchestrate.execute_conflicts(parts, orchestrate.union_policy(parts)) == ["/t"]
    own = policy({"/s/run.sh": {"execute"}, "/s": {"write"}})
    assert orchestrate.execute_conflicts([own], orchestrate.union_policy([own])) == []


def test_the_runtime_tail_carries_the_chdir_and_nothing_else(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    orchestrate.build_runtime_tail("/var/tmp/testing-dir", layout.core_dir)
    assert (layout.core_dir / "TailPhobos.cfg").read_text() == "--chdir /var/tmp/testing-dir\n"


def test_the_language_list_is_required():
    with pytest.raises(SystemExit):
        orchestrate.parse_arguments([])
