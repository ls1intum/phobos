"""Checks the orchestrator's helpers directly, which needed it to be importable at all.

Everything from the argument parser onwards used to run when the file was read, so importing
it parsed a command line and created three directories, and the only way to exercise any of
it was to start the program. test_orchestrate.py does exactly that, and keeps doing it: those
tests are the proof that the entry point still behaves as it did. These are the other half,
over the pieces a subprocess test can only reach through the whole pipeline.

The shared state the pipeline carries is the layout and the parsed arguments, and the
concurrent part is the per-language prune, so both are covered here rather than left to the
end-to-end runs.
"""

from __future__ import annotations

import pathlib
import sys
import threading

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ORCHESTRATOR_DIRECTORY = REPO_ROOT / "docker" / "prune_phase" / "orchestrate"
sys.path.insert(0, str(ORCHESTRATOR_DIRECTORY))

import orchestrate

# How long a worker waits for the others at the barrier before the test gives up.
BARRIER_TIMEOUT_SECONDS = 30


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
        "--prune-script", str(tmp_path / "prune.sh"),
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
    assert layout.make_lang_sets == tmp_path / "helpers" / "make_lang_sets.py"


def test_the_layout_does_not_create_the_scripts_it_only_names(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    assert not layout.prune_script.exists()
    assert not layout.make_lang_sets.exists()


def test_a_writable_path_wins_over_a_readable_one(tmp_path):
    union_file = tmp_path / "java_union.paths"
    union_file.write_text("r /shared\nw /shared\nr /only-read\n")
    union = orchestrate._read_union(union_file)
    assert union["w"] == {"/shared"}
    assert union["r"] == {"/only-read"}


def test_comments_blank_lines_and_lines_without_a_path_are_ignored(tmp_path):
    union_file = tmp_path / "java_union.paths"
    union_file.write_text("# a comment\n\nr\nr /kept\n")
    assert orchestrate._read_union(union_file) == {"r": {"/kept"}, "w": set()}


def write_pair(path_dir: pathlib.Path, name: str, paths: str, record: str) -> None:
    """Writes one exercise's two artefacts, the .paths and the .json beside it."""
    path_dir.mkdir(parents=True, exist_ok=True)
    (path_dir / f"{name}.paths").write_text(paths)
    (path_dir / f"{name}.json").write_text(record)


def test_artefacts_that_agree_raise_no_problem(tmp_path):
    write_pair(tmp_path, "java_one", "r /a\n",
               '{"paths_all": [{"mode": "r", "path": "/a"}]}')
    assert orchestrate.artefact_disagreements("java", tmp_path) == []


def test_a_paths_file_without_its_record_is_a_problem(tmp_path):
    tmp_path.joinpath("java_one.paths").write_text("r /a\n")
    problems = orchestrate.artefact_disagreements("java", tmp_path)
    assert len(problems) == 1
    assert "java_one.json" in problems[0]


def test_a_record_without_its_paths_file_is_a_problem(tmp_path):
    tmp_path.joinpath("java_one.json").write_text('{"paths_all": []}')
    problems = orchestrate.artefact_disagreements("java", tmp_path)
    assert len(problems) == 1
    assert "no java_one.paths" in problems[0]


def test_a_record_that_is_not_json_is_a_problem(tmp_path):
    write_pair(tmp_path, "java_one", "r /a\n", "{not json")
    problems = orchestrate.artefact_disagreements("java", tmp_path)
    assert len(problems) == 1
    assert "not readable as JSON" in problems[0]


def test_a_truncated_paths_file_disagrees_with_its_record(tmp_path):
    write_pair(tmp_path, "java_one", "r /a\n",
               '{"paths_all": [{"mode": "r", "path": "/a"}, {"mode": "w", "path": "/b"}]}')
    problems = orchestrate.artefact_disagreements("java", tmp_path)
    assert len(problems) == 1
    assert "1 path(s)" in problems[0]


def test_the_union_and_intersection_outputs_are_not_read_as_exercises(tmp_path):
    write_pair(tmp_path, "java_one", "r /a\n",
               '{"paths_all": [{"mode": "r", "path": "/a"}]}')
    tmp_path.joinpath("java_union.paths").write_text("r /a\n")
    tmp_path.joinpath("java_intersection.paths").write_text("r /a\n")
    assert orchestrate.artefact_disagreements("java", tmp_path) == []


def test_every_language_is_pruned_once_and_they_run_at_the_same_time(tmp_path, monkeypatch):
    """Every language is reached, and they really do overlap.

    The barrier is what proves the overlap rather than asserting it: each worker waits for
    the other two, so it can only be passed if all three are inside the stub at once. A
    serial pool would time out on it instead of passing.
    """
    pruned: list[str] = []
    together = threading.Barrier(3)
    lock = threading.Lock()

    def stub(lang, layout, arguments):
        together.wait(timeout=BARRIER_TIMEOUT_SECONDS)
        with lock:
            pruned.append(lang)

    monkeypatch.setattr(orchestrate, "prune_language", stub)
    arguments = arguments_for(tmp_path, langs="java,python,c", jobs=3)
    layout = orchestrate.make_layout(arguments)
    assert orchestrate.prune_every_language(["java", "python", "c"], layout, arguments) == []
    assert sorted(pruned) == ["c", "java", "python"]


def test_one_failing_language_does_not_stop_the_others_and_every_failure_is_named(
        tmp_path, monkeypatch):
    pruned: list[str] = []
    lock = threading.Lock()

    def stub(lang, layout, arguments):
        with lock:
            pruned.append(lang)
        if lang in ("python", "c"):
            raise RuntimeError(f"{lang} refused")

    monkeypatch.setattr(orchestrate, "prune_language", stub)
    arguments = arguments_for(tmp_path, langs="java,python,c", jobs=3)
    layout = orchestrate.make_layout(arguments)
    failed = orchestrate.prune_every_language(["java", "python", "c"], layout, arguments)
    assert sorted(failed) == ["c", "python"]
    assert sorted(pruned) == ["c", "java", "python"]


def test_each_language_is_handed_the_same_layout_and_arguments(tmp_path, monkeypatch):
    """The pipeline's shared state is the layout and the arguments; both must reach a worker
    unchanged, or a concurrent prune would write where a later step does not look."""
    seen: list[tuple[object, object]] = []
    lock = threading.Lock()

    def stub(lang, layout, arguments):
        with lock:
            seen.append((layout, arguments))

    monkeypatch.setattr(orchestrate, "prune_language", stub)
    arguments = arguments_for(tmp_path, langs="java,python", jobs=2)
    layout = orchestrate.make_layout(arguments)
    orchestrate.prune_every_language(["java", "python"], layout, arguments)
    assert all(handed == (layout, arguments) for handed in seen)


def test_an_earlier_run_is_forgotten_for_the_named_languages_only(tmp_path):
    tmp_path.joinpath("java_one.paths").write_text("r /a\n")
    tmp_path.joinpath("java_union.paths").write_text("r /a\n")
    tmp_path.joinpath("python_one.paths").write_text("r /b\n")
    orchestrate.forget_earlier_artefacts(["java"], tmp_path)
    assert not tmp_path.joinpath("java_one.paths").exists()
    assert not tmp_path.joinpath("java_union.paths").exists()
    assert tmp_path.joinpath("python_one.paths").exists()


def test_the_cross_language_policy_is_the_union_and_its_intersection(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    lang_data = {
        "java": {"r": {"/shared", "/java-only"}, "w": {"/work"}},
        "python": {"r": {"/shared", "/python-only"}, "w": set()},
    }
    orchestrate.write_cross_language_policy(lang_data, layout)
    union = (layout.core_dir / "BasePhobos.cfg").read_text()
    assert "/java-only" in union
    assert "/python-only" in union
    intersect = (layout.debug_dir / "BasePhobosIntersect.cfg").read_text()
    assert "/shared" in intersect
    assert "/java-only" not in intersect


def test_a_language_policy_is_applied_and_its_comparisons_are_not(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    lang_data = {
        "java": {"r": {"/shared", "/java-only"}, "w": set()},
        "python": {"r": {"/shared"}, "w": set()},
    }
    orchestrate.write_language_policies(lang_data, layout)
    assert (layout.core_dir / "BaseLanguage-java.cfg").exists()
    only = (layout.debug_dir / "BaseJavaOnly.cfg").read_text()
    assert "/java-only" in only
    assert "/shared" not in only


def test_a_writable_path_grants_read_write_create_and_delete(tmp_path):
    destination = tmp_path / "Base.cfg"
    orchestrate._write_cfg({"/readable"}, {"/writable"}, destination)
    written = destination.read_text()
    for section in ("[read]", "[execute]", "[write]", "[create]", "[delete]", "[connect]"):
        assert section in written
    assert written.index("[write]") < written.index("[connect]")


def test_the_runtime_tail_carries_the_chdir_and_nothing_else(tmp_path):
    layout = orchestrate.make_layout(arguments_for(tmp_path))
    orchestrate.build_runtime_tail("/var/tmp/testing-dir", layout.core_dir)
    assert (layout.core_dir / "TailPhobos.cfg").read_text() == "--chdir /var/tmp/testing-dir\n"


def test_the_language_list_is_required():
    with pytest.raises(SystemExit):
        orchestrate.parse_arguments([])
