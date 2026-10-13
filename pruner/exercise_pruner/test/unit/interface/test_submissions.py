"""Checks the container steps of phobos-cli.sh submissions: the template contract, the digests, the seal, the
candidate beside the grading base, the rows, and the classification of a verification."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.interface import main, submissions
from shared.src.domain import cfgfile

KEY = "java-gradle"


def template(root: pathlib.Path, settings: dict | None = None) -> pathlib.Path:
    """A template that holds: prune.json naming the key, an executable build script, an assignment directory."""
    directory = root / "template"
    (directory / "assignment").mkdir(parents=True)
    (directory / "prune.json").write_text(json.dumps({"key": KEY} if settings is None else settings))
    (directory / "build_script.sh").write_text("#!/bin/bash\nexit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    return directory


def policy(fs: dict[str, set[str]], limits: dict[str, int] | None = None, connect: tuple[str, ...] = ()) -> cfgfile.Policy:
    """A policy of the filesystem rows, rules and limits given."""
    return cfgfile.Policy(fs={path: frozenset(sections) for path, sections in fs.items()}, connect=connect, bind=(),
                          limits=limits or {})


@pytest.mark.parametrize("pattern", ["assignment/x.xml", "./assignment/x.xml", "**/x.xml", "*/x.xml", "a/../x.xml",
                                     ".", "/x.xml", "assign*/x.xml"])
def test_a_glob_that_could_reach_the_student_material_is_refused(pattern):
    assert submissions.glob_problem(pattern) is not None


@pytest.mark.parametrize("pattern", ["build/test-results/**/*.xml", "./build/x.xml", "target/surefire-reports/*.xml"])
def test_a_glob_inside_the_trusted_part_is_accepted(pattern):
    assert submissions.glob_problem(pattern) is None


def test_the_default_globs_are_accepted():
    from exercise_pruner.src.domain import verdict
    assert all(submissions.glob_problem(pattern) is None for pattern in verdict.DEFAULT_REPORT_GLOBS)


def test_a_template_that_holds_is_accepted(tmp_path):
    assert submissions.template_problems(template(tmp_path), KEY) == []


@pytest.mark.parametrize("settings, fragment", [
    ({}, "does not name the key"),
    ({"key": "python"}, "does not name the key"),
    ({"key": KEY, "declared_hosts": ["api.example.org:443"]}, "declares hosts"),
    ({"key": KEY, "pinned_read_roots": [{"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/maven-repository.sha256"}]}, "pinned read roots"),
    ({"key": KEY, "runs_compiled_programs": True, "compiled_programs_directory": "src"}, "compiled programs directory"),
    ({"key": KEY, "report_globs": ["./assignment/report.xml"]}, "could match a report"),
])
def test_a_template_that_lets_student_material_in_is_refused(tmp_path, settings, fragment):
    problems = submissions.template_problems(template(tmp_path, settings), KEY)
    assert any(fragment in problem for problem in problems), problems


def test_a_template_without_an_assignment_directory_is_refused(tmp_path):
    directory = template(tmp_path)
    (directory / "assignment").rmdir()
    (directory / "assignment").symlink_to(directory / "build_script.sh")
    assert any("no assignment directory" in problem for problem in submissions.template_problems(directory, KEY))


def test_a_template_with_a_committed_report_is_refused(tmp_path):
    directory = template(tmp_path)
    (directory / "build" / "test-results" / "test").mkdir(parents=True)
    (directory / "build" / "test-results" / "test" / "old.xml").write_text("<testsuite/>")
    assert any("already holds a report" in problem for problem in submissions.template_problems(directory, KEY))


def test_two_inventories_that_a_line_format_would_confuse_digest_differently(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    (first / "a").mkdir(parents=True)
    (first / "b").mkdir()
    (second / "a\nd 0o700 b").mkdir(parents=True)
    os.chmod(first / "a", 0o700)
    os.chmod(first / "b", 0o700)
    os.chmod(second / "a\nd 0o700 b", 0o700)
    assert submissions.tree_digest(first) != submissions.tree_digest(second)


def test_a_changed_mode_changes_the_digest(tmp_path):
    (tmp_path / "build_script.sh").write_text("exit 0\n")
    before = submissions.tree_digest(tmp_path)
    (tmp_path / "build_script.sh").chmod(0o755)
    assert submissions.tree_digest(tmp_path) != before


def test_a_link_in_a_tree_is_refused(tmp_path):
    (tmp_path / "link").symlink_to("/etc/passwd")
    with pytest.raises(submissions.Refused):
        submissions.tree_digest(tmp_path)


def test_the_fact_base_and_a_nested_execute_stand_together():
    base = policy({"/opt/python": {"read"}})
    part = policy({"/opt/python": {"read", "execute"}, "/opt/python/bin": {"read", "execute"}})
    result, _ = submissions.candidate([part], base)
    cfgfile.check_hierarchy(submissions.union_fs(base.fs, result.fs))
    assert result.fs["/opt/python/bin"] >= {"execute"}


def test_a_base_only_row_beneath_a_widened_ancestor_is_repaired():
    base = policy({"/root/.gradle/caches": {"read"}, "/root/.gradle/caches/journal-1/file-access.bin": {"write"}})
    part = policy({"/root/.gradle/caches": {"read", "write"}})
    result, added = submissions.candidate([part], base)
    cfgfile.check_hierarchy(submissions.union_fs(base.fs, result.fs))
    assert result.fs["/root/.gradle/caches/journal-1/file-access.bin"] == frozenset({"read", "write"})
    assert "/root/.gradle/caches/journal-1/file-access.bin" in added


def test_what_the_base_grants_is_left_out_and_limits_merge_as_the_policy_system_merges():
    base = policy({"/usr": {"read", "execute"}})
    parts = [policy({"/usr/lib": {"read"}, "/srv/data": {"read"}}, {"timeout": 120, "mem_mb": 1024}),
             policy({"/srv/data": {"read"}}, {"timeout": 0, "mem_mb": 2048})]
    result, _ = submissions.candidate(parts, base)
    assert result.fs == {"/srv/data": frozenset({"read"})}
    assert result.limits == {"timeout": 0, "mem_mb": 2048}


def test_execute_beside_a_write_no_submission_had_is_refused():
    parts = [policy({"/srv/work": {"write"}}), policy({"/srv/work": {"execute"}})]
    with pytest.raises(submissions.Refused):
        submissions.candidate(parts, policy({}))


def test_rows_count_the_submissions_whose_policy_holds_them_rarest_first():
    parts = {"a": policy({"/srv/data": {"read"}}, connect=("allow 192.0.2.1:443",)), "b": policy({"/srv/data": {"read"}})}
    result, _ = submissions.candidate(list(parts.values()), policy({}))
    assert submissions.rows(result, parts) == [(1, "connect", "allow 192.0.2.1:443"), (2, "read", "/srv/data")]


def make_run(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    """A sealed-ready run: two pruned submissions and one aborted, a base, an empty prune base, helpers."""
    run = root / "run"
    helpers = root / "helpers"
    (helpers / "exercise_pruner").mkdir(parents=True)
    (helpers / "exercise_pruner" / "main.py").write_text("print('main')\n")
    for folder in ("bases", "prune-base", "results", "output", "staging", "sources", "excluded", "seal", "union"):
        (run / folder).mkdir(parents=True)
    (run / "bases" / "BaseLanguage-java-gradle.cfg").write_text("[read]\n/usr\n")
    (run / "prune-base" / "BasePrune.cfg").write_text("# grants nothing\n")
    for name, text in (("alpha", "[read]\n/usr\n/srv/extra\n"), ("beta", "[read]\n/usr\n")):
        (run / "staging" / name / "submissions" / name).mkdir(parents=True)
        (run / "sources" / name).write_text(name.title())
        (run / "results" / name).write_text("0\n")
        output = run / "output" / name
        output.mkdir()
        (output / f"{KEY}_{name}.cfg").write_text(text)
        record = {"schema_version": 2, "key": KEY, "exercise": name, "stage": "all",
                  "cfg_sha256": hashlib.sha256(text.encode()).hexdigest()}
        (output / f"{KEY}_{name}.json").write_text(json.dumps(record))
    (run / "staging" / "gamma" / "submissions" / "gamma").mkdir(parents=True)
    (run / "sources" / "gamma").write_text("Gamma")
    (run / "results" / "gamma").write_text("1\n")
    (run / "output" / "gamma").mkdir()
    (run / "output" / "gamma" / f"{KEY}_gamma.aborted.json").write_text(json.dumps(
        {"schema_version": 2, "key": KEY, "exercise": "gamma", "stage": "all", "aborted": "the reference run ran no tests"}))
    return run, helpers


def test_a_run_is_sealed_and_merged(tmp_path):
    run, helpers = make_run(tmp_path)
    manifest = submissions.seal(run, KEY, helpers, "sha256:run", "sha256:prune")
    results = {entry["name"]: entry["result"] for entry in manifest["submissions"]}
    assert results == {"alpha": "ok", "beta": "ok", "gamma": "aborted"}
    submissions.write_json(run / "seal" / "manifest.json", manifest)
    submissions.union(run, KEY, helpers)
    assert (run / "union" / "candidate.cfg").read_text() == cfgfile.render(policy({"/srv/extra": {"read"}}))
    assert (run / "union" / "rows.tsv").read_text() == "1\t2\tread\t/srv/extra\n"


def test_a_base_whose_mode_changed_after_the_seal_is_refused(tmp_path):
    run, helpers = make_run(tmp_path)
    (run / "bases" / "BaseLanguage-java-gradle.cfg").chmod(0o400)
    submissions.write_json(run / "seal" / "manifest.json", submissions.seal(run, KEY, helpers, "run", "prune"))
    (run / "bases" / "BaseLanguage-java-gradle.cfg").chmod(0o600)
    with pytest.raises(submissions.Refused):
        submissions.validated_manifest(run, KEY, helpers)


@pytest.mark.parametrize("change", ["staging", "artefact", "helpers", "base"])
def test_a_change_after_the_seal_is_refused(tmp_path, change):
    run, helpers = make_run(tmp_path)
    submissions.write_json(run / "seal" / "manifest.json", submissions.seal(run, KEY, helpers, "run", "prune"))
    target = {"staging": run / "staging" / "alpha" / "submissions" / "alpha" / "new.txt",
              "artefact": run / "output" / "alpha" / f"{KEY}_alpha.cfg",
              "helpers": helpers / "exercise_pruner" / "main.py",
              "base": run / "bases" / "BaseLanguage-java-gradle.cfg"}[change]
    target.write_text("changed\n")
    with pytest.raises(submissions.Refused):
        submissions.validated_manifest(run, KEY, helpers)


@pytest.mark.parametrize("status, extra, abort", [
    ("0", True, None),
    ("2", False, None),
    ("1", False, "a defect of the pruner: KeyError"),
])
def test_a_prune_whose_status_and_artefacts_disagree_is_refused(tmp_path, status, extra, abort):
    run, helpers = make_run(tmp_path)
    (run / "results" / ("gamma" if abort else "alpha")).write_text(status)
    if extra:
        (run / "output" / "alpha" / "stray.txt").write_text("x")
    if abort:
        path = run / "output" / "gamma" / f"{KEY}_gamma.aborted.json"
        record = json.loads(path.read_text())
        path.write_text(json.dumps(record | {"aborted": abort}))
    with pytest.raises(submissions.Refused):
        submissions.seal(run, KEY, helpers, "run", "prune")


def test_a_prune_base_that_grants_something_is_refused(tmp_path):
    run, helpers = make_run(tmp_path)
    (run / "prune-base" / "BasePrune.cfg").write_text("[read]\n/\n")
    with pytest.raises(submissions.Refused):
        submissions.seal(run, KEY, helpers, "run", "prune")


def verification(root: pathlib.Path, status: str, record: dict | None) -> tuple[pathlib.Path, dict]:
    """A verification folder with one submission's status and record, and the batch it is held to."""
    folder = root / "verify-1"
    (folder / "status").mkdir(parents=True)
    (folder / "status" / "alpha").write_text(status)
    expected = {"policy_sha256": "p" * 64, "bases": {"BaseLanguage-java-gradle.cfg": "b" * 64, "BasePrune.cfg": "e" * 64}}
    if record is not None:
        (folder / "records" / "alpha" / "verify").mkdir(parents=True)
        full = {"schema_version": 2, "key": KEY, "exercise": "alpha", "configs_sha256": [expected["policy_sha256"]],
                "bases": expected["bases"], **record}
        (folder / "records" / "alpha" / "verify" / f"{KEY}_alpha.json").write_text(json.dumps(full))
    return folder, expected


@pytest.mark.parametrize("status, record, result", [
    ("0", {"verified": True}, "match"),
    ("1", {"verified": False, "aborted": submissions.MISMATCH}, "mismatch"),
    ("1", {"verified": False, "aborted": "a defect of the pruner: OSError"}, "failure"),
    ("0", {"verified": False, "aborted": submissions.MISMATCH}, "failure"),
    ("1", {"verified": True}, "failure"),
    ("137", {"verified": True}, "failure"),
    ("0", None, "failure"),
    ("0", {"verified": True, "bases": {"BaseLanguage-java-gradle.cfg": "b" * 64}}, "failure"),
    ("0", {"verified": True, "configs_sha256": ["q" * 64]}, "failure"),
])
def test_a_verification_is_classified_by_its_status_and_its_record(tmp_path, status, record, result):
    folder, expected = verification(tmp_path, status, record)
    assert submissions.verdict_of(folder, KEY, "alpha", expected) == result


def test_verify_policy_takes_no_other_mode(capsys):
    assert main.main(["--verify-policy", "/srv/policy.cfg", "--stage", "filesystem", KEY]) == main.EXIT_ABORTED
    assert "--verify-policy" in capsys.readouterr().err


def test_validate_checks_a_sealed_run_again(tmp_path):
    run, helpers = make_run(tmp_path)
    submissions.write_json(run / "seal" / "manifest.json", submissions.seal(run, KEY, helpers, "run", "prune"))
    assert submissions.main(["validate", str(run), KEY, str(helpers), "run", "prune"]) == 0
    (run / "output" / "beta" / f"{KEY}_beta.cfg").write_text("[read]\n/\n")
    assert submissions.main(["validate", str(run), KEY, str(helpers), "run", "prune"]) == submissions.EXIT_REFUSED


@pytest.mark.parametrize("run_phase_image, prune_image", [("other", "prune"), ("run", "other")])
def test_validate_refuses_images_other_than_the_sealed_ones(tmp_path, run_phase_image, prune_image):
    run, helpers = make_run(tmp_path)
    submissions.write_json(run / "seal" / "manifest.json", submissions.seal(run, KEY, helpers, "run", "prune"))
    assert submissions.main(["validate", str(run), KEY, str(helpers), run_phase_image, prune_image]) == submissions.EXIT_REFUSED


@pytest.mark.parametrize("change", ["altered", "missing"])
def test_a_prune_status_changed_after_the_seal_is_refused(tmp_path, change):
    run, helpers = make_run(tmp_path)
    submissions.write_json(run / "seal" / "manifest.json", submissions.seal(run, KEY, helpers, "run", "prune"))
    if change == "altered":
        (run / "results" / "alpha").write_text("1\n")
    else:
        (run / "results" / "alpha").unlink()
    assert submissions.main(["validate", str(run), KEY, str(helpers), "run", "prune"]) == submissions.EXIT_REFUSED


def test_a_verification_without_a_status_is_a_failure(tmp_path):
    folder, expected = verification(tmp_path, "0", {"verified": True})
    (folder / "status" / "alpha").unlink()
    assert submissions.verdict_of(folder, KEY, "alpha", expected) == "failure"


def test_neither_status_of_a_step_is_the_one_python_gives_an_uncaught_exception():
    assert 1 not in (submissions.EXIT_REFUSED, submissions.EXIT_MISMATCH, 0)
