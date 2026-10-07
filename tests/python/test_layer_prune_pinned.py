"""Checks the pinned read roots: a strict declaration, a verification by the rule of pin-repository.sh, and
the one grant they allow, in both directions (decision 7's one exception to "file by file")."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import generalise, pinned, record, runner, search, stages

GOOD = {"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/maven-repository.sha256"}


def sha(content: bytes) -> str:
    """The SHA-256 of some bytes."""
    return hashlib.sha256(content).hexdigest()


def tree(tmp_path: pathlib.Path, files: dict[str, bytes], wanted: dict[str, str] | None = None):
    """A tree and a manifest for it in tmp_path; the PinnedRoot naming them. `wanted` overrides a sum."""
    base = tmp_path / "repository"
    for relative, content in files.items():
        (base / relative).parent.mkdir(parents=True, exist_ok=True)
        (base / relative).write_bytes(content)
    lines = [f"{(wanted or {}).get(relative, pinned.digest(base / relative))}  {relative}" for relative in files]
    manifest = tmp_path / "manifest.sha256"
    manifest.write_text("\n".join(lines) + "\n")
    return pinned.PinnedRoot(path=str(base.resolve()), manifest=str(manifest))


@pytest.mark.parametrize("entry", [
    {"path": "/root/.m2/repository"},
    {**GOOD, "sections": ["write"]},
    {**GOOD, "rights": "rw"},
    {"path": "relative/path", "manifest": GOOD["manifest"]},
    {"path": "/root/.m2/../.ssh", "manifest": GOOD["manifest"]},
    {"path": "/root/.m2/repository/", "manifest": GOOD["manifest"]},
    {"path": "/root", "manifest": GOOD["manifest"]},
    {"path": "/usr/share/maven", "manifest": GOOD["manifest"]},
    {"path": "/root/.m2/repository", "manifest": "/etc/passwd"},
    {"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/../x"},
    {"path": "/root/.m2/repository", "manifest": "/srv/phobos-manifest/sub/x.sha256"},
    {"path": "/root/.m2/repository", "manifest": "relative.sha256"},
    {"path": 1, "manifest": GOOD["manifest"]},
    "a string",
])
def test_a_declaration_that_is_not_strictly_a_path_beneath_a_fine_root_with_a_manifest_is_refused(entry):
    with pytest.raises(ValueError):
        pinned.parse([entry], "prune.json")


def test_a_declaration_is_a_list_and_a_good_one_is_read_and_overlaps_are_refused():
    assert pinned.parse([GOOD], "prune.json") == (pinned.PinnedRoot(**GOOD),)
    assert pinned.parse([], "prune.json") == ()
    with pytest.raises(ValueError, match="list of objects"):
        pinned.parse(GOOD, "prune.json")
    with pytest.raises(ValueError, match="repeats or overlaps"):
        pinned.parse([GOOD, GOOD], "prune.json")
    with pytest.raises(ValueError, match="repeats or overlaps"):
        pinned.parse([GOOD, {**GOOD, "path": "/root/.m2/repository/org"}], "prune.json")


def test_the_digest_drops_the_comment_lines_of_a_remote_repositories_file_and_nothing_else(tmp_path):
    first = tmp_path / "a" / "_remote.repositories"
    second = tmp_path / "b" / "_remote.repositories"
    plain = tmp_path / "c" / "x.pom"
    for file, content in ((first, b"#NOTE\n#Wed Oct 07 10:00:00 UTC 2026\nx.pom>central=\n"),
                          (second, b"#NOTE\n#Thu Oct 08 11:11:11 UTC 2026\nx.pom>central="),
                          (plain, b"#not a comment here\n")):
        file.parent.mkdir()
        file.write_bytes(content)
    assert pinned.digest(first) == pinned.digest(second) == sha(b"x.pom>central=\n")
    assert pinned.digest(plain) == sha(b"#not a comment here\n")


def test_a_tree_that_matches_its_manifest_is_verified_and_counted(tmp_path):
    root = tree(tmp_path, {"a/a.pom": b"A", "b/_remote.repositories": b"#t\nx\n"})
    assert pinned.verify(root) == 2


@pytest.mark.parametrize("damage", ["changed", "missing", "link", "empty manifest", "malformed", "escaping path",
                                    "no manifest"])
def test_a_tree_that_does_not_match_its_manifest_is_never_verified(tmp_path, damage):
    root = tree(tmp_path, {"a/a.pom": b"A", "b/b.pom": b"B"})
    base = pathlib.Path(root.path)
    manifest = pathlib.Path(root.manifest)
    if damage == "changed":
        (base / "a" / "a.pom").write_bytes(b"tampered")
    elif damage == "missing":
        (base / "b" / "b.pom").unlink()
    elif damage == "link":
        (base / "b" / "b.pom").unlink()
        (base / "b" / "b.pom").symlink_to(base / "a" / "a.pom")
    elif damage == "empty manifest":
        manifest.write_text("")
    elif damage == "malformed":
        manifest.write_text("not a manifest line\n")
    elif damage == "escaping path":
        manifest.write_text(f"{sha(b'A')}  ../outside\n")
    else:
        manifest.unlink()
    with pytest.raises(ValueError):
        pinned.verify(root)


def test_a_tree_that_is_a_link_or_not_a_directory_is_never_verified(tmp_path):
    root = tree(tmp_path, {"a.pom": b"A"})
    link = tmp_path / "link"
    link.symlink_to(root.path)
    with pytest.raises(ValueError, match="not a real directory"):
        pinned.verify(pinned.PinnedRoot(path=str(link), manifest=root.manifest))
    with pytest.raises(ValueError, match="not a real directory"):
        pinned.verify(pinned.PinnedRoot(path=str(tmp_path / "absent"), manifest=root.manifest))


def denial(path: str, section: str) -> record.Denial:
    """A refused access of one section on one path."""
    return record.Denial(pid=300, layer=record.LAYER_FILESYSTEM, operation="openat", objects=(path,),
                         sections=frozenset({section}), address=None, port=None, transport=None, errno="EACCES",
                         run=1, tid=300)


SNAPSHOT = generalise.Snapshot(existing=frozenset({"/root/.m2/repository/a/a.pom", "/root/.m2/settings.xml",
                                                   "/root/.ssh/id", "/root/.m2/repository"}),
                               directories=frozenset({"/root/.m2", "/root/.m2/repository", "/root/.m2/repository/a",
                                                      "/root/.ssh", "/root"}), scanned=("/",))
PINNED = {"/root/.m2/repository": "pinned: why"}


def test_every_read_beneath_a_pinned_root_is_granted_as_that_one_directory_with_the_reason():
    grants, notes = generalise.grants_and_notes(
        [denial("/root/.m2/repository/a/a.pom", "read"), denial("/root/.m2/repository/b/b.jar", "read"),
         denial("/root/.m2/repository", "read")], SNAPSHOT, generalise.DEFAULT_FINE_ROOTS, None, PINNED)
    assert grants == {"/root/.m2/repository": frozenset({"read"})}
    assert notes.comments["/root/.m2/repository"] == "pinned: why"


def test_a_file_beside_the_pinned_root_is_still_granted_file_by_file_and_never_widened():
    grants, _ = generalise.grants_and_notes(
        [denial("/root/.m2/settings.xml", "read"), denial("/root/.ssh/id", "read")], SNAPSHOT,
        generalise.DEFAULT_FINE_ROOTS, None, PINNED)
    assert grants == {"/root/.m2/settings.xml": frozenset({"read"}), "/root/.ssh/id": frozenset({"read"})}
    assert "/root" not in grants and "/root/.m2" not in grants


@pytest.mark.parametrize("section", ["write", "create", "delete", "create-symlink", "restructure", "execute"])
def test_nothing_but_read_is_ever_granted_on_the_pinned_root(section):
    grants, _ = generalise.grants_and_notes([denial("/root/.m2/repository/a/a.pom", section)], SNAPSHOT,
                                            generalise.DEFAULT_FINE_ROOTS, None, PINNED)
    assert "/root/.m2/repository" not in grants


def test_without_a_declaration_the_same_reads_stay_file_by_file():
    grants, _ = generalise.grants_and_notes([denial("/root/.m2/repository/a/a.pom", "read")], SNAPSHOT,
                                            generalise.DEFAULT_FINE_ROOTS)
    assert grants == {"/root/.m2/repository/a/a.pom": frozenset({"read"})}


def exercise_with(tmp_path: pathlib.Path, roots: tuple[pinned.PinnedRoot, ...]) -> runner.Exercise:
    """A minimal exercise declaring the roots."""
    directory = tmp_path / "exercise"
    directory.mkdir()
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    found = runner.read_exercise(directory)
    return runner.Exercise(**{**found.__dict__, "pinned_read_roots": roots})


def test_the_pruning_verifies_the_declared_roots_before_it_grants_any_and_records_them(tmp_path):
    root = tree(tmp_path, {"a.pom": b"A"})
    found = stages.Pruning(exercise=exercise_with(tmp_path, (root,)), budget=stages.Budget(),
                           environment=runner.Environment())
    stages.verify_pinned_roots(found)
    assert list(found.pinned_roots) == [root.path]
    assert root.manifest in found.pinned_roots[root.path]
    assert found.log[-1]["roots"] == [{"path": root.path, "manifest": root.manifest, "files": 1}]


def test_a_root_that_does_not_match_its_manifest_aborts_the_exercise_and_grants_nothing(tmp_path):
    root = tree(tmp_path, {"a.pom": b"A"}, wanted={"a.pom": "0" * 64})
    found = stages.Pruning(exercise=exercise_with(tmp_path, (root,)), budget=stages.Budget(),
                           environment=runner.Environment())
    with pytest.raises(search.PruneAbort, match="does not match its manifest"):
        stages.verify_pinned_roots(found)
    assert found.pinned_roots == {}


def test_prune_json_declares_roots_strictly_and_the_exercise_carries_them(tmp_path):
    directory = tmp_path / "exercise"
    directory.mkdir()
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    (directory / "prune.json").write_text(json.dumps({"pinned_read_roots": [GOOD]}))
    assert runner.read_exercise(directory).pinned_read_roots == (pinned.PinnedRoot(**GOOD),)
    for bad in ({**GOOD, "sections": ["write"]}, {"path": "/root", "manifest": GOOD["manifest"]}):
        (directory / "prune.json").write_text(json.dumps({"pinned_read_roots": [bad]}))
        with pytest.raises(runner.ExerciseRefused):
            runner.read_exercise(directory)
    (directory / "prune.json").write_text(json.dumps({"pinned_read_roots": GOOD}))
    with pytest.raises(runner.ExerciseRefused):
        runner.read_exercise(directory)
