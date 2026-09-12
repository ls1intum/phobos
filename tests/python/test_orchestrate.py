"""Checks when orchestrate.py refuses to write a policy, and when it does write one.

The files it writes are a security policy: everything they do not name is denied.
Built from only part of what was asked for, they would be narrower than anyone
intended, and nothing downstream could tell that from a correct policy. So every
way a language can drop out has to stop the merge rather than shrink it.

The pruning entry point is replaced by a stub, so these tests need no container,
no bubblewrap and no exercises. The stub is told which language to fail, which to
finish without producing anything, and where to write artefacts.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ORCHESTRATOR = REPO_ROOT / "docker" / "prune_phase" / "orchestrate" / "orchestrate.py"
HELPERS = REPO_ROOT / "var" / "tmp" / "helpers"

PRUNE_STUB = """#!/usr/bin/env bash
# Stands in for run_minimal_fs_all.sh. The language is the last argument, and the
# two variables below are comma-separated lists of languages to misbehave for.
for argument in "$@"; do language="$argument"; done

case ",${FAILING_LANG}," in
  *",${language},"*)
    echo "stub: refusing to prune ${language}" >&2
    exit 1
    ;;
esac

mkdir -p "${STUB_PATH_DIR}"
case ",${SILENT_LANG}," in
  *",${language},"*) ;;
  *)
    case ",${EMPTY_LANG}," in
      *",${language},"*)
        : > "${STUB_PATH_DIR}/${language}_exercise1.paths"
        ;;
      *)
        printf 'r /usr/lib/%s\\nw /home/build/%s\\n' "${language}" "${language}" \
          > "${STUB_PATH_DIR}/${language}_exercise1.paths"
        ;;
    esac
    ;;
esac

echo "stub: pruned ${language}"
exit 0
"""


def run_orchestrator(
    tmp_path: pathlib.Path,
    failing: str = "",
    silent: str = "",
    empty: str = "",
    langs: str = "java,python",
) -> subprocess.CompletedProcess:
    """Runs the orchestrator against a stub with the named language misbehaving."""
    stub = tmp_path / "prune-stub.sh"
    stub.write_text(PRUNE_STUB)
    stub.chmod(0o755)
    path_dir = tmp_path / "path_sets"
    return subprocess.run(
        [
            sys.executable,
            str(ORCHESTRATOR),
            "--langs", langs,
            "--path-dir", str(path_dir),
            "--core-dir", str(tmp_path / "core"),
            "--helpers-dir", str(HELPERS),
            "--prune-script", str(stub),
        ],
        env={
            **os.environ,
            "FAILING_LANG": failing,
            "SILENT_LANG": silent,
            "EMPTY_LANG": empty,
            "STUB_PATH_DIR": str(path_dir),
        },
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def runtime_tail(tmp_path: pathlib.Path) -> str:
    """The tail the orchestrator writes for the runtime to use."""
    return (tmp_path / "core" / "TailPhobos.cfg").read_text()


def base_policy(tmp_path: pathlib.Path) -> pathlib.Path:
    """The union policy the orchestrator writes when it gets that far."""
    return tmp_path / "core" / "BasePhobos.cfg"


def test_every_language_contributes_to_the_policy(tmp_path):
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Done." in result.stdout
    written = base_policy(tmp_path).read_text()
    assert "/usr/lib/java" in written
    assert "/usr/lib/python" in written
    assert "/home/build/java" in written
    assert "/home/build/python" in written


def test_a_failing_language_stops_the_merge(tmp_path):
    result = run_orchestrator(tmp_path, failing="java")
    assert result.returncode != 0
    assert "Refusing to merge" in result.stdout
    assert "Done." not in result.stdout
    assert not base_policy(tmp_path).exists()


def test_the_failing_language_is_named(tmp_path):
    result = run_orchestrator(tmp_path, failing="python")
    assert result.returncode != 0
    assert "pruning failed for: python" in result.stdout


def test_every_failing_language_is_named(tmp_path):
    result = run_orchestrator(tmp_path, failing="java,python", langs="java,python")
    assert result.returncode != 0
    assert "pruning failed for: java, python" in result.stdout


def test_pruning_still_runs_for_the_other_languages(tmp_path):
    """A failure must not cancel the others, only the merge that follows them.
    The stub prints this line itself, so it is proof the stub ran to the end."""
    result = run_orchestrator(tmp_path, failing="java")
    assert result.returncode != 0
    assert "stub: pruned python" in result.stdout


def test_a_language_that_produces_nothing_stops_the_merge(tmp_path):
    """The dangerous case: pruning reports success and emits no artefacts, so the
    language drops out of the merge without anything having failed."""
    result = run_orchestrator(tmp_path, silent="python")
    assert result.returncode != 0
    assert "no usable pruning result for: python" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_last_run_s_artefacts_cannot_stand_in_for_this_run_s(tmp_path):
    """A leftover union file would otherwise answer "yes, that language produced a
    result" for a language that produced nothing this time."""
    stale = tmp_path / "path_sets"
    stale.mkdir(parents=True)
    (stale / "python_union.paths").write_text("r /from/an/earlier/run\n")
    result = run_orchestrator(tmp_path, silent="python")
    assert result.returncode != 0
    assert "no usable pruning result for: python" in result.stdout
    written = base_policy(tmp_path)
    assert not written.exists() or "/from/an/earlier/run" not in written.read_text()


def test_a_language_whose_result_names_nothing_stops_the_merge(tmp_path):
    """An empty union is not a language that needs no paths. Every real exercise
    contributes the base bindings, so emptiness means the result is unusable."""
    result = run_orchestrator(tmp_path, empty="python")
    assert result.returncode != 0
    assert "no usable pruning result for: python" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_the_runtime_tail_keeps_the_mounts_and_the_namespaces(tmp_path):
    """What the orchestrator writes has to be the sandbox the prune was measured in.
    It kept a subset, so a generated policy ran without /proc, without /dev, without a
    PID namespace of its own and without a new session."""
    path_dir = tmp_path / "path_sets"
    path_dir.mkdir(parents=True)
    (path_dir / "TailPhobos.cfg").write_text(
        "--proc /proc --dev /dev --share-net --new-session --unshare-pid "
        "--unshare-uts --unshare-ipc --chdir /tmp/exercise-1\n"
    )
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    written = runtime_tail(tmp_path)
    for option in ("--proc /proc", "--dev /dev", "--new-session", "--unshare-pid"):
        assert option in written, f"{option} missing from {written!r}"
    assert "/tmp/exercise-1" not in written


def test_a_repeated_mount_does_not_lose_its_operand(tmp_path):
    """Deduplicating tokens rather than options would leave a dangling --proc."""
    path_dir = tmp_path / "path_sets"
    path_dir.mkdir(parents=True)
    (path_dir / "TailPhobos.cfg").write_text(
        "--proc /proc --proc /proc --dev /dev --chdir /tmp/exercise-1\n"
    )
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    written = runtime_tail(tmp_path).split()
    assert written.count("--proc") == 1
    assert written[written.index("--proc") + 1] == "/proc"
    assert written[written.index("--dev") + 1] == "/dev"
