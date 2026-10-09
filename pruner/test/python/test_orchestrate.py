"""Checks when orchestrate.py refuses to write a policy, and what it writes when it does.

The files it writes are a security policy: everything they do not name is denied. Built from only
part of what was asked for, they would be narrower than anyone intended, and nothing downstream
could tell that from a correct policy. So every way a language can drop out has to stop the merge
rather than shrink it. The artefacts are written here as the layer pruner writes them, so these
tests need no container and no exercise.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

# How long the orchestrator may run before the test gives up on it.
ORCHESTRATOR_TIMEOUT_SECONDS = 120

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
ORCHESTRATOR = REPO_ROOT / "pruner" / "src" / "orchestrate" / "orchestrate.py"
HELPERS = REPO_ROOT / "pruner" / "src"

JAVA_ONE = """[read]
/usr
/var/tmp/testing-dir

[execute]
/usr

[write]
/var/tmp/testing-dir

[connect]
allow 127.0.0.1:*

[limits]
timeout=60
cpu=30
"""

JAVA_TWO = """[read]
/srv/data
/usr/lib

[bind]
allow 0

[limits]
timeout=90
"""

PYTHON_ONE = """[read]
/usr
/usr/local/lib/python3.13

[execute]
/usr

[limits]
timeout=30
"""


def run_orchestrator(tmp_path: pathlib.Path, langs: str = "java") -> subprocess.CompletedProcess:
    """Runs the orchestrator over the artefacts under tmp_path/path_sets, writing under tmp_path/core."""
    return subprocess.run(
        [
            sys.executable,
            str(ORCHESTRATOR),
            "--langs", langs,
            "--path-dir", str(tmp_path / "path_sets"),
            "--core-dir", str(tmp_path / "core"),
            "--helpers-dir", str(HELPERS),
        ],
        capture_output=True,
        text=True,
        timeout=ORCHESTRATOR_TIMEOUT_SECONDS,
        check=False,
    )


def base_policy(tmp_path: pathlib.Path) -> pathlib.Path:
    """The union policy the orchestrator writes when it gets that far."""
    return tmp_path / "core" / "BasePhobos.cfg"


def write_layer_artefacts(path_dir: pathlib.Path, exercise: str, text: str, key: str = "java",
                          stage: str = "all") -> None:
    """Writes one exercise's .cfg and the record the layer pruner writes beside it."""
    path_dir.mkdir(parents=True, exist_ok=True)
    (path_dir / f"{key}_{exercise}.cfg").write_text(text)
    record = {"schema_version": 2, "key": key, "exercise": exercise, "stage": stage,
              "cfg_sha256": hashlib.sha256(text.encode()).hexdigest()}
    (path_dir / f"{key}_{exercise}.json").write_text(json.dumps(record))


def both_languages(tmp_path: pathlib.Path) -> subprocess.CompletedProcess:
    """Merges two Java exercises and one Python exercise."""
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    write_layer_artefacts(tmp_path / "path_sets", "two", JAVA_TWO)
    write_layer_artefacts(tmp_path / "path_sets", "reference", PYTHON_ONE, key="python")
    return run_orchestrator(tmp_path, langs="java,python")


def test_the_exercises_of_a_language_are_merged_into_one_base_without_limits(tmp_path):
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Done." in result.stdout
    base = (tmp_path / "core" / "BaseLanguage-java.cfg").read_text()
    assert base == (
        "[read]\n/srv/data\n/usr\n/usr/lib\n/var/tmp/testing-dir\n\n"
        "[execute]\n/usr\n/usr/lib\n\n"
        "[write]\n/var/tmp/testing-dir\n\n"
        "[connect]\nallow 127.0.0.1:*\n\n"
        "[bind]\nallow 0\n"
    ), "exactly the union, the nested /usr/lib raised to its ancestor's rights, and no [limits]"
    assert "/usr/local/lib/python3.13" in base_policy(tmp_path).read_text()


def test_each_exercise_keeps_its_limits_and_nothing_the_base_grants(tmp_path):
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    exercises = tmp_path / "core" / "exercises"
    assert (exercises / "java_one.cfg").read_text() == "[limits]\ntimeout=60\ncpu=30\n"
    assert (exercises / "java_two.cfg").read_text() == "[limits]\ntimeout=90\n"
    assert (exercises / "python_reference.cfg").read_text() == "[limits]\ntimeout=30\n"


def test_the_debug_files_say_what_the_language_file_does_not(tmp_path):
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    debug = tmp_path / "core" / "debug"
    only_java = (debug / "BaseJavaOnly.cfg").read_text()
    assert "/srv/data" in only_java
    assert "/usr/local/lib/python3.13" not in only_java
    assert (debug / "BaseJavaCommon.cfg").read_text() == ""
    assert "/usr" in (debug / "BasePhobosIntersect.cfg").read_text()


def test_the_runtime_tail_is_only_the_runtime_chdir(tmp_path):
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "core" / "TailPhobos.cfg").read_text().split() == ["--chdir", "/var/tmp/testing-dir"]


def test_a_language_without_any_artefact_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    result = run_orchestrator(tmp_path, langs="java,python")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "no usable pruning result for: python" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_a_language_whose_policy_names_no_path_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", "[connect]\nallow 127.0.0.1:*\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "no usable pruning result for: java" in result.stdout


def test_an_exercise_that_is_gone_leaves_no_configuration_behind(tmp_path):
    exercises = tmp_path / "core" / "exercises"
    exercises.mkdir(parents=True)
    (exercises / "java_removed.cfg").write_text("[limits]\ntimeout=1\n")
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (exercises / "java_removed.cfg").exists()


def test_a_cfg_its_record_does_not_vouch_for_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    (tmp_path / "path_sets" / "java_one.cfg").write_text(JAVA_ONE.replace("/usr\n", "/\n"))
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_one.cfg is not the file java_one.json records" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_a_cfg_without_its_record_and_a_record_without_its_cfg_stop_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    write_layer_artefacts(tmp_path / "path_sets", "two", JAVA_TWO)
    (tmp_path / "path_sets" / "java_one.json").unlink()
    (tmp_path / "path_sets" / "java_three.json").write_text("{}")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_one.cfg has no java_one.json" in result.stdout
    assert "java_three.json has no java_three.cfg" in result.stdout


def test_a_record_naming_another_exercise_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    record = tmp_path / "path_sets" / "java_one.json"
    record.write_text(record.read_text().replace('"exercise": "one"', '"exercise": "two"'))
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_one.json records java/two, not java_one" in result.stdout


@pytest.mark.parametrize("record, reason", [
    (b"[1, 2]", "is not a layer pruner record of schema version 2"),
    (b'{"schema_version": 1, "key": "java", "exercise": "one", "stage": "all"}',
     "is not a layer pruner record of schema version 2"),
    (b'{"schema_version": 2, "key": "python", "exercise": "one", "stage": "all"}',
     "records python/one, not java_one"),
    (b"\xff\xfe not text", "is not readable as JSON"),
])
def test_a_record_that_is_not_the_layer_pruners_for_this_cfg_stops_the_merge(tmp_path, record, reason):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    (tmp_path / "path_sets" / "java_one.json").write_bytes(record)
    result = run_orchestrator(tmp_path, langs="java")
    assert result.returncode == 1, result.stdout + result.stderr
    assert reason in result.stdout
    assert "Traceback" not in result.stderr


def test_an_aborted_exercise_stops_the_merge_and_is_named_with_its_reason(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    (tmp_path / "path_sets" / "java_two.aborted.json").write_text(json.dumps({"aborted": "flaky reference"}))
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_two was aborted: flaky reference" in result.stdout


def test_an_aborted_record_that_cannot_be_decoded_is_named_without_a_traceback(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    (tmp_path / "path_sets" / "java_two.aborted.json").write_bytes(b"\xff\xfe")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_two was aborted: its record is not readable" in result.stdout
    assert "Traceback" not in result.stderr
    assert not base_policy(tmp_path).exists()


def test_a_path_set_left_by_the_retired_bubblewrap_pruner_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    (tmp_path / "path_sets" / "java_old.paths").write_text("r /usr\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_old.paths is a path set of the retired Bubblewrap pruner" in result.stdout
    assert not base_policy(tmp_path).exists()
    assert not (tmp_path / "core" / "BaseLanguage-java.cfg").exists()


def test_a_cfg_the_run_time_parser_would_read_differently_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", "[read]\nrelative/path\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "cannot be read" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_a_record_of_a_prune_stopped_after_an_earlier_stage_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE, stage="network")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "stopped after its network stage" in result.stdout


def test_a_union_that_puts_execute_beside_another_exercise_s_write_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", "[read]\n/srv/tool\n\n[execute]\n/srv/tool\n")
    write_layer_artefacts(tmp_path / "path_sets", "two", "[write]\n/srv/tool/cache\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java: /srv/tool" in result.stdout
    assert not (tmp_path / "core" / "BaseLanguage-java.cfg").exists()


def test_a_union_that_puts_execute_under_another_exercise_s_write_on_an_ancestor_stops_the_merge(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one", "[write]\n/srv/tool\n")
    write_layer_artefacts(tmp_path / "path_sets", "two", "[read]\n/srv/tool/bin\n\n[execute]\n/srv/tool/bin\n")
    result = run_orchestrator(tmp_path, langs="java")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java: /srv/tool/bin" in result.stdout


def test_one_exercise_s_external_rules_reach_the_base_and_not_its_exercise_file(tmp_path):
    write_layer_artefacts(tmp_path / "path_sets", "one",
                          "[connect]\nallow api.example.org:443\n\n[limits]\ntimeout=60\n")
    write_layer_artefacts(tmp_path / "path_sets", "two", "[read]\n/srv/data\n")
    result = run_orchestrator(tmp_path, langs="java")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "allow api.example.org:443" in (tmp_path / "core" / "BaseLanguage-java.cfg").read_text()
    assert (tmp_path / "core" / "exercises" / "java_one.cfg").read_text() == "[limits]\ntimeout=60\n"


def test_an_execute_one_exercise_already_had_beside_its_own_write_is_merged(tmp_path):
    own = "[read]\n/srv/app\n\n[execute]\n/srv/app/run.sh\n\n[write]\n/srv/app\n"
    write_layer_artefacts(tmp_path / "path_sets", "one", own)
    write_layer_artefacts(tmp_path / "path_sets", "two", "[read]\n/srv/data\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_cross_language_execute_beside_a_write_leaves_base_phobos_out_and_writes_the_rest(tmp_path):
    result = both_languages(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    stale = base_policy(tmp_path)
    assert stale.exists()
    write_layer_artefacts(tmp_path / "path_sets", "two", "[write]\n/opt/tool/cache\n")
    write_layer_artefacts(tmp_path / "path_sets", "reference", PYTHON_ONE + "\n[execute]\n/opt/tool\n", key="python")
    result = run_orchestrator(tmp_path, langs="java,python")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "BasePhobos.cfg is not written" in result.stdout
    assert not stale.exists()
    assert (tmp_path / "core" / "BaseLanguage-java.cfg").exists()
    assert (tmp_path / "core" / "BaseLanguage-python.cfg").exists()


def test_a_policy_render_refuses_at_write_time_stops_everything_and_leaves_earlier_files(tmp_path):
    exercises = tmp_path / "core" / "exercises"
    exercises.mkdir(parents=True)
    (exercises / "java_earlier.cfg").write_text("[limits]\ntimeout=1\n")
    write_layer_artefacts(tmp_path / "path_sets", "one", "[read]\n/usr\n\n[bind]\nallow 70000\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "cannot be written" in result.stdout
    assert not (tmp_path / "core" / "BaseLanguage-java.cfg").exists()
    assert (exercises / "java_earlier.cfg").exists()


def write_kvm_artefacts(path_dir: pathlib.Path, exercise: str, rows: str | None, key: str = "java", changes: dict | None = None) -> None:
    """Writes the KVM run's record, and its sidecar when `rows` is given, beside an exercise's .cfg."""
    cfg = (path_dir / f"{key}_{exercise}.cfg").read_bytes()
    record = {"schema_version": 1, "key": key, "exercise": exercise, "verified": True, "mismatches": [],
              "verified_cfg_sha256": hashlib.sha256(cfg).hexdigest(), "abi10_cfg_sha256": None,
              "landlock_abi": 10}
    if rows is not None:
        (path_dir / f"{key}_{exercise}.abi10.cfg").write_text(rows)
        record["abi10_cfg_sha256"] = hashlib.sha256(rows.encode()).hexdigest()
    record.update(changes or {})
    (path_dir / f"{key}_{exercise}.abi10.json").write_text(json.dumps(record))


UDP_ROW = "# from the KVM run\n[bind]\nallow 5000 udp\n"


def two_exercises(tmp_path: pathlib.Path) -> pathlib.Path:
    """Two layer-pruned Java exercises; the directory they are in."""
    write_layer_artefacts(tmp_path / "path_sets", "one", JAVA_ONE)
    write_layer_artefacts(tmp_path / "path_sets", "two", JAVA_TWO)
    return tmp_path / "path_sets"


def test_a_udp_row_the_kvm_run_added_reaches_its_own_files_and_never_the_base(tmp_path):
    write_kvm_artefacts(two_exercises(tmp_path), "two", UDP_ROW)
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    core = tmp_path / "core"
    assert "udp" not in (core / "BaseLanguage-java.cfg").read_text()
    assert "udp" not in (core / "BasePhobos.cfg").read_text()
    assert (core / "Abi10-java.cfg").read_text() == "[bind]\nallow 5000 udp\n"
    assert (core / "exercises" / "java_two.abi10.cfg").read_text() == "[bind]\nallow 5000 udp\n"
    assert (core / "exercises" / "java_two.cfg").read_text() == "[limits]\ntimeout=90\n"
    assert not (core / "exercises" / "java_one.abi10.cfg").exists()


def test_a_later_merge_without_the_kvm_run_leaves_no_abi10_file_behind(tmp_path):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "two", UDP_ROW)
    assert run_orchestrator(tmp_path).returncode == 0
    for leftover in path_dir.glob("*.abi10.*"):
        leftover.unlink()
    assert run_orchestrator(tmp_path).returncode == 0
    assert not (tmp_path / "core" / "Abi10-java.cfg").exists()
    assert not list((tmp_path / "core" / "exercises").glob("*.abi10.cfg"))


def test_a_record_without_a_sidecar_is_accepted_and_writes_no_abi10_file(tmp_path):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "one", None)
    result = run_orchestrator(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not (tmp_path / "core" / "Abi10-java.cfg").exists()


def test_a_kvm_record_that_verified_another_cfg_stops_the_merge(tmp_path):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "two", UDP_ROW)
    write_layer_artefacts(path_dir, "two", JAVA_TWO.replace("/srv/data", "/srv/other"))
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "verified another java_two.cfg than the one beside it" in result.stdout
    assert not base_policy(tmp_path).exists()


def test_a_sidecar_that_is_not_the_one_its_record_names_stops_the_merge(tmp_path):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "two", UDP_ROW)
    (path_dir / "java_two.abi10.cfg").write_text("[bind]\nallow 6000 udp\n")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_two.abi10.cfg is not the file java_two.abi10.json records" in result.stdout


@pytest.mark.parametrize("changes, reason", [
    ({"verified": False}, "did not verify the policy"),
    ({"mismatches": [{"objects": ["/x"]}]}, "did not verify the policy"),
    ({"schema_version": 2}, "is not a KVM record of schema version 1"),
    ({"landlock_abi": 9}, "a kernel below Landlock version 10"),
    ({"landlock_abi": None}, "a kernel below Landlock version 10"),
    ({"exercise": "one"}, "records java/one, not java_two"),
])
def test_a_kvm_record_that_is_not_a_clean_verification_of_this_exercise_stops_the_merge(tmp_path, changes, reason):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "two", UDP_ROW, changes=changes)
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert reason in result.stdout
    assert not base_policy(tmp_path).exists()


def test_a_sidecar_without_its_record_and_a_record_without_its_cfg_stop_the_merge(tmp_path):
    path_dir = two_exercises(tmp_path)
    (path_dir / "java_one.abi10.cfg").write_text(UDP_ROW)
    (path_dir / "java_three.abi10.json").write_text("{}")
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "java_one.abi10.cfg has no java_one.abi10.json beside it" in result.stdout
    assert "java_three.abi10.json has no java_three.cfg beside it" in result.stdout


@pytest.mark.parametrize("rows", ["[read]\n/srv/extra\n", "[connect]\nallow api.example.org:443\n",
                                  "[bind]\nallow 5000\n", "[limits]\ntimeout=1\n", "[bind]\nallow 00 udp\n",
                                  "[bind]\nallow 65536 udp\n", "[bind]\nallow 007 udp\n",
                                  "[bind]\nallow \u0665000 udp\n"])
def test_a_sidecar_holding_anything_but_udp_bind_rows_stops_the_merge_whatever_its_hash_says(tmp_path, rows):
    path_dir = two_exercises(tmp_path)
    write_kvm_artefacts(path_dir, "two", rows)
    result = run_orchestrator(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "holds more than UDP bind rows" in result.stdout
    assert "Traceback" not in result.stderr
