"""Checks the runner's command lines, the acceptance gate and the stop rule with a fake phobos.sh and strace."""

from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.infrastructure import runner
from shared.src.domain import cfgfile

# A phobos.sh stand-in: it records its arguments and the candidate it was given, prints FAKE_STDERR,
# and then either runs the command after -- (FAKE_RUN=1) or ends with FAKE_STATUS.
FAKE_PHOBOS = """#!/bin/bash
printf '%s\\n' "$@" > "$FAKE_RECORD/argv"
cp "$2" "$FAKE_RECORD/candidate.cfg"
printf '%s' "${FAKE_STDERR:-}" >&2
if [[ "${FAKE_RUN:-0}" == 1 ]]; then
  while [[ "$1" != "--" ]]; do shift; done
  shift
  "$@"
  exit "${FAKE_STATUS:-$?}"
fi
exit "${FAKE_STATUS:-0}"
"""
# A phobos-policysystem.sh stand-in that refuses any configuration file holding the word REFUSE.
FAKE_POLICYSYSTEM = """#!/bin/bash
for argument in "$@"; do
  [[ -f "$argument" ]] && grep -q REFUSE "$argument" && { echo "Policy invalid. (PHB-EPOLICY)" >&2; exit 11; }
done
exit 0
"""
# A strace stand-in: it writes an empty trace where -o says and runs the rest.
FAKE_STRACE = """#!/bin/bash
printf '%s\\n' "$@" > "$FAKE_RECORD/strace-argv"
while [[ "$1" != "-o" ]]; do shift; done
: > "$2"
shift 2
exec "$@"
"""
SHAPE_OBSERVED = runner.RunShape(observe=True, network=False, limits=False, sample=False)
SHAPE_PLAIN = runner.RunShape(observe=False, network=True, limits=True, sample=False)


def script(path: pathlib.Path, text: str) -> pathlib.Path:
    """Writes an executable script."""
    path.write_text(text)
    path.chmod(0o755)
    return path


@pytest.fixture
def environment(tmp_path, monkeypatch) -> runner.Environment:
    """An environment whose Phobos and strace are the stand-ins, everything under tmp_path."""
    home = tmp_path / "core"
    home.mkdir()
    script(home / "phobos.sh", FAKE_PHOBOS)
    script(home / "phobos-policysystem.sh", FAKE_POLICYSYSTEM)
    record = tmp_path / "record"
    record.mkdir()
    monkeypatch.setenv("FAKE_RECORD", str(record))
    for name in ("FAKE_RUN", "FAKE_STATUS", "FAKE_STDERR"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "spec").mkdir()
    return runner.Environment(phobos_home=str(home), strace=str(script(tmp_path / "strace", FAKE_STRACE)),
                              testing_dir=str(tmp_path / "testing-dir"), candidate_dir=str(tmp_path / "run"),
                              spec_parent=str(tmp_path / "spec"), log_dir=str(tmp_path / "logs"), run_seconds=30)


def exercise(tmp_path: pathlib.Path, body: str = "exit 0\n", declared_hosts: tuple[str, ...] = ()) -> runner.Exercise:
    """An exercise whose build script runs `body`."""
    directory = tmp_path / "exercises" / "fixture"
    directory.mkdir(parents=True, exist_ok=True)
    script(directory / "build_script.sh", "#!/bin/bash\n" + body)
    (directory / "prune.json").write_text(json.dumps({"declared_hosts": list(declared_hosts)}))
    return runner.read_exercise(directory)


def empty_policy() -> cfgfile.Policy:
    """A policy that grants nothing."""
    return cfgfile.Policy(fs={}, connect=(), bind=(), limits={})


def recorded(environment: runner.Environment, name: str) -> list[str]:
    """The lines a stand-in recorded."""
    return (pathlib.Path(os.environ["FAKE_RECORD"]) / name).read_text().splitlines()


def test_an_observed_run_puts_strace_outermost_and_passes_the_candidate_as_config(tmp_path, environment):
    result = runner.run_layers(exercise(tmp_path), empty_policy(), SHAPE_OBSERVED, environment)
    strace_argv = recorded(environment, "strace-argv")
    phobos_argv = recorded(environment, "argv")
    assert strace_argv[0] == "-f"
    assert strace_argv[strace_argv.index("-o") + 2].endswith("phobos.sh")
    assert phobos_argv[0] == "--config"
    assert "-nnr" in phobos_argv
    assert result.status == 0
    assert result.trace is not None


def test_limits_off_writes_zero_for_every_limit_and_limits_on_keeps_the_policys(tmp_path, environment):
    runner.run_layers(exercise(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={"cpu": 30}),
                      SHAPE_OBSERVED, environment)
    off = (pathlib.Path(os.environ["FAKE_RECORD"]) / "candidate.cfg").read_text()
    runner.run_layers(exercise(tmp_path), cfgfile.Policy(fs={}, connect=(), bind=(), limits={"cpu": 30}),
                      SHAPE_PLAIN, environment)
    on = (pathlib.Path(os.environ["FAKE_RECORD"]) / "candidate.cfg").read_text()
    assert "timeout=0" in off
    assert "mem_mb=0" in off
    assert "cpu=0" in off
    assert on == "[limits]\ncpu=30\n"


@pytest.mark.parametrize(("status", "marker"), [(11, "Policy invalid. (PHB-EPOLICY)\n"),
                                                (15, "Could not start. (PHB-ERUNTIME)\n"),
                                                (125, "[phobos-landlock-filesystem-and-networksystem] cannot open /x\n")])
def test_a_run_phobos_itself_stopped_is_a_pruner_defect_not_a_verdict(tmp_path, environment, monkeypatch, status, marker):
    monkeypatch.setenv("FAKE_STATUS", str(status))
    monkeypatch.setenv("FAKE_STDERR", marker)
    with pytest.raises(runner.PrunerDefect):
        runner.run_layers(exercise(tmp_path), empty_policy(), SHAPE_PLAIN, environment)


@pytest.mark.parametrize("status", [2, 11, 15, 125])
def test_the_commands_own_status_without_a_phobos_marker_is_a_verdict(tmp_path, environment, monkeypatch, status):
    monkeypatch.setenv("FAKE_RUN", "1")
    monkeypatch.setenv("FAKE_STATUS", str(status))
    result = runner.run_layers(exercise(tmp_path, "echo 'make: *** [all] Error 2' >&2\n"), empty_policy(),
                               SHAPE_PLAIN, environment)
    assert result.status == status


def test_a_marker_the_command_prints_itself_after_it_started_is_a_verdict(tmp_path, environment, monkeypatch):
    monkeypatch.setenv("FAKE_RUN", "1")
    monkeypatch.setenv("FAKE_STATUS", "11")
    result = runner.run_layers(exercise(tmp_path, "echo '(PHB-EPOLICY)' >&2\n"), empty_policy(), SHAPE_PLAIN, environment)
    assert result.status == 11


def test_a_candidate_the_gate_refuses_is_a_pruner_defect(tmp_path, environment):
    refused = cfgfile.Policy(fs={}, connect=("allow REFUSE:1",), bind=(), limits={})
    with pytest.raises(runner.PrunerDefect, match="refused the candidate"):
        runner.run_layers(exercise(tmp_path), refused, SHAPE_PLAIN, environment)


def test_a_pair_of_configuration_files_is_passed_as_two_config_arguments_in_the_order_given(tmp_path, environment):
    base = tmp_path / "BaseLanguage-java.cfg"
    own = tmp_path / "java_fixture.cfg"
    base.write_text("[read]\n/usr\n")
    own.write_text("[limits]\ntimeout=60\n")
    runner.run_configured(exercise(tmp_path), (base, own), SHAPE_PLAIN, environment, runner.log_paths(environment, "pair"))
    assert recorded(environment, "argv")[:4] == ["--config", str(base), "--config", str(own)]


def test_a_pair_whose_second_file_the_gate_refuses_is_a_pruner_defect(tmp_path, environment):
    base = tmp_path / "BaseLanguage-java.cfg"
    own = tmp_path / "java_fixture.cfg"
    base.write_text("[read]\n/usr\n")
    own.write_text("[connect]\nallow REFUSE:1\n")
    with pytest.raises(runner.PrunerDefect, match="refused the candidate"):
        runner.gate_configs((base, own), environment, tmp_path / "gate.log")


def test_a_candidate_render_refuses_is_a_pruner_defect(tmp_path, environment):
    with pytest.raises(runner.PrunerDefect, match="render refused"):
        runner.run_layers(exercise(tmp_path), cfgfile.Policy(fs={"relative": frozenset({"read"})}, connect=(), bind=(),
                                                             limits={}), SHAPE_PLAIN, environment)


def test_every_run_starts_from_a_fresh_copy_and_reads_its_reports(tmp_path, environment, monkeypatch):
    monkeypatch.setenv("FAKE_RUN", "1")
    body = ("[[ -e leftover ]] && exit 9\ntouch leftover\nmkdir -p build/test-results/test\n"
            "printf '<testsuite><testcase classname=\"T\" name=\"a\"/></testsuite>' > build/test-results/test/TEST-a.xml\n")
    first = runner.run_layers(exercise(tmp_path, body), empty_policy(), SHAPE_PLAIN, environment)
    second = runner.run_layers(exercise(tmp_path, body), empty_policy(), SHAPE_PLAIN, environment)
    assert (first.status, second.status) == (0, 0)
    assert second.verdict.tests == (("T.a", "passed"),)


def test_an_exercise_that_already_holds_a_report_is_refused(tmp_path):
    exercise_dir = tmp_path / "maven-reference"
    (exercise_dir / "target" / "surefire-reports").mkdir(parents=True)
    (exercise_dir / "target" / "surefire-reports" / "TEST-Stale.xml").write_text("<testsuite/>")
    script(exercise_dir / "build_script.sh", "exit 0\n")
    (exercise_dir / "prune.json").write_text('{"report_globs": ["target/surefire-reports/TEST-*.xml"], "declared_hosts": []}')
    with pytest.raises(runner.ExerciseRefused, match="report"):
        runner.read_exercise(exercise_dir)


def test_an_exercise_without_an_executable_build_script_or_with_a_malformed_host_is_refused(tmp_path):
    bare = tmp_path / "bare"
    bare.mkdir()
    with pytest.raises(runner.ExerciseRefused):
        runner.read_exercise(bare)
    script(bare / "build_script.sh", "exit 0\n")
    (bare / "prune.json").write_text('{"declared_hosts": ["*.example.org:443"]}')
    with pytest.raises(runner.ExerciseRefused, match="declares a host"):
        runner.read_exercise(bare)


def test_the_reference_of_an_exercise_with_declared_hosts_runs_under_the_layers_with_only_those_hosts(tmp_path,
                                                                                                    environment):
    runner.run_reference(exercise(tmp_path, declared_hosts=("api.example.org:443",)), environment)
    candidate = cfgfile.read_policy((pathlib.Path(os.environ["FAKE_RECORD"]) / "candidate.cfg").read_text())
    external = [rule for rule in candidate.connect if not any(word in rule for word in ("localhost", "127.0.0.1", "::1"))]
    assert external == ["allow api.example.org:443"]


def test_the_reference_of_an_exercise_without_declared_hosts_runs_without_phobos(tmp_path, environment):
    result = runner.run_reference(exercise(tmp_path), environment)
    assert result.status == 0
    assert not (pathlib.Path(os.environ["FAKE_RECORD"]) / "argv").exists()


def test_a_run_past_the_hard_limit_is_killed_with_its_group_and_reads_as_a_timeout(tmp_path, environment):
    quick = runner.Environment(**{**environment.__dict__, "run_seconds": 1})
    result = runner.run_direct(exercise(tmp_path, "sleep 30 &\nsleep 30\n"), quick)
    assert result.status == runner.HARD_LIMIT_STATUS
    assert result.verdict.exit_class == "timeout"


@pytest.mark.parametrize("settings", ["{not json", "[]", '{"heap_pinned": "false"}', '{"runs_compiled_programs": "yes"}', '{"report_globs": "x.xml"}',
                                      '{"report_globs": ["/abs/*.xml"]}', '{"declared_hosts": [1]}', '{"unknown": 1}'])
def test_a_prune_json_that_is_not_the_contract_refuses_the_exercise(tmp_path, settings):
    directory = tmp_path / "exercise"
    directory.mkdir()
    script(directory / "build_script.sh", "exit 0\n")
    (directory / "prune.json").write_text(settings)
    with pytest.raises(runner.ExerciseRefused):
        runner.read_exercise(directory)


def test_an_exercise_declares_that_it_runs_what_it_compiles_only_by_saying_so(tmp_path):
    directory = tmp_path / "exercise"
    directory.mkdir()
    script(directory / "build_script.sh", "exit 0\n")
    assert runner.read_exercise(directory).runs_compiled_programs is False
    (directory / "prune.json").write_text('{"runs_compiled_programs": true}')
    assert runner.read_exercise(directory).runs_compiled_programs is True
    (directory / "prune.json").write_text('{"runs_compiled_programs": false}')
    assert runner.read_exercise(directory).runs_compiled_programs is False


def test_a_status_phobos_could_not_read_is_a_pruner_defect_although_it_comes_after_the_command(tmp_path, environment,
                                                                                               monkeypatch):
    monkeypatch.setenv("FAKE_RUN", "1")
    monkeypatch.setenv("FAKE_STATUS", "16")
    with pytest.raises(runner.PrunerDefect, match="PHB-ESTATUS"):
        runner.run_layers(exercise(tmp_path, "echo 'cannot read the exit status. (PHB-ESTATUS)' >&2\n"), empty_policy(),
                          SHAPE_PLAIN, environment)


def test_a_candidate_is_created_afresh_and_never_through_what_is_already_there(tmp_path):
    target = tmp_path / "run" / "candidate.cfg"
    runner.write_candidate("[read]\n/usr\n", target, tmp_path / "log")
    assert target.read_text() == "[read]\n/usr\n"
    with pytest.raises(runner.PrunerDefect, match="afresh"):
        runner.write_candidate("[read]\n/\n", target, tmp_path / "log")
    assert target.read_text() == "[read]\n/usr\n"


def test_runs_leave_no_candidate_behind_so_a_later_pruner_can_reuse_the_names(tmp_path, environment):
    runner.run_layers(exercise(tmp_path), empty_policy(), SHAPE_PLAIN, environment)
    assert list(pathlib.Path(environment.candidate_dir).iterdir()) == []


@pytest.mark.skipif(not pathlib.Path("/proc/self/task").is_dir(), reason="needs procfs")
def test_a_process_a_run_leaves_behind_is_killed_and_reaped(tmp_path, environment):
    assert runner.sampler.become_subreaper()
    marker = tmp_path / "leftover.pid"
    runner.run_direct(exercise(tmp_path, f"sleep 300 &\necho $! > {marker}\n"), environment)
    pid = int(marker.read_text())
    assert not pathlib.Path(f"/proc/{pid}").exists()
