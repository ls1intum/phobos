"""Checks how a run's status, log and JUnit reports become the verdict two runs are compared by."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import verdict


def junit(path: pathlib.Path, cases: dict[str, str]) -> pathlib.Path:
    """Writes a JUnit report with one test case per entry, `outcome` passed, failed, error or skipped."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', f'<testsuite tests="{len(cases)}">']
    for test, outcome in cases.items():
        classname, _, name = test.rpartition(".")
        child = {"failed": "<failure/>", "error": "<error/>", "skipped": "<skipped/>"}.get(outcome, "")
        lines.append(f'<testcase classname="{classname}" name="{name}">{child}</testcase>')
    lines.append("</testsuite>")
    path.write_text("\n".join(lines))
    return path


def test_two_runs_agree_only_when_the_same_tests_had_the_same_outcomes(tmp_path):
    first = verdict.read_verdict(0, "", [junit(tmp_path / "a.xml", {"T.a": "passed", "T.b": "passed"})])
    second = verdict.read_verdict(0, "", [junit(tmp_path / "b.xml", {"T.a": "passed", "T.b": "failed"})])
    third = verdict.read_verdict(0, "", [junit(tmp_path / "c.xml", {"T.b": "passed", "T.a": "passed"})])
    assert not verdict.same_outcome(first, second)
    assert verdict.same_outcome(first, third)


def test_failed_tests_are_their_own_exit_class_and_an_error_is_a_failure(tmp_path):
    result = verdict.read_verdict(1, "", [junit(tmp_path / "a.xml", {"T.a": "error", "T.b": "skipped"})])
    assert result.exit_class == "tests-failed"
    assert dict(result.tests) == {"T.a": "failed", "T.b": "skipped"}


def test_no_source_with_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "> Task :compileJava NO-SOURCE\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_a_no_source_on_another_gradle_task_is_ordinary():
    assert not verdict.read_verdict(0, "> Task :processResources NO-SOURCE\n", []).no_source


def test_an_infrastructure_failure_is_recognised():
    result = verdict.read_verdict(0, "Traceback (most recent call last):\n", [])
    assert result.infra_failure


def test_a_run_with_no_reports_did_not_run_tests():
    assert verdict.read_verdict(0, "BUILD SUCCESSFUL\n", []).tests_ran is False


def test_status_fourteen_is_a_timeout_and_a_signal_is_signalled():
    assert verdict.read_verdict(14, "", []).exit_class == "timeout"
    assert verdict.read_verdict(137, "", []).exit_class == "signalled"
    assert verdict.read_verdict(2, "", []).exit_class == "failure"


def test_maven_without_tests_and_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "[INFO] No tests to run.\n[INFO] BUILD SUCCESS\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_maven_with_skipped_tests_and_status_zero_is_not_a_success():
    result = verdict.read_verdict(0, "[INFO] Tests are skipped.\n[INFO] BUILD SUCCESS\n", [])
    assert result.no_source
    assert not result.tests_ran


def test_a_surefire_report_counts_like_any_junit_report(tmp_path):
    report = junit(tmp_path / "TEST-de.phobos.reference.AdderTest.xml",
                   {"de.phobos.reference.AdderTest.addsTwoNumbers": "passed"})
    result = verdict.read_verdict(0, "[INFO] BUILD SUCCESS\n", [report])
    assert result.tests_ran
    assert not result.no_source
    assert result.exit_class == "success"


def test_a_missing_artefact_in_offline_mode_is_an_infrastructure_failure():
    log_text = ("[ERROR] Cannot access central (https://repo.maven.apache.org/maven2) in offline mode and the "
                "artifact org.junit.jupiter:junit-jupiter-engine:jar:5.13.4 has not been downloaded from it before.\n")
    assert verdict.read_verdict(1, log_text, []).infra_failure


def test_a_report_cut_short_never_agrees_with_a_run_without_tests(tmp_path):
    broken = tmp_path / "TEST-cut.xml"
    broken.write_text('<testsuite><testcase classname="T" name="a">')
    cut = verdict.read_verdict(0, "", [broken])
    assert not cut.tests_ran
    assert cut.exit_class == "tests-failed"
    assert not verdict.same_outcome(cut, verdict.read_verdict(0, "", []))


@pytest.mark.parametrize(("status", "stderr"), [
    (11, "Policy invalid: '/x' is not an absolute path. (PHB-EPOLICY)\n"),
    (15, "Could not start the connect guard. (PHB-ERUNTIME)\n"),
    (2, "phobos.sh - run a command under the Phobos sandbox.\nUSAGE\n"),
    (125, "[phobos-landlock-filesystem-and-networksystem] cannot open /x: No such file or directory\n"),
])
def test_a_run_phobos_itself_stopped_is_named_by_its_marker(status, stderr):
    assert verdict.phobos_stopped(status, stderr) is not None


@pytest.mark.parametrize("status", [2, 11, 15, 125])
def test_the_commands_own_status_without_a_phobos_marker_is_not_a_stop(status):
    assert verdict.phobos_stopped(status, "make: *** [all] Error 2\n") is None


def test_a_marker_beside_another_status_or_an_enforcer_warning_is_not_a_stop():
    assert verdict.phobos_stopped(1, "Policy invalid. (PHB-EPOLICY)\n") is None
    warning = ("[phobos-landlock-filesystem-and-networksystem] warning: Landlock version 8 cannot close UDP bind "
               "(that needs version 10)\n")
    assert verdict.phobos_stopped(2, warning) is None


def test_the_infrastructure_flag_does_not_decide_whether_two_runs_agree(tmp_path):
    report = junit(tmp_path / "a.xml", {"T.a": "passed"})
    plain = verdict.read_verdict(0, "", [report])
    noisy = verdict.read_verdict(0, "Fatal Python error: x\n", [report])
    assert noisy.infra_failure
    assert verdict.same_outcome(plain, noisy)


def test_no_source_in_a_subproject_or_for_kotlin_is_recognised():
    assert verdict.read_verdict(0, "> Task :app:test NO-SOURCE\n", []).no_source
    assert verdict.read_verdict(0, "> Task :compileKotlin NO-SOURCE\n", []).no_source


def test_pytest_collecting_no_test_is_no_source_and_ran_no_tests():
    result = verdict.read_verdict(5, "\n============================ no tests ran in 0.01s ============================\n", [])
    assert result.no_source
    assert not result.tests_ran
