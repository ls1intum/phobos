"""A run's outcome, read from its exit status, its log and the JUnit reports its tests wrote.

An exit status is not a result here (AGENTS.md): Gradle reports NO-SOURCE and Maven skips its tests
with status zero, so two runs agree only when the same tests ran with the same outcomes. The patterns
are the ones the retired Bubblewrap pruner used, Maven's two lines measured in A.8 of the
prune-on-the-layers plan and pytest's summary for a run that collected nothing, each named once here.
"""

from __future__ import annotations

import dataclasses
import pathlib
import re

# The reports are XML the exercise's own build wrote inside the disposable prune container, from
# the reference's own tests, and defusedxml is not in the image; an entity expansion there could
# only exhaust that container, so the standard parser is accepted for this input.
from xml.etree import ElementTree  # nosec B405

# The status phobos.sh ends with when the timeout layer ended the run (PHB_ETIMEOUT).
TIMEOUT_STATUS = 14
# Above this, a status is 128 plus the number of the signal that ended the command.
SIGNAL_STATUS_BASE = 128
# Where Gradle and Maven write their JUnit reports, relative to the exercise.
DEFAULT_REPORT_GLOBS = ("build/test-results/**/*.xml", "target/surefire-reports/*.xml")
# Lines that say no test source was compiled or no test ran although the status was zero: Gradle's
# NO-SOURCE on a Java or Kotlin compile task or the test task, of the root project or a subproject,
# Maven's "No tests to run." or "No tests to run!" and its "Tests are skipped.", and pytest's summary
# "no tests ran in <seconds>s", which it prints with status 5. A pytest run whose tests were all
# deselected says "deselected" instead and is not matched: its report names no test, so the baseline
# aborts on it as a run that ran no tests all the same. A NO-SOURCE on another task, such as
# processResources, is ordinary.
NO_SOURCE_PATTERNS = (
    r"> Task (?::[\w.-]+)*:(?:compileJava|compileTestJava|compileKotlin|compileTestKotlin|test) NO-SOURCE",
    r"No tests to run",
    r"Tests are skipped\.",
    r"no tests ran in [0-9.]+s",
)
# Maven's line for a pinned artefact the offline local repository lacks. Only the unsandboxed
# baseline treats it as an abort; under the layers a refused file there can surface as the same line.
MAVEN_OFFLINE_MISSING_PATTERN = "in offline mode and the artifact"
# The lines that mean the build's own machinery failed rather than its tests, at the start of a line.
INFRA_FAILURE_PATTERNS = (
    r"^Could not import runpy module",
    r"^Traceback \(most recent call last\):",
    r"^Fatal [A-Za-z].*error:",
    r"^ModuleNotFoundError: No module named ",
)
# The outcome a JUnit test case can have, and the one given to a report that cannot be read.
PASSED = "passed"
FAILED = "failed"
SKIPPED = "skipped"
UNREADABLE = "unreadable"


# The statuses phobos.sh ends with when it stopped a run itself (phobos-constants.sh): usage,
# PHB-EPOLICY, PHB-ERUNTIME, PHB-ESTATUS and the enforcer's refusal. A command may end with them too,
# so they mean a stop only beside Phobos's own marker printed before the command started (A.6.4).
PHOBOS_STOP_STATUSES = frozenset({2, 11, 15, 16, 125})
# The lines that mark such a stop on stderr: the usage text and the error codes.
PHOBOS_STOP_MARKERS = ("Usage:", "USAGE", "(PHB-EPOLICY)", "(PHB-ERUNTIME)", "(PHB-ESTATUS)")
# The prefixes of the enforcers' own lines. A refusal under one of them is a stop; their warnings,
# printed on every run (such as a Landlock version that cannot close UDP bind), are not.
ENFORCER_PREFIXES = ("[phobos-landlock-filesystem-and-networksystem]", "[phobos-seccomp-networksystem]",
                     "[phobos-seccomp-timeoutsystem]", "[phobos-seccomp-filesystem]")


@dataclasses.dataclass(frozen=True)
class Verdict:
    """What a run produced.

    `exit_class` is one of success, tests-failed, failure, timeout and signalled. `tests` holds every
    test case as (classname.name, outcome), sorted. `tests_ran` says whether a readable report named a test,
    `no_source` whether the log says no test source or no test ran, `infra_failure` whether it shows
    the build's own machinery failing; the last is recorded and decides nothing outside the baseline.
    """

    exit_class: str
    tests: tuple[tuple[str, str], ...]
    tests_ran: bool
    no_source: bool
    infra_failure: bool


def outcome_of(case: ElementTree.Element) -> str:
    """The outcome of one testcase element: failed with a failure or error child, skipped, or passed."""
    if case.find("failure") is not None or case.find("error") is not None:
        return FAILED
    if case.find("skipped") is not None:
        return SKIPPED
    return PASSED


def read_report(path: pathlib.Path) -> list[tuple[str, str]]:
    """Every test case of one JUnit report; a report that cannot be parsed is one unreadable entry.

    A report cut short (a run ended while writing it) must not read as "no tests", which another
    cut-short run would agree with, so it counts as a test of its own with an outcome no run passes.
    """
    try:
        root = ElementTree.parse(path).getroot()  # nosec B314
    except (ElementTree.ParseError, OSError):
        return [(str(path), UNREADABLE)]
    return [(f"{case.get('classname', '')}.{case.get('name', '')}", outcome_of(case)) for case in root.iter("testcase")]


def exit_class_of(status: int, tests: tuple[tuple[str, str], ...]) -> str:
    """The class of a run's end: the timeout, a signal, failed tests, success, or another failure."""
    if status == TIMEOUT_STATUS:
        return "timeout"
    if status > SIGNAL_STATUS_BASE:
        return "signalled"
    if any(outcome in (FAILED, UNREADABLE) for _, outcome in tests):
        return "tests-failed"
    if status == 0:
        return "success"
    return "failure"


def matches_any(patterns: tuple[str, ...], log_text: str) -> bool:
    """Whether any of the regular expressions matches somewhere in the log, line by line."""
    return any(re.search(pattern, log_text, re.MULTILINE) for pattern in patterns)


def read_verdict(status: int, log_text: str, report_paths: list[pathlib.Path]) -> Verdict:
    """The verdict of one run from its status, its whole log and the report files it wrote."""
    tests = tuple(sorted(case for path in report_paths for case in read_report(path)))
    infra = matches_any(INFRA_FAILURE_PATTERNS, log_text) or MAVEN_OFFLINE_MISSING_PATTERN in log_text
    return Verdict(
        exit_class=exit_class_of(status, tests),
        tests=tests,
        tests_ran=any(outcome != UNREADABLE for _, outcome in tests),
        no_source=matches_any(NO_SOURCE_PATTERNS, log_text),
        infra_failure=infra,
    )


def phobos_stopped(status: int, stderr_before_command: str) -> str | None:
    """The line showing Phobos itself stopped a run before its command started, or None (A.6.4).

    `stderr_before_command` is what the run printed on stderr before the command started; a caller
    that cannot tell where that was passes the whole of it. The run must not have been started with
    --debug, whose lines under an enforcer's prefix would read as stops. A run counts as stopped by Phobos only
    when its status is one of PHOBOS_STOP_STATUSES and that text holds one of Phobos's markers: the
    usage text, an error code, or an enforcer's line that is not a warning. Such a run is never a
    verdict but a defect of the caller, because reading it as "the policy is too narrow" would turn a
    malformed candidate into more grants.
    """
    if status not in PHOBOS_STOP_STATUSES:
        return None
    for line in stderr_before_command.splitlines():
        if any(marker in line for marker in PHOBOS_STOP_MARKERS):
            return line
        if line.startswith(ENFORCER_PREFIXES) and " warning: " not in line:
            return line
    return None


def same_outcome(first: Verdict, second: Verdict) -> bool:
    """Whether two runs agree: the same end, and the same tests with the same outcomes.

    infra_failure is left out on purpose: under the layers it classifies nothing (A.8).
    """
    return (first.exit_class == second.exit_class and first.tests == second.tests
            and first.tests_ran == second.tests_ran and first.no_source == second.no_source)
