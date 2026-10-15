"""Checks the KVM observer's logic with the kernel and the runs replaced: the capture, the self-test,
the two checks of a policy on a newer kernel, and what main.py writes and ends with."""

from __future__ import annotations

import dataclasses
import errno
import gzip
import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from exercise_pruner.src.application import kvm, search, stages
from exercise_pruner.src.domain import verdict
from exercise_pruner.src.infrastructure import runner
from exercise_pruner.src.interface import main
from shared.src.domain import cfgfile, generalise

PASSED = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
FAILED = verdict.Verdict(exit_class="tests-failed", tests=(("T.a", "failed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
TIMED_OUT = verdict.Verdict(exit_class="timeout", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                            infra_failure=False)
ORIGIN = {"pruner": "phobos layer pruner", "kernel": "7.2.9", "architecture": "x86_64", "landlock_abi": 10, "uid": 0,
          "strace": "strace -- version 6.8", "date": "2026-10-07T00:00:00Z"}
READ_RECORD = 'audit: type=1423 audit(1.0:1): domain=a blockers=fs.read_file path="/etc/hostname"'
UDP_RECORD = "audit: type=1423 audit(1.0:2): domain=a blockers=net.bind_udp lport=5000"
POLICY = cfgfile.Policy(fs={"/a": frozenset({"read"}), "/b": frozenset({"read"}), "/c": frozenset({"read"})},
                        connect=(), bind=("allow 0",),
                        limits={"cpu": 30, "timeout": 150, "mem_mb": 2048, "nproc": 64, "nofile": 512, "fsize_mb": 16})
# Where a stand-in phase would keep an observed run's trace; a test that reaches the observed run passes its own.
KEPT = pathlib.Path("/nonexistent/java_fixture.abi10.observed.trace.gz")


def run_of(found: verdict.Verdict, status: int = 0) -> runner.RunResult:
    """A run that ended with the verdict and status given."""
    return runner.RunResult(verdict=found, status=status, trace=None, samples=None, wall_seconds=1.0,
                            log_path=pathlib.Path("/dev/null"))


class FakeCapture:
    """A capture that hands out the lines it was given, once."""

    def __init__(self, *batches: list[str]) -> None:
        """Keeps the batches to hand out in turn."""
        self.batches = list(batches)

    def drain(self) -> list[str]:
        """The next batch, or nothing."""
        return self.batches.pop(0) if self.batches else []

    def collect(self) -> list[str]:
        """What the kernel has written, which for the stand-in is the next batch."""
        return self.drain()

    def close(self) -> None:
        """Nothing to close."""


def test_a_capture_reads_only_what_was_written_after_it_was_opened(tmp_path):
    ring = tmp_path / "ring"
    ring.write_text("old line\n")
    capture = kvm.Capture(str(ring))
    assert capture.drain() == []
    with open(ring, "a") as handle:
        handle.write("new line\n")
    assert capture.drain() == ["new line"]
    assert capture.drain() == []
    capture.close()


def numbered(sequence: int, message: str) -> str:
    """A line as /dev/kmsg hands it out: priority, sequence number, time and flags, then the message."""
    return f"5,{sequence},{sequence * 1000},-;{message}\n"


def test_a_gap_in_the_numbers_of_the_ring_is_indeterminate_and_a_clean_run_of_them_is_not(tmp_path):
    ring = tmp_path / "ring"
    ring.write_text("")
    capture = kvm.Capture(str(ring))
    with open(ring, "a") as handle:
        handle.write(numbered(10, "audit: one"))
    assert len(capture.drain()) == 1
    with open(ring, "a") as handle:
        handle.write(numbered(11, "audit: two"))
    assert len(capture.drain()) == 1
    with open(ring, "a") as handle:
        handle.write(numbered(13, "audit: four"))
    with pytest.raises(kvm.Indeterminate, match="skipped from record 11 to 13"):
        capture.drain()


def test_a_line_that_says_audit_records_were_dropped_is_indeterminate(tmp_path):
    ring = tmp_path / "ring"
    ring.write_text("")
    capture = kvm.Capture(str(ring))
    with open(ring, "a") as handle:
        handle.write(numbered(1, "audit: audit_lost=3 audit_rate_limit=0 audit_backlog_limit=64"))
    with pytest.raises(kvm.Indeterminate, match="dropped audit records"):
        capture.drain()


def test_a_ring_that_overwrote_records_is_indeterminate(tmp_path, monkeypatch):
    ring = tmp_path / "ring"
    ring.write_text("")
    capture = kvm.Capture(str(ring))

    def overwritten(descriptor, size):
        raise OSError(kvm.errno.EPIPE, "records were overwritten")
    monkeypatch.setattr(kvm.os, "read", overwritten)
    with pytest.raises(kvm.Indeterminate, match="overwrote records"):
        capture.drain()


def test_collecting_waits_for_the_sentinel_and_leaves_its_record_out(tmp_path):
    ring = tmp_path / "ring"
    ring.write_text("")
    sequence = iter(range(1, 10))

    def sentinel():
        with open(ring, "a") as handle:
            handle.write(numbered(next(sequence), 'audit: type=1423 audit(1.0:9): domain=a blockers=fs.read_file '
                                                  f'path="{kvm.SENTINEL_FILE}"'))
    capture = kvm.Capture(str(ring), sentinel=sentinel)
    with open(ring, "a") as handle:
        handle.write(numbered(next(sequence), READ_RECORD))
    collected = capture.collect()
    assert len(collected) == 1 and "/etc/hostname" in collected[0]
    assert kvm.SENTINEL_FILE not in "".join(collected)


def test_a_sentinel_whose_record_never_arrives_is_indeterminate(tmp_path, monkeypatch):
    ring = tmp_path / "ring"
    ring.write_text("")
    monkeypatch.setattr(kvm, "SETTLE_SECONDS", 0.2)
    capture = kvm.Capture(str(ring), sentinel=lambda: None)
    with pytest.raises(kvm.Indeterminate, match="did not arrive"):
        capture.collect()


def test_the_narrowed_policy_keeps_every_second_entry_in_path_order():
    assert sorted(kvm.narrowed(POLICY).fs) == ["/a", "/c"]
    assert kvm.narrowed(cfgfile.Policy(fs={}, connect=(), bind=(), limits={})).fs == {}


def selftest_with(monkeypatch, tmp_path, lines: list[str], version: int = 10):
    """Runs the self-test with a probe stand-in that makes the kernel write `lines`."""
    monkeypatch.setenv(kvm.LOG_VARIABLE, "1")
    monkeypatch.setattr(kvm.subprocess, "run", lambda *arguments, **keywords: subprocess.CompletedProcess([], 1, "", ""))
    return kvm.selftest(runner.Environment(testing_dir=str(tmp_path / "testing-dir")), FakeCapture([], lines), version,
                        tmp_path)


def test_the_self_test_passes_with_exactly_one_record_naming_the_refused_file(monkeypatch, tmp_path):
    proof = selftest_with(monkeypatch, tmp_path, [READ_RECORD])
    assert (tmp_path / "testing-dir").is_dir(), "Phobos refuses a run whose working directory is not there"
    assert proof["landlock_abi"] == 10 and "/etc/hostname" in proof["selftest_record"]
    assert "[execute]" in (tmp_path / "refusal.cfg").read_text()


@pytest.mark.parametrize("lines, version, why", [
    ([READ_RECORD], 8, "below 10"),
    ([], 10, "0 audit record"),
    ([READ_RECORD, READ_RECORD], 10, "2 audit record"),
    (['audit: type=1423 audit(1.0:1): domain=a blockers=fs.write_file path="/etc/hostname"'], 10, "1 audit record"),
    (['audit: type=1423 audit(1.0:1): domain=a blockers=fs.read_file path="/etc/passwd"'], 10, "1 audit record"),
])
def test_the_self_test_is_indeterminate_rather_than_a_pass_when_the_guest_cannot_observe(monkeypatch, tmp_path, lines,
                                                                                          version, why):
    with pytest.raises(kvm.Indeterminate, match=why):
        selftest_with(monkeypatch, tmp_path, lines, version)


def test_the_refusal_makes_its_scratch_directory_again_since_the_cleaning_between_runs_removes_it(monkeypatch, tmp_path):
    monkeypatch.setattr(kvm.subprocess, "run", lambda *arguments, **keywords: subprocess.CompletedProcess([], 1, "", ""))
    scratch = tmp_path / "gone" / "scratch"
    kvm.refuse_read(runner.Environment(testing_dir=str(tmp_path / "testing-dir")), scratch, "/etc/hostname")
    assert (scratch / "refusal.cfg").is_file()


def test_the_self_test_is_indeterminate_when_the_enforcer_was_not_asked_to_have_the_kernel_log(monkeypatch, tmp_path):
    monkeypatch.delenv(kvm.LOG_VARIABLE, raising=False)
    with pytest.raises(kvm.Indeterminate, match="would log no refusal"):
        kvm.selftest(runner.Environment(testing_dir=str(tmp_path / "testing-dir")), FakeCapture([], [READ_RECORD]), 10,
                     tmp_path)


def fake_pruning(monkeypatch, tmp_path):
    """A Pruning of a fixture exercise whose runs are replaced by the test."""
    directory = tmp_path / "exercise"
    directory.mkdir()
    (directory / "build_script.sh").write_text("exit 0\n")
    (directory / "build_script.sh").chmod(0o755)
    found = stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                           environment=runner.Environment())
    found.reference = PASSED
    return found


def test_the_joint_verification_passing_on_the_new_kernel_adds_nothing(monkeypatch, tmp_path):
    seen: list[cfgfile.Policy] = []
    monkeypatch.setattr(kvm, "joint_verification", lambda pruning, policy: seen.append(policy) or True)
    final, rows = kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture(), KEPT)
    assert final == POLICY and rows == []
    assert seen == [POLICY]


@pytest.mark.parametrize("outcomes, expected", [([PASSED, PASSED, PASSED], True), ([PASSED, FAILED, PASSED], False)])
def test_the_joint_verification_holds_every_run_to_the_reference(monkeypatch, tmp_path, outcomes, expected):
    results = [run_of(found) for found in outcomes]
    monkeypatch.setattr(stages.Pruning, "run", lambda self, policy, shape, stage: results.pop(0))
    assert kvm.joint_verification(fake_pruning(monkeypatch, tmp_path), POLICY) is expected


def test_a_joint_run_that_ran_out_of_time_is_inconclusive_rather_than_a_mismatch(monkeypatch, tmp_path):
    results = [run_of(PASSED), run_of(TIMED_OUT, 14)]
    monkeypatch.setattr(stages.Pruning, "run", lambda self, policy, shape, stage: results.pop(0))
    with pytest.raises(kvm.Inconclusive) as undecided:
        kvm.joint_verification(fake_pruning(monkeypatch, tmp_path), POLICY)
    assert undecided.value.evidence["run"] == "joint verification" and undecided.value.evidence["status"] == 14


def failing_then_passing(monkeypatch, decision: object, records: list[str]) -> list[cfgfile.Policy]:
    """Makes the first joint verification fail, its diagnosis ask for `decision` and the kernel write `records`."""
    runs: list[cfgfile.Policy] = []

    def joint(pruning, policy):
        runs.append(policy)
        return len(runs) > 1

    def diagnose(self, policy, shape, stage):
        runs.append(policy)
        return run_of(FAILED, 1)
    monkeypatch.setattr(kvm, "joint_verification", joint)
    monkeypatch.setattr(stages.Pruning, "run", diagnose)
    monkeypatch.setattr(stages, "network_decision", lambda pruning, result: decision)
    return runs


def test_a_udp_bind_the_kernel_refused_becomes_exactly_one_row_and_the_run_then_passes(monkeypatch, tmp_path):
    decision = type("Decision", (), {"bind": ("allow 5000 udp",), "connect": ()})()
    runs = failing_then_passing(monkeypatch, decision, [UDP_RECORD])
    final, rows = kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], [UDP_RECORD]), KEPT)
    assert [row["rule"] for row in rows] == ["allow 5000 udp"]
    assert final.bind == ("allow 0", "allow 5000 udp")
    assert len(runs) == 3
    assert all(policy.limits == POLICY.limits for policy in runs)
    assert final.limits == POLICY.limits
    assert POLICY.limits == {"cpu": 30, "timeout": 150, "mem_mb": 2048, "nproc": 64, "nofile": 512, "fsize_mb": 16}


def test_the_end_of_a_long_log_and_of_its_trace_is_read_from_the_end_of_the_file(tmp_path):
    log = tmp_path / "run-0001-layers.log"
    log.write_text("".join(f"line {number}\n" for number in range(200000)))
    log.with_suffix(".trace").write_text("1 openat(...) = 3\n2 read(3, <unfinished ...>\n")
    evidence = kvm.run_evidence(dataclasses.replace(run_of(TIMED_OUT, 14), log_path=log), "joint verification")
    assert evidence["log_tail"] == [f"line {number}" for number in range(200000 - kvm.LOG_TAIL_LINES, 200000)]
    assert evidence["trace_tail"] == ["1 openat(...) = 3", "2 read(3, <unfinished ...>"]
    assert kvm.tail_lines(tmp_path / "missing.log", 5) == []


def test_a_joint_run_that_ran_out_of_time_is_followed_by_one_observed_run_whose_trace_the_record_keeps(monkeypatch,
                                                                                                    tmp_path):
    log = tmp_path / "run-0002-layers.log"
    log.write_text("Fetching swift-ast\n")
    whole = "".join(f"7 link(\"/opt/swift-deps/pack-{number}\", ...) = -1 EXDEV\n" for number in range(1000))
    log.with_suffix(".trace").write_text(whole + "7 wait4(-1, <unfinished ...>\n")
    shapes: list[runner.RunShape] = []

    def time_out(pruning, policy):
        raise kvm.Inconclusive("the joint verification on the guest kernel ran out of time",
                               kvm.run_evidence(run_of(TIMED_OUT, 14), "joint verification"))

    def observe(self, policy, shape, stage):
        shapes.append(shape)
        return dataclasses.replace(run_of(TIMED_OUT, 14), log_path=log)
    monkeypatch.setattr(kvm, "joint_verification", time_out)
    monkeypatch.setattr(stages.Pruning, "run", observe)
    kept = tmp_path / "java_fixture.abi10.observed.trace.gz"
    with pytest.raises(kvm.Inconclusive, match="joint verification") as undecided:
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], [UDP_RECORD]), kept)
    assert shapes == [stages.OBSERVED_JOINT]
    observed = undecided.value.evidence["observed"]
    assert observed["trace_tail"][-1] == "7 wait4(-1, <unfinished ...>" and len(observed["trace_tail"]) == 300
    assert observed["log_tail"] == ["Fetching swift-ast"]
    assert observed["audit"] == [UDP_RECORD] and undecided.value.evidence["run"] == "joint verification"
    assert observed["trace_file"] == kept.name and "trace_file_failed" not in observed
    assert gzip.decompress(kept.read_bytes()).decode() == whole + "7 wait4(-1, <unfinished ...>\n"


class LateBrokenCapture(FakeCapture):
    """A capture whose kernel ring can be read before the observed run and no longer after it."""

    def collect(self) -> list[str]:
        """Nothing the first time, then fails as a ring that skipped records does."""
        if self.batches:
            return self.batches.pop(0)
        raise kvm.Indeterminate("the message ring skipped from record 4 to 9")


def test_records_that_cannot_be_read_after_the_observed_run_still_leave_its_trace_kept(monkeypatch, tmp_path):
    log = tmp_path / "run-0005-layers.log"
    log.write_text("Fetching swift-ast\n")
    log.with_suffix(".trace").write_text("7 wait4(-1, <unfinished ...>\n")

    def time_out(pruning, policy):
        raise kvm.Inconclusive("the joint verification on the guest kernel ran out of time",
                               kvm.run_evidence(run_of(TIMED_OUT, 14), "joint verification"))
    monkeypatch.setattr(kvm, "joint_verification", time_out)
    monkeypatch.setattr(stages.Pruning, "run",
                        lambda self, policy, shape, stage: dataclasses.replace(run_of(TIMED_OUT, 14), log_path=log))
    kept = tmp_path / "java_fixture.abi10.observed.trace.gz"
    with pytest.raises(kvm.Inconclusive, match="joint verification") as undecided:
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, LateBrokenCapture([]), kept)
    observed = undecided.value.evidence["observed"]
    assert observed["audit_failed"].startswith("Indeterminate") and "audit" not in observed
    assert observed["trace_file"] == kept.name and gzip.decompress(kept.read_bytes()) == b"7 wait4(-1, <unfinished ...>\n"


@pytest.mark.parametrize("failure", ["missing", "disk full", "no reserve"])
def test_a_trace_that_cannot_be_kept_is_named_in_the_record_and_leaves_no_file(monkeypatch, tmp_path, failure):
    trace = tmp_path / "run-0004-layers.trace"
    if failure != "missing":
        trace.write_text("7 wait4(-1, <unfinished ...>\n")
    if failure == "no reserve":
        monkeypatch.setattr(kvm.os, "statvfs", lambda path: os.statvfs_result((4096, 4096, 0, 0, 1, 0, 0, 0, 0, 255)))
    if failure == "disk full":

        def full(source, target):
            target.write(b"7 wait4")
            target.flush()
            raise OSError(errno.ENOSPC, "No space left on device")
        monkeypatch.setattr(kvm.shutil, "copyfileobj", full)
    kept = tmp_path / "java_fixture.abi10.observed.trace.gz"
    found = kvm.keep_trace(trace, kept)
    assert found["trace_file_failed"].startswith("FileNotFoundError" if failure == "missing" else "OSError")
    assert "trace_file" not in found and not kept.exists()


class BrokenCapture(FakeCapture):
    """A capture whose kernel ring can no longer be read."""

    def collect(self) -> list[str]:
        """Fails as a ring that skipped records does."""
        raise kvm.Indeterminate("the message ring skipped from record 4 to 9")


@pytest.mark.parametrize("failure", ["run", "capture"])
def test_an_observed_run_that_fails_keeps_the_timeout_it_was_to_explain(monkeypatch, tmp_path, failure):
    def time_out(pruning, policy):
        raise kvm.Inconclusive("the joint verification on the guest kernel ran out of time",
                               kvm.run_evidence(run_of(TIMED_OUT, 14), "joint verification"))

    def broken(self, policy, shape, stage):
        raise runner.PrunerDefect(-1, pathlib.Path("/dev/null"), "render refused the candidate")
    monkeypatch.setattr(kvm, "joint_verification", time_out)
    monkeypatch.setattr(stages.Pruning, "run", broken)
    capture = FakeCapture([]) if failure == "run" else BrokenCapture()
    with pytest.raises(kvm.Inconclusive, match="joint verification") as undecided:
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, capture, KEPT)
    assert undecided.value.evidence["run"] == "joint verification" and "observed" not in undecided.value.evidence
    assert undecided.value.evidence["observed_failed"].startswith("PrunerDefect" if failure == "run" else "Indeterminate")


def test_a_cross_check_run_that_ran_out_of_time_keeps_its_log_and_trace_tails_in_the_record(monkeypatch, tmp_path):
    log = tmp_path / "run-0003-layers.log"
    log.write_text("Computing version for swift-ast\n")
    log.with_suffix(".trace").write_text("9 futex(0x7f, FUTEX_WAIT, 0, NULL <unfinished ...>\n")
    monkeypatch.setattr(stages.Pruning, "run",
                        lambda self, policy, shape, stage: dataclasses.replace(run_of(TIMED_OUT, 14), log_path=log))
    cross = kvm.cross_check_run(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([]))
    assert cross["log_tail"] == ["Computing version for swift-ast"]
    assert cross["trace_tail"] == ["9 futex(0x7f, FUTEX_WAIT, 0, NULL <unfinished ...>"]
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), {**cross, "strace_denials": 3}, [])
    assert "cross-check run" in reason
    assert entry["inconclusive"] is True and sidecar is None
    assert entry["evidence"]["trace_tail"] == cross["trace_tail"] and entry["evidence"]["log_tail"] == cross["log_tail"]


def test_a_diagnosis_run_that_ran_out_of_time_is_inconclusive_rather_than_a_difference(monkeypatch, tmp_path):
    monkeypatch.setattr(kvm, "joint_verification", lambda pruning, policy: False)
    monkeypatch.setattr(stages.Pruning, "run", lambda self, policy, shape, stage: run_of(TIMED_OUT, 14))
    with pytest.raises(kvm.Inconclusive, match="ran out of time") as undecided:
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([]), KEPT)
    assert undecided.value.evidence["run"] == "diagnosis run"
    assert undecided.value.evidence["verdict"]["exit_class"] == "timeout"


@pytest.mark.parametrize("outcomes", [
    [TIMED_OUT],
    [PASSED, TIMED_OUT],
    [dataclasses.replace(TIMED_OUT, tests=(), tests_ran=False)],
])
def test_a_reference_run_that_ran_out_of_time_makes_the_guest_baseline_inconclusive(monkeypatch, tmp_path, outcomes):
    results = [run_of(found) for found in outcomes]
    monkeypatch.setattr(runner, "run_reference", lambda exercise, environment: results.pop(0))
    with pytest.raises(kvm.Inconclusive, match="reference run"):
        stages.baseline(fake_pruning(monkeypatch, tmp_path), inspect=kvm.refuse_timed_out_reference)


def test_a_refused_udp_connect_is_no_difference_since_the_guard_refuses_it_on_every_kernel(monkeypatch, tmp_path):
    decision = type("Decision", (), {"bind": ("allow 5000 udp",), "connect": ("allow 127.0.0.1:53 udp",)})()
    failing_then_passing(monkeypatch, decision, [UDP_RECORD])
    final, rows = kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], [UDP_RECORD]), KEPT)
    assert [row["rule"] for row in rows] == ["allow 5000 udp"]
    assert final.connect == POLICY.connect


@pytest.mark.parametrize("bind, connect, lines", [
    (("allow 5000",), (), [UDP_RECORD]),
    (("allow 6000 udp",), (), [UDP_RECORD]),
    (("allow 5000 udp",), ("allow 127.0.0.1:*",), [UDP_RECORD]),
    ((), (), [UDP_RECORD]),
    (("allow 5000 udp",), (), []),
])
def test_any_other_difference_between_the_kernels_aborts_instead_of_adding_a_row(monkeypatch, tmp_path, bind, connect,
                                                                                lines):
    decision = type("Decision", (), {"bind": bind, "connect": connect})()
    failing_then_passing(monkeypatch, decision, lines)
    with pytest.raises(search.PruneAbort, match="more than a UDP bind port") as aborted:
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], lines), KEPT)
    assert aborted.value.evidence["status"] == 1
    assert aborted.value.evidence["verdict"]["exit_class"] == "tests-failed"
    assert aborted.value.evidence["verdict"]["tests"] == (("T.a", "failed"),)


def artefacts(tmp_path: pathlib.Path, text: str = "[read]\n/a\n/b\n") -> pathlib.Path:
    """The default prune's .cfg and record for one exercise, in a directory."""
    output = tmp_path / "out"
    output.mkdir()
    (output / "java_fixture.cfg").write_text(text)
    (output / "java_fixture.json").write_text(json.dumps({"cfg_sha256": hashlib.sha256(text.encode()).hexdigest()}))
    return output


def verify(monkeypatch, tmp_path, output, cross: dict, rows: list[dict]):
    """Runs verify_exercise with the runs replaced by a cross-check result and the rows the ABI 10 phase adds."""
    exercise = tmp_path / "fixture"
    exercise.mkdir()
    (exercise / "build_script.sh").write_text("exit 0\n")
    (exercise / "build_script.sh").chmod(0o755)
    def phase(*arguments):
        if isinstance(rows, Exception):
            raise rows
        return POLICY, rows
    monkeypatch.setattr(stages, "baseline", lambda pruning, inspect: PASSED)
    monkeypatch.setattr(kvm, "cross_check_run", lambda *arguments: cross)
    monkeypatch.setattr(kvm, "abi10_phase", phase)
    return kvm.verify_exercise(exercise, "java", runner.Environment(), output, None, ORIGIN, FakeCapture(),
                               main.abort_record)


CLEAN = {"strace_denials": 3, "audit_records": 3, "unparsed": [], "mismatches": [], "audit_only": [], "status": 0,
         "verdict": dataclasses.asdict(PASSED)}
MISMATCHES = [{"operation": "openat", "objects": ["/x"], "sections": ["read"], "audit_for_object": []}]
LATE_TIMEOUT = kvm.Inconclusive("the diagnosis run on the guest kernel ran out of time", {"run": "diagnosis run"})


def test_a_clean_cross_check_and_no_row_writes_a_record_naming_the_cfg_it_verified_and_no_sidecar(monkeypatch, tmp_path):
    output = artefacts(tmp_path)
    entry, sidecar, reason = verify(monkeypatch, tmp_path, output, CLEAN, [])
    assert reason is None and sidecar is None and entry["verified"] is True
    assert entry["verified_cfg_sha256"] == hashlib.sha256((output / "java_fixture.cfg").read_bytes()).hexdigest()
    assert entry["abi10_cfg_sha256"] is None
    assert entry["inconclusive"] is False


def test_a_clean_cross_check_that_ran_out_of_time_is_inconclusive_and_keeps_its_comparison(monkeypatch, tmp_path):
    cross = {**CLEAN, **kvm.run_evidence(run_of(TIMED_OUT, 14), "cross-check run")}
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), cross, [])
    assert "ran out of time" in reason and sidecar is None
    assert entry["inconclusive"] is True and entry["verified"] is False
    assert entry["cross_check"]["strace_denials"] == 3 and entry["evidence"]["run"] == "cross-check run"


def test_a_mismatch_stays_the_reason_when_its_run_or_a_later_one_ran_out_of_time(monkeypatch, tmp_path):
    cross = {**CLEAN, "mismatches": MISMATCHES, **kvm.run_evidence(run_of(TIMED_OUT, 14), "cross-check run")}
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), cross, LATE_TIMEOUT)
    assert "do not agree" in reason and sidecar is None
    assert entry["inconclusive"] is False and entry["verified"] is False
    assert entry["abi10_inconclusive"]["aborted"] == str(LATE_TIMEOUT)


def test_a_timeout_after_a_clean_cross_check_makes_the_exercise_inconclusive_without_a_sidecar(monkeypatch, tmp_path):
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), CLEAN, LATE_TIMEOUT)
    assert reason == str(LATE_TIMEOUT) and sidecar is None
    assert entry["inconclusive"] is True and entry["verified"] is False and entry["rows"] == []


SIX_LIMITS = "[read]\n/a\n/b\n[bind]\nallow 0\n[limits]\ntimeout=150\ncpu=30\nmem_mb=2048\nnproc=64\nnofile=512\nfsize_mb=16\n"


def through_the_udp_phase(monkeypatch, tmp_path, diagnosis: verdict.Verdict):
    """verify_exercise over a cfg with all six limits, through the real ABI 10 phase, whose diagnosis sees a UDP refusal.

    The first joint verification fails and the second passes; the policies the guest ran are kept in the result.
    """
    output = artefacts(tmp_path, SIX_LIMITS)
    exercise = tmp_path / "fixture"
    exercise.mkdir()
    (exercise / "build_script.sh").write_text("exit 0\n")
    (exercise / "build_script.sh").chmod(0o755)
    ran: list[cfgfile.Policy] = []

    def joint(pruning, policy):
        ran.append(policy)
        return len(ran) > 2

    def diagnose(self, policy, shape, stage):
        ran.append(policy)
        return run_of(diagnosis, 14 if diagnosis.exit_class == "timeout" else 1)
    decision = type("Decision", (), {"bind": ("allow 5000 udp",), "connect": ()})()
    monkeypatch.setattr(stages, "baseline", lambda pruning, inspect: PASSED)
    monkeypatch.setattr(kvm, "cross_check_run", lambda *arguments: CLEAN)
    monkeypatch.setattr(kvm, "joint_verification", joint)
    monkeypatch.setattr(stages.Pruning, "run", diagnose)
    monkeypatch.setattr(stages, "network_decision", lambda pruning, result: decision)
    result = kvm.verify_exercise(exercise, "java", runner.Environment(), output, None, ORIGIN,
                                 FakeCapture([], [UDP_RECORD]), main.abort_record)
    return result, output, ran


def test_the_guest_runs_the_cfg_with_its_limits_and_leaves_the_cfg_and_the_sidecar_as_they_are(monkeypatch, tmp_path):
    (entry, sidecar, reason), output, ran = through_the_udp_phase(monkeypatch, tmp_path, FAILED)
    assert reason is None and entry["verified"] is True
    assert (output / "java_fixture.cfg").read_text() == SIX_LIMITS
    assert entry["verified_cfg_sha256"] == hashlib.sha256(SIX_LIMITS.encode()).hexdigest()
    assert [policy.limits for policy in ran] == [cfgfile.read_policy(SIX_LIMITS).limits] * 3
    assert cfgfile.read_policy(sidecar).bind == ("allow 5000 udp",) and cfgfile.read_policy(sidecar).limits == {}


def test_a_diagnosis_that_ran_out_of_time_beside_a_udp_refusal_is_inconclusive_without_a_sidecar(monkeypatch, tmp_path):
    (entry, sidecar, reason), output, _ = through_the_udp_phase(monkeypatch, tmp_path, TIMED_OUT)
    assert "ran out of time" in reason and sidecar is None
    assert entry["inconclusive"] is True and entry["evidence"]["run"] == "diagnosis run" and entry["rows"] == []
    assert (output / "java_fixture.cfg").read_text() == SIX_LIMITS


def test_a_cross_check_that_compared_nothing_although_grants_were_removed_fails_the_exercise(monkeypatch, tmp_path):
    nothing = {**CLEAN, "strace_denials": 0, "audit_records": 0}
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), nothing, [])
    assert "nothing was compared" in reason and sidecar is None and entry["verified"] is False


def test_a_row_gives_a_sidecar_whose_hash_the_record_carries(monkeypatch, tmp_path):
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), CLEAN,
                                    [{"rule": "allow 5000 udp", "audit": [UDP_RECORD]}])
    assert reason is None
    assert entry["abi10_cfg_sha256"] == hashlib.sha256(sidecar.encode()).hexdigest()
    assert cfgfile.read_policy(sidecar).bind == ("allow 5000 udp",)
    assert "KVM run on kernel 7.2.9" in sidecar


def test_a_mismatch_fails_the_exercise_and_writes_no_sidecar_even_with_a_row(monkeypatch, tmp_path):
    cross = {**CLEAN, "mismatches": MISMATCHES}
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), cross,
                                    [{"rule": "allow 5000 udp", "audit": []}])
    assert "do not agree" in reason and sidecar is None and entry["verified"] is False
    assert entry["mismatches"] == cross["mismatches"]


def test_a_cfg_its_record_does_not_vouch_for_is_never_verified(monkeypatch, tmp_path):
    output = artefacts(tmp_path)
    (output / "java_fixture.cfg").write_text("[read]\n/\n")
    entry, sidecar, reason = verify(monkeypatch, tmp_path, output, CLEAN, [])
    assert "SHA-256 differs" in reason and sidecar is None and entry["verified_cfg_sha256"] is None


def kernel_run(monkeypatch, tmp_path, capture: object, results: list):
    """Runs main.py --kernel-observer audit with the guest replaced; its status and the output directory."""
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)
    monkeypatch.setattr(kvm, "Capture", lambda sentinel=None: capture)
    monkeypatch.setattr(kvm, "selftest", lambda *arguments: {"selftest_record": "x"})
    monkeypatch.setattr(kvm, "verify_exercise", lambda *arguments: results.pop(0))
    root = tmp_path / "exercises" / "java" / "fixture"
    root.mkdir(parents=True)
    (root / "build_script.sh").write_text("exit 0\n")
    (root / "build_script.sh").chmod(0o755)
    output = tmp_path / "out"
    output.mkdir()
    (output / "java_fixture.abi10.cfg").write_text("stale")
    (output / "java_fixture.abi10.observed.trace.gz").write_text("stale")
    status = main.main(["--kernel-observer", "audit", "--testing-root", str(tmp_path / "exercises"), "--output-dir",
                        str(output), "java"])
    return status, output


def test_the_record_and_the_sidecar_are_written_and_a_stale_sidecar_is_removed(monkeypatch, tmp_path):
    entry = {"schema_version": 1, "verified": True, "inconclusive": False}
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), [(entry, None, None)])
    assert status == 0
    assert json.loads((output / "java_fixture.abi10.json").read_text()) == entry
    assert not (output / "java_fixture.abi10.cfg").exists()
    assert not (output / "java_fixture.abi10.observed.trace.gz").exists()


class Keeping(list):
    """Results for kernel_run whose exercise keeps a fresh trace while it is verified, as an observed run does."""

    def __init__(self, output: pathlib.Path, *results: tuple) -> None:
        """Keeps the results and the directory the trace is written to."""
        super().__init__(results)
        self.output = output

    def pop(self, index: int = -1) -> tuple:
        """The next result, after writing the trace its verification kept."""
        (self.output / "java_fixture.abi10.observed.trace.gz").write_bytes(gzip.compress(b"fresh\n"))
        return super().pop(index)


def test_a_trace_the_exercise_keeps_now_survives_the_removal_of_the_stale_one(monkeypatch, tmp_path):
    undecided = ({"verified": False, "inconclusive": True}, None, "the joint verification ran out of time")
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), Keeping(tmp_path / "out", undecided))
    assert status == kvm.EXIT_INDETERMINATE
    assert gzip.decompress((output / "java_fixture.abi10.observed.trace.gz").read_bytes()) == b"fresh\n"


def test_a_sidecar_is_written_where_the_exercise_added_a_row(monkeypatch, tmp_path):
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(),
                                [({"verified": True, "inconclusive": False}, "[bind]\nallow 5000 udp\n", None)])
    assert status == 0
    assert (output / "java_fixture.abi10.cfg").read_text() == "[bind]\nallow 5000 udp\n"


def test_a_failed_exercise_ends_the_command_with_status_1_and_still_writes_its_record(monkeypatch, tmp_path):
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(),
                                [({"verified": False, "inconclusive": False}, None, "a mismatch")])
    assert status == main.EXIT_ABORTED
    assert (output / "java_fixture.abi10.json").exists()


def two_exercises(tmp_path):
    """A second exercise beside the fixture kernel_run makes, so that the observer checks two."""
    second = tmp_path / "exercises" / "java" / "second"
    second.mkdir(parents=True)
    (second / "build_script.sh").write_text("exit 0\n")
    (second / "build_script.sh").chmod(0o755)


@pytest.mark.parametrize("second, expected", [
    (({"verified": True, "inconclusive": False}, None, None), kvm.EXIT_INDETERMINATE),
    (({"verified": False, "inconclusive": False}, None, "a mismatch"), main.EXIT_ABORTED),
])
def test_an_inconclusive_exercise_ends_the_command_with_status_3_unless_another_one_failed(monkeypatch, tmp_path,
                                                                                         second, expected):
    two_exercises(tmp_path)
    undecided = ({"verified": False, "inconclusive": True}, None, "the diagnosis run ran out of time")
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), [undecided, second])
    assert status == expected
    assert (output / "java_fixture.abi10.json").exists() and (output / "java_second.abi10.json").exists()
    assert not (output / "java_fixture.abi10.cfg").exists()


def test_a_guest_that_cannot_observe_ends_the_command_with_status_3_and_writes_nothing(monkeypatch, tmp_path):
    def refuse(*arguments):
        raise kvm.Indeterminate("no records")
    monkeypatch.setattr(kvm, "selftest", refuse)
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)
    monkeypatch.setattr(kvm, "Capture", lambda sentinel=None: FakeCapture())
    root = tmp_path / "exercises" / "java" / "fixture"
    root.mkdir(parents=True)
    (root / "build_script.sh").write_text("exit 0\n")
    (root / "build_script.sh").chmod(0o755)
    status = main.main(["--kernel-observer", "audit", "--testing-root", str(tmp_path / "exercises"), "--output-dir",
                        str(tmp_path / "out"), "java"])
    assert status == kvm.EXIT_INDETERMINATE
    assert not list((tmp_path / "out").glob("*.abi10.*"))


def test_the_audit_observer_takes_neither_verify_nor_a_stage(tmp_path, capsys):
    assert main.main(["--kernel-observer", "audit", "--verify", str(tmp_path), "--output-dir", str(tmp_path), "java"]) \
        == main.EXIT_ABORTED
    assert main.main(["--kernel-observer", "audit", "--stage", "network", "--output-dir", str(tmp_path), "java"]) \
        == main.EXIT_ABORTED
    assert "takes neither --verify nor --stage" in capsys.readouterr().err



def test_a_ring_that_cannot_be_opened_ends_the_command_with_status_3(monkeypatch, tmp_path):
    def cannot_open(sentinel=None):
        raise FileNotFoundError("/dev/kmsg")
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)
    monkeypatch.setattr(kvm, "Capture", cannot_open)
    root = tmp_path / "exercises" / "java" / "fixture"
    root.mkdir(parents=True)
    (root / "build_script.sh").write_text("exit 0\n")
    (root / "build_script.sh").chmod(0o755)
    status = main.main(["--kernel-observer", "audit", "--testing-root", str(tmp_path / "exercises"), "--output-dir",
                        str(tmp_path / "out"), "java"])
    assert status == kvm.EXIT_INDETERMINATE
