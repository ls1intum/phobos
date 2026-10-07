"""Checks the KVM observer's logic with the kernel and the runs replaced: the capture, the self-test,
the two checks of a policy on a newer kernel, and what main.py writes and ends with."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import cfgfile, generalise, kvm, main, runner, search, stages, verdict

PASSED = verdict.Verdict(exit_class="success", tests=(("T.a", "passed"),), tests_ran=True, no_source=False,
                         infra_failure=False)
ORIGIN = {"pruner": "phobos layer pruner", "kernel": "7.2.9", "architecture": "x86_64", "landlock_abi": 10, "uid": 0,
          "strace": "strace -- version 6.8", "date": "2026-10-07T00:00:00Z"}
READ_RECORD = 'audit: type=1423 audit(1.0:1): domain=a blockers=fs.read_file path="/etc/hostname"'
UDP_RECORD = "audit: type=1423 audit(1.0:2): domain=a blockers=net.bind_udp lport=5000"
POLICY = cfgfile.Policy(fs={"/a": frozenset({"read"}), "/b": frozenset({"read"}), "/c": frozenset({"read"})},
                        connect=(), bind=("allow 0",), limits={"cpu": 30})


class FakeCapture:
    """A capture that hands out the lines it was given, once."""

    def __init__(self, *batches: list[str]) -> None:
        """Keeps the batches to hand out in turn."""
        self.batches = list(batches)

    def drain(self) -> list[str]:
        """The next batch, or nothing."""
        return self.batches.pop(0) if self.batches else []

    def close(self) -> None:
        """Nothing to close."""


def test_a_capture_reads_only_what_was_written_after_it_was_opened(tmp_path):
    ring = tmp_path / "ring"
    ring.write_text("old line\n")
    capture = kvm.Capture(str(ring))
    assert capture.drain() == []
    with open(ring, "a") as handle:
        handle.write("new line\n")
    assert capture.drain() == ["new line\n"]
    assert capture.drain() == []
    capture.close()


def test_the_narrowed_policy_keeps_every_second_entry_in_path_order():
    assert sorted(kvm.narrowed(POLICY).fs) == ["/a", "/c"]
    assert kvm.narrowed(cfgfile.Policy(fs={}, connect=(), bind=(), limits={})).fs == {}


def selftest_with(monkeypatch, tmp_path, lines: list[str], version: int = 10):
    """Runs the self-test with a probe stand-in that makes the kernel write `lines`."""
    monkeypatch.setattr(kvm.subprocess, "run", lambda *arguments, **keywords: subprocess.CompletedProcess([], 1, "", ""))
    return kvm.selftest(runner.Environment(), FakeCapture([], lines), version, tmp_path)


def test_the_self_test_passes_with_exactly_one_record_naming_the_refused_file(monkeypatch, tmp_path):
    proof = selftest_with(monkeypatch, tmp_path, [READ_RECORD])
    assert proof["landlock_abi"] == 10 and "/etc/hostname" in proof["selftest_record"]
    assert "[execute]" in (tmp_path / "selftest.cfg").read_text()


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
    monkeypatch.setattr(stages, "joint_runs", lambda pruning, policy: True)
    final, rows = kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture())
    assert final == POLICY and rows == []


def failing_then_passing(monkeypatch, decision: object, records: list[str]) -> list[cfgfile.Policy]:
    """Makes the first joint verification fail, its diagnosis ask for `decision` and the kernel write `records`."""
    runs: list[cfgfile.Policy] = []

    def joint(pruning, policy):
        runs.append(policy)
        return len(runs) > 1
    monkeypatch.setattr(stages, "joint_runs", joint)
    monkeypatch.setattr(stages.Pruning, "run", lambda self, policy, shape, stage: object())
    monkeypatch.setattr(stages, "network_decision", lambda pruning, result: decision)
    return runs


def test_a_udp_bind_the_kernel_refused_becomes_exactly_one_row_and_the_run_then_passes(monkeypatch, tmp_path):
    decision = type("Decision", (), {"bind": ("allow 5000 udp",), "connect": ()})()
    runs = failing_then_passing(monkeypatch, decision, [UDP_RECORD])
    final, rows = kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], [UDP_RECORD]))
    assert [row["rule"] for row in rows] == ["allow 5000 udp"]
    assert final.bind == ("allow 0", "allow 5000 udp")
    assert len(runs) == 2


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
    with pytest.raises(search.PruneAbort, match="more than a UDP bind port"):
        kvm.abi10_phase(fake_pruning(monkeypatch, tmp_path), POLICY, FakeCapture([], lines))


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
    monkeypatch.setattr(stages, "baseline", lambda pruning: PASSED)
    monkeypatch.setattr(kvm, "cross_check_run", lambda *arguments: cross)
    monkeypatch.setattr(kvm, "abi10_phase", lambda *arguments: (POLICY, rows))
    return kvm.verify_exercise(exercise, "java", runner.Environment(), output, None, ORIGIN, FakeCapture(),
                               main.abort_record)


CLEAN = {"strace_denials": 3, "audit_records": 3, "unparsed": [], "mismatches": [], "audit_only": []}


def test_a_clean_cross_check_and_no_row_writes_a_record_naming_the_cfg_it_verified_and_no_sidecar(monkeypatch, tmp_path):
    output = artefacts(tmp_path)
    entry, sidecar, reason = verify(monkeypatch, tmp_path, output, CLEAN, [])
    assert reason is None and sidecar is None and entry["verified"] is True
    assert entry["verified_cfg_sha256"] == hashlib.sha256((output / "java_fixture.cfg").read_bytes()).hexdigest()
    assert entry["abi10_cfg_sha256"] is None


def test_a_row_gives_a_sidecar_whose_hash_the_record_carries(monkeypatch, tmp_path):
    entry, sidecar, reason = verify(monkeypatch, tmp_path, artefacts(tmp_path), CLEAN,
                                    [{"rule": "allow 5000 udp", "audit": [UDP_RECORD]}])
    assert reason is None
    assert entry["abi10_cfg_sha256"] == hashlib.sha256(sidecar.encode()).hexdigest()
    assert cfgfile.read_policy(sidecar).bind == ("allow 5000 udp",)
    assert "KVM run on kernel 7.2.9" in sidecar


def test_a_mismatch_fails_the_exercise_and_writes_no_sidecar_even_with_a_row(monkeypatch, tmp_path):
    cross = {**CLEAN, "mismatches": [{"operation": "openat", "objects": ["/x"], "sections": ["read"],
                                      "audit_for_object": []}]}
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
    monkeypatch.setattr(kvm, "Capture", lambda: capture)
    monkeypatch.setattr(kvm, "selftest", lambda *arguments: {"selftest_record": "x"})
    monkeypatch.setattr(kvm, "verify_exercise", lambda *arguments: results.pop(0))
    root = tmp_path / "exercises" / "java" / "fixture"
    root.mkdir(parents=True)
    (root / "build_script.sh").write_text("exit 0\n")
    (root / "build_script.sh").chmod(0o755)
    output = tmp_path / "out"
    output.mkdir()
    (output / "java_fixture.abi10.cfg").write_text("stale")
    status = main.main(["--kernel-observer", "audit", "--testing-root", str(tmp_path / "exercises"), "--output-dir",
                        str(output), "java"])
    return status, output


def test_the_record_and_the_sidecar_are_written_and_a_stale_sidecar_is_removed(monkeypatch, tmp_path):
    entry = {"schema_version": 1, "verified": True}
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), [(entry, None, None)])
    assert status == 0
    assert json.loads((output / "java_fixture.abi10.json").read_text()) == entry
    assert not (output / "java_fixture.abi10.cfg").exists()


def test_a_sidecar_is_written_where_the_exercise_added_a_row(monkeypatch, tmp_path):
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), [({"verified": True}, "[bind]\nallow 5000 udp\n", None)])
    assert status == 0
    assert (output / "java_fixture.abi10.cfg").read_text() == "[bind]\nallow 5000 udp\n"


def test_a_failed_exercise_ends_the_command_with_status_1_and_still_writes_its_record(monkeypatch, tmp_path):
    status, output = kernel_run(monkeypatch, tmp_path, FakeCapture(), [({"verified": False}, None, "a mismatch")])
    assert status == main.EXIT_ABORTED
    assert (output / "java_fixture.abi10.json").exists()


def test_a_guest_that_cannot_observe_ends_the_command_with_status_3_and_writes_nothing(monkeypatch, tmp_path):
    def refuse(*arguments):
        raise kvm.Indeterminate("no records")
    monkeypatch.setattr(kvm, "selftest", refuse)
    monkeypatch.setenv(stages.PRUNE_CONTAINER_VARIABLE, "1")
    monkeypatch.setattr(stages, "pristine_index", lambda environment: generalise.Snapshot(
        existing=frozenset(), directories=frozenset(), scanned=()))
    monkeypatch.setattr(main, "provenance", lambda environment: ORIGIN)
    monkeypatch.setattr(kvm, "Capture", lambda: FakeCapture())
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

