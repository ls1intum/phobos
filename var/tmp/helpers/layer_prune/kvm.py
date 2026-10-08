"""The KVM run's second observer: Landlock's audit records, read in a guest the pruner owns (A.6.9).

main.py --kernel-observer audit runs inside a guest booted from the prune image's root file system on a
Linux 7.2 kernel. It only verifies a policy the default prune already wrote, in two ways, and writes
what it found as `<key>_<exercise>.abi10.json`, with `<key>_<exercise>.abi10.cfg` only where it adds a row:

1. a cross-check run, under the policy with every second grant removed so that many refusals happen,
   observed by strace and by the kernel at once; each Landlock filesystem denial strace attributed must
   have an audit record that agrees (audit.cross_check);
2. the joint verification on this kernel (Landlock ABI 10): when it fails, a UDP bind refused on a port the
   kernel names becomes a `[bind] allow <port> udp` row, and any other difference between the two
   kernels fails the exercise instead.

The audit observer never grants anything by itself: a row needs the strace derivation of A.6.5 and the
kernel's record to name the same port.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import platform
import subprocess  # nosec B404
import time
from collections.abc import Callable

from layer_prune import audit, cfgfile, control, record, runner, search, stages

# The schema version of the .abi10.json record.
ABI10_SCHEMA = 1
# The Landlock version that handles UDP bind, and the first the guest kernel must offer.
ABI10_VERSION = 10
# The kernel's message ring, which carries the audit records when no audit daemon reads them.
KMSG = "/dev/kmsg"
# How many bytes one read of the ring may return; a record is far smaller.
KMSG_READ_BYTES = 8192
# The file the self-test refuses a read of, and what it must produce.
SELFTEST_FILE = "/etc/hostname"
# The status main.py ends with when the guest cannot make its observation, which is a failure of the
# job and never a pass.
EXIT_INDETERMINATE = 3
# The probe the prune image carries and the operation the self-test has it make.
PROBE = "/usr/local/libexec/phobos-prune-probe"
# The file the guest creates and the probe is refused a read of after every run: the kernel prints its
# records through a queue, in order, so once this one has arrived every record of the run before it has.
SENTINEL_FILE = "/etc/phobos-kvm-sentinel"
# How long to wait for the sentinel's record, and between two looks at the ring.
SETTLE_SECONDS = 60
SETTLE_INTERVAL_SECONDS = 0.05
# How long the probe may take.
PROBE_SECONDS = 120
# The variable that makes the enforcer ask the kernel to log what the command is refused. Without it
# the kernel logs only what the restricting process itself is refused, which is nothing.
LOG_VARIABLE = "PHOBOS_LANDLOCK_LOG_NEW_EXEC"
# What the kernel prints when it drops audit records instead of queueing them.
LOSS_MARKERS = ("audit_lost=", "audit_backlog=")


class Indeterminate(Exception):
    """The guest cannot observe Landlock's audit records, so no result of this run means anything."""


class Capture:
    """Reads the kernel's message ring from where it is when the capture is opened, without blocking.

    Records are numbered, so a gap, a record the ring overwrote before it was read and a line that
    says the audit queue dropped records each end the run as indeterminate: a missing record would
    otherwise read as a mismatch, or hide the row it should have produced.
    """

    def __init__(self, path: str = KMSG, sentinel: Callable[[], None] | None = None) -> None:
        """Opens the ring and moves to its end; `sentinel` makes the kernel log one record of its own."""
        self.descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.descriptor, 0, os.SEEK_END)
        self.sentinel = sentinel
        self.last_sequence: int | None = None

    def check_sequence(self, text: str) -> None:
        """Raises Indeterminate when a ring record's number does not follow the last one's."""
        header = text.split(";", 1)[0].split(",")
        if len(header) < 2 or not header[1].isdigit():
            return
        sequence = int(header[1])
        if self.last_sequence is not None and sequence != self.last_sequence + 1:
            raise Indeterminate(f"the message ring skipped from record {self.last_sequence} to {sequence}")
        self.last_sequence = sequence

    def drain(self) -> list[str]:
        """Every line of every record written since the last drain; the ring hands out one record per read."""
        lines: list[str] = []
        while True:
            try:
                data = os.read(self.descriptor, KMSG_READ_BYTES)
            except BlockingIOError:
                break
            except OSError as failure:
                if failure.errno == errno.EPIPE:
                    raise Indeterminate("the message ring overwrote records before they were read") from failure
                raise
            if not data:
                break
            text = data.decode("utf-8", errors="replace")
            if any(marker in text for marker in LOSS_MARKERS):
                raise Indeterminate(f"the kernel reports dropped audit records: {text.strip()[:200]}")
            self.check_sequence(text)
            lines.extend(text.splitlines())
        return lines

    def collect(self) -> list[str]:
        """Every record of the run so far, once the kernel has written them all; the sentinel's own left out.

        The sentinel is a refusal made now: the kernel prints in order, so when its record has arrived
        the records before it have too. Without a sentinel this is a plain drain.
        """
        if self.sentinel is None:
            return self.drain()
        self.sentinel()
        lines: list[str] = []
        deadline = time.monotonic() + SETTLE_SECONDS
        while True:
            lines += self.drain()
            if any(item.path == SENTINEL_FILE for item in audit.parse(lines)[0]):
                return [line for line in lines if SENTINEL_FILE not in line]
            if time.monotonic() > deadline:
                raise Indeterminate(f"the record of the sentinel refusal did not arrive in {SETTLE_SECONDS} s; "
                                    f"{len(lines)} ring line(s) were read, the last: {lines[-3:]}")
            time.sleep(SETTLE_INTERVAL_SECONDS)

    def close(self) -> None:
        """Closes the ring."""
        os.close(self.descriptor)


def refuse_read(environment: runner.Environment, directory: pathlib.Path, target: str) -> subprocess.CompletedProcess:
    """Has the probe, which is granted nothing on `target`, try to read it under the layers: one refusal for the kernel to log.

    Phobos enters the working directory before the command starts and refuses the run when it is not
    there, so the directory is made first; the first guest run found the probe never started without it. The
    scratch directory is made again as well, since the cleaning between runs removes what a run left in /tmp.
    """
    pathlib.Path(environment.testing_dir).mkdir(parents=True, exist_ok=True)
    directory.mkdir(parents=True, exist_ok=True)
    cfg = directory / "refusal.cfg"
    cfg.write_text(f"[read]\n{PROBE}\n/dev/null\n\n[execute]\n{PROBE}\n")
    argv = [os.path.join(environment.phobos_home, "phobos.sh"), "--config", str(cfg), "--", PROBE, "read", target]
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=PROBE_SECONDS)  # nosec B603


def sentinel_for(environment: runner.Environment, directory: pathlib.Path) -> Callable[[], None]:
    """The sentinel a Capture makes after each run: the probe refused a read of the sentinel file."""
    def make() -> None:
        """Makes the refusal."""
        refuse_read(environment, directory, SENTINEL_FILE)
    return make


def read_records(capture: Capture) -> tuple[list[audit.AuditRecord], list[str], list[str]]:
    """The audit records of the run so far, the lines of that type that did not parse, and every line."""
    lines = capture.collect()
    records, unparsed = audit.parse(lines)
    return records, unparsed, lines


def selftest(environment: runner.Environment, capture: Capture, version: int, directory: pathlib.Path) -> dict:
    """Proves the guest can observe Landlock before any prune run; raises Indeterminate when it cannot.

    The kernel must offer Landlock version 10 or later, the enforcer must have been asked to have the
    kernel log what the command is refused, and one deliberate refusal, a read of a file the probe was
    granted nothing on, must produce exactly one record that parses and names that file.
    """
    if version < ABI10_VERSION:
        raise Indeterminate(f"the kernel offers Landlock version {version}, below {ABI10_VERSION}")
    if os.environ.get(LOG_VARIABLE) != "1":
        raise Indeterminate(f"{LOG_VARIABLE} is not 1, so the kernel would log no refusal of a command")
    capture.collect()
    finished = refuse_read(environment, directory, SELFTEST_FILE)
    records, unparsed, lines = read_records(capture)
    if len(records) != 1 or records[0].path != SELFTEST_FILE or "fs.read_file" not in records[0].blockers:
        raise Indeterminate(f"one refused read of {SELFTEST_FILE} gave {len(records)} audit record(s), "
                            f"{len(unparsed)} unparsed, probe status {finished.returncode}: {lines[:3]}")
    return {"landlock_abi": version, "selftest_record": records[0].raw}


def narrowed(policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy with every second filesystem entry removed, in path order, so a run is refused many things."""
    kept = {path: sections for position, (path, sections) in enumerate(sorted(policy.fs.items())) if position % 2 == 0}
    return dataclasses.replace(policy, fs=kept, comments={path: text for path, text in policy.comments.items() if path in kept})


def cross_check_run(pruning: stages.Pruning, policy: cfgfile.Policy, capture: Capture) -> dict:
    """One observed run under the narrowed policy, compared denial by denial with the kernel's records."""
    capture.collect()
    result = pruning.run(stages.normalised(pruning, narrowed(policy)), stages.OBSERVED_FILESYSTEM, "kvm cross-check")
    records, unparsed, _ = read_records(capture)
    attributed = [denial for denial in stages.denials_of(pruning, result)
                  if denial.layer == record.LAYER_FILESYSTEM and control.landlock_caused(denial)]
    compared = audit.cross_check(attributed, audit.denials(records))
    return {"strace_denials": len(attributed), "audit_records": len(records), "unparsed": unparsed, **compared}


def abi10_phase(pruning: stages.Pruning, policy: cfgfile.Policy, capture: Capture) -> tuple[cfgfile.Policy, list[dict]]:
    """The joint verification on this kernel; the policy it ends with and the UDP bind rows it added, each with its audit record.

    A failing run is diagnosed with one observed run. Only a UDP bind the kernel names as refused, whose
    rule the strace derivation also asks for, is added; any other rule, or a failure with no refusal to
    explain it, aborts, because then the two kernels differ in something this run may not decide.
    """
    current = policy
    added: list[dict] = []
    for _ in range(stages.ROUTING_ROUNDS + 1):
        if stages.joint_runs(pruning, current):
            return current, added
        capture.collect()
        diagnosis = pruning.run(current, stages.OBSERVED_JOINT, "kvm abi10 diagnosis")
        records, _, _ = read_records(capture)
        decision = stages.network_decision(pruning, diagnosis)
        rows, other = audit.abi10_rows(decision.bind, records, current.bind)
        if other or decision.connect or not rows:
            raise search.PruneAbort("the guest kernel differs from the default prune's in more than a UDP bind port",
                                    {"other_bind_rules": other, "connect_rules": list(decision.connect),
                                     "audit": [item.raw for item in records][:20]})
        added += [{"rule": row, "audit": [item.raw for item in records if audit.BIND_UDP in item.blockers]} for row in rows]
        current = dataclasses.replace(current, bind=current.bind + tuple(rows))
    raise search.PruneAbort("the joint verification on the guest kernel did not settle")


def sidecar_text(origin: dict, key: str, exercise: str, rows: list[dict]) -> str:
    """The `.abi10.cfg`: a comment naming the KVM run and the rows, in the format the parser reads."""
    lines = [f"ABI 10 rows for {key}/{exercise}, from the KVM run on kernel {origin['kernel']} on {origin['date']}.",
             "Each row is a UDP bind the kernel's own audit record names as refused; see the .abi10.json beside this file."]
    for line in lines:
        cfgfile.check_rule(line)
    header = "".join(f"# {line}\n" for line in lines)
    return header + cfgfile.render(cfgfile.Policy(fs={}, connect=(), bind=tuple(row["rule"] for row in rows), limits={}))


def verify_exercise(directory: pathlib.Path, key: str, environment: runner.Environment, output: pathlib.Path,
                    pristine, origin: dict, capture: Capture,
                    describe: Callable[[BaseException], dict]) -> tuple[dict, str | None, str | None]:
    """Verifies one exercise's default-prune policy on this kernel; its record, its `.abi10.cfg` text and the failure.

    The record is always made. The sidecar text is made only when a row was added and everything else
    held. A failure is a mismatch of the cross-check, an abort or a defect, each named by `describe`,
    which turns the exception into the record's reason and evidence.
    """
    base = f"{key}_{directory.name}"
    entry: dict = {"schema_version": ABI10_SCHEMA, "key": key, "exercise": directory.name, "provenance": origin,
                   "kernel": platform.release(), "landlock_abi": origin["landlock_abi"], "verified_cfg_sha256": None,
                   "abi10_cfg_sha256": None, "mismatches": [], "audit_only": [], "rows": []}
    reason = None
    sidecar = None
    try:
        recorded = json.loads((output / f"{base}.json").read_text())
        text = (output / f"{base}.cfg").read_text()
        digest = hashlib.sha256(text.encode()).hexdigest()
        if recorded.get("cfg_sha256") != digest:
            raise search.PruneAbort(f"{base}.cfg is not the file its record describes: its SHA-256 differs")
        entry["verified_cfg_sha256"] = digest
        policy = cfgfile.read_policy(text)
        pruning = stages.Pruning(exercise=runner.read_exercise(directory), budget=stages.Budget(),
                                 environment=environment, pristine=pristine)
        pruning.reference = stages.baseline(pruning)
        entry["cross_check"] = cross_check_run(pruning, policy, capture)
        entry["mismatches"] = entry["cross_check"]["mismatches"]
        entry["audit_only"] = entry["cross_check"]["audit_only"]
        if entry["mismatches"]:
            reason = (f"the audit cross-check found {len(entry['mismatches'])} strace denial(s) the kernel's records do "
                      "not agree with")
        elif entry["cross_check"]["strace_denials"] == 0 and len(narrowed(policy).fs) < len(policy.fs):
            reason = ("the cross-check run was refused nothing strace could attribute, although it ran without "
                      f"{len(policy.fs) - len(narrowed(policy).fs)} grant(s) the policy holds, so nothing was compared")
        _, entry["rows"] = abi10_phase(pruning, policy, capture)
        if entry["rows"] and reason is None:
            sidecar = sidecar_text(origin, key, directory.name, entry["rows"])
            entry["abi10_cfg_sha256"] = hashlib.sha256(sidecar.encode()).hexdigest()
    except Exception as failure:  # noqa: BLE001
        described = describe(failure)
        entry |= described
        reason = described["aborted"]
    entry["verified"] = reason is None
    return entry, sidecar, reason
