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


class Indeterminate(Exception):
    """The guest cannot observe Landlock's audit records, so no result of this run means anything."""


class Capture:
    """Reads the kernel's message ring from where it is when the capture is opened, without blocking."""

    def __init__(self, path: str = KMSG) -> None:
        """Opens the ring and moves to its end, so that only what happens afterwards is read."""
        self.descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        os.lseek(self.descriptor, 0, os.SEEK_END)

    def drain(self) -> list[str]:
        """Every line written since the last drain, as the ring holds them."""
        lines: list[str] = []
        while True:
            try:
                data = os.read(self.descriptor, KMSG_READ_BYTES)
            except BlockingIOError:
                break
            except OSError as failure:
                if failure.errno == errno.EPIPE:
                    continue
                raise
            if not data:
                break
            lines.append(data.decode("utf-8", errors="replace"))
        return lines

    def close(self) -> None:
        """Closes the ring."""
        os.close(self.descriptor)


def read_records(capture: Capture) -> tuple[list[audit.AuditRecord], list[str], list[str]]:
    """The audit records written since the last drain, the lines of that type that did not parse, and every line."""
    lines = capture.drain()
    records, unparsed = audit.parse(lines)
    return records, unparsed, lines


def selftest(environment: runner.Environment, capture: Capture, version: int, directory: pathlib.Path) -> dict:
    """Proves the guest can observe Landlock before any prune run; raises Indeterminate when it cannot.

    The kernel must offer Landlock version 10 or later, and one deliberate refusal, a read of a file the
    probe was granted nothing on, must produce exactly one record that parses and names that file.
    """
    if version < ABI10_VERSION:
        raise Indeterminate(f"the kernel offers Landlock version {version}, below {ABI10_VERSION}")
    cfg = directory / "selftest.cfg"
    cfg.write_text(f"[read]\n{PROBE}\n/dev/null\n\n[execute]\n{PROBE}\n")
    capture.drain()
    argv = [os.path.join(environment.phobos_home, "phobos.sh"), "--config", str(cfg), "--", PROBE, "read", SELFTEST_FILE]
    finished = subprocess.run(argv, capture_output=True, text=True, check=False)  # nosec B603
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
    capture.drain()
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
        capture.drain()
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
