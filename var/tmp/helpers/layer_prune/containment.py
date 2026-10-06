"""The containment checks of A.6.4: the final policy proven in the forbidden direction too.

A passing build only shows the permitted direction. Before the first run the pruner plants canaries
no reference touches; under the final policy the protection matrix's probe must then be refused each
canary, a write into a path the policy grants only [read], a connect to 10.0.0.1:80 and a bind of
port 8080 (unless the policy names them), and must be stopped by each derived limit. A check that the
probe passes aborts the exercise.

The probe runs under the final policy plus exactly two grants it needs to run at all and nothing the
checks test: [read] and [execute] on the probe binary itself (it is static, so no library), and
[read] on /dev/null, which its descriptor check opens.
"""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import subprocess  # nosec B404
import tempfile

from layer_prune import cfgfile, search

# Where the prune image keeps the probe, compiled from tests/integration/protection-matrix/probe.c.
PROBE = "/usr/local/libexec/phobos-prune-probe"
# The canaries, files no reference touches, created before the baseline.
CANARIES = ("/srv/phobos-prune-canary/secret", "/root/phobos-prune-canary")
CANARY_TEXT = "phobos-prune-canary\n"
# The external destination and the port a policy must not reach unless it names them.
UNNAMED_DESTINATION = ("10.0.0.1", "80")
UNNAMED_PORT = "8080"
# The probe's own caps (probe.c): a limit above one cannot be exceeded by it and is reported unchecked.
PROBE_SLEEP_CAP_SECONDS = 120
PROBE_OPEN_CAP = 4000
PROBE_FORK_CAP = 600
PROBE_WRITE_CAP_MB = 600
PROBE_ALLOC_CAP_MB = 20000
# The statuses phobos.sh ends with when the timeout ends a run, and when the kernel kills at the CPU limit.
TIMEOUT_STATUS = 14
SIGKILL_STATUS = 137
# The file the file-size check writes into a writable directory of the policy, removed afterwards.
FSIZE_CHECK_FILE = "phobos-prune-fsize-check"
# The uid the kernel exempts from RLIMIT_NPROC.
ROOT_UID = 0
# How long one check may take at most, beyond the limit it exceeds.
CHECK_SECONDS = 300
OP_LINE = re.compile(r"^OP (?P<name>\S+) ret=(?P<ret>-?\d+) errno=(?P<errno>\S+)", re.MULTILINE)


@dataclasses.dataclass(frozen=True)
class ContainmentCheck:
    """One check: what the probe is asked to do, and how its refusal shows.

    `must_fail_with` holds the errno names, `OP` failures of the probe that count as refused, or
    `status:<n>` for a run that must end with status n; `expect` is an extra line the output must hold.
    """

    name: str
    probe_arguments: tuple[str, ...]
    must_fail_with: frozenset[str]
    expect: str = ""


def plant_canaries() -> None:
    """Creates every canary, readable by everyone, so only the sandbox can refuse it."""
    for canary in CANARIES:
        path = pathlib.Path(canary)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(CANARY_TEXT)
        path.chmod(0o644)


def read_only_path(policy: cfgfile.Policy) -> str | None:
    """A file to write into that the policy grants only [read]: such a file, or a new name in such a directory.

    Neither it nor an ancestor holds a write-class grant, so the write must be refused.
    """
    writable = [path for path, sections in policy.fs.items() if sections & set(cfgfile.WRITE_SECTIONS)]
    for path, sections in sorted(policy.fs.items()):
        readable_only = "read" in sections and not sections & set(cfgfile.WRITE_SECTIONS)
        if readable_only and os.path.exists(path) and not any(cfgfile.is_beneath(path, other) for other in writable):
            return path if os.path.isfile(path) else os.path.join(path, "phobos-prune-write-check")
    return None


def writable_directory(policy: cfgfile.Policy) -> str | None:
    """A directory the policy grants [write] and [create] on, where the file-size check can write."""
    for path, sections in sorted(policy.fs.items()):
        if {"write", "create"} <= sections and os.path.isdir(path):
            return path
    return None


def names_connect(policy: cfgfile.Policy, address: str, port: str) -> bool:
    """Whether a [connect] rule could name the destination: an exact rule, a range, `*` or a bare host."""
    return any(rule.split()[1] in (f"{address}:{port}", f"*:{port}", "*") or "/" in rule.split()[1]
               for rule in policy.connect if len(rule.split()) > 1)


def limit_checks(policy: cfgfile.Policy) -> list[ContainmentCheck]:
    """One check per derived limit the probe can exceed: each must be refused or must end the run."""
    found: list[ContainmentCheck] = []
    limits = policy.limits
    if 0 < limits.get("nofile", 0) < PROBE_OPEN_CAP:
        found.append(ContainmentCheck("nofile", ("openfiles", str(limits["nofile"] + 1)), frozenset({"EMFILE"}),
                                      "errno=EMFILE"))
    if 0 < limits.get("nproc", 0) < PROBE_FORK_CAP and os.geteuid() != ROOT_UID:
        found.append(ContainmentCheck("nproc", ("fork_n", str(limits["nproc"] + 1)), frozenset({"EAGAIN"}),
                                      "errno=EAGAIN"))
    if 0 < limits.get("mem_mb", 0) < PROBE_ALLOC_CAP_MB:
        found.append(ContainmentCheck("mem_mb", ("alloc", str(limits["mem_mb"] + 1)), frozenset({"ENOMEM"})))
    directory = writable_directory(policy)
    if directory is not None and 0 < limits.get("fsize_mb", 0) < PROBE_WRITE_CAP_MB:
        target = os.path.join(directory, FSIZE_CHECK_FILE)
        found.append(ContainmentCheck("fsize_mb", ("writebig", target, str(limits["fsize_mb"] + 1)),
                                      frozenset({"EFBIG"}), "errno=EFBIG"))
    if 0 < limits.get("timeout", 0) < PROBE_SLEEP_CAP_SECONDS:
        found.append(ContainmentCheck("timeout", ("sleep", str(limits["timeout"] + 5)),
                                      frozenset({f"status:{TIMEOUT_STATUS}"})))
    cpu = limits.get("cpu", 0)
    timeout = limits.get("timeout", 0)
    if 0 < cpu < PROBE_SLEEP_CAP_SECONDS and (timeout == 0 or cpu < timeout):
        found.append(ContainmentCheck("cpu", ("spin", str(cpu + 5)), frozenset({f"status:{SIGKILL_STATUS}"})))
    return found


def unchecked(policy: cfgfile.Policy) -> list[dict]:
    """The derived limits no check could exceed here, each with the reason, for the record.

    A limit above the probe's cap cannot be reached by it, and nproc does not bind uid 0, which the
    kernel exempts from RLIMIT_NPROC; a run graded as root is not bound by it either.
    """
    found = []
    caps = {"nofile": PROBE_OPEN_CAP, "nproc": PROBE_FORK_CAP, "mem_mb": PROBE_ALLOC_CAP_MB,
            "fsize_mb": PROBE_WRITE_CAP_MB, "timeout": PROBE_SLEEP_CAP_SECONDS, "cpu": PROBE_SLEEP_CAP_SECONDS}
    for limit, value in sorted(policy.limits.items()):
        if value >= caps.get(limit, 0) > 0:
            found.append({"name": limit, "refused": None, "unchecked": f"above the probe's cap of {caps[limit]}"})
    if 0 < policy.limits.get("nproc", 0) < PROBE_FORK_CAP and os.geteuid() == ROOT_UID:
        found.append({"name": "nproc", "refused": None, "unchecked": "uid 0 is exempt from RLIMIT_NPROC"})
    return found


def checks(policy: cfgfile.Policy) -> list[ContainmentCheck]:
    """Every containment check for a policy: the canaries, a read-only path, the network, and the limits."""
    found = [ContainmentCheck(f"canary {canary}", ("read", canary), frozenset({"EACCES"})) for canary in CANARIES]
    target = read_only_path(policy)
    if target is not None:
        found.append(ContainmentCheck(f"write into the read-only {target}", ("write", target, "x"),
                                      frozenset({"EACCES"})))
    address, port = UNNAMED_DESTINATION
    if not names_connect(policy, address, port):
        found.append(ContainmentCheck(f"connect {address}:{port}", ("tcp", address, port), frozenset({"EACCES"})))
    if not any(rule.split()[1:2] == [UNNAMED_PORT] for rule in policy.bind):
        found.append(ContainmentCheck(f"bind {UNNAMED_PORT}", ("bind", "127.0.0.1", UNNAMED_PORT, "tcp"),
                                      frozenset({"EACCES"})))
    return found + limit_checks(policy)


def probe_policy(policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy the probe runs under: the final one plus the probe binary and /dev/null for reading."""
    fs = dict(policy.fs)
    fs[PROBE] = fs.get(PROBE, frozenset()) | {"read", "execute"}
    fs["/dev/null"] = fs.get("/dev/null", frozenset()) | {"read"}
    return dataclasses.replace(policy, fs=fs)


def refused(check: ContainmentCheck, status: int, output: str) -> bool:
    """Whether the probe's run shows the check refused: a failed OP with an expected errno, or the expected status."""
    if f"status:{status}" in check.must_fail_with:
        return True
    if check.expect and check.expect in output:
        return True
    return any(int(match.group("ret")) < 0 and match.group("errno") in check.must_fail_with
               for match in OP_LINE.finditer(output))


def run_check(check: ContainmentCheck, cfg: pathlib.Path, phobos: str) -> dict:
    """Runs one check through phobos.sh and returns its record."""
    argv = [phobos, "--config", str(cfg), "--", PROBE, *check.probe_arguments]
    finished = subprocess.run(argv, capture_output=True, text=True, timeout=CHECK_SECONDS, check=False)  # nosec B603
    output = finished.stdout + finished.stderr
    return {"name": check.name, "arguments": list(check.probe_arguments), "status": finished.returncode,
            "refused": refused(check, finished.returncode, output),
            "evidence": [line for line in output.splitlines() if line.startswith(("OP ", "OPENED", "FORKED", "WROTE"))]}


def run_checks(policy: cfgfile.Policy, phobos: str = "/var/tmp/opt/core/phobos.sh",
               candidate_dir: str = "/run/layer-prune") -> list[dict]:
    """Runs every check under the policy; raises PruneAbort naming the first one the probe was not refused."""
    pathlib.Path(candidate_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, name = tempfile.mkstemp(prefix="containment.", suffix=".cfg", dir=candidate_dir)
    os.close(handle)
    cfg = pathlib.Path(name)
    try:
        cfg.write_text(cfgfile.render(probe_policy(policy)))
        results = [run_check(check, cfg, phobos) for check in checks(policy)] + unchecked(policy)
    finally:
        cfg.unlink(missing_ok=True)
        directory = writable_directory(policy)
        if directory is not None:
            pathlib.Path(directory, FSIZE_CHECK_FILE).unlink(missing_ok=True)
    for result in results:
        if result["refused"] is False:
            raise search.PruneAbort(f"containment check passed: {result['name']}", {"containment": results})
    return results
