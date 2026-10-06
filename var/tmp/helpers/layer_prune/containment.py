"""The containment checks of A.6.4: the final policy proven in the forbidden direction too.

A passing build only shows the permitted direction. Before the first run the pruner plants canaries
no reference touches; under the final policy the protection matrix's probe must then be refused each
canary, a write into a path the policy grants only [read], a TCP connect to 10.0.0.1:80 and a TCP bind
of port 8080 (unless the policy names them), and must be stopped by each derived limit. A check that
the probe passes aborts the exercise.

A refusal counts only where it is the sandbox's: each check is first made without Phobos and with no
limit, as the control replay of A.6.3 does for a denial, and must succeed there: a canary root cannot
read, a write a pseudo filesystem refuses anyway, a memory or file-size failure the container causes,
or a process count its cgroup caps would otherwise pass as proof. The network checks cannot succeed in
a container without a network, so there the control only must not be refused the same way. A check
whose control fails is unproven, and aborts the exercise as well. The timeout check needs no control:
status 14 is the timeout layer's own. The write check never touches /proc, /sys or /dev.

The probe runs under the final policy plus exactly two grants it needs to run at all and nothing the
checks test: [read] and [execute] on the probe binary itself (it is static, so no library), and
[read] on /dev/null, which its descriptor check opens. Nothing a check does is left behind: the write
check opens an existing file for writing without truncating it, or creates a new name and removes it.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import pathlib
import re
import signal
import subprocess  # nosec B404

from layer_prune import cfgfile, generalise, limits, runner, search, verdict

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
# The new name the write check creates in a directory granted only [read], removed after every probe run.
WRITE_CHECK_FILE = "phobos-prune-write-check"
# The file the file-size check writes into a writable directory of the policy, removed after every probe run.
FSIZE_CHECK_FILE = "phobos-prune-fsize-check"
# The uid the kernel exempts from RLIMIT_NPROC.
ROOT_UID = 0
# How long one probe run may take at most, beyond the limit it exceeds.
CHECK_SECONDS = 300
# The line the probe prints first: whatever came before it was printed before the probe started.
PROBE_START = "START\n"
# The pseudo filesystems the write check leaves alone: a write there would reach the kernel.
PSEUDO_ROOTS = ("/proc", "/sys", "/dev")
OP_LINE = re.compile(r"^OP (?P<name>\S+) ret=(?P<ret>-?\d+) errno=(?P<errno>\S+)", re.MULTILINE)


@dataclasses.dataclass(frozen=True)
class ProbeRun:
    """One run of the probe: its status, None when it outlived CHECK_SECONDS, and its output."""

    status: int | None
    output: str


@dataclasses.dataclass(frozen=True)
class ContainmentCheck:
    """One check: what the probe is asked to do, and how its refusal shows.

    `must_fail_with` holds the errno names, `OP` failures of the probe that count as refused, or
    `status:<n>` for a run that must end with status n; `expect` is an extra line the output must hold;
    `controlled` says whether the check is first made without Phobos, and `control_succeeds` whether
    that control must succeed or only must not be refused the same way; `leaves` names a file the
    probe may create, removed after every run of it.
    """

    name: str
    probe_arguments: tuple[str, ...]
    must_fail_with: frozenset[str]
    expect: str = ""
    controlled: bool = True
    control_succeeds: bool = True
    leaves: str | None = None


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
        if any(path == root or cfgfile.is_beneath(path, root) for root in PSEUDO_ROOTS):
            continue
        readable_only = "read" in sections and not sections & set(cfgfile.WRITE_SECTIONS)
        if readable_only and os.path.exists(path) and not any(cfgfile.is_beneath(path, other) for other in writable):
            return path if os.path.isfile(path) else os.path.join(path, WRITE_CHECK_FILE)
    return None


def writable_directory(policy: cfgfile.Policy) -> str | None:
    """A directory the policy grants [write] and [create] on, where the file-size check can write."""
    for path, sections in sorted(policy.fs.items()):
        if {"write", "create"} <= sections and os.path.isdir(path):
            return path
    return None


def rule_parts(rule: str) -> tuple[str, str | None]:
    """A [connect] or [bind] rule's destination or port, and its transport or None where it names none."""
    parts = [*rule.split(), "", ""]
    return parts[1], parts[2] or None


def names_connect(policy: cfgfile.Policy, address: str, port: str) -> bool:
    """Whether a TCP [connect] rule could name the destination.

    An exact rule, the address with every port, the port on every host, `*`, or a range (CIDR), whose
    extent is not worked out here, so a check is skipped rather than made against a rule that names it.
    """
    covering = (f"{address}:{port}", f"{address}:*", address, f"*:{port}", "*")
    return any((destination in covering or "/" in destination) and transport != "udp"
               for destination, transport in map(rule_parts, policy.connect))


def names_bind(policy: cfgfile.Policy, port: str) -> bool:
    """Whether a TCP [bind] rule names the port."""
    return any(rule_port == port and transport != "udp" for rule_port, transport in map(rule_parts, policy.bind))


def limit_checks(policy: cfgfile.Policy) -> list[ContainmentCheck]:
    """One check per derived limit the probe can exceed: each must be refused or must end the run."""
    found: list[ContainmentCheck] = []
    derived = policy.limits
    if 0 < derived.get("nofile", 0) < PROBE_OPEN_CAP:
        found.append(ContainmentCheck("nofile", ("openfiles", str(derived["nofile"] + 1)), frozenset({"EMFILE"}),
                                      "errno=EMFILE"))
    if 0 < derived.get("nproc", 0) < PROBE_FORK_CAP and os.geteuid() != ROOT_UID:
        found.append(ContainmentCheck("nproc", ("fork_n", str(derived["nproc"] + 1)), frozenset({"EAGAIN"}),
                                      "errno=EAGAIN"))
    if 0 < derived.get("mem_mb", 0) < PROBE_ALLOC_CAP_MB:
        found.append(ContainmentCheck("mem_mb", ("alloc", str(derived["mem_mb"] + 1)), frozenset({"ENOMEM"})))
    directory = writable_directory(policy)
    if directory is not None and 0 < derived.get("fsize_mb", 0) < PROBE_WRITE_CAP_MB:
        target = os.path.join(directory, FSIZE_CHECK_FILE)
        found.append(ContainmentCheck("fsize_mb", ("writebig", target, str(derived["fsize_mb"] + 1)),
                                      frozenset({"EFBIG"}), "errno=EFBIG", leaves=target))
    if 0 < derived.get("timeout", 0) < PROBE_SLEEP_CAP_SECONDS:
        found.append(ContainmentCheck("timeout", ("sleep", str(derived["timeout"] + 5)),
                                      frozenset({f"status:{limits.TIMEOUT_STATUS}"}), controlled=False))
    cpu = derived.get("cpu", 0)
    timeout = derived.get("timeout", 0)
    if 0 < cpu < PROBE_SLEEP_CAP_SECONDS and (timeout == 0 or cpu < timeout):
        found.append(ContainmentCheck("cpu", ("spin", str(cpu + 5)), frozenset({f"status:{limits.SIGKILL_STATUS}"})))
    return found


def unchecked(policy: cfgfile.Policy) -> list[dict]:
    """The derived limits no check could exceed here, each with the reason, for the record.

    A limit above the probe's cap cannot be reached by it; nproc does not bind uid 0, which the kernel
    exempts from RLIMIT_NPROC, and a run graded as root is not bound by it either; a CPU limit the
    timeout reaches first cannot be shown; and a file-size limit needs a directory to write into.
    """
    found = []
    caps = {"nofile": PROBE_OPEN_CAP, "nproc": PROBE_FORK_CAP, "mem_mb": PROBE_ALLOC_CAP_MB,
            "fsize_mb": PROBE_WRITE_CAP_MB, "timeout": PROBE_SLEEP_CAP_SECONDS, "cpu": PROBE_SLEEP_CAP_SECONDS}
    derived = policy.limits
    for limit, value in sorted(derived.items()):
        if value >= caps.get(limit, 0) > 0:
            found.append({"name": limit, "refused": None, "unchecked": f"above the probe's cap of {caps[limit]}"})
    if 0 < derived.get("nproc", 0) < PROBE_FORK_CAP and os.geteuid() == ROOT_UID:
        found.append({"name": "nproc", "refused": None, "unchecked": "uid 0 is exempt from RLIMIT_NPROC"})
    if 0 < derived.get("cpu", 0) < PROBE_SLEEP_CAP_SECONDS and 0 < derived.get("timeout", 0) <= derived["cpu"]:
        found.append({"name": "cpu", "refused": None, "unchecked": "the timeout ends a run before the CPU limit can"})
    if 0 < derived.get("fsize_mb", 0) < PROBE_WRITE_CAP_MB and writable_directory(policy) is None:
        found.append({"name": "fsize_mb", "refused": None,
                      "unchecked": "the policy grants no directory [write] and [create] to write a file into"})
    return found


def write_check(target: str) -> ContainmentCheck:
    """The write into a path granted only [read]: open an existing file for writing without truncating it,
    or create the new name exclusively; Landlock decides at the open, so the open alone is the proof."""
    if os.path.isfile(target):
        return ContainmentCheck(f"write into the read-only {target}", ("open", target, "w"), frozenset({"EACCES"}))
    return ContainmentCheck(f"write into the read-only {target}", ("open", target, "excl"), frozenset({"EACCES"}),
                            leaves=target)


def checks(policy: cfgfile.Policy) -> list[ContainmentCheck]:
    """Every containment check for a policy: the canaries, a read-only path, the network, and the limits."""
    found = [ContainmentCheck(f"canary {canary}", ("read", canary), frozenset({"EACCES"})) for canary in CANARIES]
    target = read_only_path(policy)
    if target is not None:
        found.append(write_check(target))
    address, port = UNNAMED_DESTINATION
    if not names_connect(policy, address, port):
        found.append(ContainmentCheck(f"connect {address}:{port}", ("tcp", address, port), frozenset({"EACCES"}),
                                      control_succeeds=False))
    if not names_bind(policy, UNNAMED_PORT):
        found.append(ContainmentCheck(f"bind {UNNAMED_PORT}", ("bind", "127.0.0.1", UNNAMED_PORT, "tcp"),
                                      frozenset({"EACCES"}), control_succeeds=False))
    return found + limit_checks(policy)


def probe_policy(policy: cfgfile.Policy) -> cfgfile.Policy:
    """The policy the probe runs under: the final one plus the probe binary and /dev/null for reading, normalised."""
    fs = dict(policy.fs)
    fs[PROBE] = fs.get(PROBE, frozenset()) | {"read", "execute"}
    fs["/dev/null"] = fs.get("/dev/null", frozenset()) | {"read"}
    return dataclasses.replace(policy, fs=generalise.normalise_hierarchy(fs))


def refused(check: ContainmentCheck, status: int | None, output: str) -> bool:
    """Whether the probe's run shows the check refused: a failed OP with an expected errno, or the expected status."""
    if status is not None and f"status:{status}" in check.must_fail_with:
        return True
    if check.expect and check.expect in output:
        return True
    return any(int(match.group("ret")) < 0 and match.group("errno") in check.must_fail_with
               for match in OP_LINE.finditer(output))


def run_probe(argv: list[str], check: ContainmentCheck) -> ProbeRun:
    """Runs one probe command in its own session, with stderr merged in order, and removes what it may leave."""
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,  # nosec B603
                               start_new_session=True, text=True, errors="replace")
    try:
        output = process.communicate(timeout=CHECK_SECONDS)[0]
        status = process.returncode
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        output = process.communicate()[0]
        status = None
    finally:
        runner.reap_leftovers()
        if check.leaves is not None:
            pathlib.Path(check.leaves).unlink(missing_ok=True)
    if status is not None and status < 0:
        status = verdict.SIGNAL_STATUS_BASE - status
    return ProbeRun(status=status, output=output)


def succeeded(run: ProbeRun) -> bool:
    """Whether a probe run did what it was asked: it started, ended with status 0, and no operation failed."""
    return PROBE_START in run.output and run.status == 0 and not any(
        int(match.group("ret")) < 0 for match in OP_LINE.finditer(run.output))


def evidence_of(output: str) -> list[str]:
    """The probe's lines that say what it did."""
    return [line for line in output.splitlines() if line.startswith(("OP ", "OPENED", "FORKED", "WROTE"))]


def run_check(check: ContainmentCheck, cfg: pathlib.Path, environment: runner.Environment) -> dict:
    """Runs one check, its control first, and returns its record; `refused` is None when the control was refused.

    Raises PrunerDefect when Phobos stopped the probe's run before the probe started.
    """
    entry: dict = {"name": check.name, "arguments": list(check.probe_arguments)}
    if check.controlled:
        control = run_probe([PROBE, *check.probe_arguments], check)
        entry["control"] = {"status": control.status, "evidence": evidence_of(control.output)}
        failed = not succeeded(control) if check.control_succeeds else refused(check, control.status, control.output)
        if PROBE_START not in control.output or failed:
            return {**entry, "refused": None, "unproven": "without Phobos the probe did not run, or did not succeed"}
    argv = [os.path.join(environment.phobos_home, "phobos.sh"), "--config", str(cfg)]
    if environment.resolver:
        argv += ["--resolver", environment.resolver]
    sandboxed = run_probe([*argv, "--", PROBE, *check.probe_arguments], check)
    status = sandboxed.status
    marker = verdict.phobos_stopped(status if status is not None else 0, sandboxed.output.split(PROBE_START, 1)[0])
    if marker is not None:
        raise runner.PrunerDefect(status if status is not None else -1, cfg,
                                  f"Phobos stopped the containment check {check.name}: {marker}")
    return {**entry, "status": status, "refused": refused(check, status, sandboxed.output),
            "evidence": evidence_of(sandboxed.output)}


def run_checks(policy: cfgfile.Policy, environment: runner.Environment) -> list[dict]:
    """Runs every check under the policy, gated like every candidate.

    Raises PruneAbort naming the first check the probe was not refused, or whose control was refused.
    """
    log_path = runner.log_paths(environment, "containment")[0]
    cfg = pathlib.Path(environment.candidate_dir) / f"{log_path.stem}.cfg"
    try:
        runner.gate(cfgfile.render(probe_policy(policy)), cfg, environment, log_path)
        results = [run_check(check, cfg, environment) for check in checks(policy)] + unchecked(policy)
    finally:
        cfg.unlink(missing_ok=True)
    for result in results:
        if result["refused"] is False:
            raise search.PruneAbort(f"containment check passed: {result['name']}", {"containment": results})
        if "unproven" in result:
            raise search.PruneAbort(f"containment check unproven: {result['name']}", {"containment": results})
    return results
