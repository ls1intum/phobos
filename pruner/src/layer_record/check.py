"""The replay check: does a recorded session still run under the real layers with its policy?

The check replays a session under phobos.sh with the recording's policy.cfg and the prune image's
base, which grants nothing, and fails on every refusal of something a recorded session did
successfully (plan A.14). It compares accesses, not call names: a refused call is turned into
exactly the (object, section) and operation pairs it needed, by the same mapping the recording
was read with (needs.pairs_of_call), so a recorded read never excuses a refused write. And no
refusal is not enough: the replay must also have run the session.

Where it may run is decided first. A replay in the recording's own container, or in one whose
starting state differs from the recording's, can pass on files the recording or an earlier run
left behind, so the check compares the container's starting state with the recording's rather
than taking freshness on trust, and refuses a container that is not fresh unless the caller opts in
with --same-container (Markus's decision 12 in the recording pruner's plan).

A recording directory holds `sessions/<n>/session.json` for every session, naming the
`container_id` it was recorded in and the `snapshot` of that container, a path relative to the
recording directory; each replay writes `check-<n>/trace` and `check-<n>/check.json` beside them.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import sys

from layer_prune import (
    attribute,
    record,
    strace_parse,
)
from layer_prune.record import (
    Denial,
    Syscall,
)

from layer_record import (
    guard,
    needs,
    observe,
    pty_script,
    snapshot,
)

NOT_FRESH_WARNING = ("Warning: this check does not run in a fresh container. Files the recording or an "
                     "earlier run left behind can make it pass where a fresh container would fail.")

# How many differing paths a refusal names before it only counts the rest.
MAX_LISTED_DIFFERENCES = 20

# The status the check ends with when a recorded access was refused or the session did not run.
EXIT_REGRESSION = 1

# The options strace runs with around a replay. No --seccomp-bpf: its filter answers
# SECCOMP_RET_TRACE and the connect guard's SECCOMP_RET_USER_NOTIF takes precedence, so every call
# the guard decides would be missing (strace_parse.STRACE_ARGUMENTS says the same). -yy and the
# recorder's trace set without the duplicating calls, which a replay does not need since a refused
# ioctl names its device in its own decoration, so a refused call is read exactly as a recorded one
# was; landlock_restrict_self marks the domain, and ftruncate and getdents64 are calls the layer
# pruner's attribution reads.
REPLAY_ARGUMENTS = (
    "-DDD",
    "-f",
    "-qq",
    "-yy",
    "-x",
    "-s",
    "4096",
    "-e",
    ("trace=%file,%network,%process,landlock_restrict_self,ioctl,fchdir,write,setsid,setpgid,io_uring_setup,"
     "ftruncate,getdents64,open_by_handle_at"),
)

# The overlay a replay adds: no timeout. GNU timeout puts the command in a process group of its own,
# which is never the terminal's foreground group, so an interactive command would be stopped by
# SIGTTIN on its first read (measured in the plan's spike). It is outside every write path.
OVERLAY_PATH = pathlib.Path("/var/tmp/phobos-record-overlay.cfg")
OVERLAY_TEXT = "# Written by phobos-record check: a replay runs without a timeout.\n[limits]\ntimeout=0\n"

# The statuses with which Phobos ends a run it stopped itself (phobos-constants.sh: PHB_EXIT_USAGE,
# PHB_EPOLICY, PHB_ERUNTIME, PHB_ENFORCER_REFUSED_EXIT), which count as its stop only together with
# one of its own markers and before the command started (the layer pruner plan's A.6.4). This is a
# local copy of the layer pruner's rule until PR 162 exposes it as a function of its runner (for
# example runner.phobos_stopped(status, stderr)); the recorder's next pull request switches to it.
PHOBOS_STOP_STATUSES = frozenset({2, 11, 15, 125})
PHOBOS_STOP_MARKERS = ("(PHB-EPOLICY)", "(PHB-ERUNTIME)", "Usage:", "[phobos-landlock-filesystem-and-networksystem]",
                       "[phobos-seccomp-networksystem]", "[phobos-seccomp-timeoutsystem]")

# How much of a scripted replay's terminal output is searched for Phobos's own markers.
STDERR_HEAD_BYTES = 65536


@dataclasses.dataclass(frozen=True)
class Refusal:
    """A refusal of the replay: the refused call, the layer pruner's Denial of it, and its pairs.

    The pairs come from needs.pairs_of_call on the refused call, never from the Denial's object
    and section sets, whose product would invent pairs a call never needed.
    """

    call: Syscall
    denial: Denial
    pairs: frozenset[tuple[str, str]]


@dataclasses.dataclass(frozen=True)
class Comparison:
    """The replay's refusals sorted: regressions, harmless fixed refusals, and new behaviour."""

    regressions: list[Refusal]
    harmless_fixed: list[Refusal]
    new_behaviour: list[Refusal]


def compare(recorded: set[tuple[str, str]], replay: list[Refusal]) -> Comparison:
    """Sorts the replay's refusals against the pairs the recorded sessions needed.

    A refusal is a regression when any of its pairs was recorded, whatever layer refused it; a
    fixed refusal of an operation that worked bare is one too. A refusal of a fixed rule that no
    session performed is harmless; anything else is new behaviour, listed and never called harmless.
    """
    regressions = []
    harmless = []
    new = []
    for refusal in replay:
        if refusal.pairs & recorded:
            regressions.append(refusal)
        elif refusal.denial.layer == record.LAYER_FIXED:
            harmless.append(refusal)
        else:
            new.append(refusal)
    return Comparison(regressions=regressions, harmless_fixed=harmless, new_behaviour=new)


def completed(trace: strace_parse.Trace, calls: list[Syscall], command: list[str], status: int, stderr_head: str,
              recorded_statuses: set[int], expectations_met: bool | None) -> list[str]:
    """The reasons the replay did not run the session; empty when it did.

    Assumes `trace` is the replay's parsed trace and `calls` every call of it (strace_parse.iter_calls),
    `stderr_head` the start of what the replay printed, empty where it went straight to the person's
    terminal, and `expectations_met` None for a replay typed by hand. The reasons: Phobos stopped the
    run itself before the command started, no execve of the command happened inside the domain, a
    scripted expectation was not met, or the status is one no recorded session ended with.
    """
    reasons = []
    started = _command_started(trace, calls, command)
    if not started and status in PHOBOS_STOP_STATUSES and any(marker in stderr_head for marker in PHOBOS_STOP_MARKERS):
        reasons.append(f"Phobos stopped the run itself with status {status} before the command started")
    if not started:
        reasons.append(f"no execve of {command[0]!r} inside the sandbox's domain: the command never ran under it")
    if expectations_met is False:
        reasons.append("an expectation of the script was not met, so the session did not run as recorded")
    if recorded_statuses and status not in recorded_statuses:
        reasons.append(f"the command ended with {status}, which no recorded session ended with "
                       f"({', '.join(str(value) for value in sorted(recorded_statuses))})")
    return reasons


def mode(recording: pathlib.Path, container_id: str, fingerprint: dict[str, str], same_container: bool) -> str:
    """Which kind of container the replay runs in, or a refusal when it may not run there.

    Assumes fingerprint is this container's starting state from snapshot.fingerprint, taken after
    the exercise was copied in afresh and before the replay. Answers "fresh-container" when no
    session of the recording ran in container_id and the fingerprint equals the one of the
    recording's first session. Otherwise answers "same-container" (a container a session ran in)
    or "changed-container" (another container whose starting state differs) when same_container
    is set, and raises guard.Refused with EXIT_ENVIRONMENT, naming the container or the
    differences, when it is not.
    """
    sessions = [meta for _, meta in _sessions(recording)]
    if any(meta["container_id"] == container_id for meta in sessions):
        if same_container:
            return "same-container"
        raise guard.Refused(guard.EXIT_ENVIRONMENT,
                            f"This container ({container_id}) recorded a session of {recording}, so a replay "
                            "here is not fresh. Run the check in a new container, or pass --same-container "
                            "to accept a check that may pass on what the recording left behind.")
    differences = _differences(_starting_state(recording, sessions[0]), fingerprint)
    if not differences:
        return "fresh-container"
    if same_container:
        return "changed-container"
    raise guard.Refused(guard.EXIT_ENVIRONMENT,
                        "This container does not start in the state the recording started in, so a replay "
                        "here is not fresh. Run the check in a new container, or pass --same-container to "
                        "accept that. What differs:\n" + _listed(differences))


def run(recording: pathlib.Path, command: list[str], script: pathlib.Path | None, same_container: bool,
        resolver: str | None, exercise: pathlib.Path | None, phobos_home: pathlib.Path) -> int:
    """Replays a session under phobos.sh with the recording's policy and judges the result.

    Assumes it runs in the prune image, whose base grants nothing, so policy.cfg alone carries the
    session, and that the caller started a new container for it. Refuses the recording's own
    container before it changes anything, then copies the exercise afresh into the tail's working
    directory, compares the starting state, and runs the command under strace and phobos.sh, typed
    from the script when one is given. Answers 0 only with no regression and a replay that ran the
    session, EXIT_REGRESSION otherwise; raises guard.Refused where it may not run.
    """
    actions = _script_actions(script)
    policy = recording / "policy.cfg"
    if not policy.is_file():
        raise guard.Refused(guard.EXIT_USAGE, f"{policy} does not exist: put the policy to check there.")
    sessions = _sessions(recording)
    observe.require_strace()
    container = observe.container_id()
    if not same_container and any(meta["container_id"] == container for _, meta in sessions):
        mode(recording, container, {}, same_container)
    workdir = observe.tail_chdir(phobos_home / "TailPhobos.cfg")
    observe.copy_exercise(exercise, workdir)
    kind = mode(recording, container, snapshot.fingerprint(), same_container)
    fresh = kind == "fresh-container"
    if not fresh:
        print(NOT_FRESH_WARNING, file=sys.stderr)
    directory = _next_check(recording)
    OVERLAY_PATH.write_text(OVERLAY_TEXT, encoding="utf-8")
    argv = ["strace", *REPLAY_ARGUMENTS, "-o", str(directory / "trace"), "--", str(phobos_home / "phobos.sh")]
    argv += ["--resolver", resolver] if resolver else []
    argv += ["--config", str(policy), "--config", str(OVERLAY_PATH), "--", *command]
    traced = observe.run_traced(argv, workdir, actions, directory / "transcript")
    transcript = directory / "transcript"
    stderr_head = transcript.read_bytes()[:STDERR_HEAD_BYTES].decode("utf-8", "replace") if transcript.exists() else ""
    report = judge(recording, sessions, directory / "trace", command, traced.status, stderr_head,
                   traced.expectations_met, script, str(workdir))
    report["mode"] = kind
    report["stopped_leftovers"] = traced.stopped
    (directory / "check.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    _print_summary(report, script is not None)
    if not fresh:
        print(NOT_FRESH_WARNING, file=sys.stderr)
    return 0 if not report["regressions"] and not report["not_completed"] else EXIT_REGRESSION


def judge(recording: pathlib.Path, sessions: list[tuple[pathlib.Path, dict]], trace_path: pathlib.Path,
          command: list[str], status: int, stderr_head: str, expectations_met: bool | None,
          script: pathlib.Path | None, workdir: str) -> dict:
    """The verdict on one replay trace against the recording's sessions, as check.json holds it.

    Assumes the replay ran in `workdir` and that every session's trace and snapshot are where its
    session.json says. Only sessions of the same command whose script, if any, was met count; of
    those, a scripted replay is held to the ones typed from the same script. When none is left, the
    replay did not run a recorded session, which is a reason of its own.
    """
    lines = trace_path.read_text(encoding="utf-8", errors="surrogateescape").split("\n")
    trace = strace_parse.parse_trace(lines)
    calls = list(strace_parse.iter_calls(lines))
    first = snapshot.existing(recording / sessions[0][1]["snapshot"])
    replay = [Refusal(call=call, denial=denial, pairs=frozenset(needs.pairs_of_call(call, first, cwd)))
              for call, denial, cwd in attribute.refusals(trace, workdir)]
    recorded: set[tuple[str, str]] = set()
    recorded_calls = 0
    for directory, meta in sessions:
        session_calls = list(strace_parse.iter_calls(
            (directory / "trace").read_text(encoding="utf-8", errors="surrogateescape").split("\n")))
        recorded_calls += len(session_calls)
        recorded |= needs.access_pairs(session_calls, snapshot.existing(recording / meta["snapshot"]),
                                       meta.get("workdir", workdir))
    comparison = compare(recorded, replay)
    statuses, unmatched = _recorded_statuses([meta for _, meta in sessions], command, script)
    reasons = unmatched + completed(trace, calls, command, status, stderr_head, statuses, expectations_met)
    return {
        "status": status,
        "recorded_statuses": sorted(statuses),
        "expectations_met": expectations_met,
        "regressions": [_refusal_record(refusal) for refusal in comparison.regressions],
        "harmless_fixed": [_refusal_record(refusal) for refusal in comparison.harmless_fixed],
        "new_behaviour": [_refusal_record(refusal) for refusal in comparison.new_behaviour],
        "not_completed": reasons,
        "recorded_calls": recorded_calls,
        "replay_calls_in_domain": len(domain_calls(trace, calls)),
    }


def domain_calls(trace: strace_parse.Trace, calls: list[Syscall]) -> list[Syscall]:
    """The calls of a replay made inside the command's Landlock domain, in log order.

    Assumes `trace` is the parsed trace of the same calls. A thread is inside once its own
    landlock_restrict_self that counted for the domain succeeded, and every process it creates
    afterwards is inside from its first call, as strace_parse decides the domain; a child whose own
    calls strace printed before its creator's clone returned is inside from the start.
    """
    restricting = {call.pid for call in calls if call.name == "landlock_restrict_self"}
    inside = {pid for pid, start in trace.domain_from.items() if start == 0 and pid not in restricting}
    found = []
    for call in calls:
        if call.pid in inside:
            found.append(call)
        restricted = call.name == "landlock_restrict_self" and call.errno is None and call.result == 0
        if restricted and call.pid in trace.domain_pids:
            inside.add(call.pid)
        child = strace_parse.forked_child(call)
        if child is not None and call.pid in inside:
            inside.add(child)
    return found


def _command_started(trace: strace_parse.Trace, calls: list[Syscall], command: list[str]) -> bool:
    """Whether a process executed the command after it was inside the domain, judged by the name.

    Assumes the calls are the replay's, in log order; an execve before the same process restricted
    itself does not count, whatever it executed.
    """
    wanted = os.path.basename(command[0])
    for call in domain_calls(trace, calls):
        if call.name not in ("execve", "execveat") or call.errno is not None:
            continue
        program = strace_parse.path_argument(call, 0 if call.name == "execve" else 1) or ""
        if os.path.basename(program) == wanted:
            return True
    return False


def _recorded_statuses(metas: list[dict], command: list[str], script: pathlib.Path | None) -> tuple[set[int], list[str]]:
    """The statuses the replay is held to, and the reasons it matches no recorded session.

    Sessions of another command, and scripted sessions whose expectations failed, never count. A
    scripted replay is held to the sessions typed from the same script; a replay by hand to every
    remaining session of the command.
    """
    same = [meta for meta in metas if meta.get("command") == command and meta.get("expectations_met") is not False]
    if not same:
        return set(), [f"no recorded session ran {command!r} to its end, so the replay has nothing to match"]
    digest = observe.script_digest(script)
    if digest is not None:
        same = [meta for meta in same if meta.get("script_sha256") == digest]
        if not same:
            return set(), [(f"no recorded session of {command!r} was typed from {script}, so its statuses "
                            "cannot be compared")]
    return {int(meta["status"]) for meta in same if isinstance(meta.get("status"), int)}, []


def _script_actions(script: pathlib.Path | None) -> list[pty_script.Action] | None:
    """A script's actions, or None without one; a malformed script is refused before anything runs."""
    if script is None:
        return None
    try:
        return pty_script.parse(script.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise guard.Refused(guard.EXIT_USAGE, f"the script {script} cannot be used: {error}") from error


def _refusal_record(refusal: Refusal) -> dict:
    """A refusal as check.json lists it: the call, the layer and the pairs."""
    call = refusal.call
    return {
        "call": f"{call.pid} {call.name}({call.arguments}) = {call.result} {call.errno or ''}".rstrip(),
        "layer": refusal.denial.layer,
        "pairs": sorted([list(pair) for pair in refusal.pairs]),
    }


def _print_summary(report: dict, scripted: bool) -> None:
    """Prints the verdict in a few lines, naming the mode, so a pass never hides where it ran."""
    print(f"phobos-record check ({report['mode']}): {len(report['regressions'])} regressions, "
          f"{len(report['harmless_fixed'])} harmless fixed refusals, {len(report['new_behaviour'])} new behaviour")
    for entry in report["regressions"]:
        print(f"  regression: {entry['call']} ({entry['layer']})")
    for entry in report["new_behaviour"]:
        print(f"  new behaviour: {entry['call']} ({entry['layer']})")
    for reason in report["not_completed"]:
        print(f"  not completed: {reason}")
    if report["stopped_leftovers"]:
        print(f"  stopped what the replay left running: {', '.join(report['stopped_leftovers'])}")
    if not scripted:
        print(f"  recorded statuses {report['recorded_statuses']}, replayed status {report['status']}; "
              f"{report['recorded_calls']} calls recorded, {report['replay_calls_in_domain']} replayed inside the "
              "sandbox. Only a scripted check (--script) is a proof that the session ran.")


def _next_check(recording: pathlib.Path) -> pathlib.Path:
    """A new, numbered directory for one replay of the recording."""
    numbers = [int(path.name.removeprefix("check-")) for path in recording.glob("check-*")
               if path.name.removeprefix("check-").isdigit()]
    directory = recording / f"check-{max(numbers, default=0) + 1}"
    directory.mkdir()
    return directory


def _sessions(recording: pathlib.Path) -> list[tuple[pathlib.Path, dict]]:
    """Every session of the recording with its metadata, in the order the sessions were recorded.

    Assumes sessions are the numbered directories under `sessions/`. Raises guard.Refused with
    EXIT_USAGE when there is none, when a session has no readable session.json (a recorder that was
    killed), or when one lacks the keys the check reads.
    """
    numbered = [path for path in (recording / "sessions").glob("*") if path.name.isdigit()]
    sessions = []
    for directory in sorted(numbered, key=lambda path: int(path.name)):
        try:
            meta = json.loads((directory / "session.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise guard.Refused(guard.EXIT_USAGE, f"session {directory} is incomplete ({error}); remove it and "
                                                  "record it again.") from error
        valid = isinstance(meta, dict) and isinstance(meta.get("container_id"), str) \
            and isinstance(meta.get("snapshot"), str)
        if not valid:
            raise guard.Refused(guard.EXIT_USAGE,
                                f"{directory / 'session.json'} does not name its container_id and snapshot.")
        sessions.append((directory, meta))
    if not sessions:
        raise guard.Refused(guard.EXIT_USAGE,
                            f"{recording} holds no recorded session. Record one with phobos-record record first.")
    return sessions


def _starting_state(recording: pathlib.Path, first: dict) -> dict[str, str]:
    """The first session's snapshot as a fingerprint, the files Docker writes itself left out.

    Assumes the snapshot was written by snapshot.take, which keeps those files.
    """
    listing = snapshot.read_listing(recording / first["snapshot"])
    return {path: value for path, value in listing.items() if path not in snapshot.DOCKER_MANAGED}


def _differences(recorded: dict[str, str], current: dict[str, str]) -> list[str]:
    """Every path whose fingerprint differs between the two states, with what differs, sorted.

    Assumes both mappings were made with the same rules, so a difference is a change and not a
    difference in how they were taken. Paths and fingerprints are quoted as Python literals, so a
    name holding a line break cannot make the message say something else.
    """
    differences = []
    for path in sorted(recorded.keys() | current.keys()):
        was = recorded.get(path)
        now = current.get(path)
        if was == now:
            continue
        if was is None:
            differences.append(f"{path!r}: added ({now!r})")
        elif now is None:
            differences.append(f"{path!r}: removed (was {was!r})")
        else:
            differences.append(f"{path!r}: was {was!r}, now {now!r}")
    return differences


def _listed(differences: list[str]) -> str:
    """At most MAX_LISTED_DIFFERENCES differences, one per line, and the number left out."""
    lines = [f"  {difference}" for difference in differences[:MAX_LISTED_DIFFERENCES]]
    rest = len(differences) - MAX_LISTED_DIFFERENCES
    if rest > 0:
        lines.append(f"  and {rest} more")
    return "\n".join(lines)
