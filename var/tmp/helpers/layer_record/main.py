"""The command line of phobos-record, the recording pruner: record a session, generate a policy, replay it as a check.

It is started only through the phobos-record script beside it, in the prune image, and is never
reachable from phobos.sh or any layer: a grading run cannot reach the recorder because the
run-phase image does not hold it.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import signal
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from layer_prune import cfgfile

from layer_record import (
    check,
    diff,
    generate,
    guard,
    observe,
    pty_script,
)

HELP = """\
Records the reference program of an exercise. While it records, the program runs with no sandbox at all: the
recorder grants everything and only watches. Record the instructor's reference program, never an untrusted
submission.

A session runs in the working directory grading uses (the --chdir of TailPhobos.cfg), with the terminal passed
through, or typed from a script with --script. Every path the program touches and every endpoint it reaches is
recorded under /var/tmp/recordings/<name>. generate turns every session of a recording into policy.cfg and
record.json beside them. check replays a session under phobos.sh with the recording's policy, in a new container,
and fails on every refusal of something the recording did. diff lists what a policy lacks for the sessions and what
it grants that no session used; it changes nothing.

A program that traces itself (a debugger, a sanitiser, some profilers) cannot be recorded: strace is its tracer.
Processes a session leaves running are stopped after a short wait, so a daemon (a build tool's, for one) cannot keep
a recording open; run the program without one.
"""

DEFAULT_PHOBOS_HOME = "/var/tmp/opt/core"
RECORDINGS = pathlib.Path("/var/tmp/recordings")
DEFAULT_EXERCISE = pathlib.Path("/srv/phobos-record-exercise")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def main(arguments: list[str] | None = None) -> int:
    """Runs one subcommand and answers the status to exit with.

    Assumes it runs in the prune image as the container's entry point. A refusal is printed with
    its reason and ends with its own status (2 for a wrong use, 3 for the wrong place).
    """
    given = sys.argv[1:] if arguments is None else arguments
    try:
        return _run(given)
    except guard.Refused as refused:
        print(f"phobos-record: {refused.message}", file=sys.stderr)
        return refused.status


class _Parser(argparse.ArgumentParser):
    """An argument parser whose help begins with the warning, before even the usage line."""

    def format_help(self) -> str:
        """The warning of the plan's A.10, then argparse's own help."""
        return HELP + "\n" + super().format_help()


def build_parser() -> argparse.ArgumentParser:
    """The argument parser, whose help opens with the warning of the plan's A.10."""
    parser = _Parser(prog="phobos-record", allow_abbrev=False)
    subcommands = parser.add_subparsers(dest="subcommand", required=True)
    recording = subcommands.add_parser("record", help="record one session of a program", allow_abbrev=False)
    _common(recording)
    recording.add_argument("--sample", action="store_true",
                           help="sample the session's processes, so generate --limits can derive limits from it")
    replay = subcommands.add_parser("check", help="replay a session under phobos.sh and fail on every regression",
                                    allow_abbrev=False)
    _common(replay)
    replay.add_argument("--same-container", action="store_true",
                        help="replay in a container that is not fresh; a pass may then rest on leftovers")
    replay.add_argument("--resolver", help="the resolver phobos.sh passes to the network layer")
    producing = subcommands.add_parser("generate", help="write policy.cfg and record.json from the sessions",
                                       allow_abbrev=False)
    producing.add_argument("--name", default="default", help="the recording's name under /var/tmp/recordings")
    producing.add_argument("--limits", action="store_true", help="derive [limits] from the sampled sessions")
    producing.add_argument("--memory-pinned", action="store_true",
                           help="assert the program pins its address space, so mem_mb is derived too")
    comparing = subcommands.add_parser("diff", help="compare recorded sessions with an existing policy",
                                       allow_abbrev=False)
    comparing.add_argument("--name", action="append", help="a recording to read; repeat to merge several")
    comparing.add_argument("--policy", type=pathlib.Path, required=True, help="the policy to compare with")
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    """The options record and check share, and the command after --."""
    parser.add_argument("--name", default="default", help="the recording's name under /var/tmp/recordings")
    parser.add_argument("--exercise", type=pathlib.Path, help="the exercise to copy into the working directory")
    parser.add_argument("--script", type=pathlib.Path, help="type the session from this script")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- the program and its arguments")


def _run(given: list[str]) -> int:
    """The subcommand's work, raising guard.Refused for every refusal of the plan's A.10."""
    subcommand = given[0] if given else ""
    guard.refuse_grading_options(given, allowed=frozenset({"--resolver"}) if subcommand == "check" else frozenset())
    options = build_parser().parse_args(given)
    home = pathlib.Path(os.environ.get("PHOBOS_HOME", DEFAULT_PHOBOS_HOME))
    guard.refuse_outside_prune_image(home)
    guard.refuse_when_traced(_own_status())
    if options.subcommand == "generate":
        return _generate(options, home)
    if options.subcommand == "diff":
        return _diff(options)
    command = options.command[1:] if options.command[:1] == ["--"] else options.command
    if not command:
        raise guard.Refused(guard.EXIT_USAGE, "name the program to run after --, for example: record -- python3 -q")
    workdir = _workdir(home)
    guard.refuse_layer_command(command, home, workdir)
    _recording_name(options.name)
    _check_script(options.script)
    if options.exercise is not None and not options.exercise.is_dir():
        raise guard.Refused(guard.EXIT_USAGE, f"the exercise {options.exercise} is not a directory")
    recording = RECORDINGS / options.name
    exercise = options.exercise or (DEFAULT_EXERCISE if DEFAULT_EXERCISE.is_dir() else None)
    if options.subcommand == "check":
        return check.run(recording, command, options.script, options.same_container, options.resolver, exercise, home)
    observe.require_strace()
    listing = observe.prepare_container(recording, workdir, exercise)
    result = observe.record_session(command, recording, workdir, options.script, listing, options.sample)
    if result.expectations_met is False:
        print(f"phobos-record: an expectation of {options.script} was not met; session {result.number} is "
              "incomplete", file=sys.stderr)
        return pty_script.EXPECT_FAILED
    if result.signal is not None:
        _end_by(result.signal)
    return result.status


def _generate(options: argparse.Namespace, home: pathlib.Path) -> int:
    """Writes policy.cfg and record.json for a recording and answers generate's status."""
    recording = RECORDINGS / _recording_name(options.name)
    try:
        return generate.write(recording, options.limits, options.memory_pinned, generate.policysystem_gate(home))
    except (generate.ImageMismatch, ValueError, OSError) as error:
        raise guard.Refused(guard.EXIT_USAGE, f"cannot generate from {recording}: {error}") from error


def _diff(options: argparse.Namespace) -> int:
    """Prints what the recordings need that the policy lacks and what it grants that no session used."""
    try:
        policy = cfgfile.read_policy(options.policy.read_text(encoding="utf-8"))
        recordings = [generate.load(RECORDINGS / _recording_name(name)) for name in options.name or ["default"]]
    except (generate.ImageMismatch, ValueError, OSError) as error:
        raise guard.Refused(guard.EXIT_USAGE, f"cannot compare: {error}") from error
    print(diff.render(diff.compare(recordings, policy)), end="")
    return 0


def _recording_name(name: str) -> str:
    """The recording name, refused as a wrong use when it is not letters, digits and . _ -."""
    if not NAME.match(name):
        raise guard.Refused(guard.EXIT_USAGE, f"{name!r} is not a recording name: letters, digits, . _ - only")
    return name


def _workdir(home: pathlib.Path) -> pathlib.Path:
    """The tail's working directory, refused as the wrong place when the tail flags name none."""
    try:
        return observe.tail_chdir(home / "TailPhobos.cfg")
    except (OSError, ValueError) as error:
        raise guard.Refused(guard.EXIT_ENVIRONMENT, f"phobos-record needs the tail flags of the prune image: {error}") \
            from error


def _check_script(script: pathlib.Path | None) -> None:
    """Refuses a script that is missing or malformed before anything is created."""
    if script is None:
        return
    try:
        pty_script.parse(script.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise guard.Refused(guard.EXIT_USAGE, f"the script {script} cannot be used: {error}") from error


def _end_by(number: int) -> None:
    """Ends this process by the signal that ended the recorded command, so its caller sees the same.

    Assumes the signal's default action ends a process; one whose default does not returns, and the
    caller then exits with the shell's status for it.
    """
    signal.signal(number, signal.SIG_DFL)
    os.kill(os.getpid(), number)


def _own_status() -> str:
    """The text of this process's /proc status, or empty where there is none."""
    try:
        return pathlib.Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return ""


if __name__ == "__main__":
    sys.exit(main())
