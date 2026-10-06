"""The recorder's refusals, so that it is never mistaken for grading or run where grading runs.

These are safeguards against a mistake, not containment. The guarantee is structural: nothing
under core/ reaches the recorder, and the run-phase image holds neither it nor strace. What is
checked here is narrow and says so: a grading option given to the recorder, a command that names
a file of the layers, an image that does not have the prune image's shape, and a recorder that is
itself being traced. A wrapper script or `bash -c` that starts the layers is not caught.
"""

from __future__ import annotations

import os
import pathlib
import re
import shutil

# Wrong use of the command line: a grading option, or the layers given as the command.
EXIT_USAGE = 2

# The wrong place to record: not the prune image, or a recorder that is itself traced.
EXIT_ENVIRONMENT = 3

# The options of phobos.sh that configure or switch off a layer. Given to the recorder, each one
# says the caller expects a sandbox, and the recorder applies none.
GRADING_OPTIONS = frozenset({
    "--config",
    "-c",
    "--resolver",
    "--no-timeoutsystem-restriction",
    "-ntr",
    "--no-networksystem-restriction",
    "-nnr",
    "--no-resourcesystem-restriction",
    "-nrr",
    "--no-filesystem-restriction",
    "-nfr",
    "--no-restriction",
    "-nr",
})

# The base the prune image ships in place of every other base (the layer pruner's Task 3.1).
PRUNE_BASE = "BasePrune.cfg"

GRADING_MESSAGE = ("phobos-record records a program with no sandbox at all; it does not grade. "
                   "Grade with phobos.sh --config <file>.")

TRACER_PID = re.compile(r"^TracerPid:\s*(\d+)\s*$", re.MULTILINE)


class Refused(Exception):
    """A refusal to record, with the exit status the recorder ends with and the reason."""

    def __init__(self, status: int, message: str):
        """Keeps the status and the message; assumes the message is a full sentence for a person."""
        super().__init__(message)
        self.status = status
        self.message = message


def refuse_grading_options(arguments: list[str], allowed: frozenset[str] = frozenset()) -> None:
    """Refuses a phobos.sh grading option among the recorder's own arguments.

    Assumes the arguments are the recorder's command line without the program name, and that
    everything after the first `--` belongs to the recorded command, so it is not looked at.
    An option given as `--option=value` is refused like `--option value`. `allowed` names options
    a subcommand takes on purpose, as the replay check takes --resolver for phobos.sh.
    """
    for argument in arguments:
        if argument == "--":
            return
        name = argument.split("=", 1)[0]
        if name in allowed:
            continue
        if argument in GRADING_OPTIONS or name in GRADING_OPTIONS:
            raise Refused(EXIT_USAGE, f"{GRADING_MESSAGE} (refused option: {argument})")


def refuse_outside_prune_image(phobos_home: pathlib.Path) -> None:
    """Refuses to run unless PHOBOS_HOME has the prune image's shape.

    Assumes the prune image holds BasePrune.cfg as its only Base*.cfg beside phobos.sh, as the
    layer pruner's image does. That catches the run-phase image started by mistake; it proves
    nothing about an image built to look the same.
    """
    if not (phobos_home / PRUNE_BASE).is_file():
        raise Refused(EXIT_ENVIRONMENT,
                      f"phobos-record runs only in the prune image: {phobos_home / PRUNE_BASE} is missing, "
                      "so this looks like an image an exercise is graded in.")
    others = sorted(path.name for path in phobos_home.glob("Base*.cfg") if path.name != PRUNE_BASE)
    if others:
        raise Refused(EXIT_ENVIRONMENT,
                      f"phobos-record runs only in the prune image: {phobos_home} also holds "
                      f"{', '.join(others)}, which the prune image never ships.")


def refuse_layer_command(command: list[str], phobos_home: pathlib.Path, cwd: pathlib.Path | None = None) -> None:
    """Refuses a command any of whose words resolves to a file under PHOBOS_HOME.

    Assumes relative words are relative to `cwd`, the directory the command will run in (the
    current directory when None), and that the first word is also looked up in PATH, as a shell
    would. That catches `phobos.sh`, a link to it and `sh phobos.sh`; a wrapper script or `bash -c`
    that starts the layers is not caught.
    """
    home = os.path.realpath(phobos_home)
    base = os.fspath(cwd) if cwd is not None else os.getcwd()
    for word in _candidate_files(command):
        resolved = os.path.realpath(os.path.join(base, word))
        if os.path.isfile(resolved) and os.path.commonpath([home, resolved]) == home:
            raise Refused(EXIT_USAGE,
                          f"phobos-record does not record Phobos itself: {word} is part of the layers under "
                          f"{phobos_home}. {GRADING_MESSAGE}")


def refuse_when_traced(status_text: str) -> None:
    """Refuses to record when the recorder itself is traced, since strace could not then attach.

    Assumes status_text is the text of /proc/self/status; a text without a TracerPid line, as on
    a system without procfs, counts as untraced.
    """
    match = TRACER_PID.search(status_text)
    if match and int(match.group(1)) != 0:
        raise Refused(EXIT_ENVIRONMENT,
                      f"phobos-record is itself being traced (TracerPid {match.group(1)}), so the session's "
                      "own tracer could not attach. Start it without a debugger or tracer.")


def _candidate_files(command: list[str]) -> list[str]:
    """Every word of the command as a path, and the first word as PATH would find it.

    Assumes nothing about the words; a word that names no file simply resolves to nothing
    under PHOBOS_HOME.
    """
    candidates = list(command)
    if command:
        found = shutil.which(command[0])
        if found:
            candidates.append(found)
    return candidates
