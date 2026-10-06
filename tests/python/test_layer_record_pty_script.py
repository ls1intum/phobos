"""Checks that a recorded session can be typed from a script through a real pseudo-terminal.

A scripted session is what makes a recording repeatable and what lets the replay check prove
anything: an expectation that is not met must fail the session, never pass it quietly.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_record import pty_script


def test_a_script_is_parsed_line_by_line_and_comments_are_skipped():
    actions = pty_script.parse("# setup\nsend import os\nexpect ^OK\nkey ctrl-c\nsleep 1\n")
    assert [action.kind for action in actions] == ["send", "expect", "key", "sleep"]
    assert actions[0].value == "import os"


def test_the_text_to_send_keeps_its_inner_spacing():
    [action] = pty_script.parse("send print(1,  2)\n")
    assert action.value == "print(1,  2)"


def test_a_bare_send_is_an_enter():
    [action] = pty_script.parse("send\n")
    assert action == pty_script.Action("send", "")


def test_an_unknown_action_is_refused():
    with pytest.raises(ValueError, match="line 1"):
        pty_script.parse("type x\n")


@pytest.mark.parametrize("text", ["key ctrl-q\n", "sleep soon\n", "sleep -1\n", "expect (\n", "expect\n"])
def test_a_malformed_action_is_refused_with_its_line(text):
    with pytest.raises(ValueError, match="line 2"):
        pty_script.parse("# first\n" + text)


def test_a_session_runs_in_a_terminal_and_an_expectation_must_hold(tmp_path):
    actions = pty_script.parse('send import sys; print("OK-" + str(sys.stdin.isatty()))\nexpect OK-True\nsend exit()\n')
    assert pty_script.run([sys.executable, "-q", "-i"], actions, tmp_path, tmp_path / "t.txt") == 0
    assert "OK-True" in (tmp_path / "t.txt").read_text()


def test_the_commands_own_status_is_returned(tmp_path):
    actions = pty_script.parse('send import sys; sys.exit(7)\n')
    assert pty_script.run([sys.executable, "-q", "-i"], actions, tmp_path, tmp_path / "t.txt") == 7


def test_the_session_runs_in_the_directory_it_is_given(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    actions = pty_script.parse('send import os; print("OK-" + os.path.basename(os.getcwd()))\nexpect OK-work\n'
                               'send exit()\n')
    assert pty_script.run([sys.executable, "-q", "-i"], actions, work, tmp_path / "t.txt") == 0


def test_an_expectation_that_never_holds_fails_the_session(tmp_path):
    actions = pty_script.parse("expect never-printed\n")
    assert pty_script.run(["cat"], actions, tmp_path, tmp_path / "t.txt", step_seconds=1.0) == pty_script.EXPECT_FAILED


def test_ctrl_c_reaches_the_program_through_the_terminal(tmp_path):
    actions = pty_script.parse('send import time\nsend time.sleep(30)\nsleep 0.5\nkey ctrl-c\nexpect KeyboardInterrupt\n'
                               'send print("OK-" + "C1")\nexpect OK-C1\nsend exit()\n')
    assert pty_script.run([sys.executable, "-q", "-i"], actions, tmp_path, tmp_path / "t.txt", step_seconds=20.0) == 0


def test_a_program_that_never_ends_after_the_script_is_hung_up_on(tmp_path):
    actions = pty_script.parse("send hello\nexpect hello\n")
    status = pty_script.run(["cat"], actions, tmp_path, tmp_path / "t.txt", step_seconds=1.0)
    assert status != 0
    assert status != pty_script.EXPECT_FAILED
