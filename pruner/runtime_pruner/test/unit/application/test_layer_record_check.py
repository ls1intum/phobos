"""Checks the replay check: where it may run, how it judges a refusal, and when a replay counts.

A replay in the recording's own container, or in one that something changed, can pass on what
was left behind. The check therefore compares the container's starting state with the
recording's instead of taking freshness on trust, and refuses a container that is not fresh
unless the caller explicitly opts in (Markus's decision 12 in the plan). A refusal is judged by
the accesses its call needed, never by its name, and a replay that did not run the session fails
however few refusals it had.
"""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from runtime_pruner.src.application import check
from runtime_pruner.src.domain import needs
from runtime_pruner.src.infrastructure import guard, snapshot
from shared.src.domain import attribute, strace_parse

START = {"/": "d 0755", "/etc": "d 0755", "/etc/os-release": "f 0644 386 1700000000000000000",
         "/var/tmp/testing-dir": "d 0755", "/var/tmp/testing-dir/old.txt": "f 0644 4 1700000000000000000"}


def recording_with_session(directory: pathlib.Path, container_id: str, fingerprint: dict[str, str],
                           number: int = 1) -> pathlib.Path:
    """Writes a recording directory holding one session recorded in the given container.

    The snapshot also lists the three files Docker writes into every container, as a real one
    taken by snapshot.take does, so the comparison has to leave them out to call a container
    fresh.
    """
    recording = directory / "recording"
    session = recording / "sessions" / str(number)
    session.mkdir(parents=True)
    (recording / "snapshots").mkdir(exist_ok=True)
    listed = fingerprint | {path: "f 0644 12 1700000000000000000" for path in snapshot.DOCKER_MANAGED}
    lines = "".join(f"{value}\t{path}\n" for path, value in sorted(listed.items()))
    (recording / "snapshots" / f"{container_id}.txt").write_text(lines)
    meta = {"container_id": container_id, "snapshot": f"snapshots/{container_id}.txt"}
    (session / "session.json").write_text(json.dumps(meta))
    return recording


def test_another_container_with_the_recordings_starting_state_is_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "bbb", START, same_container=False) == "fresh-container"


def test_a_fresh_container_stays_fresh_with_the_opt_in(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "bbb", START, same_container=True) == "fresh-container"


def test_an_added_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/var/tmp/testing-dir/out.txt": "f 0644 1 1700000000000000001"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "/var/tmp/testing-dir/out.txt" in refused.value.message
    assert check.mode(recording, "bbb", changed, same_container=True) == "changed-container"


def test_a_removed_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = {path: value for path, value in START.items() if path != "/var/tmp/testing-dir/old.txt"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/var/tmp/testing-dir/old.txt" in refused.value.message


def test_a_modified_file_at_an_existing_path_is_not_called_fresh(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {"/etc/os-release": "f 0644 391 1700000000500000000"}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/etc/os-release" in refused.value.message


def test_at_most_twenty_differences_are_named(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    changed = START | {f"/var/tmp/leftover-{number:02d}": "f 0644 1 1" for number in range(25)}
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "bbb", changed, same_container=False)
    assert "/var/tmp/leftover-19" in refused.value.message
    assert "/var/tmp/leftover-20" not in refused.value.message
    assert "5 more" in refused.value.message


def test_the_fingerprint_sees_contents_change_through_size_and_time_and_skips_docker_files(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "os-release").write_text("A\n")
    (root / "etc" / "hostname").write_text("one\n")
    before = snapshot.fingerprint(root=root)
    (root / "etc" / "os-release").write_text("AB\n")
    (root / "etc" / "hostname").write_text("another\n")
    after = snapshot.fingerprint(root=root)
    assert before["/etc/os-release"] != after["/etc/os-release"]
    assert "/etc/hostname" not in before


def test_the_recordings_own_container_is_refused_without_the_opt_in(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    with pytest.raises(guard.Refused) as refused:
        check.mode(recording, "aaa", START, same_container=False)
    assert refused.value.status == guard.EXIT_ENVIRONMENT
    assert "aaa" in refused.value.message


def test_a_container_any_session_ran_in_is_the_recordings_own(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    recording_with_session(tmp_path, container_id="ccc", fingerprint=START, number=2)
    with pytest.raises(guard.Refused):
        check.mode(recording, "ccc", START, same_container=False)


def test_the_opt_in_runs_in_the_same_container_and_says_so(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    assert check.mode(recording, "aaa", START, same_container=True) == "same-container"
    assert "can make it pass where a fresh container would fail" in check.NOT_FRESH_WARNING


def test_the_first_session_decides_the_starting_state(tmp_path):
    recording = recording_with_session(tmp_path, container_id="aaa", fingerprint=START)
    later = START | {"/var/tmp/testing-dir/out.txt": "f 0644 1 1"}
    recording_with_session(tmp_path, container_id="ccc", fingerprint=later, number=10)
    assert check.mode(recording, "bbb", START, same_container=False) == "fresh-container"


def test_a_recording_without_a_session_is_refused(tmp_path):
    (tmp_path / "empty" / "sessions").mkdir(parents=True)
    with pytest.raises(guard.Refused) as refused:
        check.mode(tmp_path / "empty", "bbb", START, same_container=False)
    assert refused.value.status == guard.EXIT_USAGE


RESTRICT = "20 landlock_restrict_self(3, 0) = 0"


class Existing:
    """A snapshot in which exactly the given paths existed."""

    def __init__(self, *paths: str):
        """Holds the paths given."""
        self.paths = frozenset(paths)

    def existed(self, path: str) -> bool:
        """Whether the path was one of those given."""
        return path in self.paths


SNAPSHOT = Existing("/a", "/b", "/a/x", "/w", "/w/data.txt", "/usr/bin/python3")


def denials_of(*lines: str) -> list[check.Refusal]:
    """The replay refusals a trace of the given lines holds, each with the pairs of its call."""
    trace = strace_parse.parse_trace(lines)
    return [check.Refusal(call=call, denial=denial, pairs=frozenset(needs.pairs_of_call(call, SNAPSHOT, cwd)))
            for call, denial, cwd in attribute.refusals(trace, "/w")]


def trace_and_calls(*lines: str) -> tuple[strace_parse.Trace, list]:
    """The parsed trace of the given lines and every call in it."""
    return strace_parse.parse_trace(lines), list(strace_parse.iter_calls(lines))


def test_a_refusal_of_an_access_the_recording_needed_is_a_regression():
    recorded = {("/opt/tool/bin/run", "execute"), ("/opt/tool/bin/run", "read")}
    replay = denials_of(RESTRICT, '20 execve("/opt/tool/bin/run", ["run"], 0x0 /* 1 var */) = -1 EACCES (Permission denied)')
    assert len(check.compare(recorded, replay).regressions) == 1


def test_a_write_refused_where_the_recording_only_read_is_new_behaviour_not_harmless():
    recorded = {("/w/data.txt", "read")}
    replay = denials_of(RESTRICT, '20 openat(AT_FDCWD</w>, "/w/data.txt", O_WRONLY) = -1 EACCES (Permission denied)')
    comparison = check.compare(recorded, replay)
    assert comparison.regressions == []
    assert comparison.harmless_fixed == []
    assert len(comparison.new_behaviour) == 1


def test_a_refused_unix_connect_that_failed_while_recording_too_is_harmless():
    replay = denials_of(RESTRICT, '20 connect(3<UNIX-STREAM:[2]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)'
                                  ' = -1 EACCES (Permission denied)')
    comparison = check.compare(set(), replay)
    assert len(comparison.harmless_fixed) == 1
    assert comparison.regressions == []


def test_a_fixed_refusal_of_an_operation_that_worked_while_recording_is_a_regression():
    recorded = {("unix:/run/dbus/system_bus_socket", "connect")}
    replay = denials_of(RESTRICT, '20 connect(3<UNIX-STREAM:[2]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"},'
                                  ' 110) = -1 EACCES (Permission denied)')
    assert len(check.compare(recorded, replay).regressions) == 1


def test_a_refused_setsid_that_worked_while_recording_is_a_regression():
    assert len(check.compare({("setsid", "call")}, denials_of(RESTRICT, "20 setsid() = -1 EPERM (Operation not permitted)"))
               .regressions) == 1


def test_a_grant_on_one_side_of_a_move_does_not_excuse_the_other():
    replay = denials_of(RESTRICT, '20 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0) = -1 EXDEV (Invalid cross-device link)')
    [refusal] = replay
    assert ("/b", "create") in refusal.pairs
    assert ("/a", "create") not in refusal.pairs
    assert ("/b", "delete") not in refusal.pairs
    assert check.compare({("/a", "delete")}, replay).regressions == [refusal]
    assert check.compare({("/a", "create"), ("/b", "delete")}, replay).regressions == []


def test_a_refused_connect_to_a_recorded_endpoint_is_a_regression_and_another_port_is_not():
    line = ('20 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16)'
            ' = -1 EACCES (Permission denied)')
    assert len(check.compare({("192.0.2.7:80 tcp", "connect")}, denials_of(RESTRICT, line)).regressions) == 1
    assert check.compare({("192.0.2.7:443 tcp", "connect")}, denials_of(RESTRICT, line)).regressions == []


def test_a_refusal_before_any_restriction_is_not_counted():
    assert denials_of('20 openat(AT_FDCWD</w>, "/x", O_RDONLY) = -1 EACCES (Permission denied)') == []


def test_a_replay_phobos_stopped_before_the_command_did_not_run_the_session():
    trace, calls = trace_and_calls('20 execve("/var/tmp/opt/core/phobos.sh", ["phobos.sh"], 0x0 /* 1 var */) = 0')
    reasons = check.completed(trace, calls, ["python3"], 11, "Policy invalid: x. (PHB-EPOLICY)", {0}, None)
    assert any("Phobos stopped" in reason for reason in reasons)


def test_a_replay_in_which_the_command_never_started_did_not_run_the_session():
    trace, calls = trace_and_calls(RESTRICT, '20 execve("/usr/bin/cat", ["cat"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, calls, ["python3"], 0, "", {0}, True)


def test_an_execve_of_the_command_outside_the_domain_does_not_count():
    trace, calls = trace_and_calls('19 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0', RESTRICT)
    assert check.completed(trace, calls, ["python3"], 0, "", {0}, True)


def test_a_replay_whose_script_expectation_failed_did_not_run_the_session():
    trace, calls = trace_and_calls(RESTRICT, '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, calls, ["python3"], 0, "", {0}, False)


def test_a_replay_with_another_status_than_every_recording_did_not_run_the_session():
    trace, calls = trace_and_calls(RESTRICT, '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, calls, ["python3"], 1, "", {0}, True)


def test_a_complete_replay_has_no_reason():
    trace, calls = trace_and_calls(RESTRICT, '20 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, calls, ["python3"], 0, "", {0}, True) == []
    assert check.completed(trace, calls, ["/usr/bin/python3", "-q"], 4, "", {4}, True) == []


def test_an_execve_of_the_commands_name_before_the_same_process_restricted_itself_does_not_count():
    trace, calls = trace_and_calls('20 execve("/usr/bin/bash", ["bash"], 0x0 /* 1 var */) = 0', RESTRICT,
                                   '20 execve("/usr/bin/cat", ["cat"], 0x0 /* 1 var */) = 0')
    assert check.completed(trace, calls, ["bash"], 0, "", {0}, True)
    assert check.completed(trace, calls, ["cat"], 0, "", {0}, True) == []


def test_a_child_of_a_restricted_process_is_inside_the_domain_from_its_first_call():
    trace, calls = trace_and_calls(RESTRICT, "20 clone(child_stack=NULL, flags=SIGCHLD) = 21",
                                   '21 execve("/usr/bin/python3", ["python3"], 0x0 /* 1 var */) = 0')
    assert [call.pid for call in check.domain_calls(trace, calls)] == [20, 21]
    assert check.completed(trace, calls, ["python3"], 0, "", {0}, True) == []


SESSIONS = [
    {"command": ["python3", "-q"], "status": 0, "script_sha256": "aa", "expectations_met": True},
    {"command": ["python3", "-q"], "status": 3, "script_sha256": None, "expectations_met": None},
    {"command": ["python3", "-q"], "status": 137, "script_sha256": "aa", "expectations_met": False},
    {"command": ["sh"], "status": 9, "script_sha256": None, "expectations_met": None},
]


def test_a_replay_by_hand_is_held_to_every_complete_session_of_its_command(tmp_path):
    statuses, reasons = check._recorded_statuses(SESSIONS, ["python3", "-q"], None)
    assert statuses == {0, 3}
    assert reasons == []


def test_a_scripted_replay_is_held_to_the_sessions_of_its_script(tmp_path, monkeypatch):
    script = tmp_path / "s.script"
    script.write_text("expect x\n")
    monkeypatch.setattr(check.observe, "script_digest", lambda path: "aa")
    statuses, reasons = check._recorded_statuses(SESSIONS, ["python3", "-q"], script)
    assert statuses == {0}
    assert reasons == []


def test_a_script_no_session_was_typed_from_is_a_reason(tmp_path, monkeypatch):
    script = tmp_path / "s.script"
    script.write_text("expect x\n")
    monkeypatch.setattr(check.observe, "script_digest", lambda path: "bb")
    statuses, reasons = check._recorded_statuses(SESSIONS, ["python3", "-q"], script)
    assert statuses == set()
    assert reasons


def test_another_command_than_any_recorded_one_is_a_reason():
    statuses, reasons = check._recorded_statuses(SESSIONS, ["true"], None)
    assert statuses == set()
    assert any("no recorded session ran" in reason for reason in reasons)


def test_a_session_without_its_metadata_is_refused_cleanly(tmp_path):
    (tmp_path / "recording" / "sessions" / "1").mkdir(parents=True)
    with pytest.raises(guard.Refused) as refused:
        check.mode(tmp_path / "recording", "bbb", START, same_container=False)
    assert refused.value.status == guard.EXIT_USAGE
    assert "incomplete" in refused.value.message


def test_a_session_whose_snapshot_is_not_named_is_refused(tmp_path):
    session = tmp_path / "recording" / "sessions" / "1"
    session.mkdir(parents=True)
    (session / "session.json").write_text(json.dumps({"container_id": "aaa", "snapshot": None}))
    with pytest.raises(guard.Refused):
        check.mode(tmp_path / "recording", "bbb", START, same_container=False)
