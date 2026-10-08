"""Checks how a strace -f log becomes the system calls the pruner reasons about."""

from __future__ import annotations

import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import strace_parse

FIXTURES = REPO_ROOT / "tests" / "python" / "fixtures" / "strace"


def test_a_refused_openat_keeps_its_path_and_errno():
    line = '210 openat(AT_FDCWD</var/tmp/testing-dir>, "/var/log/dpkg.log", O_RDONLY) = -1 EACCES (Permission denied)'
    call = strace_parse.parse_line(line)
    assert call.pid == 210
    assert call.name == "openat"
    assert call.result == -1
    assert call.errno == "EACCES"
    assert '"/var/log/dpkg.log"' in call.arguments


def test_a_successful_call_with_a_decorated_result_has_no_errno():
    line = '16 openat(AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>'
    call = strace_parse.parse_line(line)
    assert call.result == 3
    assert call.errno is None
    assert call.arguments == 'AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC'


def test_a_call_that_never_returned_has_no_result():
    call = strace_parse.parse_line("454   exit_group(1)                     = ?")
    assert call.name == "exit_group"
    assert call.result is None
    assert call.errno is None


def test_an_unfinished_call_is_joined_with_its_resumption():
    lines = [
        '7 openat(AT_FDCWD</w>, "a", O_RDONLY <unfinished ...>',
        "8 +++ exited with 0 +++",
        "7 <... openat resumed>) = -1 EACCES (Permission denied)",
    ]
    trace = strace_parse.parse_trace(lines)
    refused = [call for call in trace.syscalls if call.name == "openat"]
    assert len(refused) == 1
    assert refused[0].errno == "EACCES"
    assert strace_parse.path_argument(refused[0], 1) == "a"


def test_a_thread_created_with_clone_thread_belongs_to_its_creators_thread_group():
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
        "101 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 105",
        '105 openat(AT_FDCWD</w>, "/proc/self/status", O_RDONLY) = -1 EACCES (Permission denied)',
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.thread_group[105] == 101
    assert trace.thread_group[101] == 101


def test_a_thread_whose_creating_clone_is_printed_late_still_passes_its_group_on():
    lines = [
        "100 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND, exit_signal=0}, 88 <unfinished ...>",
        "101 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND, exit_signal=0}, 88) = 102",
        "100 <... clone3 resumed>) = 101",
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.thread_group == {100: 100, 101: 100, 102: 100}


def test_a_process_id_handed_out_twice_is_refused_rather_than_guessed_at():
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
    ]
    with pytest.raises(strace_parse.ReusedProcessId):
        strace_parse.parse_trace(lines)


def test_a_clone_returning_the_root_process_id_is_refused():
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
        "100 exit_group(0) = ?",
        "101 clone(child_stack=NULL, flags=SIGCHLD) = 100",
    ]
    with pytest.raises(strace_parse.ReusedProcessId):
        strace_parse.parse_trace(lines)


def test_only_processes_after_landlock_restrict_self_are_in_the_domain():
    lines = [
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 101",
        "101 landlock_restrict_self(3, 0) = 0",
        "101 clone(child_stack=NULL, flags=SIGCHLD) = 102",
        "100 clone(child_stack=NULL, flags=SIGCHLD) = 103",
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.domain_pids == frozenset({101, 102})


def test_a_refusal_before_the_process_restricted_itself_is_outside_the_domain():
    lines = [
        '101 openat(AT_FDCWD</w>, "/etc/a", O_RDONLY) = -1 EACCES (Permission denied)',
        "101 landlock_restrict_self(3, 0) = 0",
        '101 openat(AT_FDCWD</w>, "/etc/b", O_RDONLY) = -1 EACCES (Permission denied)',
    ]
    trace = strace_parse.parse_trace(lines)
    verdicts = [(strace_parse.path_argument(call, 1), trace.in_domain(index))
                for index, call in enumerate(trace.syscalls) if call.name == "openat"]
    assert verdicts == [("/etc/a", False), ("/etc/b", True)]


def test_a_child_whose_clone_result_is_printed_late_is_still_in_the_domain():
    lines = [
        "101 landlock_restrict_self(3, 0) = 0",
        "101 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>",
        '102 openat(AT_FDCWD</w>, "/etc/c", O_RDONLY) = -1 EACCES (Permission denied)',
        "101 <... clone resumed>) = 102",
    ]
    trace = strace_parse.parse_trace(lines)
    [index] = [index for index, call in enumerate(trace.syscalls) if call.name == "openat"]
    assert trace.in_domain(index)


def test_the_network_layers_port_only_domain_does_not_put_the_filesystem_layer_in_the_domain():
    lines = [
        ('369 execve("/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem", '
         '["/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem", "--no-filesystem", "--close-bind", '
         '"--", "/var/tmp/opt/core/phobos-filesystem.sh"], 0xffff /* 14 vars */) = 0'),
        "369 landlock_restrict_self(3<anon_inode:[landlock-ruleset]>, 0) = 0",
        "369 clone(child_stack=NULL, flags=SIGCHLD) = 400",
        '400 connect(3<socket:[1]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 EACCES (Permission denied)',
        "369 clone(child_stack=NULL, flags=SIGCHLD) = 455",
        ('455 execve("/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem", '
         '["/var/tmp/opt/core/phobos-landlock-filesystem-and-networksystem", "--rights=rx", "/usr", "--", "/bin/cat"], '
         "0xffff /* 14 vars */) = 0"),
        "455 landlock_restrict_self(3<anon_inode:[landlock-ruleset]>, 0) = 0",
        '455 execve("/bin/cat", ["/bin/cat", "/etc/hostname"], 0xffff /* 14 vars */) = 0',
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.domain_pids == frozenset({455})


def test_with_only_the_port_only_domain_its_processes_are_the_domain():
    lines = [
        ('369 execve("/x/phobos-landlock-filesystem-and-networksystem", '
         '["/x/phobos-landlock-filesystem-and-networksystem", "--no-filesystem", "--", "/bin/true"], 0x1 /* 1 var */) = 0'),
        "369 landlock_restrict_self(3<anon_inode:[landlock-ruleset]>, 0) = 0",
        "369 clone(child_stack=NULL, flags=SIGCHLD) = 370",
    ]
    trace = strace_parse.parse_trace(lines)
    assert trace.domain_pids == frozenset({369, 370})


def test_only_refused_calls_and_the_named_successes_are_kept():
    lines = [
        '16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>',
        '16 openat(AT_FDCWD</w>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)',
        "16 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 3<socket:[1]>",
    ]
    kept = strace_parse.parse_trace(lines).syscalls
    assert [(call.name, call.errno) for call in kept] == [("openat", "EACCES"), ("socket", None)]
    assert all(call.errno or call.name in strace_parse.KEPT_SUCCESSES for call in kept)


def test_an_escaped_path_is_unescaped():
    line = r'5 openat(AT_FDCWD</w>, "/tmp/a\"b\nc", O_RDONLY) = -1 EACCES (Permission denied)'
    call = strace_parse.parse_line(line)
    assert strace_parse.path_argument(call, 1) == '/tmp/a"b\nc'


def test_octal_and_hexadecimal_escapes_are_unescaped():
    line = r'5 openat(AT_FDCWD</w>, "/tmp/\303\251\x41\\", O_RDONLY) = -1 EACCES (Permission denied)'
    call = strace_parse.parse_line(line)
    assert strace_parse.path_argument(call, 1) == "/tmp/éA\\"


def test_a_comma_inside_a_string_or_a_structure_does_not_split_an_argument():
    line = ('5 connect(3<socket:[9]>, {sa_family=AF_INET, sin_port=htons(80), '
            'sin_addr=inet_addr("10.0.0.1")}, 16) = -1 EACCES (Permission denied)')
    call = strace_parse.parse_line(line)
    assert strace_parse.split_arguments(call.arguments) == [
        "3<socket:[9]>", '{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}', "16"]


def test_an_arrow_in_a_socket_decoration_does_not_close_a_bracket():
    line = '16 write(3<TCP:[172.17.0.2:32972->172.66.157.237:443]>, "\\x16\\x03\\x01", 3) = 3'
    call = strace_parse.parse_line(line)
    assert strace_parse.split_arguments(call.arguments) == [
        "3<TCP:[172.17.0.2:32972->172.66.157.237:443]>", '"\\x16\\x03\\x01"', "3"]


def test_an_in_out_length_does_not_close_a_bracket():
    line = ('16 getsockname(3<TCP:[127.0.0.1:4]>, {sa_family=AF_INET, sin_port=htons(4), '
            'sin_addr=inet_addr("127.0.0.1")}, [128 => 16]) = 0')
    call = strace_parse.parse_line(line)
    assert len(strace_parse.split_arguments(call.arguments)) == 3


def test_a_decorated_descriptor_names_its_path():
    call = strace_parse.parse_line('5 openat(3</srv/a b>, "c", O_RDONLY) = -1 EACCES (Permission denied)')
    assert strace_parse.descriptor_path(call, 0) == "/srv/a b"
    undecorated = strace_parse.parse_line('5 openat(AT_FDCWD, "c", O_RDONLY) = -1 EACCES (Permission denied)')
    assert strace_parse.descriptor_path(undecorated, 0) is None


def test_status_lines_and_halves_are_known_non_calls():
    for raw in ("8 +++ exited with 0 +++", "38 --- SIGCHLD {si_signo=SIGCHLD} ---",
                "strace: Process 7 attached", '7 openat(AT_FDCWD</w>, "a", O_RDONLY <unfinished ...>',
                "7 <... openat resumed>) = 0", ""):
        assert strace_parse.parse_line(raw) is None
        assert strace_parse.is_non_call(raw), raw


def test_every_golden_line_parses_or_is_a_known_non_call():
    for raw in (FIXTURES / "basic.txt").read_text().splitlines():
        call = strace_parse.parse_line(raw)
        assert call is not None or strace_parse.is_non_call(raw), raw


def test_the_golden_trace_holds_the_refusals_inside_the_domain_and_none_of_the_layers_own():
    trace = strace_parse.parse_trace((FIXTURES / "basic.txt").read_text().splitlines())
    refused = sorted({strace_parse.path_argument(call, 1) for index, call in enumerate(trace.syscalls)
                      if call.name in ("openat", "mkdirat") and call.errno == "EACCES" and trace.in_domain(index)})
    assert "/etc/hostname" in refused
    assert "/etc/x" in refused
    assert '/tmp/a"b\nc' in refused
    outside = [call for index, call in enumerate(trace.syscalls)
               if call.name == "connect" and call.errno == "EACCES" and not trace.in_domain(index)]
    assert outside, "the golden trace keeps a guard refusal of a layer's own helper outside the domain"


def test_iter_calls_keeps_successful_calls_and_their_decoration():
    line = '16 openat(AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>'
    [call] = list(strace_parse.iter_calls([line]))
    assert call.result == 3
    assert call.errno is None
    assert call.decoration == "</usr/lib/libc.so.6>"


def test_a_socket_and_a_device_keep_their_whole_decoration():
    lines = [
        ("17 accept4(3<TCP:[127.0.0.1:47399]>, {sa_family=AF_INET, sin_port=htons(57692), "
         'sin_addr=inet_addr("127.0.0.1")}, [16], SOCK_CLOEXEC) = 4<TCP:[127.0.0.1:47399->127.0.0.1:57692]>'),
        '18 openat(AT_FDCWD</w>, "/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null<char 1:3>>',
    ]
    accepted, opened = strace_parse.iter_calls(lines)
    assert accepted.decoration == "<TCP:[127.0.0.1:47399->127.0.0.1:57692]>"
    assert opened.decoration == "</dev/null<char 1:3>>"


def test_a_failed_call_and_an_undecorated_result_have_no_decoration():
    lines = [
        '16 openat(AT_FDCWD</w>, "/etc/missing", O_RDONLY) = -1 ENOENT (No such file or directory)',
        "16 setsid() = 16",
    ]
    assert [call.decoration for call in strace_parse.iter_calls(lines)] == ["", ""]


def test_iter_calls_joins_halves_and_yields_every_call_in_log_order():
    lines = [
        '7 openat(AT_FDCWD</w>, "a", O_RDONLY <unfinished ...>',
        '8 openat(AT_FDCWD</w>, "b", O_RDONLY) = 3</w/b>',
        "7 <... openat resumed>) = 4</w/a>",
        "8 --- SIGCHLD {si_signo=SIGCHLD} ---",
    ]
    calls = list(strace_parse.iter_calls(lines))
    assert [(call.pid, call.decoration) for call in calls] == [(8, "</w/b>"), (7, "</w/a>")]


def test_parse_trace_still_drops_the_successes_it_never_kept():
    lines = [
        '16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>',
        '16 openat(AT_FDCWD</w>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)',
    ]
    kept = strace_parse.parse_trace(lines).syscalls
    assert [call.errno for call in kept] == ["EACCES"]
    assert all(call.errno or call.name in strace_parse.KEPT_SUCCESSES for call in kept)


def test_the_recorders_options_trace_successes_with_full_decorations_and_a_detached_tracer():
    options = strace_parse.RECORD_ARGUMENTS
    assert "-DDD" in options
    assert "-yy" in options
    assert "--seccomp-bpf" in options
    trace_set = options[options.index("-e") + 1].removeprefix("trace=").split(",")
    for name in ("%file", "%network", "%process", "ioctl", "fchdir", "write", "setsid", "setpgid", "io_uring_setup",
                 "dup2", "fcntl", "open_by_handle_at"):
        assert name in trace_set


def test_every_golden_record_line_parses_or_is_a_known_non_call():
    for raw in (FIXTURES / "record.txt").read_text().splitlines():
        assert strace_parse.parse_line(raw) is not None or strace_parse.is_non_call(raw), raw


def test_the_golden_record_yields_the_calls_the_recorder_reads():
    calls = list(strace_parse.iter_calls((FIXTURES / "record.txt").read_text().splitlines()))
    names = {call.name for call in calls}
    assert {"bind", "listen", "connect", "accept4", "getsockname", "sendto", "renameat", "mkdirat", "unlinkat",
            "execve", "clone"} <= names
    [connect] = [call for call in calls if call.name == "connect"]
    assert strace_parse.split_arguments(connect.arguments)[0] == "5<TCP:[11417184]>"
    hostname_reads = [call for call in calls if call.name == "openat" and call.decoration == "</etc/hostname>"]
    assert len(hostname_reads) == 2
