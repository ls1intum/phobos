"""Checks how a refused call is attributed to a layer and to the right that granting it would need.

One case per row of the table in A.6.2 of the prune-on-the-layers plan, plus the filters that keep a
refusal outside the domain, an ordinary error and a foreign refusal from ever becoming a grant.
"""

from __future__ import annotations

import os
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
sys.path.insert(0, str(REPO_ROOT / "pruner"))

from shared.src.domain import attribute, record, strace_parse

RESTRICT = "300 landlock_restrict_self(3, 0) = 0"


def trace_of(*lines: str) -> strace_parse.Trace:
    """A parsed trace of the given lines."""
    return strace_parse.parse_trace(lines)


def only_denial(*lines: str) -> record.Denial:
    """The one denial a trace of a restrict line and the given lines produces."""
    [denial] = attribute.denials(trace_of(RESTRICT, *lines), "/w")
    return denial


def test_a_refused_read_of_a_file_asks_for_read_on_that_file():
    denial = only_denial('300 openat(AT_FDCWD</w>, "/srv/a/data.txt", O_RDONLY) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_FILESYSTEM
    assert denial.operation == "openat"
    assert denial.objects == ("/srv/a/data.txt",)
    assert denial.sections == frozenset({attribute.SECTION_READ})


def test_a_refused_open_of_a_directory_asks_for_read_on_it():
    denial = only_denial('300 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY|O_DIRECTORY) = -1 EACCES (Permission denied)')
    assert denial.objects == ("/srv/a",)
    assert denial.sections == frozenset({attribute.SECTION_READ})


def test_a_refused_listing_of_an_open_directory_asks_for_read_on_it():
    denial = only_denial("300 getdents64(3</srv/a>, 0x1, 32768) = -1 EACCES (Permission denied)")
    assert denial.objects == ("/srv/a",)
    assert denial.sections == frozenset({attribute.SECTION_READ})


def test_a_relative_path_is_resolved_against_a_decorated_directory_descriptor():
    denial = only_denial('300 openat(3</srv/a>, "data.txt", O_RDONLY) = -1 EACCES (Permission denied)')
    assert denial.objects == ("/srv/a/data.txt",)


def test_a_relative_path_without_a_decoration_uses_the_working_directory_and_follows_chdir():
    trace = trace_of(RESTRICT,
                     '300 openat(AT_FDCWD, "one", O_RDONLY) = -1 EACCES (Permission denied)',
                     '300 chdir("sub") = 0',
                     '300 openat(AT_FDCWD, "two", O_RDONLY) = -1 EACCES (Permission denied)')
    assert [denial.objects for denial in attribute.denials(trace, "/w")] == [("/w/one",), ("/w/sub/two",)]


def test_a_vfork_child_resolves_a_relative_path_against_the_working_directory_it_inherited():
    trace = trace_of(RESTRICT,
                     '300 chdir("/w/test") = 0',
                     "300 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>",
                     '301 chdir("../assignment/") = 0',
                     '301 openat(AT_FDCWD, "exercise", O_RDONLY) = -1 EACCES (Permission denied)',
                     "300 <... clone resumed>) = 301")
    paths = [os.path.normpath(path) for denial in attribute.denials(trace, "/w") for path in denial.objects]
    assert paths == ["/w/assignment/exercise"]


def test_a_refused_write_asks_for_write_and_a_read_write_open_for_both():
    write = only_denial('300 openat(AT_FDCWD</w>, "/srv/out", O_WRONLY) = -1 EACCES (Permission denied)')
    both = only_denial('300 openat(AT_FDCWD</w>, "/srv/out", O_RDWR) = -1 EACCES (Permission denied)')
    assert write.sections == frozenset({attribute.SECTION_WRITE})
    assert both.sections == frozenset({attribute.SECTION_READ, attribute.SECTION_WRITE})


def test_a_refused_truncation_asks_for_write_on_the_file():
    by_open = only_denial('300 openat(AT_FDCWD</w>, "/srv/o", O_RDONLY|O_TRUNC) = -1 EACCES (Permission denied)')
    by_path = only_denial('300 truncate("/srv/o", 0) = -1 EACCES (Permission denied)')
    by_descriptor = only_denial("300 ftruncate(4</srv/o>, 0) = -1 EACCES (Permission denied)")
    assert attribute.SECTION_WRITE in by_open.sections
    assert by_path.objects == ("/srv/o",)
    assert by_path.sections == frozenset({attribute.SECTION_WRITE})
    assert by_descriptor.objects == ("/srv/o",)
    assert by_descriptor.sections == frozenset({attribute.SECTION_WRITE})


def test_a_refused_create_asks_for_create_on_the_parent():
    denial = only_denial(
        '300 openat(AT_FDCWD</w>, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EACCES (Permission denied)')
    assert denial.objects == ("/w/build",)
    assert denial.sections == frozenset({attribute.SECTION_CREATE})


def test_a_refused_open_with_create_of_an_existing_file_asks_for_write_on_it(tmp_path):
    existing = tmp_path / "existing"
    existing.write_text("x")
    denial = only_denial(f'300 openat(AT_FDCWD</w>, "{existing}", O_WRONLY|O_CREAT, 0644) = -1 EACCES (Permission denied)')
    assert denial.objects == (str(existing),)
    assert denial.sections == frozenset({attribute.SECTION_WRITE})


def test_a_refused_mkdir_asks_for_create_on_the_parent():
    denial = only_denial('300 mkdirat(AT_FDCWD</w>, "/etc/x", 0777) = -1 EACCES (Permission denied)')
    assert denial.objects == ("/etc",)
    assert denial.sections == frozenset({attribute.SECTION_CREATE})


def test_a_refused_fifo_or_unix_socket_asks_for_create_ipc_on_the_parent():
    fifo = only_denial('300 mknodat(AT_FDCWD</w>, "/srv/p", S_IFIFO|0644) = -1 EACCES (Permission denied)')
    unix = only_denial('300 bind(4<socket:[1]>, {sa_family=AF_UNIX, sun_path="/srv/s.sock"}, 110) = -1 EACCES (Permission denied)')
    assert (fifo.objects, fifo.sections) == (("/srv",), frozenset({attribute.SECTION_CREATE_IPC}))
    assert unix.layer == record.LAYER_FILESYSTEM
    assert (unix.objects, unix.sections) == (("/srv",), frozenset({attribute.SECTION_CREATE_IPC}))


def test_a_refused_device_node_is_fixed():
    denial = only_denial('300 mknodat(AT_FDCWD</w>, "/srv/d", S_IFCHR|0600, makedev(0x1, 0x3)) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_a_refused_symlink_asks_for_create_symlink_on_the_parent():
    denial = only_denial('300 symlinkat("/x", AT_FDCWD</w>, "/srv/l") = -1 EACCES (Permission denied)')
    assert (denial.objects, denial.sections) == (("/srv",), frozenset({attribute.SECTION_CREATE_SYMLINK}))


def test_a_refused_removal_asks_for_delete_on_the_parent():
    unlink = only_denial('300 unlinkat(AT_FDCWD</w>, "/srv/f", 0) = -1 EACCES (Permission denied)')
    rmdir = only_denial('300 unlinkat(AT_FDCWD</w>, "/srv/d", AT_REMOVEDIR) = -1 EACCES (Permission denied)')
    assert (unlink.objects, unlink.sections) == (("/srv",), frozenset({attribute.SECTION_DELETE}))
    assert (rmdir.objects, rmdir.sections) == (("/srv",), frozenset({attribute.SECTION_DELETE}))


def test_a_rename_across_directories_refused_with_exdev_asks_for_restructure_on_both_parents():
    denial = only_denial(
        '300 renameat2(AT_FDCWD</w>, "/srv/a/f", AT_FDCWD</w>, "/srv/b/f", 0) = -1 EXDEV (Invalid cross-device link)')
    assert denial.objects == ("/srv/a", "/srv/b")
    assert denial.sections == frozenset({attribute.SECTION_RESTRUCTURE})


def test_a_rename_within_one_directory_asks_for_create_and_delete_on_it():
    denial = only_denial('300 rename("/srv/a/f", "/srv/a/g") = -1 EACCES (Permission denied)')
    assert denial.objects == ("/srv/a",)
    assert denial.sections == frozenset({attribute.SECTION_CREATE, attribute.SECTION_DELETE})


def test_a_refused_execve_asks_for_execute_and_read_on_the_binary(tmp_path):
    binary = tmp_path / "tool"
    binary.write_bytes(b"\x7fELF")
    denial = only_denial(f'300 execve("{binary}", ["tool"], 0x1 /* 3 vars */) = -1 EACCES (Permission denied)')
    assert denial.objects == (str(binary),)
    assert denial.sections == frozenset({attribute.SECTION_EXECUTE, attribute.SECTION_READ})


def test_a_refused_script_also_asks_for_its_interpreter(tmp_path):
    script = tmp_path / "run.sh"
    script.write_text("#!/bin/sh -e\necho\n")
    denial = only_denial(f'300 execve("{script}", ["run.sh"], 0x1 /* 3 vars */) = -1 EACCES (Permission denied)')
    assert denial.objects == (str(script), "/bin/sh")


def test_a_refused_elf_also_asks_for_its_program_interpreter(tmp_path):
    binary = tmp_path / "dynamic"
    binary.write_bytes(elf_with_interpreter(b"/lib/ld-linux-aarch64.so.1"))
    denial = only_denial(f'300 execve("{binary}", ["dynamic"], 0x1 /* 3 vars */) = -1 EACCES (Permission denied)')
    assert denial.objects == (str(binary), "/lib/ld-linux-aarch64.so.1")


def test_a_refused_device_ioctl_is_fixed():
    denial = only_denial("300 ioctl(3</dev/tty>, TCGETS, 0x1) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_a_refused_connect_keeps_address_port_and_transport():
    denial = only_denial(
        "300 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 4<socket:[1]>",
        '300 connect(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.1")}, 16) '
        "= -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_NETWORK
    assert denial.sections == frozenset({attribute.SECTION_CONNECT})
    assert (denial.address, denial.port, denial.transport) == ("10.0.0.1", 80, "tcp")


def test_a_refused_ipv6_datagram_keeps_its_destination():
    denial = only_denial(
        "300 socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP) = 5<socket:[2]>",
        '300 sendto(5<socket:[2]>, "x", 1, 0, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), '
        'inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 EACCES (Permission denied)')
    assert (denial.address, denial.port, denial.transport) == ("2001:db8::1", 53, "udp")
    assert denial.sections == frozenset({attribute.SECTION_CONNECT})


def test_a_refused_sendmsg_reads_its_message_name():
    denial = only_denial(
        "300 socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 5<socket:[2]>",
        "300 sendmsg(5<socket:[2]>, {msg_name={sa_family=AF_INET, sin_port=htons(123), "
        'sin_addr=inet_addr("192.0.2.4")}, msg_namelen=16, msg_iov=[{iov_base="x", iov_len=1}], msg_iovlen=1, '
        "msg_controllen=0, msg_flags=0}, 0) = -1 EACCES (Permission denied)")
    assert (denial.address, denial.port, denial.transport) == ("192.0.2.4", 123, "udp")


def test_a_refused_bind_keeps_its_local_port():
    denial = only_denial(
        "300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4<socket:[1]>",
        '300 bind(4<socket:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) '
        "= -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_NETWORK
    assert denial.sections == frozenset({attribute.SECTION_BIND})
    assert (denial.port, denial.transport) == (8080, "tcp")


def test_a_refused_listen_on_an_unbound_socket_asks_for_port_zero():
    denial = only_denial("300 socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) = 4<socket:[1]>",
                         "300 listen(4<socket:[1]>, 50) = -1 EACCES (Permission denied)")
    assert denial.sections == frozenset({attribute.SECTION_BIND})
    assert (denial.port, denial.transport) == (0, "tcp")


def test_a_refused_unix_connect_is_a_fixed_rule_of_the_guard():
    denial = only_denial(
        '300 connect(3<socket:[9]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_a_refused_connect_of_another_family_is_a_fixed_rule_of_the_guard():
    denial = only_denial("300 connect(5<socket:[2]>, {sa_family=AF_UNSPEC, sa_data=\"\"}, 16) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_a_refused_send_without_a_destination_is_never_a_network_grant():
    denial = only_denial("300 socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) = 5<socket:[2]>",
                         '300 sendto(5<socket:[2]>, "x", 1, 0, NULL, 0) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_OTHER
    assert denial.sections == frozenset()


def test_a_refused_bind_of_an_abstract_socket_or_another_family_is_never_a_grant():
    abstract = only_denial('300 bind(4<socket:[1]>, {sa_family=AF_UNIX, sun_path=@"x"}, 4) = -1 EACCES (Permission denied)')
    netlink = only_denial("300 bind(4<socket:[1]>, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) "
                          "= -1 EACCES (Permission denied)")
    assert abstract.layer == record.LAYER_OTHER
    assert netlink.layer == record.LAYER_OTHER


def test_a_refused_unnamed_temporary_file_is_never_a_grant():
    denial = only_denial('300 openat(AT_FDCWD</w>, "/srv", O_RDWR|O_EXCL|O_TMPFILE, 0600) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_OTHER
    assert denial.sections == frozenset()


def test_a_refused_raw_or_packet_socket_is_fixed():
    raw = only_denial("300 socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = -1 EACCES (Permission denied)")
    packet = only_denial("300 socket(AF_PACKET, SOCK_DGRAM, 768) = -1 EACCES (Permission denied)")
    assert raw.layer == record.LAYER_FIXED
    assert packet.layer == record.LAYER_FIXED


def test_a_refused_setsid_is_a_fixed_rule_and_never_a_grant():
    denial = only_denial("300 setsid() = -1 EPERM (Operation not permitted)")
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_eperm_on_a_path_call_is_another_mechanisms_refusal():
    denial = only_denial('300 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY) = -1 EPERM (Operation not permitted)')
    assert denial.layer == record.LAYER_OTHER
    assert denial.sections == frozenset()


def test_an_o_path_open_refused_is_not_landlock():
    denial = only_denial('300 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY|O_PATH) = -1 EACCES (Permission denied)')
    assert denial.layer == record.LAYER_OTHER


def test_exhausted_resources_are_limit_refusals_only_for_the_calls_that_meet_a_limit():
    trace = trace_of(RESTRICT,
                     '300 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY) = -1 EMFILE (Too many open files)',
                     "300 clone(child_stack=NULL, flags=SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable)",
                     "300 read(4<socket:[1]>, 0x1, 10) = -1 EAGAIN (Resource temporarily unavailable)")
    denials = attribute.denials(trace, "/w")
    assert [(denial.operation, denial.layer) for denial in denials] == [
        ("openat", record.LAYER_LIMIT), ("clone", record.LAYER_LIMIT)]


def test_a_denial_names_the_refusing_thread_and_its_process():
    trace = trace_of(RESTRICT,
                     "300 clone3({flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND, exit_signal=0}, 88) = 305",
                     '305 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY) = -1 EACCES (Permission denied)')
    [denial] = attribute.denials(trace, "/w")
    assert (denial.pid, denial.tid, denial.run) == (300, 305, 0)


def test_a_refusal_outside_the_domain_is_ignored():
    trace = trace_of('200 openat(AT_FDCWD</w>, "/srv/a", O_RDONLY) = -1 EACCES (Permission denied)')
    assert attribute.denials(trace, "/w") == []


def test_enoent_is_not_a_denial():
    trace = trace_of(RESTRICT,
                     '300 openat(AT_FDCWD</w>, "/srv/missing", O_RDONLY) = -1 ENOENT (No such file or directory)')
    assert attribute.denials(trace, "/w") == []


def test_refusals_pair_each_denial_with_its_call_and_the_threads_working_directory():
    trace = trace_of(RESTRICT,
                     '300 chdir("/srv") = 0',
                     '300 openat(AT_FDCWD, "a/data.txt", O_RDONLY) = -1 EACCES (Permission denied)',
                     '300 openat(AT_FDCWD</srv>, "/srv/missing", O_RDONLY) = -1 ENOENT (No such file or directory)')
    [(call, denial, directory)] = attribute.refusals(trace, "/w")
    assert call.name == "openat"
    assert call.errno == "EACCES"
    assert denial.objects == ("/srv/a/data.txt",)
    assert directory == "/srv"
    assert attribute.denials(trace, "/w") == [denial]


def elf_with_interpreter(interpreter: bytes) -> bytes:
    """A minimal 64-bit little-endian ELF header with one PT_INTERP program header naming `interpreter`."""
    header_size = 64
    program_header_size = 56
    offset = header_size + program_header_size
    elf = bytearray(header_size)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2
    elf[5] = 1
    elf[6] = 1
    elf[32:40] = header_size.to_bytes(8, "little")
    elf[54:56] = program_header_size.to_bytes(2, "little")
    elf[56:58] = (1).to_bytes(2, "little")
    program_header = bytearray(program_header_size)
    program_header[0:4] = (3).to_bytes(4, "little")
    program_header[8:16] = offset.to_bytes(8, "little")
    program_header[32:40] = (len(interpreter) + 1).to_bytes(8, "little")
    return bytes(elf + program_header + interpreter + b"\x00")


def test_a_refused_pty_request_on_the_master_asks_for_ioctl_with_the_request_named():
    denial = only_denial("300 ioctl(3</dev/pts/ptmx>, TIOCSPTLCK, [0]) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FILESYSTEM
    assert denial.objects == ("/dev/pts/ptmx",)
    assert denial.sections == frozenset({attribute.SECTION_IOCTL})
    assert denial.detail == "TIOCSPTLCK"


def test_a_refused_terminal_request_on_a_numbered_slave_asks_for_ioctl():
    denial = only_denial("300 ioctl(4</dev/pts/3>, TCGETS, 0x7ffc1) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FILESYSTEM
    assert denial.objects == ("/dev/pts/3",)
    assert denial.detail == "TCGETS"


def test_a_request_the_replay_cannot_repeat_stays_a_fixed_refusal():
    denial = only_denial("300 ioctl(4</dev/pts/3>, TIOCSCTTY, 0) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FIXED
    assert denial.sections == frozenset()


def test_an_ioctl_on_any_other_device_stays_a_fixed_refusal():
    denial = only_denial("300 ioctl(4</dev/tty>, TCGETS, 0x7ffc1) = -1 EACCES (Permission denied)")
    assert denial.layer == record.LAYER_FIXED


def test_a_path_that_only_looks_like_a_pty_device_stays_a_fixed_refusal():
    for path in ("/dev/pts/ptmx2", "/dev/pts/1/x", "/dev/pts/", "/dev/ptmx2", "/dev/pts/a", "/tmp/dev/pts/3"):
        denial = only_denial(f"300 ioctl(4<{path}>, TCGETS, 0x7ffc1) = -1 EACCES (Permission denied)")
        assert denial.layer == record.LAYER_FIXED, path


def test_a_request_of_the_other_side_of_the_pair_stays_a_fixed_refusal():
    on_slave = only_denial("300 ioctl(4</dev/pts/3>, TIOCGPTN, 0x7ffc1) = -1 EACCES (Permission denied)")
    on_master = only_denial("300 ioctl(3</dev/pts/ptmx>, TCGETS, 0x7ffc1) = -1 EACCES (Permission denied)")
    assert on_slave.layer == record.LAYER_FIXED
    assert on_master.layer == record.LAYER_FIXED


def test_a_path_ending_in_a_newline_is_no_pty_device():
    assert attribute.PSEUDO_TERMINAL_DEVICE.match("/dev/pts/3\n") is None
    assert attribute.pseudo_terminal_request("/dev/pts/3\n", "TCGETS") is False
    assert attribute.pseudo_terminal_request("/dev/pts/3", "TCGETS") is True
