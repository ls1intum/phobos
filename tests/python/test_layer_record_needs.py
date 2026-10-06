"""Checks how every successful call of a recorded session becomes the access Landlock checks for it.

One case per row of the mapping in A.6.1 and A.6.3 of the recording pruner's plan, each beside
the neighbouring call that needs nothing, since a recorder that grants too little fails a correct
run and one that grants too much widens the sandbox without anyone noticing.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "var" / "tmp" / "helpers"))

from layer_prune import strace_parse
from layer_record import needs


class Existing:
    """Answers which paths existed before the session, as a recording's snapshot does."""

    def __init__(self, *paths: str):
        """Holds the paths given; assumes they are absolute."""
        self.paths = frozenset(paths)

    def existed(self, path: str) -> bool:
        """Whether the path was one of those given."""
        return path in self.paths


EMPTY = Existing()


def snapshot_with(*paths: str) -> Existing:
    """A snapshot in which exactly the given paths existed."""
    return Existing(*paths)


def needs_of(*arguments) -> needs.SessionNeeds:
    """Reads the given trace lines as one session; the last argument is the snapshot."""
    *lines, snapshot = arguments
    return needs.read_session(strace_parse.iter_calls(lines), snapshot, "/w", 1)


def sections_on(result: needs.SessionNeeds, path: str) -> set[str]:
    """Every section the session's needs ask for on the path."""
    found = set()
    for need in result.needs:
        if path in need.objects:
            found |= need.sections
    return found


def elf_with_interpreter(path: pathlib.Path, interpreter: str) -> pathlib.Path:
    """Writes a minimal 64-bit little-endian ELF file with one PT_INTERP header naming `interpreter`."""
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
    path.write_bytes(bytes(elf + program_header + interpreter.encode() + b"\x00"))
    return path


def test_an_open_for_reading_needs_read_on_the_resolved_file():
    result = needs_of('16 openat(AT_FDCWD</w>, "/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3</usr/lib/libc.so.6>', EMPTY)
    assert sections_on(result, "/usr/lib/libc.so.6") == {"read"}
    assert sections_on(result, "/lib/libc.so.6") == set()


def test_an_o_path_open_needs_nothing():
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc", O_RDONLY|O_PATH|O_DIRECTORY) = 3</etc>', EMPTY)
    assert result.needs == []


def test_a_failed_open_needs_nothing():
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc/missing", O_RDONLY) = -1 ENOENT (No such file or directory)', EMPTY)
    assert result.needs == []


def test_a_stat_needs_nothing():
    result = needs_of('16 newfstatat(AT_FDCWD</w>, "/etc/shadow", {st_mode=S_IFREG|0640, st_size=1, ...}, 0) = 0', EMPTY)
    assert result.needs == []
    assert result.unsupported == []


def test_an_open_for_writing_an_existing_file_needs_write_only():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/out.txt>',
                      snapshot_with("/w", "/w/out.txt"))
    assert sections_on(result, "/w/out.txt") == {"write"}
    assert sections_on(result, "/w") == set()


def test_an_open_for_reading_and_writing_needs_both():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/data", O_RDWR) = 3</w/data>', snapshot_with("/w", "/w/data"))
    assert sections_on(result, "/w/data") == {"read", "write"}


def test_truncating_on_open_needs_write_even_for_reading():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/data", O_RDONLY|O_TRUNC) = 3</w/data>', snapshot_with("/w", "/w/data"))
    assert sections_on(result, "/w/data") == {"read", "write"}


def test_creating_a_new_file_needs_create_on_the_parent_and_write_on_the_new_file():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</w/out.txt>',
                      snapshot_with("/w"))
    assert sections_on(result, "/w") == {"create"}
    assert sections_on(result, "/w/out.txt") == {"write"}


def test_creat_is_a_write_only_create():
    result = needs_of('16 creat("/w/new", 0644) = 3</w/new>', snapshot_with("/w"))
    assert sections_on(result, "/w") == {"create"}
    assert sections_on(result, "/w/new") == {"write"}


def test_a_file_the_session_created_earlier_is_not_created_again():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/x", O_WRONLY|O_CREAT, 0666) = 3</w/x>',
                      '16 unlinkat(AT_FDCWD</w>, "/w/y", 0) = 0',
                      '16 openat(AT_FDCWD</w>, "/w/x", O_RDONLY|O_CREAT, 0666) = 4</w/x>',
                      snapshot_with("/w", "/w/y"))
    creations = [need for need in result.needs if "create" in need.sections]
    assert len(creations) == 1


def test_a_relative_path_is_resolved_against_the_descriptor_it_names():
    result = needs_of('16 openat(3</srv/data>, "a.txt", O_RDONLY) = 4</srv/data/a.txt>', EMPTY)
    assert sections_on(result, "/srv/data/a.txt") == {"read"}


def test_a_device_open_is_judged_on_the_device_path_without_its_numbers():
    result = needs_of('18 openat(AT_FDCWD</w>, "/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3</dev/null<char 1:3>>',
                      snapshot_with("/dev", "/dev/null"))
    assert sections_on(result, "/dev/null") == {"write"}


def test_opening_a_directory_for_reading_needs_read_and_counts_as_listing_it():
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc/ssl/certs", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY)'
                      ' = 3</etc/ssl/certs>', EMPTY)
    assert sections_on(result, "/etc/ssl/certs") == {"read"}
    assert result.listed_directories == {"/etc/ssl/certs"}


def test_reading_a_file_is_not_listing_a_directory():
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>', EMPTY)
    assert result.listed_directories == set()


def test_openat2_with_resolve_flags_is_judged_by_the_object_it_reached():
    line = ('16 openat2(AT_FDCWD</w>, "/etc/hostname", {flags=O_RDONLY|O_CLOEXEC, resolve=RESOLVE_NO_SYMLINKS}, 24)'
            ' = 3</etc/hostname>')
    assert sections_on(needs_of(line, EMPTY), "/etc/hostname") == {"read"}


def test_an_o_tmpfile_open_is_unsupported_and_never_silently_dropped():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w", O_RDWR|O_TMPFILE, 0600) = 3</w/#1234 (deleted)>', EMPTY)
    assert result.needs == []
    assert len(result.unsupported) == 1


def test_an_execve_needs_execute_and_read_on_the_binary_and_its_interpreter(tmp_path):
    interpreter = tmp_path / "ld.so"
    interpreter.write_bytes(b"\x7fELF")
    binary = elf_with_interpreter(tmp_path / "tool", str(interpreter))
    result = needs_of(f'16 execve("{binary}", ["tool"], 0x0 /* 1 var */) = 0', snapshot_with(str(tmp_path)))
    assert sections_on(result, str(binary)) == {"execute", "read"}
    assert sections_on(result, str(interpreter)) == {"execute", "read"}


def test_a_script_needs_its_whole_interpreter_chain(tmp_path):
    loader = tmp_path / "ld.so"
    loader.write_bytes(b"\x7fELF")
    shell = elf_with_interpreter(tmp_path / "sh", str(loader))
    script = tmp_path / "tool.sh"
    script.write_text(f"#!{shell} -e\necho hi\n")
    assert needs.exec_chain(str(script)) == [str(script), str(shell), str(loader)]


def test_a_failed_execve_needs_nothing(tmp_path):
    result = needs_of('16 execve("/usr/local/bin/python3", ["python3"], 0x0 /* 1 var */)'
                      ' = -1 ENOENT (No such file or directory)', EMPTY)
    assert result.needs == []


def test_fexecve_is_judged_by_the_descriptors_path(tmp_path):
    interpreter = tmp_path / "ld.so"
    interpreter.write_bytes(b"\x7fELF")
    binary = elf_with_interpreter(tmp_path / "tool", str(interpreter))
    line = f'16 execveat(3<{binary}>, "", ["tool"], 0x0 /* 1 var */, AT_EMPTY_PATH) = 0'
    result = needs_of(line, snapshot_with(str(tmp_path)))
    assert sections_on(result, str(binary)) == {"execute", "read"}


def test_fexecve_of_a_descriptor_without_a_path_is_unsupported():
    result = needs_of('16 execveat(3</memfd:tool (deleted)>, "", ["tool"], 0x0 /* 1 var */, AT_EMPTY_PATH) = 0', EMPTY)
    assert result.needs == []
    assert len(result.unsupported) == 1


def test_making_a_directory_needs_create_on_the_parent():
    result = needs_of('16 mkdirat(AT_FDCWD</w>, "/w/cache", 0777) = 0', snapshot_with("/w"))
    assert sections_on(result, "/w") == {"create"}
    assert sections_on(result, "/w/cache") == set()


def test_a_fifo_needs_create_ipc_and_a_device_node_is_a_fixed_refusal():
    fifo = needs_of('16 mknodat(AT_FDCWD</w>, "/w/pipe", S_IFIFO|0600) = 0', snapshot_with("/w"))
    assert sections_on(fifo, "/w") == {"create-ipc"}
    device = needs_of('16 mknodat(AT_FDCWD</w>, "/w/null", S_IFCHR|0600, makedev(0x1, 0x3)) = 0', snapshot_with("/w"))
    assert device.needs == []
    assert any("mknod" in line for line in device.fixed)


def test_a_symbolic_link_needs_create_symlink_on_the_links_parent():
    result = needs_of('16 symlinkat("/etc/hostname", AT_FDCWD</w>, "/w/link") = 0', snapshot_with("/w"))
    assert sections_on(result, "/w") == {"create-symlink"}
    assert sections_on(result, "/etc") == set()


def test_removing_a_file_or_a_directory_needs_delete_on_the_parent():
    result = needs_of('16 unlinkat(AT_FDCWD</w>, "/w/old.txt", 0) = 0',
                      '16 unlinkat(AT_FDCWD</w>, "/t/d", AT_REMOVEDIR) = 0', snapshot_with("/w", "/w/old.txt", "/t/d"))
    assert sections_on(result, "/w") == {"delete"}
    assert sections_on(result, "/t") == {"delete"}


def test_truncate_needs_write_on_the_file():
    result = needs_of('16 truncate("/w/data", 0) = 0', snapshot_with("/w", "/w/data"))
    assert sections_on(result, "/w/data") == {"write"}


def test_a_move_within_one_directory_needs_create_and_delete_there():
    result = needs_of('16 renameat2(AT_FDCWD</w>, "/w/tmp1", AT_FDCWD</w>, "/w/out.txt", 0) = 0',
                      snapshot_with("/w", "/w/tmp1"))
    assert sections_on(result, "/w") == {"create", "delete"}
    assert result.moves == set()


def test_a_move_across_directories_needs_restructure_on_both_parents_and_is_remembered():
    result = needs_of('16 renameat2(AT_FDCWD</w>, "/t/a", AT_FDCWD</w>, "/w/b", 0) = 0', snapshot_with("/t", "/w", "/t/a"))
    assert sections_on(result, "/t") == {"delete", "restructure"}
    assert sections_on(result, "/w") == {"create", "restructure"}
    assert result.moves == {("/t", "/w")}


def test_a_move_onto_an_existing_name_also_needs_delete_on_the_destination():
    result = needs_of('16 renameat(AT_FDCWD</w>, "/w/tmp1", AT_FDCWD</w>, "/w/out.txt") = 0',
                      snapshot_with("/w", "/w/tmp1", "/w/out.txt"))
    assert sections_on(result, "/w") == {"create", "delete"}


def test_a_move_onto_a_name_the_session_created_also_needs_delete():
    result = needs_of('16 openat(AT_FDCWD</w>, "/v/out.txt", O_WRONLY|O_CREAT, 0666) = 3</v/out.txt>',
                      '16 renameat(AT_FDCWD</w>, "/w/tmp1", AT_FDCWD</w>, "/v/out.txt") = 0',
                      snapshot_with("/w", "/v", "/w/tmp1"))
    assert "delete" in sections_on(result, "/v")


def test_an_exchange_needs_both_directions():
    result = needs_of('16 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/y", RENAME_EXCHANGE) = 0',
                      snapshot_with("/a", "/b", "/a/x", "/b/y"))
    assert {"create", "delete", "restructure"} <= sections_on(result, "/a")
    assert {"create", "delete", "restructure"} <= sections_on(result, "/b")
    assert result.moves == {("/a", "/b"), ("/b", "/a")}


def test_a_hard_link_across_directories_needs_restructure_on_both():
    result = needs_of('16 linkat(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0) = 0', snapshot_with("/a", "/b", "/a/x"))
    assert sections_on(result, "/b") == {"create", "restructure"}
    assert sections_on(result, "/a") == {"restructure"}
    assert result.moves == {("/a", "/b")}


def test_binding_a_pathname_unix_socket_needs_create_ipc_and_an_abstract_one_nothing():
    pathname = needs_of('16 bind(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/w/sock"}, 110) = 0', snapshot_with("/w"))
    assert sections_on(pathname, "/w") == {"create-ipc"}
    abstract = needs_of('16 bind(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path=@"name"}, 8) = 0', EMPTY)
    assert abstract.needs == []


def test_a_unix_connect_is_a_fixed_refusal_and_no_grant():
    result = needs_of('16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0',
                      EMPTY)
    assert result.needs == []
    assert any("UNIX" in line for line in result.fixed)


def test_a_failed_unix_connect_is_no_refusal_of_anything():
    result = needs_of('16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110)'
                      ' = -1 ENOENT (No such file or directory)', EMPTY)
    assert result.fixed == []


def test_a_terminal_ioctl_on_an_inherited_descriptor_is_not_a_refusal():
    result = needs_of('16 ioctl(0</dev/pts/0<char 136:0>>, TCGETS, {c_iflag=ICRNL}) = 0', EMPTY)
    assert result.fixed == []


def test_a_terminal_ioctl_on_a_device_the_session_opened_is_a_fixed_refusal():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      '16 ioctl(3</dev/tty<char 5:0>>, TCGETS, {c_iflag=ICRNL}) = 0', snapshot_with("/dev/tty"))
    assert any("IOCTL_DEV" in line for line in result.fixed)


def test_an_ioctl_landlock_always_allows_is_not_a_refusal():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      '16 ioctl(3</dev/tty<char 5:0>>, FIOCLEX) = 0', snapshot_with("/dev/tty"))
    assert result.fixed == []


def test_an_ioctl_on_a_regular_file_is_not_a_refusal():
    result = needs_of('16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>',
                      '16 ioctl(3</etc/hostname>, TCGETS, 0xffff) = -1 ENOTTY (Inappropriate ioctl for device)', EMPTY)
    assert result.fixed == []


def test_a_child_inherits_the_devices_its_parent_opened():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      "16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
                      '17 ioctl(3</dev/tty<char 5:0>>, TIOCGWINSZ, {ws_row=24}) = 0', snapshot_with("/dev/tty"))
    assert any("IOCTL_DEV" in line for line in result.fixed)


@pytest.mark.parametrize("line", ["16 setsid() = 16", "16 setpgid(0, 0) = 0",
                                  "16 io_uring_setup(8, {flags=0}) = 3<anon_inode:[io_uring]>",
                                  "16 socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) = 3<PACKET:[1]>",
                                  "16 socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = 3<RAW:[1]>",
                                  "16 socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) = 3<PING:[1]>"])
def test_what_the_layers_always_refuse_is_a_fixed_refusal(line):
    result = needs_of(line, EMPTY)
    assert result.needs == []
    assert len(result.fixed) == 1


def test_an_ordinary_socket_is_not_a_refusal():
    result = needs_of("16 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3<TCP:[1]>", EMPTY)
    assert result.fixed == []


def test_an_unmapped_file_call_that_succeeded_is_unsupported():
    result = needs_of('16 open_by_handle_at(3</w>, {handle_bytes=8, handle_type=1}, O_RDONLY) = 4</w/f>', EMPTY)
    assert len(result.unsupported) == 1


def test_a_call_landlock_checks_no_right_for_needs_nothing_and_is_not_unsupported():
    result = needs_of('16 fchmodat(AT_FDCWD</w>, "/w/f", 0644) = 0', '16 readlinkat(AT_FDCWD</w>, "/w/l", "f", 4096) = 1',
                      '16 faccessat2(AT_FDCWD</w>, "/w/f", R_OK, 0) = 0', '16 getcwd("/w", 4096) = 3', EMPTY)
    assert result.needs == []
    assert result.unsupported == []


def test_the_process_ids_of_the_whole_session_are_known():
    result = needs_of("16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
                      "17 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0}, 88) = 18",
                      '18 openat(AT_FDCWD</w>, "/proc/16/status", O_RDONLY) = 3</proc/16/status>', EMPTY)
    assert result.process_ids == frozenset({16, 17, 18})
    [need] = result.needs
    assert (need.tid, need.tgid, need.run) == (18, 17, 1)


def test_a_working_directory_follows_chdir_and_is_inherited():
    result = needs_of('16 chdir("/srv") = 0', "16 clone(child_stack=NULL, flags=SIGCHLD) = 17",
                      '17 open("data", O_RDONLY) = 3</srv/data>', '17 unlink("old") = 0', snapshot_with("/srv/old"))
    assert sections_on(result, "/srv") == {"delete"}


def test_access_pairs_spell_each_access_once_before_any_generalisation():
    calls = list(strace_parse.iter_calls([
        '16 openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>',
        '16 renameat2(AT_FDCWD</w>, "/t/a", AT_FDCWD</w>, "/w/b", 0) = 0',
        "16 setsid() = 16",
        '16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/dbus/system_bus_socket"}, 110) = 0',
    ]))
    pairs = needs.access_pairs(calls, snapshot_with("/t", "/w", "/t/a"), "/w")
    assert ("/etc/hostname", "read") in pairs
    assert {("/t", "delete"), ("/t", "restructure"), ("/w", "create"), ("/w", "restructure")} <= pairs
    assert ("/t", "create") not in pairs
    assert ("setsid", "call") in pairs
    assert ("unix:/run/dbus/system_bus_socket", "connect") in pairs


def test_a_refused_call_has_the_pairs_it_would_have_needed():
    [call] = strace_parse.iter_calls([('20 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0)'
                                       ' = -1 EXDEV (Invalid cross-device link)')])
    pairs = needs.pairs_of_call(call, snapshot_with("/a", "/b", "/a/x"), "/w")
    assert pairs == {("/a", "delete"), ("/a", "restructure"), ("/b", "create"), ("/b", "restructure")}


def test_a_refused_open_has_the_pairs_of_its_resolved_path():
    [call] = strace_parse.iter_calls(['20 openat(AT_FDCWD</w>, "data.txt", O_WRONLY) = -1 EACCES (Permission denied)'])
    assert needs.pairs_of_call(call, snapshot_with("/w", "/w/data.txt"), "/w") == {("/w/data.txt", "write")}


def test_network_pairs_carry_the_transport_from_the_socket():
    calls = list(strace_parse.iter_calls([
        '16 connect(5<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = 0',
        '16 bind(4<UDP:[2]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
        '16 sendto(6<UDP:[3]>, "x", 1, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.53")}, 16) = 1',
        ('16 connect(7<TCPv6:[4]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
         'inet_pton(AF_INET6, "::ffff:192.0.2.8", &sin6_addr), sin6_scope_id=0}, 28) = 0'),
    ]))
    pairs = needs.access_pairs(calls, EMPTY, "/w")
    assert {("192.0.2.7:80 tcp", "connect"), ("0 udp", "bind"), ("192.0.2.53:53 udp", "connect"),
            ("192.0.2.8:443 tcp", "connect")} <= pairs


def test_a_datagram_connect_counts_only_with_a_datagram_sent_to_it():
    probe = '16 connect(5<UDP:[3]>, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("104.20.26.136")}, 16) = 0'
    unsent = needs.access_pairs(strace_parse.iter_calls([probe]), EMPTY, "/w")
    assert ("104.20.26.136:443 udp", "connect") not in unsent
    sent = needs.access_pairs(strace_parse.iter_calls([
        probe, '16 write(5<UDP:[10.0.0.2:40000->104.20.26.136:443]>, "q", 1) = 1']), EMPTY, "/w")
    assert ("104.20.26.136:443 udp", "connect") in sent


def test_listening_on_an_unbound_socket_is_an_ephemeral_bind_and_on_a_bound_one_nothing_more():
    unbound = needs.access_pairs(strace_parse.iter_calls(["16 listen(3<TCP:[11419046]>, 128) = 0"]), EMPTY, "/w")
    assert ("0 tcp", "bind") in unbound
    bound = needs.access_pairs(strace_parse.iter_calls(["16 listen(3<TCP:[127.0.0.1:47399]>, 128) = 0"]), EMPTY, "/w")
    assert bound == set()


def test_the_golden_record_reads_without_unsupported_calls():
    lines = (REPO_ROOT / "tests" / "python" / "fixtures" / "strace" / "record.txt").read_text().splitlines()
    temporary = os.path.realpath("/tmp")
    snapshot = snapshot_with(temporary, temporary + "/a", os.path.realpath("/var/tmp"))
    result = needs.read_session(strace_parse.iter_calls(lines), snapshot, "/var/tmp", 1)
    assert result.unsupported == []
    assert "/etc/hostname" in {path for need in result.needs for path in need.objects}
    assert result.moves == set()
    assert sections_on(result, temporary) >= {"create", "delete"}


def test_a_symbolic_link_is_created_beside_its_name_even_when_it_points_elsewhere(tmp_path):
    work = tmp_path / "w"
    elsewhere = tmp_path / "opt"
    work.mkdir()
    elsewhere.mkdir()
    (elsewhere / "x").write_text("x")
    (work / "link").symlink_to(elsewhere / "x")
    base = os.path.realpath(tmp_path)
    result = needs_of(f'16 symlinkat("{elsewhere}/x", AT_FDCWD</w>, "{work}/link") = 0', snapshot_with(base + "/w"))
    assert sections_on(result, base + "/w") == {"create-symlink"}
    assert sections_on(result, base + "/opt") == set()


def test_a_rename_over_a_symbolic_link_acts_on_the_links_directory(tmp_path):
    work = tmp_path / "w"
    elsewhere = tmp_path / "opt"
    work.mkdir()
    elsewhere.mkdir()
    (work / "current").symlink_to(elsewhere)
    (work / "current.tmp").symlink_to(elsewhere)
    base = os.path.realpath(tmp_path)
    result = needs_of(f'16 renameat(AT_FDCWD</w>, "{work}/current.tmp", AT_FDCWD</w>, "{work}/current") = 0',
                      snapshot_with(base + "/w", base + "/w/current", base + "/w/current.tmp"))
    assert sections_on(result, base + "/w") == {"create-symlink", "delete"}
    assert sections_on(result, base + "/opt") == set()
    assert result.moves == set()


def test_reading_a_pipe_through_dev_stdin_needs_no_path():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/stdin", O_RDONLY) = 3<pipe:[123]>', EMPTY)
    assert result.needs == []
    assert result.unsupported == []


def test_proc_self_of_a_refused_call_is_the_refusing_process_and_compares_with_the_recording():
    [refused] = strace_parse.iter_calls(['20 openat(AT_FDCWD</w>, "/proc/self/status", O_RDONLY) = -1 EACCES (Permission denied)'])
    replayed = needs.pairs_of_call(refused, EMPTY, "/w")
    recorded_line = '16 openat(AT_FDCWD</w>, "/proc/self/status", O_RDONLY) = 3</proc/16/status>'
    recorded = needs.access_pairs(strace_parse.iter_calls([recorded_line]), EMPTY, "/w")
    assert replayed == {("/proc/<pid>/status", "read")}
    assert replayed & recorded


def test_a_pseudo_terminal_compares_whatever_its_number():
    assert needs.comparable("/dev/pts/3") == needs.comparable("/dev/pts/0") == "/dev/pts/<n>"
    assert needs.comparable("/proc/977/task/978/stat") == "/proc/<pid>/task/<tid>/stat"
    assert needs.comparable("/proc/sys/kernel/pid_max") == "/proc/sys/kernel/pid_max"


def test_a_stale_descriptor_number_is_no_device():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      '16 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3<TCP:[1]>',
                      '16 ioctl(3<TCP:[1]>, FIONREAD, [0]) = 0', snapshot_with("/dev/tty"))
    assert result.fixed == []


def test_a_device_duplicated_onto_another_descriptor_is_still_the_sessions():
    result = needs_of('16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
                      '16 dup2(3</dev/tty<char 5:0>>, 10) = 10</dev/tty<char 5:0>>',
                      '16 ioctl(10</dev/tty<char 5:0>>, TCSETS, {c_iflag=ICRNL}) = 0', snapshot_with("/dev/tty"))
    assert any("IOCTL_DEV" in line for line in result.fixed)


def test_glibc_probes_the_guard_refuses_are_tolerated_and_no_pair():
    lines = ["16 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 4<NETLINK:[1]>",
             '16 connect(5<UDP:[3]>, {sa_family=AF_UNSPEC, sa_data="\\0"}, 16) = 0']
    result = needs_of(*lines, EMPTY)
    assert result.fixed == []
    assert len(result.tolerated) == 2
    assert needs.access_pairs(strace_parse.iter_calls(lines), EMPTY, "/w") == set()


def test_an_af_unspec_connect_on_a_stream_socket_is_still_a_fixed_refusal():
    result = needs_of('16 connect(5<TCP:[3]>, {sa_family=AF_UNSPEC, sa_data="\\0"}, 16) = 0', EMPTY)
    assert len(result.fixed) == 1


def test_a_non_blocking_connect_is_compared_but_never_granted():
    line = ('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16)'
            ' = -1 EINPROGRESS (Operation now in progress)')
    assert ("192.0.2.7:80 tcp", "connect") in needs.access_pairs(strace_parse.iter_calls([line]), EMPTY, "/w")
    assert needs_of(line, EMPTY).needs == []


def test_a_name_beneath_a_moved_directory_no_longer_exists():
    result = needs_of('16 renameat(AT_FDCWD</w>, "/w/build", AT_FDCWD</w>, "/w/build.old") = 0',
                      '16 mkdirat(AT_FDCWD</w>, "/w/build", 0777) = 0',
                      '16 openat(AT_FDCWD</w>, "/w/build/x", O_WRONLY|O_CREAT, 0666) = 3</w/build/x>',
                      snapshot_with("/w", "/w/build", "/w/build/x"))
    assert "create" in sections_on(result, "/w/build")


def test_truncating_a_file_the_open_just_created_needs_no_write():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/new", O_RDONLY|O_CREAT|O_TRUNC, 0644) = 3</w/new>', snapshot_with("/w"))
    assert sections_on(result, "/w/new") == {"read"}


def test_setting_an_extended_attribute_needs_nothing_and_is_mapped():
    result = needs_of('16 setxattr("/w/f", "user.x", "1", 1, 0) = 0', snapshot_with("/w", "/w/f"))
    assert result.needs == []
    assert result.unsupported == []


def test_an_interpreter_chain_stops_where_the_kernel_stops(tmp_path):
    previous = None
    for number in range(7):
        script = tmp_path / f"s{number}"
        script.write_text(f"#!{previous}\n" if previous else "#!/bin/false\n")
        previous = script
    assert len(needs.exec_chain(str(previous))) == needs.MAX_INTERPRETERS + 1


@pytest.mark.parametrize(("succeeded", "refused"), [
    ('16 openat(AT_FDCWD</w>, "/w/data.txt", O_RDONLY) = 3</w/data.txt>',
     '20 openat(AT_FDCWD</w>, "/w/data.txt", O_RDONLY) = -1 EACCES (Permission denied)'),
    ('16 openat(AT_FDCWD</w>, "/w/new.txt", O_WRONLY|O_CREAT, 0666) = 3</w/new.txt>',
     '20 openat(AT_FDCWD</w>, "/w/new.txt", O_WRONLY|O_CREAT, 0666) = -1 EACCES (Permission denied)'),
    ('16 mkdirat(AT_FDCWD</w>, "/w/cache", 0777) = 0',
     '20 mkdirat(AT_FDCWD</w>, "/w/cache", 0777) = -1 EACCES (Permission denied)'),
    ('16 unlinkat(AT_FDCWD</w>, "/w/data.txt", 0) = 0',
     '20 unlinkat(AT_FDCWD</w>, "/w/data.txt", 0) = -1 EACCES (Permission denied)'),
    ('16 symlinkat("/x", AT_FDCWD</w>, "/w/l") = 0',
     '20 symlinkat("/x", AT_FDCWD</w>, "/w/l") = -1 EACCES (Permission denied)'),
    ('16 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0) = 0',
     '20 renameat2(AT_FDCWD</w>, "/a/x", AT_FDCWD</w>, "/b/x", 0) = -1 EXDEV (Invalid cross-device link)'),
    ('16 execve("/opt/tool/run", ["run"], 0x0 /* 1 var */) = 0',
     '20 execve("/opt/tool/run", ["run"], 0x0 /* 1 var */) = -1 EACCES (Permission denied)'),
    ("16 setsid() = 16", "20 setsid() = -1 EPERM (Operation not permitted)"),
    ('16 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110) = 0',
     '20 connect(3<UNIX-STREAM:[9]>, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110) = -1 EACCES (Permission denied)'),
    ('16 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16) = 0',
     ('20 connect(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.7")}, 16)'
      ' = -1 EACCES (Permission denied)')),
    ('16 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0',
     ('20 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16)'
      ' = -1 EACCES (Permission denied)')),
])
def test_every_row_refused_in_a_replay_meets_what_its_success_recorded(succeeded, refused):
    snapshot = snapshot_with("/w", "/w/data.txt", "/a", "/b", "/a/x")
    recorded = needs.access_pairs(strace_parse.iter_calls([succeeded]), snapshot, "/w")
    [call] = strace_parse.iter_calls([refused])
    assert recorded
    assert needs.pairs_of_call(call, snapshot, "/w") & recorded


def test_a_refused_device_ioctl_meets_what_its_success_recorded():
    recorded = needs.access_pairs(strace_parse.iter_calls([
        '16 openat(AT_FDCWD</w>, "/dev/tty", O_RDWR) = 3</dev/tty<char 5:0>>',
        '16 ioctl(3</dev/tty<char 5:0>>, TCSETS, {c_iflag=ICRNL}) = 0']), snapshot_with("/dev/tty"), "/w")
    [call] = strace_parse.iter_calls(['20 ioctl(3</dev/tty<char 5:0>>, TCSETS, {c_iflag=ICRNL}) = -1 EACCES (Permission denied)'])
    assert needs.pairs_of_call(call, EMPTY, "/w") == {("ioctl TCSETS /dev/tty", "call")}
    assert needs.pairs_of_call(call, EMPTY, "/w") & recorded


def test_a_duplicate_of_the_inherited_terminal_is_no_device_of_the_session():
    result = needs_of("16 dup2(1</dev/pts/0<char 136:0>>, 2) = 2</dev/pts/0<char 136:0>>",
                      "16 ioctl(2</dev/pts/0<char 136:0>>, TCGETS, {c_iflag=ICRNL}) = 0", EMPTY)
    assert result.fixed == []


def test_a_file_another_process_removed_after_the_open_is_still_granted():
    result = needs_of('16 openat(AT_FDCWD</w>, "/w/x", O_RDWR) = 3</w/x (deleted)>', snapshot_with("/w", "/w/x"))
    assert sections_on(result, "/w/x") == {"read", "write"}


def test_a_netlink_datagram_socket_is_no_refusal():
    result = needs_of("16 socket(AF_NETLINK, SOCK_DGRAM|SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT) = 3<NETLINK:[1]>", EMPTY)
    assert result.fixed == []
    assert result.tolerated == []


def test_executing_through_proc_is_unsupported_rather_than_granted_on_proc():
    result = needs_of('16 execve("/proc/self/exe", ["x"], 0x0 /* 1 var */) = 0', EMPTY)
    assert result.needs == []
    assert len(result.unsupported) == 1


def test_a_name_reached_through_a_link_and_dot_dot_follows_the_link_first(tmp_path):
    real = tmp_path / "real" / "inner"
    real.mkdir(parents=True)
    (tmp_path / "w").mkdir()
    (tmp_path / "w" / "link").symlink_to(real)
    base = os.path.realpath(tmp_path)
    result = needs_of(f'16 mkdirat(AT_FDCWD</w>, "{tmp_path}/w/link/../made", 0777) = 0', snapshot_with(base + "/real"))
    assert sections_on(result, base + "/real") == {"create"}
