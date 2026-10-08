"""Checks the control replay: whether a refused access also fails outside every Landlock domain.

A replay that fails outside the sandbox means the refusal was not Landlock's (a mode, an owner, a
mount), so granting would not help and the denial must never become a grant. Every case is built in
a temporary directory, so nothing outside it is opened, created or changed.
"""

from __future__ import annotations

import os
import pathlib
import socket
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "pruner" / "src"))

from layer_prune import (
    attribute,
    control,
    record,
)


def denial(objects: tuple[str, ...], sections: frozenset[str], layer: str = record.LAYER_FILESYSTEM,
           errno: str = "EACCES") -> record.Denial:
    """A denial of the given objects and sections, as attribute.denials would build it."""
    return record.Denial(pid=1, layer=layer, operation="openat", objects=objects, sections=sections,
                         address=None, port=None, transport=None, errno=errno)


def read_denial(path: str) -> record.Denial:
    """A refused read of one path."""
    return denial((path,), frozenset({attribute.SECTION_READ}))


def running_as_root() -> bool:
    """Whether DAC cannot refuse anything here, because the tests run as root."""
    return os.geteuid() == 0


def test_a_file_the_uid_cannot_read_is_not_landlock_caused(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("x")
    secret.chmod(0)
    if running_as_root():
        pytest.skip("root reads a mode-000 file, so DAC cannot refuse here")
    assert control.landlock_caused(read_denial(str(secret))) is False


def test_a_readable_file_refused_in_the_sandbox_is_landlock_caused(tmp_path):
    readable = tmp_path / "readable"
    readable.write_text("x")
    assert control.landlock_caused(read_denial(str(readable))) is True


def test_a_readable_directory_is_landlock_caused(tmp_path):
    assert control.landlock_caused(read_denial(str(tmp_path))) is True


def test_a_symbolic_link_is_replayed_on_its_target_and_never_followed_by_the_replay(tmp_path):
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert control.landlock_caused(read_denial(str(link))) is True


def test_a_path_that_no_longer_exists_cannot_be_confirmed(tmp_path):
    assert control.landlock_caused(read_denial(str(tmp_path / "gone"))) is False


def test_a_writable_file_is_landlock_caused_and_is_not_truncated(tmp_path):
    output = tmp_path / "out"
    output.write_text("keep")
    assert control.landlock_caused(denial((str(output),), frozenset({attribute.SECTION_WRITE}))) is True
    assert output.read_text() == "keep"


def test_a_read_only_file_refused_for_writing_is_not_landlock_caused(tmp_path):
    output = tmp_path / "out"
    output.write_text("keep")
    output.chmod(0o444)
    if running_as_root():
        pytest.skip("root writes a read-only file, so DAC cannot refuse here")
    assert control.landlock_caused(denial((str(output),), frozenset({attribute.SECTION_WRITE}))) is False


def test_a_writable_device_is_checked_without_being_opened():
    assert control.landlock_caused(denial(("/dev/null",), frozenset({attribute.SECTION_WRITE}))) is True


def test_a_writable_directory_allows_a_creation_and_is_left_as_it_was(tmp_path):
    assert control.landlock_caused(denial((str(tmp_path),), frozenset({attribute.SECTION_CREATE}))) is True
    assert list(tmp_path.iterdir()) == []


def test_a_creation_in_a_directory_the_run_created_is_replayed_in_its_nearest_existing_ancestor(tmp_path):
    missing = tmp_path / "build" / "classes"
    assert control.landlock_caused(denial((str(missing),), frozenset({attribute.SECTION_CREATE}))) is True
    assert list(tmp_path.iterdir()) == []


def test_a_read_only_directory_refuses_a_creation(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o555)
    if running_as_root():
        pytest.skip("root creates in a read-only directory, so DAC cannot refuse here")
    try:
        assert control.landlock_caused(denial((str(locked),), frozenset({attribute.SECTION_CREATE}))) is False
    finally:
        locked.chmod(0o755)


def test_an_executable_is_landlock_caused_and_a_plain_file_is_not(tmp_path):
    tool = tmp_path / "tool"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o755)
    plain = tmp_path / "plain"
    plain.write_text("x")
    plain.chmod(0o644)
    sections = frozenset({attribute.SECTION_EXECUTE, attribute.SECTION_READ})
    assert control.landlock_caused(denial((str(tool),), sections)) is True
    assert control.landlock_caused(denial((str(plain),), sections)) is False


def test_a_rename_between_two_parents_on_one_filesystem_is_landlock_caused(tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    refer = denial((str(first), str(second)), frozenset({attribute.SECTION_RESTRUCTURE}), errno="EXDEV")
    assert control.landlock_caused(refer) is True


def test_a_rename_between_two_filesystems_is_the_filesystems_own_exdev(tmp_path):
    if os.stat(tmp_path).st_dev == os.stat("/dev").st_dev:
        pytest.skip("the temporary directory and /dev share a device here")
    refer = denial((str(tmp_path), "/dev"), frozenset({attribute.SECTION_RESTRUCTURE}), errno="EXDEV")
    assert control.landlock_caused(refer) is False


def bind_denial(port: int) -> record.Denial:
    """A refused bind of one TCP port on any IPv4 address."""
    return record.Denial(pid=1, layer=record.LAYER_NETWORK, operation="bind", objects=(),
                         sections=frozenset({attribute.SECTION_BIND}), address="0.0.0.0", port=port,
                         transport="tcp", errno="EACCES")


def free_port() -> int:
    """A loopback TCP port nothing holds right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_refused_bind_of_a_port_the_uid_may_bind_is_landlock_caused():
    assert control.landlock_caused(bind_denial(free_port())) is True
    assert control.landlock_caused(bind_denial(0)) is True


def test_a_refused_bind_of_a_port_the_kernel_refuses_this_uid_is_not_landlock_caused():
    privileged = 80
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", privileged))
    except PermissionError:
        assert control.landlock_caused(bind_denial(privileged)) is False
        return
    except OSError:
        pytest.skip("port 80 is held here, so the kernel's own refusal cannot be shown")
    pytest.skip("this uid may bind port 80 here, so the kernel's own refusal cannot be shown")


def connect_denial(address: str, port: int, transport: str) -> record.Denial:
    """A refused connect or datagram to one destination."""
    return record.Denial(pid=1, layer=record.LAYER_NETWORK, operation="connect", objects=(),
                         sections=frozenset({attribute.SECTION_CONNECT}), address=address, port=port,
                         transport=transport, errno="EACCES")


def test_a_refused_connect_to_a_destination_the_kernel_lets_the_uid_address_is_landlock_caused():
    assert control.landlock_caused(connect_denial("10.0.0.1", 80, "tcp")) is True
    assert control.landlock_caused(connect_denial("127.0.0.1", free_port(), "tcp")) is True


def test_a_refused_datagram_to_a_destination_the_kernel_refuses_is_not_landlock_caused():
    broadcast = "255.255.255.255"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((broadcast, 9))
    except PermissionError:
        assert control.landlock_caused(connect_denial(broadcast, 9, "udp")) is False
        return
    except OSError:
        pytest.skip("the broadcast address is unreachable here, so the kernel's own refusal cannot be shown")
    pytest.skip("the kernel lets this uid address the broadcast address here")


def test_a_refused_connect_without_a_destination_is_never_landlock_caused():
    assert control.landlock_caused(record.Denial(
        pid=1, layer=record.LAYER_NETWORK, operation="sendto", objects=(), sections=frozenset({attribute.SECTION_CONNECT}),
        address=None, port=None, transport="udp", errno="EACCES")) is False


def test_the_fixed_limit_and_other_layers_are_never_landlock_caused():
    for layer in (record.LAYER_FIXED, record.LAYER_LIMIT, record.LAYER_OTHER):
        assert control.landlock_caused(denial(("/dev/null",), frozenset(), layer=layer)) is False


@pytest.mark.parametrize(("path", "replayed"), [
    ("/proc/412/status", "/proc/self/status"),
    ("/proc/412", "/proc/self"),
    ("/proc/412/task/413/stat", "/proc/thread-self/stat"),
    ("/proc/412/fd/7", "/proc/self/fd"),
    ("/proc/412/fdinfo/7", "/proc/self/fdinfo"),
    ("/proc/413/status", "/proc/413/status"),
    ("/proc/sys/kernel/pid_max", "/proc/sys/kernel/pid_max"),
    ("/proc/0412/status", "/proc/0412/status"),
    ("/etc/hosts", "/etc/hosts"),
])
def test_the_refusing_process_s_own_entry_is_replayed_on_the_pruner_s_and_no_other(path, replayed):
    assert control.own_equivalent(path, 412) == replayed


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="needs procfs")
def test_a_refused_read_of_an_exited_process_s_status_is_landlock_caused():
    exited = max(int(entry) for entry in os.listdir("/proc") if entry.isdigit()) + 100000
    assert not os.path.exists(f"/proc/{exited}")
    own = record.Denial(pid=exited, layer=record.LAYER_FILESYSTEM, operation="openat", objects=(f"/proc/{exited}/status",),
                        sections=frozenset({attribute.SECTION_READ}), address=None, port=None, transport=None,
                        errno="EACCES")
    assert control.landlock_caused(own) is True
    assert control.landlock_caused(read_denial(f"/proc/{exited}/status")) is False
