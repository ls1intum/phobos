"""Landlock's own audit records, read as denials, checked against what strace attributed (A.3.1, A.6.9).

In a guest the pruner owns the kernel, so it can read the `AUDIT_LANDLOCK_ACCESS` record the kernel
writes for each refusal. The record names the missing rights (`blockers=`) and the object (`path=` for
the filesystem, a port for the network) exactly. This module turns such records into the same
`Denial` values attribute.py builds from strace, and compares the two:

* every Landlock denial strace attributed must have an audit record for the same object whose blockers
  map to sections strace asked for, or A.6.2's derivation of a right from a call is wrong for that call;
* audit denials strace did not attribute are reported, never granted;
* the only thing an audit record ever adds to a policy is a UDP bind row on a port the kernel names
  (abi10_rows), since the container kernels the default prune runs on do not handle that right.

The record's layout is the kernel's, as documented for the Landlock audit series (Linux 6.15). A
record that does not match it is kept as an `unparsed` entry for the report and never read as a denial.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable

from layer_prune import attribute, record

# The record type, as the kernel logs it (numeric in the printk fallback, symbolic from auditd).
RECORD_TYPES = ("LANDLOCK_ACCESS", "1423")
# The right every file system blocker names, mapped to the configuration sections that grant it (A.6.2).
FILESYSTEM_SECTIONS = {
    "fs.execute": frozenset({attribute.SECTION_EXECUTE}),
    "fs.write_file": frozenset({attribute.SECTION_WRITE}),
    "fs.read_file": frozenset({attribute.SECTION_READ}),
    "fs.read_dir": frozenset({attribute.SECTION_READ}),
    "fs.truncate": frozenset({attribute.SECTION_WRITE}),
    "fs.remove_dir": frozenset({attribute.SECTION_DELETE}),
    "fs.remove_file": frozenset({attribute.SECTION_DELETE}),
    "fs.make_reg": frozenset({attribute.SECTION_CREATE}),
    "fs.make_dir": frozenset({attribute.SECTION_CREATE}),
    "fs.make_sym": frozenset({attribute.SECTION_CREATE_SYMLINK}),
    "fs.make_sock": frozenset({attribute.SECTION_CREATE_IPC}),
    "fs.make_fifo": frozenset({attribute.SECTION_CREATE_IPC}),
    "fs.refer": frozenset({attribute.SECTION_RESTRUCTURE}),
}
# Blockers no section grants: a device ioctl, a device node, a pathname UNIX connect, a scope.
UNGRANTABLE_BLOCKERS = frozenset({"fs.ioctl_dev", "fs.make_char", "fs.make_block", "fs.resolve_unix",
                                  "scope.abstract_unix_socket", "scope.signal"})
BIND_UDP = "net.bind_udp"
NETWORK_BLOCKERS = frozenset({"net.bind_tcp", "net.connect_tcp", BIND_UDP, "net.connect_send_udp"})
# The keys a network record can carry its port under, by what the blocker does with it.
LOCAL_PORT_KEYS = ("lport", "src", "sport")
REMOTE_PORT_KEYS = ("dest", "fport", "dport")

# A UDP bind rule a row may be: a port from 1 to 65535 in ASCII digits, no leading zero, and the marker.
UDP_BIND_RULE = re.compile(r"allow ([1-9][0-9]{0,4}) udp", re.ASCII)
PORT_MAXIMUM = 65535
RECORD_PATTERN = re.compile(r"type=(?P<type>\w+)\b.*?audit\((?P<stamp>[0-9.]+):(?P<serial>\d+)\):\s*(?P<body>.*)$")
FIELD_PATTERN = re.compile(r'(?P<key>[a-z_]+)=(?:"(?P<quoted>[^"]*)"|(?P<bare>\S+))')


@dataclasses.dataclass(frozen=True)
class AuditRecord:
    """One Landlock access record: its domain, its blockers, and the object or port it names."""

    serial: int
    domain: str
    blockers: tuple[str, ...]
    path: str | None
    port: int | None
    raw: str


def decode_path(value: str) -> str:
    """The path of a `path=` field: audit writes a path holding an unprintable byte as upper-case hex."""
    if value and len(value) % 2 == 0 and re.fullmatch(r"[0-9A-F]+", value):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="surrogateescape")
        except ValueError:
            return value
    return value


def port_of(fields: dict[str, str], blockers: tuple[str, ...]) -> int | None:
    """The port a network record names: the local port for a bind, the remote one for a connect."""
    keys = LOCAL_PORT_KEYS if any(blocker.startswith("net.bind") for blocker in blockers) else REMOTE_PORT_KEYS
    for key in keys:
        if key in fields and fields[key].isdigit():
            return int(fields[key])
    return None


def parse_line(line: str) -> AuditRecord | None:
    """The record a line holds, or None when it is not a Landlock access record or does not read as one."""
    matched = RECORD_PATTERN.search(line)
    if matched is None or matched.group("type") not in RECORD_TYPES:
        return None
    fields: dict[str, str] = {}
    bare: set[str] = set()
    for found in FIELD_PATTERN.finditer(matched.group("body")):
        if found.group("quoted") is None:
            bare.add(found.group("key"))
        fields[found.group("key")] = found.group("quoted") if found.group("quoted") is not None else found.group("bare")
    if "domain" not in fields or "blockers" not in fields:
        return None
    blockers = tuple(blocker for blocker in fields["blockers"].split(",") if blocker)
    path = (decode_path(fields["path"]) if "path" in bare else fields["path"]) if "path" in fields else None
    return AuditRecord(serial=int(matched.group("serial")), domain=fields["domain"], blockers=blockers, path=path,
                       port=port_of(fields, blockers), raw=line.strip())


def parse(lines: Iterable[str]) -> tuple[list[AuditRecord], list[str]]:
    """Every Landlock access record in the lines, and the lines of that type that did not read as one."""
    records: list[AuditRecord] = []
    unparsed: list[str] = []
    for line in lines:
        found = parse_line(line)
        if found is not None:
            records.append(found)
        elif any(f"type={kind}" in line for kind in RECORD_TYPES):
            unparsed.append(line.strip())
    return records, unparsed


def sections_of(audit: AuditRecord) -> frozenset[str]:
    """The sections that would grant what a record's blockers name; empty where none can."""
    return frozenset().union(*(FILESYSTEM_SECTIONS.get(blocker, frozenset()) for blocker in audit.blockers))


def is_network(audit: AuditRecord) -> bool:
    """Whether a record names a network right."""
    return any(blocker in NETWORK_BLOCKERS for blocker in audit.blockers)


def denials(records: Iterable[AuditRecord], run: int = 0) -> list[record.Denial]:
    """The records as the denials attribute.py builds from strace: layer, object, sections and port."""
    found = []
    for audit in records:
        if is_network(audit):
            transport = "udp" if any(blocker.endswith("udp") for blocker in audit.blockers) else "tcp"
            operation = "bind" if any(blocker.startswith("net.bind") for blocker in audit.blockers) else "connect"
            found.append(record.Denial(pid=0, layer=record.LAYER_NETWORK, operation=operation, objects=(),
                                       sections=frozenset(), address=None, port=audit.port, transport=transport,
                                       errno="EACCES", run=run))
        elif audit.path is not None:
            found.append(record.Denial(pid=0, layer=record.LAYER_FILESYSTEM, operation="audit",
                                       objects=(audit.path,), sections=sections_of(audit), address=None, port=None,
                                       transport=None, errno="EACCES", run=run))
    return found


def agrees(attributed: record.Denial, audit: record.Denial) -> bool:
    """Whether an audit denial is the kernel's account of a strace denial.

    The same object, and sections that overlap with none left over: strace asks for every right the call
    could need (an open for reading and writing asks for both), while the kernel names only the ones the
    domain lacked, so the audit's sections are a non-empty part of strace's.
    """
    if not set(attributed.objects) & set(audit.objects):
        return False
    return bool(audit.sections) and audit.sections <= attributed.sections


def cross_check(strace_denials: Iterable[record.Denial], audit_denials: Iterable[record.Denial]) -> dict[str, list[dict]]:
    """Pairs each Landlock filesystem denial strace attributed with an audit denial; what is left over is reported.

    Each audit denial answers one strace denial at most, and strace denials that ask for fewer sections are
    paired first, so one that asks for more cannot take the record meant for them. `mismatches` are strace denials with no audit
    denial that agrees, which means A.6.2's derivation is wrong for that call; `audit_only` are filesystem
    audit denials no strace denial explains, reported and never granted.
    """
    unmatched = [denial for denial in audit_denials if denial.layer == record.LAYER_FILESYSTEM]
    mismatches = []
    for attributed in sorted(strace_denials, key=lambda denial: len(denial.sections)):
        if attributed.layer != record.LAYER_FILESYSTEM:
            continue
        partner = next((denial for denial in unmatched if agrees(attributed, denial)), None)
        if partner is None:
            mismatches.append({"operation": attributed.operation, "objects": list(attributed.objects),
                               "sections": sorted(attributed.sections),
                               "audit_for_object": [sorted(denial.sections) for denial in unmatched
                                                    if set(denial.objects) & set(attributed.objects)]})
        else:
            unmatched.remove(partner)
    return {"mismatches": mismatches,
            "audit_only": [{"objects": list(denial.objects), "sections": sorted(denial.sections)} for denial in unmatched]}


def udp_bind_ports(records: Iterable[AuditRecord]) -> set[int]:
    """The local ports the kernel says a UDP bind was refused on."""
    return {audit.port for audit in records if BIND_UDP in audit.blockers and audit.port is not None}


def abi10_rows(strace_bind_rules: Iterable[str], records: Iterable[AuditRecord], held: Iterable[str]) -> tuple[list[str], list[str]]:
    """The UDP bind rows to add, and the rules left that no row may carry.

    `strace_bind_rules` are the [bind] rules the observed run's strace refusals ask for (network.py has
    already applied the loopback-service condition). A UDP row is taken only when the kernel's own record
    names the same port as refused for `net.bind_udp`; any other rule asked for is returned as `other`,
    and the caller fails the job on it, since only this right differs between the kernels.
    """
    refused = udp_bind_ports(records)
    rows = []
    other = []
    for rule in strace_bind_rules:
        if rule in held:
            continue
        matched = UDP_BIND_RULE.fullmatch(rule)
        if matched is not None and int(matched.group(1)) <= PORT_MAXIMUM and int(matched.group(1)) in refused:
            rows.append(rule)
        else:
            other.append(rule)
    return rows, other
