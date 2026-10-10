"""Host names recovered from what a recorded session sent and received.

The system calls only show addresses, so a name comes from one of three sources, in this order
of trust: the TLS host name (SNI) of a ClientHello the program wrote, which is the name the
egress broker checks at grading time; the A and AAAA answers of a DNS response the program read,
mapped to the name it asked; and the hosts file as it was before the first session.

Everything here is written by the program or by the network, so each parser survives malformed
input without raising and returns names raw, every byte kept. Whether a name may become a rule is
decided by valid_hostname alone, which every caller applies first; a name it refuses is never a
rule, and the address is used instead.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct

# A DNS message's header: id, flags, and the four section counts, each 16 bits.
DNS_HEADER = struct.Struct("!HHHHHH")

# A resource record after its owner name: type, class, time to live and data length.
DNS_RECORD = struct.Struct("!HHIH")

# The flag that marks a DNS message as a response rather than a query.
DNS_RESPONSE_FLAG = 0x8000

# The record types read from an answer section.
DNS_TYPE_A = 1
DNS_TYPE_CNAME = 5
DNS_TYPE_AAAA = 28

# The class every answer read here must carry: the Internet.
DNS_CLASS_IN = 1

# The two top bits of a length byte that mark a compression pointer instead of a label, and the
# bits that remain of that byte as the high part of the pointer's offset.
DNS_POINTER_BITS = 0xC0
DNS_POINTER_HIGH_BITS = 0x3F

# The longest a name may be on the wire, in bytes, length bytes included.
DNS_NAME_MAX_BYTES = 255

# How many compression pointers one name may follow; each must also point backwards.
DNS_MAX_JUMPS = 32

# A TLS record carrying a handshake, and the handshake message that opens one.
TLS_HANDSHAKE_RECORD = 22
TLS_CLIENT_HELLO = 1

# The extension that carries the server name, and the name type for a host name within it.
TLS_SERVER_NAME_EXTENSION = 0
TLS_HOST_NAME_TYPE = 0

# A TLS record's header: content type, legacy version and length.
TLS_RECORD_HEADER_BYTES = 5

# The client version and random that open a ClientHello's body.
TLS_HELLO_FIXED_BYTES = 2 + 32

# The longest a host name may be, in characters (RFC 1035).
HOSTNAME_MAX_LENGTH = 253

# One label of a host name: 1 to 63 letters, digits and hyphens, a hyphen at neither end (RFC 1123).
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# A label of digits only, which no top-level domain is.
NUMERIC_LABEL = re.compile(r"^[0-9]+$")


class _Malformed(Exception):
    """Raised inside a parser when the input ends early or breaks its format; never escapes."""


def dns_answers(message: bytes) -> list[tuple[str, str]]:
    """The A and AAAA addresses of a DNS response, each with the name its question asked.

    Assumes message is one DNS message as the program received it. Only a response with exactly
    one question is read, and only an address owned by the asked name or by a name a CNAME of the
    same answer section leads to from it, so an address the resolver added for another name is
    not attributed. Answers before a point where the message breaks off are kept. Never raises.
    """
    try:
        return _answers(message)
    except _Malformed:
        return []


def client_hello_server_name(record: bytes) -> str | None:
    """The host name a TLS ClientHello presents in its server name extension, or None.

    Assumes record holds the first bytes the program wrote on a stream socket. Anything that is
    not a complete handshake record opening with a ClientHello, or holds no host name, gives None.
    The name is returned raw, every byte as one character. Never raises.
    """
    try:
        return _server_name(record)
    except _Malformed:
        return None


def hosts_file(text: str) -> dict[str, str]:
    """Every address of a hosts file mapped to the first name given for it.

    Assumes text is the file's contents. A line whose first field is not an address, or that
    names no host, is skipped; the first line for an address wins, as a lookup by address would
    answer. Addresses are written as Python's ipaddress writes them. Names are returned raw.
    """
    mapping = {}
    for line in text.split("\n"):
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            continue
        mapping.setdefault(address, fields[1])
    return mapping


def valid_hostname(name: str) -> str | None:
    """The name lower-cased when it is a plain DNS host name that may become a rule, else None.

    Assumes nothing about name. A plain name has labels of 1 to 63 letters, digits and hyphens,
    neither starting nor ending with a hyphen, at most 253 characters in all, no trailing dot, and
    is not an address. A last label of digits only is refused as well, since no top-level domain
    is numeric and the policy parser refuses a name made of digits and dots as a malformed address.
    """
    lowered = name.lower()
    if not lowered or len(lowered) > HOSTNAME_MAX_LENGTH or not lowered.isascii():
        return None
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        pass
    else:
        return None
    labels = lowered.split(".")
    if not all(LABEL.match(label) for label in labels) or NUMERIC_LABEL.match(labels[-1]):
        return None
    return lowered


def rule_hostname(name: str) -> str | None:
    """The name when it may stand in a rule for a host the session reached, else None.

    valid_hostname's grammar, and also not localhost or beneath it (which names the loopback, not the
    address that was reached) and not a spelling the C library reads as an address (`0x7f.1`, a number).
    """
    valid = valid_hostname(name)
    if valid is None or valid == "localhost" or valid.endswith(".localhost"):
        return None
    try:
        socket.inet_aton(valid)
    except OSError:
        return valid
    return None


def _answers(message: bytes) -> list[tuple[str, str]]:
    """dns_answers' work, raising _Malformed where the header or question cannot be read.

    Assumes nothing about message.
    """
    _, flags, questions, answers, _, _ = _unpack(DNS_HEADER, message, 0)
    if not flags & DNS_RESPONSE_FLAG or questions != 1:
        return []
    asked, offset = _dns_name(message, DNS_HEADER.size)
    offset += 4
    aliases = {asked.lower()}
    found = []
    for _ in range(answers):
        try:
            owner, offset = _dns_name(message, offset)
            record_type, record_class, _, length = _unpack(DNS_RECORD, message, offset)
            start = offset + DNS_RECORD.size
            offset = start + length
            if offset > len(message):
                break
        except _Malformed:
            break
        if record_class != DNS_CLASS_IN or owner.lower() not in aliases:
            continue
        address = _address(record_type, message[start:offset])
        if address is not None:
            found.append((address, asked))
        elif record_type == DNS_TYPE_CNAME:
            try:
                aliases.add(_dns_name(message, start)[0].lower())
            except _Malformed:
                break
    return found


def _address(record_type: int, data: bytes) -> str | None:
    """The address an A or AAAA record's data holds, or None for any other record or length."""
    if record_type == DNS_TYPE_A and len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if record_type == DNS_TYPE_AAAA and len(data) == 16:
        return str(ipaddress.IPv6Address(data))
    return None


def _dns_name(message: bytes, offset: int) -> tuple[str, int]:
    """Reads a possibly compressed name at offset; answers it and the offset after it.

    Assumes nothing about message. A compression pointer must point before the label it replaces,
    which rules out loops, and at most DNS_MAX_JUMPS are followed. Each label is kept byte for
    byte, a dot or backslash inside it written as `\\.` or `\\\\` as DNS presentation format does, so
    one label can never read as two. Raises _Malformed when the name breaks off or breaks a rule.
    """
    labels = []
    end = None
    jumps = 0
    wire_bytes = 0
    while True:
        length = _byte(message, offset)
        if length & DNS_POINTER_BITS == DNS_POINTER_BITS:
            target = ((length & DNS_POINTER_HIGH_BITS) << 8) | _byte(message, offset + 1)
            jumps += 1
            if target >= offset or jumps > DNS_MAX_JUMPS:
                raise _Malformed
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & DNS_POINTER_BITS:
            raise _Malformed
        wire_bytes += 1 + length
        if wire_bytes > DNS_NAME_MAX_BYTES:
            raise _Malformed
        if length == 0:
            return ".".join(labels), (end if end is not None else offset + 1)
        label = message[offset + 1:offset + 1 + length]
        if len(label) != length:
            raise _Malformed
        labels.append(label.decode("latin-1").replace("\\", "\\\\").replace(".", "\\."))
        offset += 1 + length


def _server_name(record: bytes) -> str | None:
    """client_hello_server_name's work, raising _Malformed where the hello cannot be read.

    Assumes nothing about record. Every length is checked against the end of the record.
    """
    if _byte(record, 0) != TLS_HANDSHAKE_RECORD:
        return None
    end = min(len(record), TLS_RECORD_HEADER_BYTES + _uint(record, 3, 2))
    offset = TLS_RECORD_HEADER_BYTES
    if _byte(record, offset) != TLS_CLIENT_HELLO:
        return None
    end = min(end, offset + 4 + _uint(record, offset + 1, 3))
    offset += 4 + TLS_HELLO_FIXED_BYTES
    offset += 1 + _byte(record, offset)
    offset += 2 + _uint(record, offset, 2)
    offset += 1 + _byte(record, offset)
    extensions_end = min(end, offset + 2 + _uint(record, offset, 2))
    offset += 2
    while offset + 4 <= extensions_end:
        kind = _uint(record, offset, 2)
        length = _uint(record, offset + 2, 2)
        if offset + 4 + length > extensions_end:
            raise _Malformed
        if kind == TLS_SERVER_NAME_EXTENSION:
            return _host_name(record[offset + 4:offset + 4 + length])
        offset += 4 + length
    return None


def _host_name(extension: bytes) -> str | None:
    """The first host name in a server name extension's data, or None when it holds none.

    Assumes extension is the extension's data, already cut to its declared length.
    """
    end = min(len(extension), 2 + _uint(extension, 0, 2))
    offset = 2
    while offset + 3 <= end:
        kind = _byte(extension, offset)
        length = _uint(extension, offset + 1, 2)
        if offset + 3 + length > end:
            raise _Malformed
        if kind == TLS_HOST_NAME_TYPE:
            return extension[offset + 3:offset + 3 + length].decode("latin-1")
        offset += 3 + length
    return None


def _unpack(layout: struct.Struct, data: bytes, offset: int) -> tuple:
    """The fields of layout at offset; raises _Malformed when data ends before them."""
    if offset + layout.size > len(data):
        raise _Malformed
    return layout.unpack_from(data, offset)


def _byte(data: bytes, offset: int) -> int:
    """The byte at offset; raises _Malformed when data ends before it."""
    if offset >= len(data):
        raise _Malformed
    return data[offset]


def _uint(data: bytes, offset: int, size: int) -> int:
    """The big-endian unsigned number of size bytes at offset; raises _Malformed past the end."""
    if offset + size > len(data):
        raise _Malformed
    return int.from_bytes(data[offset:offset + size], "big")
