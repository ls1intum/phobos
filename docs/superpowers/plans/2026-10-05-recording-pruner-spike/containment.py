"""Spike only. The forbidden direction: what no recorded session touched must stay refused.

Run under phobos.sh with the generated configuration. Each probe prints PROBE <name> <outcome>,
where the outcome is "refused <errno>" or "allowed". The first probe is a permitted neighbour,
so a run that refuses everything (a broken policy) is told apart from a tight one.
"""

from __future__ import annotations

import errno
import os
import socket


def read(path: str) -> None:
    """Opens the file for reading and reads it."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        handle.read()


def write(path: str) -> None:
    """Creates or opens the file for writing and writes one byte."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("x")


# Each probe: a name, and the action that the generated policy must refuse.
PROBES = (
    ("read-recorded-neighbour", lambda: read("/opt/java/openjdk/release")),
    ("read-unrecorded-etc-file", lambda: read("/etc/passwd")),
    ("read-unrecorded-system-file", lambda: read("/var/log/dpkg.log")),
    ("write-into-read-only-dir", lambda: write("/usr/share/doc/phobos-probe")),
    ("create-in-unrecorded-dir", lambda: os.mkdir("/var/tmp/phobos-probe")),
    ("connect-unrecorded-address", lambda: socket.create_connection(("10.0.0.1", 80), timeout=3)),
    ("bind-named-port", lambda: socket.socket().bind(("127.0.0.1", 8080))),
)


def main() -> None:
    """Runs every probe and prints its outcome."""
    for name, action in PROBES:
        try:
            action()
            outcome = "allowed"
        except OSError as failure:
            outcome = f"refused {errno.errorcode.get(failure.errno, failure.errno)}"
        print(f"PROBE {name} {outcome}", flush=True)


if __name__ == "__main__":
    main()
