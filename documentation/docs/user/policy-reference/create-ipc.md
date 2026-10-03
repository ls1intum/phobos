---
title: "[create-ipc]"
sidebar_position: 6
description: "One path per line, granted the right to create UNIX sockets and named pipes beneath it."
---

:::tip[Simple Story]
Some tools talk to themselves through a pipe in the corner of the desk.

That is harmless and it is still a permission, so it is asked for by name rather than arriving
with the right to create ordinary files.
:::

## Position in the example policy file

The section documented on this page is marked in red. Every page in this section shows the same
example file, so reading them in order walks it from top to bottom.

```ini title="exercise.cfg"
# Every section this reference documents, gathered in one file so that each page can
# point at its own. A real policy names only what its command needs.

[read]
/srv/reference-data
/opt/toolchain

[execute]
/opt/toolchain

[write]
/var/tmp/workspace

[create]
/var/tmp/workspace

[delete]
/var/tmp/workspace

# policy-focus-start
[create-ipc]
/var/tmp/workspace/run
# policy-focus-end

[create-symlink]
/var/tmp/workspace/build

[restructure]
/var/tmp/workspace

[connect]
allow 192.0.2.10:443
allow repo.example.org:443
allow 203.0.113.53:53 udp

[bind]
allow 8080
allow 5353 udp

[accept]
expose 18080 to 8080 from 198.51.100.0/24

[limits]
timeout=120
mem_mb=2048
nproc=256
nofile=1024
fsize_mb=512
cpu=100
```

That file is a catalogue rather than a working configuration. Three of its entries change what
a run needs, and [the Policy Reference index](index.md) says which.

## Syntax

One path per line.

```ini
[create-ipc]
/var/tmp/workspace/run
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_SOCKET` | creating a UNIX-domain socket file |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_NAMED_PIPE` | creating a named pipe, or FIFO |

The rule carries the letter `p`.

## What enforces it

The path is materialised like a `[write]` path, and the rule is emitted as `--rights=p <path>`.

## Notes

**This is for local inter-process communication (IPC) objects alone.** A tool that needs a
control socket in its run directory gets this section and nothing more, so it does not gain the
right to create ordinary files there.

**A nested entry adds to its ancestor, it never narrows it.** In the example above,
`/var/tmp/workspace/run` lies beneath `/var/tmp/workspace`, which already holds write, create,
delete and the REFER right. Landlock unions the rights of every rule along a path, so the nested entry holds
those rights too, plus the socket and pipe rights it names. Writing a nested entry with a
strict subset of an ancestor's rights is refused outright, because such a restriction could not
hold.

**Reaching a socket is a different question from creating one.** Connecting to a pathname UNIX
socket whose server lives outside the Landlock domain is gated by `RESOLVE_UNIX`, which rides
with [`[read]`](read.md), and an abstract UNIX socket outside the sandbox is refused by scoping
from Landlock version 6.

## Further reading

- [`[create]`](create.md) — regular files and directories
- [Landlock](/contributor/technologies/landlock) — the scoping the ruleset applies
