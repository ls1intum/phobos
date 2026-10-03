---
title: "[create]"
sidebar_position: 4
description: "One path per line, granted the right to create regular files and directories beneath it."
---

:::tip[Simple Story]
Adding a sheet of paper to the pile.

Not a socket, not a pipe, not a link, and never a device. Each of those is a separate
permission, because each carries a different risk.
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

# policy-focus-start
[create]
/var/tmp/workspace
# policy-focus-end

[delete]
/var/tmp/workspace

[create-ipc]
/var/tmp/workspace/run

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
[create]
/var/tmp/workspace
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE` | creating a regular file |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_DIRECTORY` | creating a directory |

The rule carries the letter `m`.

## What enforces it

The path is materialised like a `[write]` path, and the rule is emitted as `--rights=m <path>`.

## Notes

**Creating a device node is never granted.** A character or block device reaches hardware the
policy never named, and no build tool needs one, so the right stays in the handled set and is
denied rather than left unregulated. There is no section that grants it.

**Sockets, named pipes and symbolic links have their own sections.** They were once part of one
blanket create right; they are now [`[create-ipc]`](create-ipc.md) and
[`[create-symlink]`](create-symlink.md), so a policy that needs one of them does not gain the
others.

**Creating is not moving.** Creating a file in one directory and deleting it in another is not
a rename. Landlock requires the REFER right for a rename or a hard link across directories, and
that right is granted only by [`[restructure]`](restructure.md).

## Further reading

- [`[restructure]`](restructure.md) — create, delete and move together
- [Writing an output file](/user/policy-cookbook/writing-an-output-file) — the recipe
