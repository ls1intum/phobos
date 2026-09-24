---
title: "[read]"
sidebar_position: 1
description: "One path per line, granted the right to read a file and list a directory beneath it."
---

:::tip[Simple Story]
This is the list of drawers that open.

Opening one is not permission to change what is inside. Reading, replacing, creating, running
and destroying are separate permissions, each granted on its own.
:::

## Position in the example policy file

The section documented on this page is marked in red. Every page in this section shows the same
example file, so reading them in order walks it from top to bottom.

```ini title="exercise.cfg"
# Every section this reference documents, gathered in one file so that each page can
# point at its own. A real policy names only what its command needs.

# policy-focus-start
[read]
/srv/reference-data
/opt/toolchain
# policy-focus-end

[execute]
/opt/toolchain

[write]
/var/tmp/workspace

[create]
/var/tmp/workspace

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

One path per line. Everything from a `#` to the end of the line is a comment, in every section.

```ini
[read]
/srv/reference-data
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_READ_FILE` | opening a file for reading |
| `LANDLOCK_ACCESS_FILESYSTEM_READ_DIRECTORY` | listing a directory |
| `LANDLOCK_ACCESS_FILESYSTEM_RESOLVE_UNIX` | reaching a pathname UNIX socket whose server was created outside this Landlock domain, from version 9 |

The rule carries the letter `r`, and it applies to the path and everything beneath it. Landlock
grants a whole subtree and cannot carve an exception inside it.

`RESOLVE_UNIX` rides with the read right on purpose: reaching such a socket by its pathname is
a read-like resolution, so a path you may read, you may reach the sockets beneath, and a path
you may not read, you may not.

## What enforces it

`phobos-filesystem.sh` collects the path, resolves it through its symbolic links and emits
`--rights=r <path>` for `phobos-landlock`, which opens the path with `O_PATH` and adds one
`LANDLOCK_RULE_PATH_BENEATH` rule. The kernel enforces it from `landlock_restrict_self`
onwards, and neither the command nor anything it starts can regain the access.

## Notes

**A read path that does not exist is dropped without a word.** A system path absent from this
image is not a policy error, so the entry disappears rather than ending the run. A changeable
path is treated the other way round: see [`[write]`](write.md).

**Reading is not executing.** A program tree needs both `[read]` and `[execute]`; a pure data
tree needs only `[read]`. An interpreted script needs `[read]` on the script and `[execute]` on
the interpreter.

**A denied path stays visible.** Landlock withholds access rather than building a new view of
the filesystem, so the name of a path the policy never granted remains readable. The discovery
phase hides a directory; a protected run refuses it.

## Further reading

- [`[execute]`](execute.md) — the other half of a program tree
- [Reading a data tree](/user/policy-cookbook/reading-a-data-tree) — the recipe
- [Landlock](/contributor/technologies/landlock) — the rights and the versions they arrived in
