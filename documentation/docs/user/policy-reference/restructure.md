---
title: "[restructure]"
sidebar_position: 8
description: "One path per line, granted create, delete and the REFER right together, so a tree may be rearranged."
---

:::tip[Simple Story]
Moving a sheet from one pile to another is not the same as copying it and burning the original.

The kernel treats a move as its own privilege, and so does Phobos: a tree that has to be
rearranged says so.
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

[create-ipc]
/var/tmp/workspace/run

[create-symlink]
/var/tmp/workspace/build

# policy-focus-start
[restructure]
/var/tmp/workspace
# policy-focus-end

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
[restructure]
/var/tmp/workspace
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_REGULAR_FILE`, `..._MAKE_DIRECTORY` | creating, as [`[create]`](create.md) |
| `LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE`, `..._REMOVE_DIRECTORY` | deleting, as [`[delete]`](delete.md) |
| `LANDLOCK_ACCESS_FILESYSTEM_REFER` | renaming or hard-linking across directories, from version 2 |

The rule carries the letters `m`, `d` and `f`. A path listed here needs no entry in `[create]`
or `[delete]`.

## What enforces it

The parser writes the path into the create, the delete and the refer path set at once, so the
filesystem layer emits one rule carrying all three letters.

## Notes

**REFER is not derived from create plus delete.** It governs the rename and link
privilege-escalation surface Landlock guards, so a policy grants it deliberately rather than
gaining it as a side effect. Both sides of a rename have to hold it.

**Without REFER the kernel answers `EXDEV`.** On a kernel below Landlock version 2 the right
does not exist at all, and every rename across directories is refused even where the policy
permits both sides. That breaks a build loudly rather than weakening the sandbox quietly, so
`phobos-landlock` reports it as a note rather than as a warning.

**A tool that moves a temporary file into place needs this.** Writing to `out.tmp` and renaming
it to `out` is the common shape, and it fails with `EXDEV` under `[write]`, `[create]` and
`[delete]` alone when the two names sit in different directories.

## Further reading

- [`[create]`](create.md) and [`[delete]`](delete.md) — the two halves this section carries too
- [Landlock](/contributor/technologies/landlock) — what REFER guards
