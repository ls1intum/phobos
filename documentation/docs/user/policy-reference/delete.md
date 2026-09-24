---
title: "[delete]"
sidebar_position: 5
description: "One path per line, granted the right to delete files and directories beneath it."
---

:::tip[Simple Story]
Throwing a sheet away.

Separate from writing on it, and separate from adding a new one, so a policy that only produces
output never gains the right to destroy what was there.
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

# policy-focus-start
[delete]
/var/tmp/workspace
# policy-focus-end

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
[delete]
/var/tmp/workspace
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_REMOVE_FILE` | deleting a file |
| `LANDLOCK_ACCESS_FILESYSTEM_REMOVE_DIRECTORY` | deleting a directory |

The rule carries the letter `d`.

## What enforces it

The path is materialised like a `[write]` path, and the rule is emitted as `--rights=d <path>`.

## Notes

**A build tree usually needs all three.** A tool that rebuilds in place writes, creates and
deletes, so its scratch directory is named in `[write]`, `[create]` and `[delete]`, or in
[`[restructure]`](restructure.md) where it moves files too.

**Deleting is not moving.** See [`[restructure]`](restructure.md).

## Further reading

- [`[restructure]`](restructure.md) — create, delete and move together
