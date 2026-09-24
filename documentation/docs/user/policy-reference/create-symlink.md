---
title: "[create-symlink]"
sidebar_position: 7
description: "One path per line, granted the right to create symbolic links beneath it."
---

:::tip[Simple Story]
A note that says "the thing you want is over there".

Writing such a note is a permission of its own. Following it changes nothing about where you
are allowed to go.
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

# policy-focus-start
[create-symlink]
/var/tmp/workspace/build
# policy-focus-end

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
[create-symlink]
/var/tmp/workspace/build
```

## What it grants

| Landlock right | What it permits |
| --- | --- |
| `LANDLOCK_ACCESS_FILESYSTEM_MAKE_SYMBOLIC_LINK` | creating a symbolic link |

The rule carries the letter `l`.

## What enforces it

The path is materialised like a `[write]` path, and the rule is emitted as `--rights=l <path>`.

## Notes

**A created link reaches nothing new.** A write through a symbolic link is resolved by the
kernel and checked against the link's target, so a link the command creates cannot reach a
path the policy does not name.

**A rule that may change something never follows a final link.** `phobos-landlock` opens such a
path with `O_NOFOLLOW`, and a changeable path that is itself a symbolic link is refused, so a
link cannot redirect a rule.

**A nested entry adds to its ancestor**, exactly as described on
[`[create-ipc]`](create-ipc.md).

## Further reading

- [`[create]`](create.md) — regular files and directories
- [`[write]`](write.md) — why a changeable rule refuses to follow a link
